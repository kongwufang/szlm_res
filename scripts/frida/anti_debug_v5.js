'use strict';
// anti_debug_v4.js — v3 + 过滤 /proc/self/maps 内容

// ★ v4 新增（依据）：
//   v3 的钩子都装上了（prctl/kill/exit/open/strstr/ptrace），但连接仍被杀
//   => 说明检测点不在这些调用上
//   => 最可能是：app 读 /proc/self/maps（合法路径，我们没拦）并【扫描内容】
//      找 "frida-agent" / "memfd:frida" / "gum" 之类
//   => 对策：挂钩 read()，当读的是 maps 类文件时，把含 frida 的行【过滤掉】
//
// 过滤目标（maps 里的特征）：
//   /memfd:frida-agent-64.so (deleted)
//   /data/local/tmp/fs
//   frida-helper-*.dex
//   .gum / gum-js-loop
const LOG = (m) => send(String(m));

const DIRS = ['/data/data/com.coolapk.market/files/cap',
              '/data/data/com.coolapk.market/files',
              '/data/local/tmp'];
const RESOLVER = 0x1143BC;
const ENC_ENTRY = 0x0E123C;
const ENC_LOOP = 0x0E1994;
const PRCTL_MAGIC = 0x53564D41;

let tokMap = {}, tokOrder = [];
let encEvents = [], initEvents = [], adEvents = [];
let loopHits = 0, libduSeen = false, javaHooked = false;
let blocked = 0, filtered = 0;
let myPid = Process.id;
let origPrctl = null, origKill = null;
let mapsFds = {};       // fd -> 是否 maps 类文件
let nameFds = {};       // fd -> 路径

const BAD = /frida|gum|gadget|substrate|linjector|re\.frida|memfd:frida|flymed|magisk/i;

function save(name, txt) {
    for (let i = 0; i < DIRS.length; i++) {
        try {
            const f = new File(DIRS[i] + '/' + name, 'w');
            f.write(txt); f.flush(); f.close(); return DIRS[i];
        } catch (e) { }
    }
    return null;
}

function dump(tag) {
    const L = [];
    L.push('# pid=' + myPid + ' libdu=' + (libduSeen ? 'YES' : 'no')
        + ' blocked=' + blocked + ' filtered=' + filtered);
    L.push('# === antidbg ' + adEvents.length + ' ===');
    adEvents.slice(-150).forEach((x) => L.push('AD\t' + x));
    L.push('# === init ' + initEvents.length + ' ===');
    initEvents.slice(-300).forEach((x) => L.push('INIT\t' + x));
    L.push('# === tokens ' + tokOrder.length + ' ===');
    tokOrder.forEach((t) => L.push('TOK\t0x' + t.toString(16) + '\t' + JSON.stringify(tokMap[t])));
    L.push('# === enc ' + encEvents.length + ' loop=' + loopHits + ' ===');
    encEvents.forEach((x) => L.push('ENC\t' + x));
    const p = save('AD4_' + tag + '_' + myPid + '.txt', L.join('\n'));
    LOG('DONE ' + p + ' ad=' + adEvents.length + ' init=' + initEvents.length
        + ' tok=' + tokOrder.length + ' enc=' + encEvents.length
        + ' blocked=' + blocked + ' filtered=' + filtered);
}

function hexOf(p, n) {
    try {
        const b = new Uint8Array(p.readByteArray(n));
        let h = '', a = '';
        for (let i = 0; i < b.length; i++) {
            h += ('0' + b[i].toString(16)).slice(-2);
            a += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : '.';
        }
        return { hex: h, asc: a };
    } catch (e) { return { hex: '?', asc: '?' }; }
}

function lu() {
    let m = Process.findModuleByName('libdu.so');
    if (m) return m;
    try {
        const all = Process.enumerateModules();
        for (let i = 0; i < all.length; i++) {
            if ((all[i].path || '').indexOf('libdu') >= 0) return all[i];
        }
    } catch (e) { }
    return null;
}

// ════ ★★★ maps 内容过滤 ════
function installMapsFilter() {
    const openA = Module.findExportByName(null, 'open');
    const openatA = Module.findExportByName(null, 'openat');
    const fopenA = Module.findExportByName(null, 'fopen');

    function trackOpen(ret, path) {
        try {
            const fd = ret.toInt32();
            if (fd >= 0 && path) {
                nameFds[fd] = path;
                if (/\/maps|\/smaps|task\/\d+\/maps/i.test(path)) {
                    mapsFds[fd] = true;
                    LOG('[maps] app 打开了 ' + path + ' fd=' + fd);
                }
            }
        } catch (e) { }
    }

    if (openA) {
        try {
            Interceptor.attach(openA, {
                onEnter(a) { try { this.p = a[0].readCString(); } catch (e) { this.p = null; } },
                onLeave(r) { trackOpen(r, this.p); }
            });
        } catch (e) { }
    }
    if (openatA) {
        try {
            Interceptor.attach(openatA, {
                onEnter(a) { try { this.p = a[1].readCString(); } catch (e) { this.p = null; } },
                onLeave(r) { trackOpen(r, this.p); }
            });
        } catch (e) { }
    }
    if (fopenA) {
        try {
            Interceptor.attach(fopenA, {
                onEnter(a) { try { this.p = a[0].readCString(); } catch (e) { this.p = null; } },
                onLeave(r) {
                    if (this.p && /\/maps|\/smaps/i.test(this.p)) {
                        LOG('[maps] fopen ' + this.p + ' -> ' + r);
                        mapsFds[r.toString()] = true;
                    }
                }
            });
        } catch (e) { }
    }

    // read()：过滤 maps 内容
    const readA = Module.findExportByName(null, 'read');
    if (readA) {
        try {
            Interceptor.attach(readA, {
                onEnter(a) {
                    this.fd = a[0].toInt32();
                    this.buf = a[1];
                    this.n = a[2].toInt32();
                },
                onLeave(r) {
                    const got = r.toInt32();
                    if (got <= 0) return;
                    if (!mapsFds[this.fd]) return;
                    try {
                        const s = this.buf.readUtf8String(got);
                        if (!s) return;
                        const lines = s.split('\n');
                        const keep = lines.filter(function (l) { return !BAD.test(l); });
                        if (keep.length === lines.length) return;
                        filtered++;
                        const out = keep.join('\n');
                        this.buf.writeUtf8String(out + '\u0000');
                        r.replace(ptr(out.length));
                    } catch (e) { }
                }
            });
            LOG('[ok] read（maps 过滤）');
        } catch (e) { }
    }

    // 也挂 fgets / getline（有些实现用它们读 maps）
    ['fgets'].forEach(function (nm) {
        const a = Module.findExportByName(null, nm);
        if (!a) return;
        try {
            Interceptor.attach(a, {
                onEnter(args) { this.buf = args[0]; },
                onLeave(r) {
                    if (r.isNull()) return;
                    try {
                        const s = this.buf.readCString();
                        if (s && BAD.test(s)) {
                            filtered++;
                            this.buf.writeUtf8String('\n');
                        }
                    } catch (e) { }
                }
            });
            LOG('[ok] ' + nm);
        } catch (e) { }
    });
}

// ════ Native 侧（同 v3）════
function installNative() {
    const prctlAddr = Module.findExportByName(null, 'prctl');
    if (prctlAddr) {
        try {
            origPrctl = new NativeFunction(prctlAddr, 'int',
                ['int', 'pointer', 'pointer', 'pointer', 'pointer']);
            Interceptor.replace(prctlAddr, new NativeCallback(function (op, a2, a3, a4, a5) {
                const o = op & 0xffffffff;
                if (o === PRCTL_MAGIC) { blocked++; adEvents.push('prctl(SVMA)'); return 0; }
                if (o === 4 && a2.toInt32() === 0) {
                    blocked++; adEvents.push('prctl(DUMPABLE,0)->1');
                    return origPrctl(4, ptr(1), a3, a4, a5);
                }
                return origPrctl(op, a2, a3, a4, a5);
            }, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']));
            LOG('[ok] prctl');
        } catch (e) { }
    }
    const killAddr = Module.findExportByName(null, 'kill');
    if (killAddr) {
        try {
            origKill = new NativeFunction(killAddr, 'int', ['int', 'int']);
            Interceptor.replace(killAddr, new NativeCallback(function (pid, sig) {
                if (pid === myPid || pid === -myPid) {
                    blocked++; adEvents.push('kill(' + pid + ',' + sig + ')');
                    return 0;
                }
                return origKill(pid, sig);
            }, 'int', ['int', 'int']));
            LOG('[ok] kill');
        } catch (e) { }
    }
    // ★★★ 关键：反调试用 tgkill/tkill 发 SIGTRAP（signal 5）
    //     logcat: "Fatal signal 5 (SIGTRAP), code -6 (SI_TKILL)"
    //     => 必须拦截 tgkill / tkill / raise / pthread_kill 里的 SIGTRAP
    const SIGTRAP = 5, SIGABRT = 6, SIGKILL = 9, SIGSEGV = 11;
    function mkFilter(name, sigIdx, tidIdx) {
        const a = Module.findExportByName(null, name);
        if (!a) { LOG('[--] ' + name + ' 不存在'); return null; }
        try {
            const orig = new NativeFunction(a, 'int', ['int', 'int', 'int']);
            Interceptor.replace(a, new NativeCallback(function (p1, p2, p3) {
                const sig = (sigIdx === 0) ? p1 : ((sigIdx === 1) ? p2 : p3);
                const tid = (tidIdx === 0) ? p1 : ((tidIdx === 1) ? p2 : p3);
                if (sig === SIGTRAP || sig === SIGABRT) {
                    blocked++;
                    adEvents.push(name + '(sig=' + sig + ', tid=' + tid + ') -> 拦截');
                    LOG('★★ 拦截 ' + name + '(sig=' + sig + ') #' + blocked);
                    return 0;
                }
                return orig(p1, p2, p3);
            }, 'int', ['int', 'int', 'int']));
            LOG('[ok] ' + name + '（拦截 SIGTRAP/SIGABRT）');
            return orig;
        } catch (e) { LOG('[x] ' + name + ': ' + e); return null; }
    }
    mkFilter('tgkill', 2, 1);      // tgkill(tgid, tid, sig)
    mkFilter('tkill', 1, 0);       // tkill(tid, sig)
    mkFilter('pthread_kill', 1, 0);// pthread_kill(thread, sig)

    // raise(sig) 单参数
    const raiseA = Module.findExportByName(null, 'raise');
    if (raiseA) {
        try {
            const origRaise = new NativeFunction(raiseA, 'int', ['int']);
            Interceptor.replace(raiseA, new NativeCallback(function (sig) {
                if (sig === SIGTRAP || sig === SIGABRT) {
                    blocked++; adEvents.push('raise(' + sig + ') -> 拦截');
                    LOG('★★ 拦截 raise(' + sig + ')');
                    return 0;
                }
                return origRaise(sig);
            }, 'int', ['int']));
            LOG('[ok] raise（拦截 SIGTRAP/SIGABRT）');
        } catch (e) { }
    }

    ['_exit', 'exit', 'abort'].forEach(function (nm) {
        const a = Module.findExportByName(null, nm);
        if (!a) return;
        try {
            Interceptor.attach(a, {
                onEnter() { blocked++; adEvents.push(nm); LOG('★ ' + nm); }
            });
        } catch (e) { }
    });
    const ss = Module.findExportByName(null, 'strstr');
    if (ss) {
        try {
            Interceptor.attach(ss, {
                onEnter(args) { try { this.n = args[1].readCString(); } catch (e) { } },
                onLeave(r) {
                    if (this.n && BAD.test(this.n)) {
                        blocked++; adEvents.push('strstr(' + this.n + ')');
                        try { r.replace(ptr(0)); } catch (e) { }
                    }
                }
            });
        } catch (e) { }
    }
    const pt = Module.findExportByName(null, 'ptrace');
    if (pt) {
        try {
            Interceptor.attach(pt, {
                onEnter(args) { if (args[0].toInt32() === 0) { this.b = true; blocked++; adEvents.push('ptrace'); } },
                onLeave(r) { if (this.b) { try { r.replace(ptr(0)); } catch (e) { } } }
            });
        } catch (e) { }
    }
    LOG('=== Native 就绪 ===');
}

// ════ Java 侧 ════
function hookJavaMisc() {
    try {
        const P = Java.use('android.os.Process');
        try {
            P.killProcess.overload('int').implementation = function (pid) {
                if (pid === myPid) { blocked++; adEvents.push('killProcess(' + pid + ')'); return; }
                return this.killProcess(pid);
            };
        } catch (e) { }
        try { P.exit.overload('int').implementation = function () { blocked++; adEvents.push('Process.exit'); }; } catch (e) { }
    } catch (e) { }
    try {
        const S = Java.use('java.lang.System');
        try { S.exit.overload('int').implementation = function () { blocked++; adEvents.push('System.exit'); }; } catch (e) { }
    } catch (e) { }
    // 过滤 Java 侧的 maps 读取
    try {
        const BR = Java.use('java.io.BufferedReader');
        // 不挂钩 Java 层（太慢），靠 native read 过滤已覆盖
    } catch (e) { }
}

function tryHookJava() {
    if (javaHooked) return;
    try {
        const Main = Java.use('cn.shuzilm.core.Main');
        javaHooked = true;
        ['init', 'setConfig', 'setData', 'onEvent', 'getQueryID', 'getDeviceLabel',
         'getVersion', 'getTraceInfo', 'optReport', 'getNetCode'].forEach(function (mn) {
            let ovs;
            try { ovs = Main[mn].overloads; } catch (e) { return; }
            ovs.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        const a = Array.prototype.slice.call(arguments);
                        let desc = '';
                        try {
                            desc = a.map(function (x) {
                                if (x === null || x === undefined) return 'null';
                                const s = String(x);
                                if (s.indexOf('@') === 0) {
                                    let pk = '';
                                    try { pk = x.getPackageName ? String(x.getPackageName()) : ''; } catch (e2) { }
                                    return 'Ctx(' + pk + ')';
                                }
                                return s.slice(0, 140);
                            }).join(' | ');
                        } catch (e) { }
                        initEvents.push('Main.' + mn + ' [' + desc + ']');
                        LOG('★★★ MAIN.' + mn + ' [' + desc.slice(0, 160) + ']');
                        const r = ov.apply(this, a);
                        try { LOG('     -> ' + String(r).slice(0, 180)); } catch (e) { }
                        dump('main_' + mn);
                        return r;
                    };
                } catch (e) { }
            });
        });
        LOG('[ok] ★ cn.shuzilm.core.Main');
    } catch (e) { }
}

function hookLibdu(m) {
    LOG('★ libdu base=' + m.base + ' size=' + m.size + ' pid=' + myPid);
    try {
        Interceptor.attach(m.base.add(RESOLVER), {
            onEnter(a) { this.t = a[0].toInt32() >>> 0; },
            onLeave(r) {
                const t = this.t;
                if (tokMap[t] === undefined) {
                    let s = null;
                    try { s = r.readCString(); } catch (e) { }
                    tokMap[t] = (s === null) ? '(非字符串)' : s;
                    tokOrder.push(t);
                    LOG('TOK 0x' + t.toString(16) + ' -> ' + JSON.stringify(tokMap[t]).slice(0, 150));
                }
            }
        });
        LOG('[ok] 解析器');
    } catch (e) { }
    try {
        Interceptor.attach(m.base.add(ENC_ENTRY), {
            onEnter(a) {
                const idx = encEvents.length;
                this.idx = idx;
                const r = hexOf(a[0], 48);
                encEvents.push('x0=' + a[0] + ' len=' + a[2].toInt32()
                    + ' in_hex=' + r.hex + ' in_asc=' + JSON.stringify(r.asc));
                LOG('★ENC[' + idx + '] len=' + a[2].toInt32() + ' in=' + JSON.stringify(r.asc));
            },
            onLeave(r) {
                const o = hexOf(r, 64);
                if (encEvents[this.idx]) encEvents[this.idx] += ' OUT=' + JSON.stringify(o.asc);
                LOG('★ENC[' + this.idx + '] OUT=' + JSON.stringify(o.asc));
                dump('enc' + this.idx);
            }
        });
        LOG('[ok] 编码器');
    } catch (e) { }
    try { Interceptor.attach(m.base.add(ENC_LOOP), { onEnter() { loopHits++; } }); } catch (e) { }
}

// ════ 启动 ════
installMapsFilter();     // ★ 先装过滤（在 read 被用之前）
installNative();

Java.perform(function () {
    LOG('=== anti_debug_v4 启动 pid=' + myPid + ' ===');
    hookJavaMisc();
    tryHookJava();

    let t = 0;
    (function poll() {
        t++;
        if (!libduSeen) {
            const m = lu();
            if (m) { libduSeen = true; hookLibdu(m); dump('libdu'); }
        }
        if (t % 300 === 0) tryHookJava();
        if (t < 500000) setImmediate(poll);
    })();

    let tick = 0;
    (function hb() {
        tick++;
        if (tick % 3000000 === 0) {
            LOG('[心跳] pid=' + myPid + ' libdu=' + (libduSeen ? 'YES' : 'no')
                + ' ad=' + adEvents.length + ' blocked=' + blocked + ' filtered=' + filtered
                + ' init=' + initEvents.length + ' tok=' + tokOrder.length + ' enc=' + encEvents.length);
            dump('hb' + (tick / 3000000));
        }
        if (tick < 90000000) setImmediate(hb);
    })();

    LOG('=== 就绪 ===');
});
