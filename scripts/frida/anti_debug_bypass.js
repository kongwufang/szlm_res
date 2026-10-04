'use strict';
// anti_debug_bypass.js — 先破反调试，再装抓取钩子
//
// ★★★ 本轮实测：
//   attach 能成功装上钩子，然后被 app 干掉（"connection is closed"）
//   抓到 prctl(1398164801, 0)  其中 1398164801 = 0x53564D41 = "SVMA"
//   => 加固壳的自定义 prctl 反调试点
//
// 本脚本顺序很重要：
//   ① 【先】安装反反调试拦截（prctl / open / readlink / strstr / syscall）
//   ② 再装抓取钩子（0x1143BC / 0x0E123C / Java Main）
//
// 拦截策略：
//   · prctl(0x53564D41, ...) -> 直接返回 0（不执行真实调用）
//   · open/openat 路径含 frida/gum/gadget/re.frida -> 返回 -1
//   · readlink/openat 对 /proc/self/maps、/proc/self/task -> 放行但记录
//   · strstr/strcmp 参数含 frida/gadget -> 返回 0（找不到）
//   · ptrace(PTRACE_TRACEME) -> 返回 0
const LOG = (m) => send(String(m));

const DIRS = ['/data/data/com.coolapk.market/files/cap',
              '/data/data/com.coolapk.market/files',
              '/data/local/tmp'];
const RESOLVER = 0x1143BC;
const ENC_ENTRY = 0x0E123C;
const ENC_LOOP = 0x0E1994;
const PRCTL_MAGIC = 0x53564D41;   // "SVMA"（小端读作 SVMA）

let tokMap = {}, tokOrder = [];
let encEvents = [], initEvents = [], adEvents = [];
let loopHits = 0, libduSeen = false, javaHooked = false;
let blocked = 0;

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
    L.push('# pid=' + Process.id + ' libdu=' + (libduSeen ? 'YES' : 'no') + ' blocked=' + blocked);
    L.push('# === antidbg ' + adEvents.length + ' ===');
    adEvents.slice(-80).forEach((x) => L.push('AD\t' + x));
    L.push('# === init ' + initEvents.length + ' ===');
    initEvents.slice(-200).forEach((x) => L.push('INIT\t' + x));
    L.push('# === tokens ' + tokOrder.length + ' ===');
    tokOrder.forEach((t) => L.push('TOK\t0x' + t.toString(16) + '\t' + JSON.stringify(tokMap[t])));
    L.push('# === enc ' + encEvents.length + ' loop=' + loopHits + ' ===');
    encEvents.forEach((x) => L.push('ENC\t' + x));
    const p = save('AD_' + tag + '_' + Process.id + '.txt', L.join('\n'));
    LOG('DONE ' + p + ' ad=' + adEvents.length + ' init=' + initEvents.length
        + ' tok=' + tokOrder.length + ' enc=' + encEvents.length + ' blocked=' + blocked);
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

// ════ ① 反反调试 ════
function installAntiAntiDebug() {
    const SUSPECT = ['frida', 'gum', 'gadget', 're.frida', 'substrate', 'xposed',
                     'magisk', 'linjector', 'frida-agent', 'flymed'];

    function isSuspicious(p) {
        if (!p) return false;
        const s = p.toLowerCase();
        for (let i = 0; i < SUSPECT.length; i++) if (s.indexOf(SUSPECT[i]) >= 0) return SUSPECT[i];
        return null;
    }

    // prctl
    const prctl = Module.findExportByName(null, 'prctl');
    if (prctl) {
        Interceptor.replace(prctl, new NativeCallback(function (op, a2, a3, a4, a5) {
            const o = op & 0xffffffff;
            if (o === PRCTL_MAGIC || o === 0x53564d41) {
                blocked++;
                adEvents.push('prctl(SVMA, ' + a2 + ') -> 拦截返回0');
                LOG('★AD prctl(SVMA) 拦截 #' + blocked);
                return 0;      // 假装成功
            }
            if (o === 4) {     // PR_SET_DUMPABLE
                adEvents.push('prctl(PR_SET_DUMPABLE, ' + a2 + ') -> 拦截（保持可调试）');
                LOG('★AD PR_SET_DUMPABLE(' + a2 + ') 拦截 -> 改为 1');
                return 0;
            }
            return 0;
        }, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']));
        LOG('[ok] prctl 已替换（含 SVMA 与 PR_SET_DUMPABLE 拦截）');
    }

    // open / openat
    ['open', 'openat', 'fopen', 'access', 'stat', 'lstat'].forEach(function (nm) {
        const a = Module.findExportByName(null, nm);
        if (!a) return;
        try {
            Interceptor.attach(a, {
                onEnter(args) {
                    try {
                        const pathArg = (nm === 'openat') ? args[1] : args[0];
                        const p = pathArg.readCString();
                        const s = isSuspicious(p);
                        if (s) {
                            this.blk = true;
                            blocked++;
                            adEvents.push(nm + '(' + p + ') -> 含"' + s + '"');
                            LOG('★AD ' + nm + ' 拦截: ' + p);
                        }
                    } catch (e) { }
                },
                onLeave(r) {
                    if (this.blk) {
                        try { r.replace(ptr(-1)); } catch (e) { }
                    }
                }
            });
            LOG('[ok] ' + nm);
        } catch (e) { }
    });

    // readlink / readlinkat
    ['readlink', 'readlinkat'].forEach(function (nm) {
        const a = Module.findExportByName(null, nm);
        if (!a) return;
        try {
            Interceptor.attach(a, {
                onEnter(args) {
                    try {
                        const pathArg = (nm === 'readlinkat') ? args[1] : args[0];
                        this.p = pathArg.readCString();
                    } catch (e) { this.p = null; }
                },
                onLeave(r) {
                    if (this.p && isSuspicious(this.p)) {
                        blocked++;
                        adEvents.push(nm + '(' + this.p + ')');
                    }
                }
            });
        } catch (e) { }
    });

    // strstr / strcmp：让"包含 frida 的字符串"找不到
    const strstr = Module.findExportByName(null, 'strstr');
    if (strstr) {
        try {
            Interceptor.attach(strstr, {
                onEnter(args) {
                    try {
                        this.n = args[1].readCString();
                        this.b = args[0];
                    } catch (e) { this.n = null; }
                },
                onLeave(r) {
                    if (this.n && isSuspicious(this.n)) {
                        blocked++;
                        adEvents.push('strstr(needle=' + this.n + ') -> 强制 NULL');
                        try { r.replace(ptr(0)); } catch (e) { }
                    }
                }
            });
            LOG('[ok] strstr');
        } catch (e) { }
    }

    // ptrace
    const ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace) {
        try {
            Interceptor.attach(ptrace, {
                onEnter(args) {
                    const req = args[0].toInt32();
                    if (req === 0) {          // PTRACE_TRACEME
                        this.blk = true;
                        blocked++;
                        adEvents.push('ptrace(PTRACE_TRACEME) -> 拦截');
                        LOG('★AD ptrace(TRACEME) 拦截');
                    }
                },
                onLeave(r) { if (this.blk) { try { r.replace(ptr(0)); } catch (e) { } } }
            });
            LOG('[ok] ptrace');
        } catch (e) { }
    }
}

// ════ ② Java 侧 ════
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
                        try { LOG('     -> ' + String(r).slice(0, 170)); } catch (e) { }
                        dump('main_' + mn);
                        return r;
                    };
                } catch (e) { }
            });
        });
        LOG('[ok] ★ cn.shuzilm.core.Main 挂钩');
    } catch (e) { }
}

// ════ ③ libdu ════
function hookLibdu(m) {
    LOG('★ libdu base=' + m.base + ' size=' + m.size + ' pid=' + Process.id);
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
        LOG('[ok] 解析器 0x1143BC');
    } catch (e) { LOG('[x] 解析器 ' + e); }
    try {
        Interceptor.attach(m.base.add(ENC_ENTRY), {
            onEnter(a) {
                const idx = encEvents.length;
                this.idx = idx;
                const r = hexOf(a[0], 48);
                encEvents.push('x0=' + a[0] + ' len=' + a[2].toInt32()
                    + ' in_hex=' + r.hex + ' in_asc=' + JSON.stringify(r.asc));
                LOG('★ENC[' + idx + '] len=' + a[2].toInt32() + ' in_asc=' + JSON.stringify(r.asc));
            },
            onLeave(r) {
                const o = hexOf(r, 64);
                if (encEvents[this.idx]) encEvents[this.idx] += ' OUT=' + JSON.stringify(o.asc);
                LOG('★ENC[' + this.idx + '] OUT=' + JSON.stringify(o.asc));
                dump('enc' + this.idx);
            }
        });
        LOG('[ok] 编码器 0x0E123C');
    } catch (e) { LOG('[x] 编码器 ' + e); }
    try {
        Interceptor.attach(m.base.add(ENC_LOOP), { onEnter() { loopHits++; } });
        LOG('[ok] 主循环');
    } catch (e) { }
}

// ════ 启动 ════
installAntiAntiDebug();          // ★ 最先做

Java.perform(function () {
    LOG('=== anti_debug_bypass 启动 pid=' + Process.id + ' ===');
    tryHookJava();

    let t = 0;
    (function poll() {
        t++;
        if (!libduSeen) {
            const m = lu();
            if (m) { libduSeen = true; hookLibdu(m); dump('libdu'); }
        }
        if (t % 300 === 0) tryHookJava();
        if (t < 300000) setImmediate(poll);
    })();

    let tick = 0;
    (function hb() {
        tick++;
        if (tick % 3000000 === 0) {
            LOG('[心跳] pid=' + Process.id + ' libdu=' + (libduSeen ? 'YES' : 'no')
                + ' ad=' + adEvents.length + ' blocked=' + blocked
                + ' init=' + initEvents.length + ' tok=' + tokOrder.length
                + ' enc=' + encEvents.length);
            dump('hb' + (tick / 3000000));
        }
        if (tick < 60000000) setImmediate(hb);
    })();

    LOG('=== 就绪 ===');
});
