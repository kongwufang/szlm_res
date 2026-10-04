'use strict';
// hook_stealth.js — ★ 完整四层隐身 + Cipher/SSL 采集
//
// ★★ 依据 anti_debug_v5.js（文档标记「★ 成功」，App 存活 400 秒+）：
//     ① maps 内容过滤 —— ★ 最关键的一层，之前漏掉导致"检测到注入 so 就退出"
//        挂 open/openat/fopen 记录 maps 类 fd；挂 read() 把含
//        frida|gum|gadget|substrate|re.frida|memfd:frida 的行过滤掉；另挂 fgets
//     ② prctl(SVMA) + prctl(DUMPABLE,0)
//     ③ tgkill/tkill/pthread_kill/raise 拦 SIGTRAP(5)/SIGABRT(6)
//     ④ strstr 命中关键词置 0 / ptrace 置 0 / _exit/exit/abort 记录
//     ⑤ Java: Process.killProcess / Process.exit / System.exit
//
// ★ 顺序纪律（文档明确）：installMapsFilter() 必须【最先】装
//     —— 要在 read 被使用之前就把过滤器就位
//
// ★ 采集（HOOK_LESSONS.md 纪律）：
//     · Cipher.doFinal 用 .call() 调原方法，绝不用 this.doFinal()（自递归 bug）
//     · 消息 tag 带 PID（CAPTURE_PIPELINE.md bug 2）
const LOG = (m) => send(String(m));

const DIRS = ['/data/local/tmp', '/data/data/com.coolapk.market/files'];
const PRCTL_MAGIC = 0x53564D41;
const MY_PID = Process.id;
const T0 = Date.now();

const BAD = /frida|gum|gadget|substrate|linjector|re\.frida|memfd:frida|flymed|magisk/i;

let recs = [];
let sslN = 0, cifN = 0, blocked = 0, filtered = 0, exitN = 0;
let mapsFds = {}, nameFds = {};
const MODE = 2;   // 1=只计数  2=读参数

function save(name, txt) {
    for (let i = 0; i < DIRS.length; i++) {
        try { const f = new File(DIRS[i] + '/' + name, 'w'); f.write(txt); f.flush(); f.close(); return DIRS[i]; } catch (e) { }
    }
    return null;
}

function toHex(arr, n) {
    try {
        const b = new Uint8Array(arr);
        let h = '';
        const lim = Math.min(b.length, n || b.length);
        for (let i = 0; i < lim; i++) h += ('0' + b[i].toString(16)).slice(-2);
        return h;
    } catch (e) { return '?'; }
}

function dump(tag) {
    const L = [];
    L.push('# p' + MY_PID + ' t=' + (Date.now() - T0) + ' ssl=' + sslN + ' cipher=' + cifN
        + ' blocked=' + blocked + ' filtered=' + filtered + ' exit=' + exitN + ' recs=' + recs.length);
    recs.forEach(function (r) {
        L.push('REC p' + MY_PID + ' t=' + r.t + ' ' + r.src + ' ' + r.dir
            + ' n=' + r.n + ' hex=' + r.hex);
    });
    const p = save('HS_' + tag + '_p' + MY_PID + '.txt', L.join('\n'));
    LOG('DONE ' + p + ' recs=' + recs.length + ' ssl=' + sslN + ' cipher=' + cifN
        + ' blocked=' + blocked + ' filtered=' + filtered);
}

function push(src, dir, arr, n) {
    recs.push({
        t: Date.now() - T0, src: src, dir: dir, n: n,
        hex: MODE >= 2 ? toHex(arr, Math.min(n || 16384, 16384)) : ''
    });
    if (recs.length % 20 === 1) dump('n' + recs.length);
    if (recs.length > 3000) recs.splice(0, 1200);
}

// ════════════ ① ★★★ maps 内容过滤（必须最先装）════════════
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
                    LOG('[maps] 打开 ' + path + ' fd=' + fd);
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
            LOG('[ok] open');
        } catch (e) { }
    }
    if (openatA) {
        try {
            Interceptor.attach(openatA, {
                onEnter(a) { try { this.p = a[1].readCString(); } catch (e) { this.p = null; } },
                onLeave(r) { trackOpen(r, this.p); }
            });
            LOG('[ok] openat');
        } catch (e) { }
    }
    if (fopenA) {
        try {
            Interceptor.attach(fopenA, {
                onEnter(a) { try { this.p = a[0].readCString(); } catch (e) { this.p = null; } },
                onLeave(r) {
                    try {
                        if (this.p && /\/maps|\/smaps/i.test(this.p)) {
                            mapsFds[r.toString()] = true;
                            LOG('[maps] fopen ' + this.p + ' -> ' + r);
                        }
                    } catch (e) { }
                }
            });
            LOG('[ok] fopen');
        } catch (e) { }
    }

    // ★★★ 核心：read() 里过滤 maps 内容
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
                    if (!mapsFds[this.fd]) return;    // ★ 只处理 maps 类文件
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
                        if (filtered <= 5) LOG('★★ 过滤 maps 行 ' + (lines.length - keep.length) + ' 条');
                    } catch (e) { }
                }
            });
            LOG('[ok] read（maps 过滤）');
        } catch (e) { LOG('[x] read: ' + e); }
    }

    // fgets
    const fgA = Module.findExportByName(null, 'fgets');
    if (fgA) {
        try {
            Interceptor.attach(fgA, {
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
            LOG('[ok] fgets');
        } catch (e) { }
    }
}

// ════════════ ②③④ Native 反调试 ════════════
function installNative() {
    const prctlAddr = Module.findExportByName(null, 'prctl');
    if (prctlAddr) {
        try {
            const orig = new NativeFunction(prctlAddr, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']);
            Interceptor.replace(prctlAddr, new NativeCallback(function (op, a2, a3, a4, a5) {
                const o = op & 0xffffffff;
                if (o === PRCTL_MAGIC) { blocked++; return 0; }
                if (o === 4 && a2.toInt32() === 0) { blocked++; return orig(4, ptr(1), a3, a4, a5); }
                return orig(op, a2, a3, a4, a5);   // ★ 其余原样透传（否则 ANR）
            }, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']));
            LOG('[ok] prctl');
        } catch (e) { }
    }
    const killAddr = Module.findExportByName(null, 'kill');
    if (killAddr) {
        try {
            const orig = new NativeFunction(killAddr, 'int', ['int', 'int']);
            Interceptor.replace(killAddr, new NativeCallback(function (pid, sig) {
                if (pid === MY_PID || pid === -MY_PID) { blocked++; return 0; }
                return orig(pid, sig);
            }, 'int', ['int']));
            LOG('[ok] kill');
        } catch (e) { }
    }
    const SIGTRAP = 5, SIGABRT = 6;
    function mkFilter(name, sigIdx) {
        const a = Module.findExportByName(null, name);
        if (!a) return;
        try {
            const orig = new NativeFunction(a, 'int', ['int', 'int', 'int']);
            Interceptor.replace(a, new NativeCallback(function (p1, p2, p3) {
                const sig = [p1, p2, p3][sigIdx];
                if (sig === SIGTRAP || sig === SIGABRT) { blocked++; return 0; }
                return orig(p1, p2, p3);
            }, 'int', ['int', 'int', 'int']));
            LOG('[ok] ' + name);
        } catch (e) { }
    }
    mkFilter('tgkill', 2);
    mkFilter('tkill', 1);
    mkFilter('pthread_kill', 1);
    const raiseA = Module.findExportByName(null, 'raise');
    if (raiseA) {
        try {
            const orig = new NativeFunction(raiseA, 'int', ['int']);
            Interceptor.replace(raiseA, new NativeCallback(function (sig) {
                if (sig === SIGTRAP || sig === SIGABRT) { blocked++; return 0; }
                return orig(sig);
            }, 'int', ['int']));
            LOG('[ok] raise');
        } catch (e) { }
    }
    // ★ 只记录不拦截（拦了可能卡死）
    ['_exit', 'exit', 'abort'].forEach(function (nm) {
        const a = Module.findExportByName(null, nm);
        if (!a) return;
        try {
            Interceptor.attach(a, { onEnter() { exitN++; if (exitN <= 5) LOG('★ ' + nm + ' 被调用'); } });
        } catch (e) { }
    });
    // strstr 命中 BAD 关键词 -> 返回 0
    const ss = Module.findExportByName(null, 'strstr');
    if (ss) {
        try {
            Interceptor.attach(ss, {
                onEnter(args) { try { this.n = args[1].readCString(); } catch (e) { } },
                onLeave(r) {
                    try {
                        if (this.n && BAD.test(this.n)) {
                            blocked++;
                            r.replace(ptr(0));
                        }
                    } catch (e) { }
                }
            });
            LOG('[ok] strstr');
        } catch (e) { }
    }
    // ptrace -> 0
    const pt = Module.findExportByName(null, 'ptrace');
    if (pt) {
        try {
            Interceptor.attach(pt, {
                onEnter(args) { this.b = (args[0].toInt32() === 0); if (this.b) blocked++; },
                onLeave(r) { if (this.b) { try { r.replace(ptr(0)); } catch (e) { } } }
            });
            LOG('[ok] ptrace');
        } catch (e) { }
    }
}

// ════════════ ⑤ Java 侧退出拦截 ════════════
function hookJavaMisc() {
    try {
        const P = Java.use('android.os.Process');
        try {
            P.killProcess.overload('int').implementation = function (pid) {
                if (pid === MY_PID) { blocked++; LOG('★ killProcess(' + pid + ') 拦截'); return; }
                return this.killProcess(pid);
            };
        } catch (e) { }
        try { P.exit.overload('int').implementation = function () { blocked++; LOG('★ Process.exit 拦截'); }; } catch (e) { }
    } catch (e) { }
    try {
        const S = Java.use('java.lang.System');
        try { S.exit.overload('int').implementation = function () { blocked++; LOG('★ System.exit 拦截'); }; } catch (e) { }
    } catch (e) { }
    LOG('[ok] Java 退出拦截');
}

// ════════════ 采集：SSL + Cipher ════════════
function hookSSL() {
    const got = [];
    ['libssl.so', 'libjavacrypto.so'].forEach(function (mn) {
        let mod = null;
        try { mod = Process.findModuleByName(mn); } catch (e) { }
        if (!mod) return;
        ['SSL_write', 'SSL_read'].forEach(function (fn) {
            let a = null;
            try { a = mod.findExportByName(fn); } catch (e) { }
            if (!a) return;
            const isW = fn.indexOf('write') >= 0;
            try {
                Interceptor.attach(a, {
                    onEnter(args) { this.buf = isW ? args[1] : args[0]; this.n = (isW ? args[2] : args[1]).toInt32(); },
                    onLeave(r) {
                        sslN++;
                        let n = this.n;
                        if (!isW) { n = r.toInt32(); if (n <= 0) return; }
                        if (n < 64 || n > 300000) return;
                        push('SSL', isW ? 'OUT' : 'IN', this.buf, n);
                    }
                });
                got.push(mn + '.' + fn);
            } catch (e) { }
        });
    });
    LOG('[ok] SSL: ' + (got.join(',') || '(无)'));
}

function hookCipher() {
    try {
        const Cipher = Java.use('javax.crypto.Cipher');
        const ov = Cipher.doFinal.overload('[B');
        ov.implementation = function (input) {
            cifN++;
            const out = ov.call(this, input);       // ★ 用 .call()，绝不 this.doFinal()
            if (MODE >= 2) {
                try {
                    if (input && input.length > 0) push('CIPHER', 'IN', input, input.length);
                    if (out && out.length > 0) push('CIPHER', 'OUT', out, out.length);
                } catch (e) { }
            }
            if (cifN % 5 === 1) LOG('[doFinal] 第 ' + cifN + ' 次 in=' + (input ? input.length : -1)
                + ' out=' + (out ? out.length : -1));
            return out;
        };
        LOG('[ok] Cipher.doFinal（.call 模式）');
    } catch (e) { LOG('[x] Cipher: ' + e); }
}

// ════════════ 启动（★ 顺序：maps 过滤必须最先）════════════
installMapsFilter();     // ① 最先
installNative();         // ②③④

Java.perform(function () {
    LOG('=== hook_stealth 启动 p' + MY_PID + ' MODE=' + MODE + ' ===');
    hookJavaMisc();      // ⑤
    hookSSL();
    hookCipher();

    recv(function (msg) {
        try {
            if (msg && msg.cmd === 'dump') { dump('forced'); send('FORCED p' + MY_PID + ' recs=' + recs.length); }
        } catch (e) { }
    });

    let tick = 0;
    (function hb() {
        tick++;
        if (tick % 200000 === 0) {
            LOG('[心跳 p' + MY_PID + '] ssl=' + sslN + ' cipher=' + cifN
                + ' blocked=' + blocked + ' filtered=' + filtered);
            dump('hb' + (tick / 200000));
        }
        if (tick < 400000000) setImmediate(hb);
    })();
    LOG('=== 就绪 ===');
});
