'use strict';
// hook_stealth2.js — ★ 完整隐身（重定向版：不钩 read，避免 ANR）
//
// ★★ 为什么改方案：
//     上一版学了 anti_debug_v5.js 的「挂 read() 过滤 maps 内容」，
//     但 read 是极高频函数 —— 全 app 的每次读都进 JS 回调 => 酷安直接 ANR。
//     （这正是 HOOK_LESSONS.md §三 记录的同类错误：高频 hook 必崩）
//
// ★★ 新方案：在 open/openat 层【重定向】
//     ① 拦住对 /proc/self/maps、/proc/<pid>/maps、/proc/self/smaps 的打开
//     ② 现场生成一份【滤掉 frida 行】的副本，写到 app 自己的目录
//     ③ 把副本的真实 fd 返回给调用方
//     ⇒ 完全不碰 read，零高频开销
//
// ★ 其余层保留（anti_debug_v5.js 验证有效的）：
//     prctl(SVMA/DUMPABLE) / kill / tgkill·tkill·pthread_kill·raise 拦 SIGTRAP
//     strstr 命中关键词置 0 / ptrace 置 0 / _exit·exit·abort 记录
//     Java: Process.killProcess / Process.exit / System.exit
const LOG = (m) => send(String(m));

const DIRS = ['/data/data/com.coolapk.market/files', '/data/local/tmp'];
const PRCTL_MAGIC = 0x53564D41;
const MY_PID = Process.id;
const T0 = Date.now();
const BAD = /frida|gum|gadget|substrate|linjector|re\.frida|memfd:frida|flymed|magisk/i;
const TMPMAPS = '/data/data/com.coolapk.market/files/.cmaps';

let recs = [];
const KEEPS = [];   // ★ szlm HTTP 请求永久保留（不参与 recs 的 splice 淘汰）
let sslN = 0, cifN = 0, sockN = 0, blocked = 0, redirected = 0, exitN = 0;
const MODE = 2;

function save(name, txt) {
    for (let i = 0; i < DIRS.length; i++) {
        try { const f = new File(DIRS[i] + '/' + name, 'w'); f.write(txt); f.flush(); f.close(); return DIRS[i]; } catch (e) { }
    }
    return null;
}

function toHex(arr, n) {
    try {
        // ★★★ 关键修复：
        //   CIPHER 传进来的是 Java byte[]，用 new Uint8Array(arr) 可以
        //   SOCK/SSL 传进来的是 NativePointer，必须用 arr.readByteArray(n)
        //   ★ 之前只写了 new Uint8Array(arr)，导致 SSL/SOCK 的 hex 恒为空，
        //     所有 SSL 数据被静默丢弃（mdna 就一直丢在这里）
        let b = null;
        try {
            if (arr && typeof arr.readByteArray === 'function') {
                const ab = arr.readByteArray(n);
                if (ab) b = new Uint8Array(ab);
            }
        } catch (e) { }
        if (!b || b.length === 0) {
            try { b = new Uint8Array(arr); } catch (e) { }
        }
        if (!b || b.length === 0) return '';
        let h = '';
        const lim = Math.min(b.length, n || b.length);
        for (let i = 0; i < lim; i++) h += ('0' + b[i].toString(16)).slice(-2);
        return h;
    } catch (e) { return '?'; }
}

function dump(tag) {
    const L = [];
    L.push('# p' + MY_PID + ' t=' + (Date.now() - T0) + ' ssl=' + sslN + ' cipher=' + cifN
        + ' blocked=' + blocked + ' redirected=' + redirected + ' exit=' + exitN + ' sock=' + sockN + ' recs=' + recs.length);
    KEEPS.forEach(function (r) { L.push('KEEP p' + MY_PID + ' t=' + r.t + ' '
        + r.src + ' ' + r.dir + ' n=' + r.n + ' hex=' + r.hex); });
    recs.forEach(function (r) {
        L.push('REC p' + MY_PID + ' t=' + r.t + ' ' + r.src + ' ' + r.dir + ' n=' + r.n + ' hex=' + r.hex);
    });
    const p = save('HS2_' + tag + '_p' + MY_PID + '.txt', L.join('\n'));
    LOG('DONE ' + p + ' recs=' + recs.length + ' ssl=' + sslN + ' cipher=' + cifN
        + ' blocked=' + blocked + ' redirected=' + redirected + ' sock=' + sockN);
}

function push(src, dir, arr, n) {
    const t = Date.now() - T0;
    // ★★★ 关键优化：不做无差别 hex 转换（16384×N 会导致 ANR）
    let keepHex = false, cap = 0;
    if (src === 'CIPHER') { keepHex = true; cap = 32768; }
    else if (src === 'SOCK') {
        // ★★ native socket：只对【像 HTTP】的记录做 hex
        //    （write/send 是高频调用，一律 hex 会 ANR —— 这个错我犯过两次）
        try {
            const b = new Uint8Array(arr.readByteArray(4));
            keepHex = (b[0] === 0x50 && b[1] === 0x4f && b[2] === 0x53 && b[3] === 0x54)   // POST
                   || (b[0] === 0x47 && b[1] === 0x45 && b[2] === 0x54 && b[3] === 0x20)   // GET
                   || (b[0] === 0x48 && b[1] === 0x54 && b[2] === 0x54 && b[3] === 0x50);  // HTTP
            cap = 4096;
        } catch (e) { }
    }
    else if (src === 'SSL') {
        // ★ 恢复严格版（放宽版导致 ANR：hex 转换量暴涨）
        //   只留「像 HTTP」或「够大（可能是 HTTP 请求体）」的记录
        try {
            const b = new Uint8Array(arr.readByteArray(8));
            const httpLike = (b[0] === 0x47 && b[1] === 0x45) || (b[0] === 0x50 && b[1] === 0x4f)
                          || (b[0] === 0x48 && b[1] === 0x54) || (b[0] === 0x50 && b[1] === 0x55);
            keepHex = httpLike || (n >= 800);
            cap = 2048;
        } catch (e) { }
    }
    recs.push({ t: t, src: src, dir: dir, n: n,
                hex: (MODE >= 2 && keepHex) ? toHex(arr, Math.min(n || cap, cap)) : '' });
    // ★★★ 关键：szlm 的 HTTP 请求单独存一份【永不淘汰】
    //    之前 recs 超过 2000 条会 splice 掉最老的 800 条，
    //    而 mdna 在注册最早期发出 → 一直被冲掉
    const rr = recs[recs.length - 1];
    if (rr.hex && (src === 'SSL' || src === 'SOCK')) {
        const h0 = rr.hex.slice(0, 8);
        if (h0 === '504f5354' || h0 === '47455420') {          // POST / GET
            if (rr.hex.indexOf('74656c65636f6d65') >= 0         // "telecome"
                || rr.hex.indexOf('6d646e61') >= 0              // "mdna"
                || rr.hex.indexOf('61756e69') >= 0) {           // "auni"
                KEEPS.push(Object.assign({}, rr));
                if (KEEPS.length % 5 === 1) dump('keep' + KEEPS.length);
            }
        }
    }
    if (recs.length % 20 === 1) dump('n' + recs.length);
    if (recs.length > 2000) recs.splice(0, 800);
}

// ══════ ① maps 重定向（不钩 read）══════
function installMapsRedirect() {
    const openA = Module.findExportByName(null, 'open');
    const openatA = Module.findExportByName(null, 'openat');
    if (!openA && !openatA) { LOG('[x] 找不到 open'); return; }

    const origOpen = openA ? new NativeFunction(openA, 'int', ['pointer', 'int', 'int']) : null;
    const origOpenat = openatA ? new NativeFunction(openatA, 'int', ['int', 'pointer', 'int', 'int']) : null;

    function isMapsPath(p) {
        if (!p) return false;
        return /^\/proc\/(self|\d+)\/maps$/.test(p)
            || /^\/proc\/(self|\d+)\/smaps$/.test(p)
            || /^\/proc\/(self|\d+)\/task\/\d+\/maps$/.test(p);
    }

    // 生成一份滤掉 frida 行的 maps 副本
    let lastGen = 0;
    function genCleanMaps() {
        const now = Date.now();
        // 最多每 2 秒重新生成一次（避免频繁 IO）
        if (now - lastGen < 2000) return true;
        lastGen = now;
        try {
            const pOpen = Module.findExportByName(null, 'open');
            const o = new NativeFunction(pOpen, 'int', ['pointer', 'int', 'int']);
            const realFd = o(Memory.allocUtf8String('/proc/self/maps'), 0, 0);
            if (realFd < 0) return false;
            const pRead = Module.findExportByName(null, 'read');
            const pClose = Module.findExportByName(null, 'close');
            const rd = new NativeFunction(pRead, 'long', ['int', 'pointer', 'long']);
            const cl = new NativeFunction(pClose, 'int', ['int']);
            const buf = Memory.alloc(1024 * 1024);
            let total = 0;
            for (let i = 0; i < 64; i++) {
                const n = rd(realFd, buf.add(total), 65536);
                if (n <= 0) break;
                total += n;
                if (total > 900000) break;
            }
            cl(realFd);
            if (total <= 0) return false;
            const s = buf.readUtf8String(total) || '';
            const lines = s.split('\n');
            const keep = lines.filter(function (l) { return !BAD.test(l); });
            const out = keep.join('\n');
            const f = new File(TMPMAPS, 'w');
            f.write(out); f.flush(); f.close();
            if (redirected === 0) {
                LOG('[maps] 已生成干净副本：原 ' + lines.length + ' 行 → ' + keep.length + ' 行（滤掉 '
                    + (lines.length - keep.length) + ' 行）');
            }
            return true;
        } catch (e) { return false; }
    }

    if (openA) {
        try {
            Interceptor.replace(openA, new NativeCallback(function (pathPtr, flags, mode) {
                let p = null;
                try { p = pathPtr.readCString(); } catch (e) { }
                if (isMapsPath(p)) {
                    if (genCleanMaps()) {
                        const fd = origOpen(Memory.allocUtf8String(TMPMAPS), flags, mode);
                        if (fd >= 0) {
                            redirected++;
                            if (redirected <= 3) LOG('★★ 重定向 maps: ' + p + ' -> fd=' + fd);
                            return fd;
                        }
                    }
                }
                return origOpen(pathPtr, flags, mode);
            }, 'int', ['pointer', 'int', 'int']));
            LOG('[ok] open（maps 重定向）');
        } catch (e) { LOG('[x] open: ' + e); }
    }

    if (openatA) {
        try {
            Interceptor.replace(openatA, new NativeCallback(function (dirfd, pathPtr, flags, mode) {
                let p = null;
                try { p = pathPtr.readCString(); } catch (e) { }
                if (isMapsPath(p)) {
                    if (genCleanMaps()) {
                        const fd = origOpenat(dirfd, Memory.allocUtf8String(TMPMAPS), flags, mode);
                        if (fd >= 0) {
                            redirected++;
                            if (redirected <= 3) LOG('★★ 重定向 openat maps: ' + p + ' -> fd=' + fd);
                            return fd;
                        }
                    }
                }
                return origOpenat(dirfd, pathPtr, flags, mode);
            }, 'int', ['int', 'pointer', 'int', 'int']));
            LOG('[ok] openat（maps 重定向）');
        } catch (e) { LOG('[x] openat: ' + e); }
    }
    // ★ 刻意【不】钩 read —— 那是上一版 ANR 的原因
}

// ══════ ②③④ Native 反调试 ══════
function installNative() {
    const pa = Module.findExportByName(null, 'prctl');
    if (pa) {
        try {
            const orig = new NativeFunction(pa, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']);
            Interceptor.replace(pa, new NativeCallback(function (op, a2, a3, a4, a5) {
                const o = op & 0xffffffff;
                if (o === PRCTL_MAGIC) { blocked++; return 0; }
                if (o === 4 && a2.toInt32() === 0) { blocked++; return orig(4, ptr(1), a3, a4, a5); }
                return orig(op, a2, a3, a4, a5);
            }, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']));
        } catch (e) { }
    }
    const ka = Module.findExportByName(null, 'kill');
    if (ka) {
        try {
            const orig = new NativeFunction(ka, 'int', ['int', 'int']);
            Interceptor.replace(ka, new NativeCallback(function (pid, sig) {
                if (pid === MY_PID || pid === -MY_PID) { blocked++; return 0; }
                return orig(pid, sig);
            }, 'int', ['int']));
        } catch (e) { }
    }
    const ST = 5, SA = 6;
    [['tgkill', 2], ['tkill', 1], ['pthread_kill', 1]].forEach(function (p) {
        const a = Module.findExportByName(null, p[0]);
        if (!a) return;
        try {
            const orig = new NativeFunction(a, 'int', ['int', 'int', 'int']);
            Interceptor.replace(a, new NativeCallback(function (x, y, z) {
                const sig = [x, y, z][p[1]];
                if (sig === ST || sig === SA) { blocked++; return 0; }
                return orig(x, y, z);
            }, 'int', ['int', 'int', 'int']));
        } catch (e) { }
    });
    const ra = Module.findExportByName(null, 'raise');
    if (ra) {
        try {
            const orig = new NativeFunction(ra, 'int', ['int']);
            Interceptor.replace(ra, new NativeCallback(function (sig) {
                if (sig === ST || sig === SA) { blocked++; return 0; }
                return orig(sig);
            }, 'int', ['int']));
        } catch (e) { }
    }
    ['_exit', 'exit', 'abort'].forEach(function (nm) {
        const a = Module.findExportByName(null, nm);
        if (!a) return;
        try { Interceptor.attach(a, { onEnter() { exitN++; if (exitN <= 5) LOG('★ ' + nm + ' 被调用'); } }); } catch (e) { }
    });
    const ss = Module.findExportByName(null, 'strstr');
    if (ss) {
        try {
            Interceptor.attach(ss, {
                onEnter(args) { try { this.n = args[1].readCString(); } catch (e) { } },
                onLeave(r) {
                    try { if (this.n && BAD.test(this.n)) { blocked++; r.replace(ptr(0)); } } catch (e) { }
                }
            });
        } catch (e) { }
    }
    const pt = Module.findExportByName(null, 'ptrace');
    if (pt) {
        try {
            Interceptor.attach(pt, {
                onEnter(args) { this.b = (args[0].toInt32() === 0); if (this.b) blocked++; },
                onLeave(r) { if (this.b) { try { r.replace(ptr(0)); } catch (e) { } } }
            });
        } catch (e) { }
    }
    LOG('[ok] prctl/kill/tgkill/tkill/pthread_kill/raise/strstr/ptrace/exit-trace');
}

// ══════ ⑤ Java 退出拦截 ══════
function hookJavaMisc() {
    try {
        const P = Java.use('android.os.Process');
        try { P.killProcess.overload('int').implementation = function (pid) { if (pid === MY_PID) { blocked++; return; } return this.killProcess(pid); }; } catch (e) { }
        try { P.exit.overload('int').implementation = function () { blocked++; }; } catch (e) { }
    } catch (e) { }
    try {
        const S = Java.use('java.lang.System');
        try { S.exit.overload('int').implementation = function () { blocked++; }; } catch (e) { }
    } catch (e) { }
}

// ══════ 采集：SSL + Cipher ══════
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
    const got = [];
    try {
        const Cipher = Java.use('javax.crypto.Cipher');
        // ★ 单参数版
        try {
            const ov1 = Cipher.doFinal.overload('[B');
            ov1.implementation = function (input) {
                cifN++;
                const out = ov1.call(this, input);      // ★ 用 .call()
                if (MODE >= 2) {
                    try {
                        if (input && input.length > 0) push('CIPHER', 'IN', input, input.length);
                        if (out && out.length > 0) push('CIPHER', 'OUT', out, out.length);
                    } catch (e) { }
                }
                return out;
            };
            got.push('doFinal([B)');
        } catch (e) { }
        // ★★ 三参数版（之前漏了）
        try {
            const ov3 = Cipher.doFinal.overload('[B', 'int', 'int');
            ov3.implementation = function (input, off, len) {
                cifN++;
                const out = ov3.call(this, input, off, len);
                if (MODE >= 2) {
                    try {
                        if (input && input.length > 0) push('CIPHER', 'IN', input, input.length);
                        if (out && out.length > 0) push('CIPHER', 'OUT', out, out.length);
                    } catch (e) { }
                }
                return out;
            };
            got.push('doFinal([B,int,int)');
        } catch (e) { }
        LOG('[ok] Cipher: ' + (got.join(',') || '(无)'));
    } catch (e) { LOG('[x] Cipher: ' + e); }
}

// ══════ ⑥ native socket（★ mdna 可能走这条）══════
function hookSock() {
    const got = [];
    ['send', 'sendto'].forEach(function (fn) {
        const a = Module.findExportByName(null, fn);
        if (!a) return;
        try {
            Interceptor.attach(a, {
                onEnter(args) { this.fd = args[0].toInt32(); this.buf = args[1]; this.n = args[2].toInt32(); },
                onLeave(r) {
                    sockN++;
                    const n = r.toInt32();
                    if (n < 32 || n > 300000) return;
                    push('SOCK', 'OUT', this.buf, n);
                }
            });
            got.push(fn);
        } catch (e) { }
    });
    // ★ 刻意不 hook write —— write 覆盖面太广（含文件写）且频率极高，是 ANR 隐患；
    //   send/sendto 已覆盖 socket 出站，HTTP 走 socket 一定经过它们
    // ★ 也刻意不 hook read/recv —— read 极高频，之前就是这么 ANR 的
    LOG('[ok] SOCK: ' + (got.join(',') || '(无)'));
}

// ══════ 启动 ══════
installMapsRedirect();   // ★ 最先
installNative();

Java.perform(function () {
    LOG('=== hook_stealth2 启动 p' + MY_PID + ' ===');
    hookJavaMisc();
    hookSSL();
    hookCipher();
    hookSock();

    recv(function (msg) {
        try { if (msg && msg.cmd === 'dump') { dump('forced'); send('FORCED p' + MY_PID); } } catch (e) { }
    });

    let tick = 0;
    (function hb() {
        tick++;
        if (tick % 200000 === 0) {
            LOG('[心跳 p' + MY_PID + '] ssl=' + sslN + ' cipher=' + cifN
                + ' blocked=' + blocked + ' redirected=' + redirected + ' sock=' + sockN);
            dump('hb' + (tick / 200000));
        }
        if (tick < 400000000) setImmediate(hb);
    })();
    LOG('=== 就绪 ===');
});
