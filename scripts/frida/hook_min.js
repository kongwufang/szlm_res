'use strict';
// hook_min.js — ★ 最小钩子集（严格遵守 HOOK_LESSONS.md 的低压验证纪律）
//
// ★ 纪律（HOOK_LESSONS.md §五）：
//     1. 先只挂【一个点】，只记调用次数（不读参数）
//     2. 观察 30 秒，确认稳定
//     3. 再逐步加读参数、读返回值
//     4. 任何一步卡顿立即撤回
//
// ★ 本版遵守：
//     · Cipher.doFinal 用 .call() 调原方法 —— 绝不用 this.doFinal()（自递归 bug）
//     · 只挂 SSL_write / SSL_read（文档列为安全）+ 一个 Cipher 点
//     · 反调试只保留 tgkill/raise 的 SIGTRAP 拦截（文档验证有效）
//     · 所有消息 tag 带 PID（CAPTURE_PIPELINE.md bug 2 的修法）
const LOG = (m) => send(String(m));

const SAVE_DIRS = ['/data/local/tmp', '/data/data/com.coolapk.market/files'];
const PRCTL_MAGIC = 0x53564D41;
const MY_PID = Process.id;

let recs = [];
let sslN = 0, cifN = 0, blocked = 0;
const T0 = Date.now();

// ★ 模式：1 = 只计数（第一阶段，验证稳定性）
//         2 = 读参数（第二阶段）
const MODE = 2;

function save(name, txt) {
    for (let i = 0; i < SAVE_DIRS.length; i++) {
        try { const f = new File(SAVE_DIRS[i] + '/' + name, 'w'); f.write(txt); f.flush(); f.close(); return SAVE_DIRS[i]; } catch (e) { }
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
    L.push('# p' + MY_PID + ' t=' + (Date.now() - T0) + ' ssl=' + sslN
        + ' cipher=' + cifN + ' blocked=' + blocked + ' recs=' + recs.length);
    recs.forEach(function (r) {
        L.push('REC p' + MY_PID + ' t=' + r.t + ' ' + r.src + ' ' + r.dir
            + ' n=' + r.n + ' hex=' + r.hex);
    });
    const p = save('HM_' + tag + '_p' + MY_PID + '.txt', L.join('\n'));
    LOG('DONE ' + p + ' recs=' + recs.length + ' ssl=' + sslN + ' cipher=' + cifN);
}

function push(src, dir, arr, n) {
    const t = Date.now() - T0;
    // ★★★ 关键优化：不做无差别 hex 转换。
    //     之前对每条 SSL 记录都转 16384 字节 -> 7000 万次 JS 字符操作 -> 酷安 ANR
    //     现在：只对「像 HTTP 的 SSL 记录」和「CIPHER 记录」保留 hex，且各有上限
    let keepHex = false, cap = 0;
    if (src === 'CIPHER') {
        keepHex = true; cap = 32768;
    } else if (src === 'SSL') {
        try {
            const b = new Uint8Array(arr.readByteArray(8));
            keepHex = (b[0] === 0x47 && b[1] === 0x45)      // "GE"
                   || (b[0] === 0x50 && b[1] === 0x4f)      // "PO"
                   || (b[0] === 0x48 && b[1] === 0x54)      // "HT"
                   || (b[0] === 0x50 && b[1] === 0x55);     // "PU"
            cap = 4096;
        } catch (e) { }
    }
    recs.push({
        t: t, src: src, dir: dir, n: n,
        hex: (MODE >= 2 && keepHex) ? toHex(arr, Math.min(n || cap, cap)) : ''
    });
    if (recs.length % 20 === 1) dump('n' + recs.length);
    if (recs.length > 2000) recs.splice(0, 800);
}

// ════ SSL（文档列为安全）════
function hookSSL() {
    const got = [];
    ['libssl.so', 'libjavacrypto.so'].forEach(function (mn) {
        let mod = null;
        try { mod = Process.findModuleByName(mn); } catch (e) { }
        if (!mod) { LOG('[--] ' + mn + ' 未加载'); return; }
        ['SSL_write', 'SSL_read'].forEach(function (fn) {
            let a = null;
            try { a = mod.findExportByName(fn); } catch (e) { }
            if (!a) { LOG('[--] ' + mn + '.' + fn + ' 无导出'); return; }
            const isW = fn.indexOf('write') >= 0;
            try {
                Interceptor.attach(a, {
                    onEnter(args) {
                        this.buf = isW ? args[1] : args[0];
                        this.n = (isW ? args[2] : args[1]).toInt32();
                    },
                    onLeave(r) {
                        sslN++;
                        let n = this.n;
                        if (!isW) { n = r.toInt32(); if (n <= 0) return; }
                        if (n < 64 || n > 300000) return;
                        push('SSL', isW ? 'OUT' : 'IN', this.buf, n);
                    }
                });
                got.push(mn + '.' + fn);
            } catch (e) { LOG('[x] ' + mn + '.' + fn + ': ' + e); }
        });
    });
    LOG('[ok] SSL: ' + (got.join(',') || '(无)'));
}

// ════ Cipher.doFinal（★ 用 .call，绝不 this.doFinal）════
function hookCipher() {
    try {
        const Cipher = Java.use('javax.crypto.Cipher');
        const ov = Cipher.doFinal.overload('[B');
        ov.implementation = function (input) {
            cifN++;
            // ★★ 关键：用 overload 的 .call(this, ...) 调原方法
            const out = ov.call(this, input);
            if (MODE >= 2) {
                try {
                    if (input && input.length > 0) push('CIPHER', 'IN', input, input.length);
                    if (out && out.length > 0) push('CIPHER', 'OUT', out, out.length);
                } catch (e) { }
            }
            if (cifN % 10 === 1) LOG('[doFinal] 第 ' + cifN + ' 次 in=' + (input ? input.length : -1)
                + ' out=' + (out ? out.length : -1));
            return out;
        };
        LOG('[ok] Cipher.doFinal([B) —— 已用 .call() 调用');
    } catch (e) {
        LOG('[x] Cipher: ' + e);
    }
}

// ════ 反调试：只保留文档验证有效的部分 ════
function installNative() {
    const SIGTRAP = 5, SIGABRT = 6;
    // prctl(SVMA) —— 必须【其余调用原样透传】，v1 全返回 0 会导致 ANR
    const pa = Module.findExportByName(null, 'prctl');
    if (pa) {
        try {
            const o = new NativeFunction(pa, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']);
            Interceptor.replace(pa, new NativeCallback(function (op, a2, a3, a4, a5) {
                const v = op & 0xffffffff;
                if (v === PRCTL_MAGIC) { blocked++; return 0; }
                return o(op, a2, a3, a4, a5);
            }, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']));
        } catch (e) { }
    }
    // ★ tgkill 是决定性的一击（普通 kill 钩子拦不到）
    [['tgkill', 2], ['tkill', 1], ['pthread_kill', 1]].forEach(function (p) {
        const a = Module.findExportByName(null, p[0]);
        if (!a) return;
        try {
            const o = new NativeFunction(a, 'int', ['int', 'int', 'int']);
            Interceptor.replace(a, new NativeCallback(function (x, y, z) {
                const sig = [x, y, z][p[1]];
                if (sig === SIGTRAP || sig === SIGABRT) { blocked++; return 0; }
                return o(x, y, z);
            }, 'int', ['int', 'int', 'int']));
        } catch (e) { }
    });
    const ra = Module.findExportByName(null, 'raise');
    if (ra) {
        try {
            const o = new NativeFunction(ra, 'int', ['int']);
            Interceptor.replace(ra, new NativeCallback(function (sig) {
                if (sig === SIGTRAP || sig === SIGABRT) { blocked++; return 0; }
                return o(sig);
            }, 'int', ['int']));
        } catch (e) { }
    }
    LOG('[ok] 反调试：prctl(SVMA) + tgkill/tkill/pthread_kill/raise 的 SIGTRAP/SIGABRT');
}

Java.perform(function () {
    LOG('=== hook_min 启动 p' + MY_PID + ' MODE=' + MODE + ' ===');
    installNative();
    hookSSL();      // 先只装 SSL（文档列为安全）
    hookCipher();   // 再装 Cipher（低频，文档推荐）

    recv(function (msg) {
        try {
            if (msg && msg.cmd === 'dump') { dump('forced'); send('FORCED p' + MY_PID + ' recs=' + recs.length); }
            if (msg && msg.cmd === 'mode') { send('MODE is const=' + MODE); }
        } catch (e) { }
    });

    let tick = 0;
    (function hb() {
        tick++;
        if (tick % 200000 === 0) {
            LOG('[心跳 p' + MY_PID + '] ssl=' + sslN + ' cipher=' + cifN + ' recs=' + recs.length);
            dump('hb' + (tick / 200000));
        }
        if (tick < 400000000) setImmediate(hb);
    })();
    LOG('=== 就绪 ===');
});
