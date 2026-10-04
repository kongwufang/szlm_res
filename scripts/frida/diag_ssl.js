'use strict';
// diag_ssl.js — 60 秒诊断：SSL 钩子里 push() 的判断到底发生了什么

const LOG = (m) => send(String(m));
const MY_PID = Process.id;
let n = 0;

function probe(tag, arr, len) {
    let info = tag + ' n=' + len + ' ptr=' + arr;
    try {
        const b = new Uint8Array(arr.readByteArray(8));
        info += ' read8=[' + Array.prototype.join.call(b, ',') + ']';
        info += ' len8=' + b.length;
        const httpLike = (b[0] === 0x47 && b[1] === 0x45) || (b[0] === 0x50 && b[1] === 0x4f)
                      || (b[0] === 0x48 && b[1] === 0x54) || (b[0] === 0x50 && b[1] === 0x55);
        info += ' httpLike=' + httpLike + ' n>=800? ' + (len >= 800);
    } catch (e) {
        info += ' ✗ readByteArray 抛异常: ' + e;
    }
    LOG(info);
}

function hexOf(arr, len) {
    try {
        const b = new Uint8Array(arr.readByteArray(Math.min(len, 64)));
        let h = '';
        for (let i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
        return h;
    } catch (e) { return '(' + e + ')'; }
}

Java.perform(function () {
    LOG('=== diag_ssl 启动 p' + MY_PID + ' ===');
    let hooked = [];
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
                        n++;
                        let ln = this.n;
                        if (!isW) { ln = r.toInt32(); if (ln <= 0) return; }
                        if (ln < 64 || ln > 300000) return;
                        if (n <= 25) {
                            probe('#%d %s.%s %s' % (n, mn, fn, isW ? 'OUT' : 'IN'), this.buf, ln);
                            LOG('     hex64=' + hexOf(this.buf, ln));
                        }
                        if (n === 26) LOG('…后续省略');
                    }
                });
                hooked.push(mn + '.' + fn);
            } catch (e) { LOG('[x] ' + mn + '.' + fn + ': ' + e); }
        });
    });
    LOG('[ok] 钩子: ' + (hooked.join(',') || '(无)'));

    let t = 0;
    (function hb() {
        t++;
        if (t % 1000000 === 0) LOG('[心跳] SSL 调用 ' + n + ' 次');
        if (t < 200000000) setImmediate(hb);
    })();
    LOG('=== 就绪（60 秒后看输出）===');
});
