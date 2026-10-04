'use strict';
// cap_ssl.js — 同时覆盖两条传输路径
//   Path A（Java URLConnection + OpenSSL）-> SSL_write / SSL_read
//   Path B（native 裸 socket）           -> sendto / send / sendmsg
const LOG = (m) => send(String(m));

function asc(p, n) {
    try {
        const b = new Uint8Array(p.readByteArray(n));
        let s = '';
        for (let i = 0; i < b.length; i++) { const c = b[i]; s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.'; }
        return s;
    } catch (e) { return '(err)'; }
}
function HX(p, n) {
    try {
        const a = new Uint8Array(p.readByteArray(n));
        let s = [];
        for (let i = 0; i < a.length; i++) s.push(('0' + a[i].toString(16)).slice(-2));
        return s.join('');
    } catch (e) { return '(err)'; }
}

function handle(kind, name, p, len) {
    if (len <= 0 || len > 400000) return;
    let head = '';
    try { head = asc(p, Math.min(len, 1400)); } catch (e) { return; }
    const hasHttp = (head.indexOf('POST /') >= 0 || head.indexOf('GET /') >= 0
                     || head.indexOf('HTTP/1.') === 0);
    const hasA = head.indexOf('/a/') >= 0;
    if (!hasHttp && !hasA) return;

    LOG('=== ' + kind + ' ' + name + ' wired=' + len);
    LOG('  line=' + head.slice(0, 220).replace(/\r?\n/g, ' | '));
    const mh = /[?&]h=([0-9A-Fa-f]{0,64})/.exec(head);
    const mc = /Content-Length:\s*(\d+)/i.exec(head);
    LOG('  h=' + (mh ? mh[1] : '-') + '  CL=' + (mc ? mc[1] : '-'));

    const sep = head.indexOf('....');
    if (sep >= 0) {
        const off = sep + 4;
        if (off < len) {
            const blen = len - off;                 // 全量，不截断
            LOG('  bodylen=' + blen);
            LOG('  ### BODY:' + blen + ':' + HX(p.add(off), blen));
        }
    }
}

['sendto', 'send', 'sendmsg'].forEach(function (n) {
    const a = Module.findExportByName(null, n);
    if (!a) return;
    try {
        Interceptor.attach(a, { onEnter(args) { try { handle('SOCK', n, args[1], args[2].toInt32()); } catch (e) {} } });
    } catch (e) {}
});
LOG('[ok] send 家族');

let sslDone = false;
function installSsl() {
    if (sslDone) return true;
    const m = Process.findModuleByName('libssl.so');
    if (!m) return false;
    let ex = [];
    try { ex = m.enumerateExports(); } catch (e) { return false; }
    ex.forEach(function (e) {
        if (e.type !== 'function') return;
        if (e.name === 'SSL_write') {
            try {
                Interceptor.attach(e.address, { onEnter(args) { try { handle('SSL', 'SSL_write', args[1], args[2].toInt32()); } catch (e) {} } });
                LOG('[ok] SSL_write');
            } catch (e) {}
        } else if (e.name === 'SSL_read') {
            try {
                Interceptor.attach(e.address, {
                    onEnter(args) { this.buf = args[1]; },
                    onLeave(r) {
                        const got = r.toInt32();
                        if (got <= 0 || got > 400000) return;
                        try {
                            const h = asc(this.buf, Math.min(got, 40));
                            if (h.indexOf('HTTP/1.') < 0) return;
                            LOG('=== SSL_read 响应 ' + got + ' 字节');
                            LOG('  ### RESP:' + got + ':' + HX(this.buf, got));
                        } catch (e) {}
                    }
                });
                LOG('[ok] SSL_read');
            } catch (e) {}
        }
    });
    sslDone = true;
    return true;
}
if (!installSsl()) {
    LOG('[..] libssl 未加载，每 500ms 重试');
    const t = setInterval(function () { if (installSsl()) clearInterval(t); }, 500);
}

LOG('[ok] 全部安装完毕 pid=' + Process.id);
