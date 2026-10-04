'use strict';
// diag_sock.js — 30 秒诊断：send() 的 NativePointer 到底能不能读
const LOG = (m) => send(String(m));
const MY_PID = Process.id;
let sn = 0, wn = 0;

Java.perform(function () {
    LOG('=== diag_sock p' + MY_PID + ' ===');

    // ── 原始 send ──
    const a = Module.findExportByName(null, 'send');
    LOG('send 地址 = ' + a);
    if (a) {
        try {
            Interceptor.attach(a, {
                onEnter(args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    this.n = args[2].toInt32();
                },
                onLeave(r) {
                    sn++;
                    if (sn > 8) return;
                    const ret = r.toInt32();
                    LOG('send#' + sn + ' fd=' + this.fd + ' n=' + this.n + ' ret=' + ret
                        + ' buf=' + this.buf);
                    // ① 直接 readByteArray
                    try {
                        const b = new Uint8Array(this.buf.readByteArray(Math.min(this.n, 32)));
                        let h = '';
                        for (let i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
                        LOG('  ① readByteArray(' + Math.min(this.n, 32) + ') -> len=' + b.length + ' hex=' + h);
                    } catch (e) { LOG('  ① 抛异常: ' + e); }
                    // ② 用 readByteArray(0) 看是否空
                    try {
                        const b2 = new Uint8Array(this.buf.readByteArray(0));
                        LOG('  ② readByteArray(0) -> len=' + b2.length);
                    } catch (e) { LOG('  ② 抛异常: ' + e); }
                    // ③ 用 Memory.readByteArray
                    try {
                        const b3 = new Uint8Array(Memory.readByteArray(this.buf, Math.min(this.n, 32)));
                        LOG('  ③ Memory.readByteArray -> len=' + b3.length);
                    } catch (e) { LOG('  ③ 抛异常: ' + e); }
                    // ④ readU8 逐字节
                    try {
                        let h = '';
                        for (let i = 0; i < Math.min(this.n, 16); i++) h += ('0' + this.buf.add(i).readU8().toString(16)).slice(-2);
                        LOG('  ④ readU8 逐字节 = ' + h);
                    } catch (e) { LOG('  ④ 抛异常: ' + e); }
                }
            });
            LOG('[ok] send 已挂钩');
        } catch (e) { LOG('[x] send: ' + e); }
    }

    // ── write ──
    const w = Module.findExportByName(null, 'write');
    if (w) {
        try {
            Interceptor.attach(w, {
                onEnter(args) { this.fd = args[0].toInt32(); this.buf = args[1]; this.n = args[2].toInt32(); },
                onLeave(r) {
                    if (this.fd <= 2) return;
                    wn++;
                    if (wn > 5) return;
                    LOG('write#' + wn + ' fd=' + this.fd + ' n=' + this.n + ' ret=' + r.toInt32());
                    try {
                        const b = new Uint8Array(this.buf.readByteArray(Math.min(this.n, 32)));
                        let h = '';
                        for (let i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
                        LOG('  readByteArray -> len=' + b.length + ' hex=' + h);
                    } catch (e) { LOG('  抛异常: ' + e); }
                }
            });
            LOG('[ok] write 已挂钩');
        } catch (e) { LOG('[x] write: ' + e); }
    }

    let t = 0;
    (function hb() {
        t++;
        if (t % 800000 === 0) LOG('[心跳] send=' + sn + ' write=' + wn);
        if (t < 100000000) setImmediate(hb);
    })();
    LOG('=== 就绪 ===');
});
