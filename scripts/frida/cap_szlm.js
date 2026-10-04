// cap_szlm.js — 抓数盟上报：sendto/recvfrom 层，全量不截断
// 关键修正：不过滤成 4000 字节，body 全量落盘（上次 d2api/daa 就是被 slice 截掉的）
'use strict';
const LOG = (m) => send(String(m));
const HX = (p, n) => {
    try {
        const a = new Uint8Array(p.readByteArray(n));
        let s = [];
        for (let i = 0; i < a.length; i++) s.push(('0' + a[i].toString(16)).slice(-2));
        return s.join('');
    } catch (e) { return '(err)'; }
};

let idx = 0;
let seen = {};

function handleSo(name, p, len) {
    if (len <= 0 || len > 300000) return;
    // 先读头部做判定（只读 1KB，省 CPU）
    let head = '';
    try {
        const b = new Uint8Array(p.readByteArray(Math.min(len, 1024)));
        for (let i = 0; i < b.length; i++) {
            const c = b[i];
            head += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        }
    } catch (e) { return; }
    const mi = head.indexOf('POST /a/');
    if (mi < 0) return;

    // 去重（同一次发送可能被多次 syscall 观到）
    const key = name + ':' + head.slice(mi, mi + 120);
    if (seen[key]) return;
    seen[key] = true;

    idx++;
    const mh = /[?&]h=([0-9A-Fa-f]{0,64})/.exec(head);
    const mp = /[?&]p=([0-9A-Fa-f]{32})/.exec(head);
    const mr = /[?&]r=([0-9A-Fa-f]{0,64})/.exec(head);
    const mn = /[?&]n=(-?\d+)/.exec(head);
    const ml = /[?&]l=(-?\d+)/.exec(head);
    const mc = /Content-Length:\s*(\d+)/i.exec(head);
    const sep = head.indexOf('....');
    const bodyOff = sep >= 0 ? sep + 4 : -1;

    LOG('=== REQ#' + idx + ' via ' + name + ' ===');
    LOG('  line = ' + head.slice(mi, mi + 240));
    LOG('  p=' + (mp ? mp[1] : '-') + '  r=' + (mr ? mr[1] : '-')
        + '  n=' + (mn ? mn[1] : '-') + '  l=' + (ml ? ml[1] : '-')
        + '  h=' + (mh ? mh[1] : '-') + '  CL=' + (mc ? mc[1] : '-'));
    LOG('  wired = ' + len + '  bodyOff = ' + bodyOff);

    if (bodyOff > 0 && bodyOff < len) {
        const blen = len - bodyOff;
        LOG('  ### BODY#' + idx + ':' + blen + ':' + HX(p.add(bodyOff), blen));
    }
}

function installSend(name) {
    const a = Module.findExportByName(null, name);
    if (!a) return;
    try {
        Interceptor.attach(a, {
            onEnter(args) {
                try {
                    // sendto(fd, buf, len, flags, addr, addrlen)
                    // send(fd, buf, len, flags)
                    const buf = args[1];
                    const len = args[2].toInt32();
                    handleSo(name, buf, len);
                } catch (e) {}
            }
        });
        LOG('[ok] hook ' + name);
    } catch (e) { LOG('[!] ' + name + ' ' + e); }
}

function installRecv(name) {
    const a = Module.findExportByName(null, name);
    if (!a) return;
    try {
        Interceptor.attach(a, {
            onEnter(args) {
                this.buf = args[1];
                this.max = args[2].toInt32();
            },
            onLeave(r) {
                try {
                    const got = r.toInt32();
                    if (got <= 0 || got > 300000) return;
                    const b = new Uint8Array(this.buf.readByteArray(Math.min(got, 64)));
                    let h = '';
                    for (let i = 0; i < b.length; i++) {
                        const c = b[i];
                        h += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
                    }
                    if (h.indexOf('HTTP/1.') < 0) return;
                    idx++;
                    LOG('=== RESP#' + idx + ' via ' + name + ' ===');
                    LOG('  ### RESPRAW#' + idx + ':' + got + ':' + HX(this.buf, got));
                } catch (e) {}
            }
        });
        LOG('[ok] hook ' + name);
    } catch (e) { LOG('[!] ' + name + ' ' + e); }
}

// 隐身：/proc/self/maps 与 status 过滤掉 frida 痕迹
// ⚠ D1(TK_Watch / Android 8.1) 实测：open 重定向会让酷安启动即 SIGSEGV。
//   所以默认【不开】，需要时用 STEALTH=1 打开。
const STEALTH = 0;
const BAD = ['frida', 'gum-js', 'gmain', 'gdbus', 'linjector', '27042', 're.frida'];
function isBad(s) { if (!s) return false; for (let i = 0; i < BAD.length; i++) if (s.indexOf(BAD[i]) >= 0) return true; return false; }
const CM = '/data/data/com.coolapk.market/files/.cm';
const CS = '/data/data/com.coolapk.market/files/.cs';
let ready = false;
function bc() {
    try {
        File.writeAllText(CM, File.readAllText('/proc/self/maps').split('\n').filter(function (l) { return !isBad(l); }).join('\n'));
        File.writeAllText(CS, File.readAllText('/proc/self/status').split('\n').filter(function (l) { return !isBad(l); }).join('\n'));
        ready = true;
    } catch (e) {}
}
if (STEALTH) {
    bc(); setInterval(bc, 800);
    ['fopen', 'open', 'openat'].forEach(function (fn) {
        const a = Module.findExportByName(null, fn);
        if (!a) return;
        const isAt = (fn === 'openat');
        Interceptor.attach(a, { onEnter(args) {
            let p = null; try { p = (isAt ? args[1] : args[0]).readCString(); } catch (e) {}
            if (!p || !ready) return;
            let t = null;
            if (p.indexOf('/proc/self/maps') === 0 || p.indexOf('/proc/' + Process.id + '/maps') === 0) t = CM;
            else if (p.indexOf('/proc/self/status') === 0 || p.indexOf('/proc/' + Process.id + '/status') === 0) t = CS;
            if (t) { try { if (isAt) args[1] = Memory.allocUtf8String(t); else args[0] = Memory.allocUtf8String(t); } catch (e) {} }
        }});
    });
    LOG('[ok] 隐身已开');
} else {
    LOG('[ok] 隐身关闭（D1 上开它会崩）');
}
['kill', 'tgkill'].forEach(function (fn) {
    const a = Module.findExportByName(null, fn);
    if (!a) return;
    const isTg = (fn === 'tgkill');
    Interceptor.attach(a, { onEnter(args) {
        const t = isTg ? args[1].toInt32() : args[0].toInt32();
        if (t === Process.id || t === 0) { this.blk = true; }
    }, onLeave(r) { if (this.blk) r.replace(ptr(0)); }});
});
LOG('[ok] 自杀拦截 (pid=' + Process.id + ')');

['sendto', 'send', 'sendmsg'].forEach(installSend);
['recvfrom', 'recv'].forEach(installRecv);
LOG('[ok] 全部 hook 安装完毕');
