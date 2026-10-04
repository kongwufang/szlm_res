// dujni.js — 直接 hook libdu.so 的 6 个返回 String 的 native 函数，读取其返回值
//
// 依据（上一轮 RegisterNatives 映射）：
//   run        (Context,String,String)String   -> libdu.so+0x13a250
//   query      (Context,String,String,IJJ[I)String -> libdu.so+0x13a280
//   onEvent    (Context,String,String,String)String -> libdu.so+0x13a440
//   onIEvent   (Context,String,String,String)String -> libdu.so+0x13a46c
//   zZVTFJRA   (Context,String)String          -> libdu.so+0x13a498
//   c6M2YmYQ   (Context,I)String               -> libdu.so+0x13a4a4
//   c6M3YmYQ   (Context,I,String)String        -> libdu.so+0x13a4b8
//   ttERIJNQ   (Context,String,String)String   -> libdu.so+0x13a1f0
//   ntERIJNQ   (Context,I,String)String        -> libdu.so+0x13a4b0
//   nYfbIIFp   (Context,String,String)String   -> libdu.so+0x13a220
//
// 本脚本：在 native 层 Interceptor.attach，onLeave 时用 JNI 的
//         GetStringUTFChars(下标 169) 读返回值 —— 完全不碰 Java 反射
'use strict';
function LOG() {
    let s = "";
    for (let i = 0; i < arguments.length; i++) s += (i ? " " : "") + String(arguments[i]);
    send(s);
}

// ===== 隐身 =====
const BAD = ['frida', 'gum-js', 'gmain', 'gdbus', 'linjector', '27042', 'xposed', 'substrate', 'magisk', 're.frida'];
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
bc(); setInterval(bc, 700);
['fopen', 'open', 'openat'].forEach(function (fn) {
    const a = Module.findExportByName(null, fn);
    if (!a) return;
    const isAt = (fn === 'openat');
    Interceptor.attach(a, { onEnter(args) {
        let p = null; try { p = (isAt ? args[1] : args[0]).readCString(); } catch (e) {}
        if (!p || !ready) return;
        let t = null;
        if (p.indexOf('/proc/self/maps') === 0 || p.indexOf('/proc/' + Process.id + '/maps') === 0) t = CM;
        else if (p.indexOf('/proc/' + Process.id + '/status') === 0) t = CS;
        if (t) { try { if (isAt) args[1] = Memory.allocUtf8String(t); else args[0] = Memory.allocUtf8String(t); } catch (e) {} }
    }});
});
const MYPID = Process.id;
['kill', 'tgkill'].forEach(function (fn) {
    const a = Module.findExportByName(null, fn);
    if (!a) return;
    const isTg = (fn === 'tgkill');
    Interceptor.attach(a, { onEnter(args) {
        const t = isTg ? args[1].toInt32() : args[0].toInt32();
        if (t === MYPID || t === 0) { this.blk = true; }
    }, onLeave(r) { if (this.blk) r.replace(ptr(0)); }});
});
LOG('[ok] 隐身 pid=' + Process.id);

// ===== JNI 辅助 =====
const PS = Process.pointerSize;
let envTable = null;
let GetStringUTFChars = null;
let ReleaseStringUTFChars = null;
let GetStringUTFLength = null;

Java.perform(function () {
    try {
        envTable = Java.vm.getEnv().handle.readPointer();
        GetStringUTFLength = new NativeFunction(envTable.add(168 * PS).readPointer(),
            'long', ['pointer', 'pointer']);
        GetStringUTFChars = new NativeFunction(envTable.add(169 * PS).readPointer(),
            'pointer', ['pointer', 'pointer', 'pointer']);
        ReleaseStringUTFChars = new NativeFunction(envTable.add(170 * PS).readPointer(),
            'void', ['pointer', 'pointer', 'pointer']);
        LOG('[jni] GetStringUTFChars(169)=' + GetStringUTFChars +
            '  GetStringUTFLength(168)=' + GetStringUTFLength);
    } catch (e) { LOG('[e] JNI 表: ' + e); }
});

function jstr(env, js) {
    if (!js || js.isNull() || !GetStringUTFChars) return null;
    let p = null, len = 0;
    try { len = GetStringUTFLength(env, js); } catch (e) {}
    try { p = GetStringUTFChars(env, js, ptr(0)); } catch (e) { return null; }
    if (!p || p.isNull()) return null;
    let s = null;
    try { s = p.readUtf8String(); } catch (e) {}
    try { ReleaseStringUTFChars(env, js, p); } catch (e) {}
    return { s: s, len: len };
}

function show(r, tag) {
    if (!r || r.s === null) { LOG('   [' + tag + '] -> null'); return; }
    const s = r.s;
    let hexlen = 0;
    try { hexlen = s.length; } catch (e) {}
    LOG('   [' + tag + '] 长度=' + hexlen + ' (JNI len=' + r.len + ')');
    // 判定内容形态
    const pr = s.slice(0, 400);
    if (/^[0-9a-fA-F]+$/.test(pr) && pr.length > 40) {
        LOG('      [hex] ' + pr.slice(0, 160));
    } else if (/^[A-Za-z0-9+/=]+$/.test(pr) && pr.length > 40) {
        LOG('      [b64?] ' + pr.slice(0, 160));
    } else {
        let hx = '';
        for (let i = 0; i < Math.min(s.length, 64); i++) {
            hx += ('0' + (s.charCodeAt(i) & 0xff).toString(16)).slice(-2);
        }
        LOG('      [raw-hex] ' + hx);
        LOG('      [可打印] ' + JSON.stringify(s.slice(0, 160)));
    }
}

const TARGETS = [
    ['run', 0x13a250],
    ['query', 0x13a280],
    ['onEvent', 0x13a440],
    ['onIEvent', 0x13a46c],
    ['zZVTFJRA', 0x13a498],
    ['c6M2YmYQ', 0x13a4a4],
    ['c6M3YmYQ', 0x13a4b8],
    ['ttERIJNQ', 0x13a1f0],
    ['ntERIJNQ', 0x13a4b0],
    ['nYfbIIFp', 0x13a220],
    ['dGZvcmRQ', 0x13cf80],
    ['oxlbmV0d', 0x13cfb4],
];

let nHit = 0;
let duBase = null;

function install() {
    const m = Process.findModuleByName('libdu.so');
    if (!m) return;
    if (duBase && duBase.equals(m.base)) return;
    duBase = m.base;
    LOG('[du] libdu.so base=' + m.base);
    TARGETS.forEach(function (t) {
        const addr = m.base.add(t[1]);
        try {
            Interceptor.attach(addr, {
                onEnter(args) {
                    this.env = args[0];
                    this.a1 = args[1];
                    this.a2 = args[2];
                    this.a3 = args[3];
                },
                onLeave(retval) {
                    nHit++;
                    if (nHit > 60) return;
                    LOG('#### ' + t[0] + ' #' + nHit + '  (libdu+0x' + t[1].toString(16) + ')');
                    const e = this.env;
                    const r = jstr(e, retval);
                    show(r, t[0]);
                    // 参数里的 String
                    if (this.a2 && !this.a2.isNull()) {
                        const s2 = jstr(e, this.a2);
                        if (s2 && s2.s !== null) LOG('       arg2= ' + JSON.stringify(s2.s.slice(0, 200)));
                    }
                    if (this.a3 && !this.a3.isNull()) {
                        const s3 = jstr(e, this.a3);
                        if (s3 && s3.s !== null) LOG('       arg3= ' + JSON.stringify(s3.s.slice(0, 200)));
                    }
                }
            });
            LOG('[du] hook ' + t[0] + ' @' + addr);
        } catch (e) { LOG('[e] hook ' + t[0] + ': ' + String(e).slice(0, 100)); }
    });
}
install();
setInterval(install, 800);

setInterval(function () {
    LOG('[心跳 pid=' + Process.id + '] native命中=' + nHit + ' libdu=' + (duBase ? 'yes' : 'no'));
}, 9000);
