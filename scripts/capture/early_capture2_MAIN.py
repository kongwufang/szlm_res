#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""early_capture2.py — ★ 带截图 + 每次点按前重新确认按钮

★★★ 修正上一版的两个问题：
   ① 盲点：用缓存的按钮坐标点按 —— 页面一变就点到《用户协议》链接 → 跳浏览器
      修法：每次点按前【重新 dump UI】，确认「同意协议并继续」确实在场才点
   ② 看不到屏幕：靠 dumpsys 猜界面状态
      修法：周期性 screencap 截图，落盘到 devout/SHOT/，供人工/模型直接看

★★★ 其余沿用（已验证有效）：
   · 设备端守望 watch.sh + frida 侧轮询双通道
   · hook_min.js（4 个钩子，无 maps 过滤 —— 这版能跑通完整注册）
   · tag 带 pid（避免多进程撞车）
"""
import base64
import io
import os
import re
import subprocess
import sys
import threading
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ADB = r"C:\tool\adb-fastboot\adb.exe"
REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
PKG = "com.coolapk.market"
TMPD = "/data/local/tmp"
PORT = 31337
FS = TMPD + "/fs"
SHOTDIR = os.path.join(REV, "devout", "SHOT")

serial = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.38:5555"
minutes = float(sys.argv[2]) if len(sys.argv) > 2 else 6
JS = sys.argv[3] if len(sys.argv) > 3 else "hook_min.js"
RUN = sys.argv[4] if len(sys.argv) > 4 else "c1"
TAG = serial.replace(":", "_").replace(".", "_")
LOG = open(os.path.join(REV, "dev2", "EC2_%s_%s.txt" % (TAG, RUN)), "w", encoding="utf-8")
LOCK = threading.Lock()
os.makedirs(SHOTDIR, exist_ok=True)


def raw(c, timeout=60):
    r = subprocess.run([ADB, "-s", serial, "shell", c], capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode(errors="replace").strip()


def su(c, timeout=90):
    b = base64.b64encode(c.encode()).decode()
    return raw('echo %s | base64 -d > /data/local/tmp/.s.sh; su -c "sh /data/local/tmp/.s.sh"' % b, timeout)


def say(s):
    with LOCK:
        print(s)
        LOG.write(s + "\n")
        LOG.flush()


def shot(tag):
    """截图并拉到本地"""
    try:
        raw("screencap -p /sdcard/.sc.png", timeout=45)
        dst = os.path.join(SHOTDIR, "%s_%s.png" % (RUN, tag))
        r = subprocess.run([ADB, "-s", serial, "pull", "/sdcard/.sc.png", dst],
                           capture_output=True, timeout=60)
        if os.path.exists(dst) and os.path.getsize(dst) > 1000:
            return dst
    except Exception:
        pass
    return None


def dump_ui():
    """返回 [(text, (x0,y0,x1,y1)), ...]"""
    try:
        raw("rm -f /sdcard/u.xml")
        raw("uiautomator dump /sdcard/u.xml", timeout=45)
        x = raw("cat /sdcard/u.xml", timeout=45)
    except Exception:
        return []
    out = []
    for m in re.finditer(r'<node[^>]*>', x):
        s = m.group(0)
        t = re.search(r'text="([^"]*)"', s)
        bo = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', s)
        if bo:
            out.append((t.group(1) if t else "", tuple(map(int, bo.groups()))))
    return out


def find_agree():
    """★ 只在按钮确实在场时返回 bounds"""
    for t, bo in dump_ui():
        if t == "同意协议并继续":
            return bo
    return None


def find_perm():
    for t, bo in dump_ui():
        if t in ("允许", "始终允许", "ALLOW"):
            return bo
    return None


# ★★★ 安全按钮白名单（点这些不会造成副作用）
DIALOG_SAFE = ("取消", "以后再说", "稍后", "暂不更新", "关闭", "我知道了",
               "跳过", "不再提示", "忽略", "等待", "确定")
# ★★★ 绝不允许点的（会触发下载/安装/付费）
DIALOG_FORBID = ("立即更新", "更新", "下载", "安装", "升级", "允许并继续", "同意并继续")


def handle_dialog():
    """★ 关掉挡路的弹窗。只点白名单按钮，绝不碰禁点按钮。返回点了什么。"""
    nd = dump_ui()
    texts = [t for t, _ in nd if t]
    # 有禁点按钮 -> 说明是危险弹窗，按 BACK 而不是点按钮
    for t, bo in nd:
        if t in DIALOG_FORBID:
            return ("BACK-回避:" + t)
    for t, bo in nd:
        if t in DIALOG_SAFE:
            cx = (bo[0] + bo[2]) // 2
            cy = (bo[1] + bo[3]) // 2
            raw("input tap %d %d" % (cx, cy))
            return ("点了:" + t)
    return None


def prefs_n():
    v = su("ls /data/data/%s/shared_prefs 2>/dev/null | wc -l" % PKG)
    return int(v) if v.isdigit() else 0


def fg():
    return raw("dumpsys window 2>/dev/null | grep -m1 mCurrentFocus", timeout=25)


say("=" * 96)
say("  带截图 + 安全点按的采集   %s   js=%s   run=%s" % (serial, JS, RUN))
say("=" * 96)

# ── ① frida-server ──
say("\n[1] 起 frida-server")
su("pkill -9 -f frida; pkill -9 -f '/tmp/fs'; sleep 1; echo ok")
su("cp -f %s/frida-server %s; chmod 777 %s" % (TMPD, FS, FS))
su("setsid %s -l 0.0.0.0:%d > %s/fs.log 2>&1 & echo go" % (FS, PORT, TMPD))
time.sleep(5)
subprocess.run([ADB, "-s", serial, "forward", "tcp:%d" % PORT, "tcp:%d" % PORT],
               capture_output=True, timeout=30)
import frida
dev = None
for i in range(5):
    try:
        dev = frida.get_device_manager().add_remote_device("127.0.0.1:%d" % PORT)
        say("    ✓ %d 进程" % len(dev.enumerate_processes()))
        break
    except Exception:
        time.sleep(3)
if dev is None:
    sys.exit(1)

# ── ② 部署守望 + 清数据 ──
say("\n[2] 部署守望 + 清数据")
sh = open(os.path.join(REV, "watch.sh"), encoding="utf-8").read().replace("\r\n", "\n")
su("echo %s | base64 -d > %s/watch.sh; chmod 755 %s/watch.sh; echo ok"
   % (base64.b64encode(sh.encode()).decode(), TMPD, TMPD))
raw("am force-stop " + PKG)
time.sleep(1)
say("    " + raw("pm clear " + PKG))
say("    prefs=%d" % prefs_n())

# ── ③ 启动守望管道 + 轮询线程 ──
say("\n[3] 启动守望（设备端 + frida 侧双通道）")
proc = subprocess.Popen([ADB, "-s", serial, "shell", 'su -c "sh %s/watch.sh"' % TMPD],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
js_src = open(os.path.join(REV, JS), encoding="utf-8").read()
attached = {}
msgs = []
stop = threading.Event()
MSG_F = open(os.path.join(REV, "dev2", "EC2_%s_%s_msgs.txt" % (TAG, RUN)), "w", encoding="utf-8")


def on_msg_factory(pid):
    def on_msg(m, d):
        try:
            if m.get("type") == "error":
                say("      [JS错误 p%s] %s" % (pid, str(m.get("description", ""))[:140]))
                return
            if m.get("type") != "send":
                return
            p = str(m.get("payload", ""))
            msgs.append((pid, p))
            MSG_F.write("p%s %s\n" % (pid, p))
            MSG_F.flush()
            if p.startswith(("★", "[ok]", "[x]", "[--]", "DONE", "[[doFinal", "[doFinal", "===")):
                say("      [p%s] %s" % (pid, p[:170]))
        except Exception:
            pass
    return on_msg


def try_attach(pid, why):
    if pid in attached:
        return
    try:
        sess = dev.attach(pid)
        sc = sess.create_script(js_src)
        sc.on("message", on_msg_factory(pid))
        sc.load()
        attached[pid] = (sess, sc)
        say("    ★★★ [%s] pid=%s → 钩子已装" % (why, pid))
    except Exception:
        pass


def reader():
    t0 = time.time()
    for line in iter(proc.stdout.readline, b""):
        try:
            s = line.decode("utf-8", "replace").strip()
        except Exception:
            continue
        if not s:
            continue
        if s.startswith("WATCH_READY"):
            say("    ✓ 设备端守望就绪")
            continue
        m = re.match(r'(?:NEW|EXIST) (\d+) (\S+)', s)
        if m:
            try_attach(int(m.group(1)), "守望+%.1fs" % (time.time() - t0))


def poll_loop():
    t0 = time.time()
    n_enum = 0
    while not stop.is_set() and time.time() - t0 < minutes * 60 + 120:
        # ★ 先用 get_process 直查（比 enumerate 快得多），失败再退回 enumerate
        got = False
        try:
            pr = dev.get_process(PKG)
            if pr is not None:
                try_attach(pr.pid, "直查+%.1fs" % (time.time() - t0))
                got = True
        except Exception:
            pass
        if not got:
            n_enum += 1
            try:
                for pr in dev.enumerate_processes():
                    n = str(getattr(pr, "name", ""))
                    if n == PKG or n.startswith(PKG + ":"):
                        try_attach(pr.pid, "轮询+%.1fs" % (time.time() - t0))
            except Exception:
                pass
        time.sleep(0.03)


threading.Thread(target=reader, daemon=True).start()
threading.Thread(target=poll_loop, daemon=True).start()

# ── ④ am start ──
say("\n[4] am start（轮询线程已在跑）")
raw("input keyevent KEYCODE_WAKEUP")
raw("am start -n %s/.view.main.MainActivity" % PKG)
time.sleep(3)

# ── ⑤ ★ 安全点按循环 ──
say("\n[5] ★ 安全点按（每次点按前重新确认按钮在场；不在就绝不点）")
t0 = time.time()
tapped = 0
last_state = ""
shots = 0
shot("start")
while time.time() - t0 < minutes * 60:
    el = int(time.time() - t0)

    # ★★★ 第一步：先处理挡路弹窗（更新提示等）
    dl = handle_dialog()
    if dl:
        if dl.startswith("BACK-回避"):
            raw("input keyevent KEYCODE_BACK")
            say("    [%3ds] 检测到危险弹窗(%s) -> 按 BACK 回避" % (el, dl.split(":")[-1]))
            shot("dlg%d" % el)
        else:
            say("    [%3ds] 弹窗处理: %s" % (el, dl))
            shot("close%d" % el)
        time.sleep(1.2)
        continue

    # 权限框
    bp = find_perm()
    if bp:
        raw("input tap %d %d" % ((bp[0] + bp[2]) // 2, (bp[1] + bp[3]) // 2))
        say("    [%3ds] 点了权限框" % el)
        time.sleep(1)
        continue

    # ★★★ 每次点按前【重新确认】按钮
    ba = find_agree()
    if ba:
        cx = (ba[0] + ba[2]) // 2
        cy = ba[1] + 14
        raw("input tap %d %d" % (cx, cy))
        tapped += 1
        st = "协议页 点按#%d @(%d,%d) bounds=%s" % (tapped, cx, cy, ba)
        if tapped <= 3 or tapped % 10 == 0:
            shot("tap%d" % tapped)
            shots += 1
    else:
        f = fg()
        st = "非协议页（不点） 前台=%s" % f[:70]

    p = prefs_n()
    line = "[%3ds] prefs=%-4d %s attach=%d 消息=%d" % (el, p, st, len(attached), len(msgs))
    if line[:40] != last_state[:40] or el % 20 < 3:
        say("    " + line[:185])
        last_state = line

    # 每 30 秒截一张，便于回看
    if el and el % 30 < 2:
        shot("t%03d" % el)
        shots += 1

    time.sleep(1.5)

# ── ⑥ 落盘 + 取回 ──
say("\n[6] 强制落盘 + 取回")
for pid, (sess, sc) in list(attached.items()):
    try:
        sc.post({"cmd": "dump"})
    except Exception:
        pass
time.sleep(3)
stop.set()
try:
    proc.kill()
except Exception:
    pass
shot("end")

files = []
for d in [TMPD, "/data/data/%s/files" % PKG]:
    for n in [x for x in su("ls %s 2>/dev/null" % d).split() if x.startswith(("HM_","HS2_","HS_","SP_"))]:
        t = su("cat %s/%s 2>/dev/null" % (d, n))
        if not t:
            continue
        pth = os.path.join(REV, "devout", "C4_%s_%s" % (RUN, n))
        with open(pth, "w", encoding="utf-8") as fh:
            fh.write(t)
        files.append(pth)
say("    取回 %d 个文件；截图 %d 张（%s）" % (len(files), shots, SHOTDIR))

tot = sslc = cifc = 0
for pth in files:
    try:
        t = open(pth, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    for line in t.split("\n"):
        if not line.startswith("REC"):
            continue
        tot += 1
        if " SSL " in line:
            sslc += 1
        elif " CIPHER " in line:
            cifc += 1
say("    协议 %d：SSL=%d  CIPHER=%d" % (tot, sslc, cifc))
say("    attach 过的进程: %s" % list(attached.keys()))
say("\n[7] prefs=%d  dna=%s" % (
    prefs_n(),
    su("grep -o 'device_id\">[^<]*' /data/data/%s/shared_prefs/%s_dna.xml 2>/dev/null" % (PKG, PKG)) or "(无)"))
MSG_F.close()
LOG.close()
