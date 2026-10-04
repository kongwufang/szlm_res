#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""early_capture.py — ★ 设备端守望 + 流式读取 + 即刻 attach

★★★ 依据文档：
   DEVICE_LESSONS_AND_SHORT_LIVED_PROC.md §七 方向 A（推荐）：
     「把监控搬到设备端，用设备端 shell 循环发现新进程，
       消除 adb 往返延迟」
   CAPTURE_PIPELINE.md bug 2：
     「消息 tag 必须带 pid，否则多进程互相覆盖」

★★★ 架构：
   设备端 watch.sh 常驻，每 30ms 扫一次 /proc，发现新 pid 就
   立刻 echo 到 stdout
   Python 用一个【长驻的 adb shell 管道】流式读取 —— 没有 per-poll 的 adb 往返
   读到 pid 立刻 frida attach + load 钩子

★★★ 纪律（HOOK_LESSONS.md §五）：
   先只装【一个点】看稳定性，再逐步加
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

serial = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.38:5555"
minutes = float(sys.argv[2]) if len(sys.argv) > 2 else 5
JS = sys.argv[3] if len(sys.argv) > 3 else "hook_min.js"
RUN = sys.argv[4] if len(sys.argv) > 4 else "e1"
TAG = serial.replace(":", "_").replace(".", "_")
LOG = open(os.path.join(REV, "dev2", "EARLY_%s_%s.txt" % (TAG, RUN)), "w", encoding="utf-8")
LOCK = threading.Lock()


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


def nodes():
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


def prefs_n():
    v = su("ls /data/data/%s/shared_prefs 2>/dev/null | wc -l" % PKG)
    return int(v) if v.isdigit() else 0


def fg():
    return raw("dumpsys window 2>/dev/null | grep -m1 mCurrentFocus", timeout=25)


say("=" * 96)
say("  设备端守望 + 即刻 attach   %s   js=%s   run=%s" % (serial, JS, RUN))
say("=" * 96)

# ── ① frida-server ──
say("\n[1] 起 frida-server")
su("pkill -f frida; pkill -f '/tmp/fs'; sleep 1; echo ok")
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

# ── ② 部署 watch.sh ──
say("\n[2] 部署设备端守望脚本")
sh = open(os.path.join(REV, "watch.sh"), encoding="utf-8").read().replace("\r\n", "\n")
b64 = base64.b64encode(sh.encode()).decode()
su("echo %s | base64 -d > %s/watch.sh; chmod 755 %s/watch.sh; echo ok" % (b64, TMPD, TMPD))
say("    " + su("head -3 %s/watch.sh" % TMPD))

# ── ③ pm clear ──
say("\n[3] 清数据")
raw("am force-stop " + PKG)
time.sleep(1)
say("    " + raw("pm clear " + PKG))
say("    prefs=%d" % prefs_n())

# ── ④ 启动【长驻】守望管道 ──
say("\n[4] 启动长驻守望管道（无 per-poll adb 往返）")
proc = subprocess.Popen(
    [ADB, "-s", serial, "shell", 'su -c "sh %s/watch.sh"' % TMPD],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

js_src = open(os.path.join(REV, JS), encoding="utf-8").read()
attached = {}
msgs = []
stop = threading.Event()
MSG_F = open(os.path.join(REV, "dev2", "EARLY_%s_%s_msgs.txt" % (TAG, RUN)), "w", encoding="utf-8")


def on_msg_factory(pid):
    def on_msg(m, d):
        try:
            if m.get("type") == "error":
                say("      [JS错误 p%s] %s" % (pid, str(m.get("description", ""))[:150]))
                return
            if m.get("type") != "send":
                return
            p = str(m.get("payload", ""))
            msgs.append((pid, p))
            MSG_F.write("p%s %s\n" % (pid, p))
            MSG_F.flush()
            if p.startswith(("★", "[ok]", "[x]", "[--]", "DONE", "[心跳]", "===", "[doFinal")):
                say("      [p%s] %s" % (pid, p[:175]))
        except Exception:
            pass
    return on_msg


def reader():
    """流式读取设备端输出：每读到一行 NEW <pid> <name>，立刻 attach"""
    t0 = time.time()
    for line in iter(proc.stdout.readline, b""):
        try:
            s = line.decode("utf-8", "replace").strip()
        except Exception:
            continue
        if not s:
            continue
        if s.startswith("WATCH_READY"):
            say("    ✓ 设备端守望已就绪")
            continue
        m = re.match(r'(?:NEW|EXIST) (\d+) (\S+)', s)
        if not m:
            continue
        pid = int(m.group(1))
        name = m.group(2)
        if pid in attached:
            continue
        dt = time.time() - t0
        try:
            sess = dev.attach(pid)
            sc = sess.create_script(js_src)
            sc.on("message", on_msg_factory(pid))
            sc.load()
            attached[pid] = (sess, sc)
            say("    ★★★ [+%.2fs] NEW pid=%s (%s) → 钩子已装" % (dt, pid, name))
        except Exception as e:
            say("    ✗ [+%.2fs] pid=%s attach 失败: %s" % (dt, pid, str(e)[:90]))
        if time.time() - t0 > minutes * 60 + 120:
            break


th = threading.Thread(target=reader, daemon=True)
th.start()
time.sleep(1)

# ── ⑤ 启动 app ──
say("\n[5] am start")
raw("input keyevent KEYCODE_WAKEUP")
raw("am start -n %s/.view.main.MainActivity" % PKG)

# ★ 双保险：主动补捉主进程（守望可能漏掉启动极早的进程）
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
    except Exception as ex:
        pass

# ★ 常驻轮询线程：与设备端守望并行，双通道捕捉
def frida_poll():
    t0 = time.time()
    while not stop.is_set() and time.time() - t0 < minutes * 60 + 120:
        try:
            lst = dev.enumerate_processes()
        except Exception:
            time.sleep(0.2); continue
        for pr in lst:
            try:
                if pr.name == PKG or str(pr.name).startswith(PKG + ":"):
                    try_attach(pr.pid, "frida轮询")
            except Exception:
                pass
        time.sleep(0.1)

threading.Thread(target=frida_poll, daemon=True).start()
say("    ✓ frida 侧轮询线程已启动（与设备端守望并行）")

# ── ⑥ 协议页 + 点同意（全程守望）──
say("\n[6] 等协议页 → 点同意")
btn = None
for i in range(25):
    time.sleep(2)
    f = fg()
    if "permissioncontroller" in f:
        for t, bo in nodes():
            if t in ("允许", "始终允许", "ALLOW"):
                raw("input tap %d %d" % ((bo[0] + bo[2]) // 2, (bo[1] + bo[3]) // 2))
                time.sleep(1)
        continue
    for t, bo in nodes():
        if t == "同意协议并继续":
            btn = bo
            break
    if btn:
        break
say("    按钮=%s" % (btn,))

t0 = time.time()
tapped = 0
last_p = -1
while time.time() - t0 < minutes * 60:
    el = int(time.time() - t0)
    f = fg()
    if "permissioncontroller" in f:
        for t, bo in nodes():
            if t in ("允许", "始终允许", "ALLOW"):
                raw("input tap %d %d" % ((bo[0] + bo[2]) // 2, (bo[1] + bo[3]) // 2))
                time.sleep(1)
    elif "Not Responding" in f or "ANR" in f:
        raw("input keyevent KEYCODE_ENTER")
        time.sleep(1)

    p = prefs_n()
    if btn and PKG in f and p < 300 and tapped < 60:
        raw("input tap %d %d" % ((btn[0] + btn[2]) // 2, btn[1] + 14))
        tapped += 1
        time.sleep(0.5)

    if p != last_p:
        last_p = p
        say("    [%3ds] prefs=%-4d tap=%-3d 已attach=%d 消息=%d"
            % (el, p, tapped, len(attached), len(msgs)))
    time.sleep(2)

# ── ⑦ 落盘 + 取回 ──
say("\n[7] 对所有已 attach 的进程强制落盘")
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

files = []
for d in [TMPD, "/data/data/%s/files" % PKG]:
    for n in [x for x in su("ls %s 2>/dev/null" % d).split() if x.startswith("HM_")]:
        t = su("cat %s/%s 2>/dev/null" % (d, n))
        if not t:
            continue
        pth = os.path.join(REV, "devout", "EARLY_%s_%s" % (RUN, n))
        with open(pth, "w", encoding="utf-8") as fh:
            fh.write(t)
        files.append(pth)
say("    取回 %d 个文件" % len(files))

# ── ⑧ 统计 ──
say("\n[8] 统计")
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
say("    attach 过的进程 %d 个: %s" % (len(attached), list(attached.keys())[:20]))
say("\n[9] prefs=%d  dna=%s" % (
    prefs_n(),
    su("grep -o 'device_id\">[^<]*' /data/data/%s/shared_prefs/%s_dna.xml 2>/dev/null" % (PKG, PKG)) or "(无)"))
MSG_F.close()
LOG.close()
