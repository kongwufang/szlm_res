#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""watch_capture.py — 进程守望：一出现就 attach，覆盖 app 的自杀重启

★★★ 上一轮失败原因（已确诊）：
     spawn 的 pid 20089 在几秒后消失，新进程 20200 从 zygote 起来
     ⇒ 钩子随旧进程一起没了，所以 doFinal=0 / ssl=0

★ 本脚本：
     ① 起 frida-server（热着，attach 只需百毫秒）
     ② pm clear
     ③ 起一个【守望线程】，每 0.15s 扫一次包名下的进程，
        一出现新 pid 就立刻 attach + load 钩子
     ④ 同时 am start 启动 app
     ⑤ 点同意
     ⑥ 全程守望，覆盖任意次重启

★ 另外：把「进程出生/死亡」都记下来，好判断自杀重启发生在什么时候
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
minutes = float(sys.argv[2]) if len(sys.argv) > 2 else 6
RUN = sys.argv[3] if len(sys.argv) > 3 else "w1"
TAG = serial.replace(":", "_").replace(".", "_")
LOG = open(os.path.join(REV, "dev2", "WATCH_%s_%s.txt" % (TAG, RUN)), "w", encoding="utf-8")
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
say("  进程守望抓注册   %s   run=%s   %.0f 分钟" % (serial, RUN, minutes))
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

js_src = open(os.path.join(REV, "spawn_hook.js"), encoding="utf-8").read()

# ── ② pm clear ──
say("\n[2] 清数据")
raw("am force-stop " + PKG)
time.sleep(1)
say("    " + raw("pm clear " + PKG))
say("    prefs=%d" % prefs_n())

# ── ③ 守望线程 ──
attached = {}          # pid -> (session, script)
seen = set()
stop = threading.Event()
msgs = []
MSGLOG = os.path.join(REV, "dev2", "WATCH_%s_%s_msgs.txt" % (TAG, RUN))
MSG_F = open(MSGLOG, "w", encoding="utf-8")


def on_msg_factory(pid):
    def on_msg(m, d):
        try:
            if m.get("type") == "error":
                say("      [JS错误 pid=%s] %s" % (pid, str(m.get("description", ""))[:150]))
                return
            if m.get("type") != "send":
                return
            p = str(m.get("payload", ""))
            msgs.append((pid, p))
            MSG_F.write("pid=%s %s\n" % (pid, p))
            MSG_F.flush()
            if p.startswith(("★", "[ok]", "[x]", "[--]", "DONE", "[心跳]", "===", "[doFinal")):
                say("      [pid=%s] %s" % (pid, p[:175]))
        except Exception:
            pass
    return on_msg


def watcher():
    t0 = time.time()
    while not stop.is_set():
        try:
            procs = dev.enumerate_processes()
        except Exception:
            time.sleep(0.3)
            continue
        for pr in procs:
            if pr.name != PKG and not pr.name.startswith(PKG + ":"):
                continue
            key = pr.pid
            if key in seen:
                continue
            seen.add(key)
            if pr.pid in attached:
                continue
            try:
                s = dev.attach(pr.pid)
                sc = s.create_script(js_src)
                sc.on("message", on_msg_factory(pr.pid))
                sc.load()
                attached[pr.pid] = (s, sc)
                say("    ★★★ [+%.2fs] 捕捉到进程 pid=%s，钩子已装"
                    % (time.time() - t0, pr.pid))
            except Exception as e:
                say("    [x] pid=%s attach 失败: %s" % (pr.pid, str(e)[:80]))
        # 记录消失的进程
        live = set(pr.pid for pr in procs)
        for pid in list(attached.keys()):
            if pid not in live:
                say("    ✗ [-%.2fs] pid=%s 已消失" % (time.time() - t0, pid))
                try:
                    attached[pid][0].detach()
                except Exception:
                    pass
                del attached[pid]
        time.sleep(0.15)


th = threading.Thread(target=watcher, daemon=True)
th.start()
say("\n[3] 守望线程已启动")

# ── ④ 启动 app ──
say("\n[4] am start")
raw("input keyevent KEYCODE_WAKEUP")
raw("am start -n %s/.view.main.MainActivity" % PKG)

# ── ⑤ 等协议页 + 点同意 ──
say("\n[5] 等协议页 → 点同意")
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
    if btn and PKG in f and p <= 8 and tapped < 40:
        raw("input tap %d %d" % ((btn[0] + btn[2]) // 2, btn[1] + 14))
        tapped += 1
        time.sleep(0.5)

    if p != last_p:
        last_p = p
        say("    [%3ds] prefs=%-4d tap=%-3d 已捕进程=%d 消息=%d"
            % (el, p, tapped, len(attached), len(msgs)))
    time.sleep(2)

# ── ⑥ 落盘 + 取回 ──
say("\n[6] 强制落盘（对所有已捕进程）")
for pid, (s, sc) in list(attached.items()):
    try:
        sc.post({"cmd": "dump"})
    except Exception:
        pass
time.sleep(3)
stop.set()

files = []
for d in ["/data/data/%s/files" % PKG, TMPD]:
    for n in [x for x in su("ls %s 2>/dev/null" % d).split() if x.startswith("SP_")]:
        t = su("cat %s/%s 2>/dev/null" % (d, n))
        if not t:
            continue
        pth = os.path.join(REV, "devout", "WATCH_%s_%s" % (RUN, n))
        with open(pth, "w", encoding="utf-8") as fh:
            fh.write(t)
        files.append(pth)
say("    取回 %d 个文件：%s" % (len(files), [os.path.basename(x) for x in files]))

# ── ⑦ 统计 ──
say("\n[7] 统计")
tot = cif = sslc = sockc = classc = 0
for pth in files:
    try:
        t = open(pth, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    for line in t.split("\n"):
        if not line.startswith("REC"):
            continue
        tot += 1
        if " CIPHER " in line:
            cif += 1
        elif " SSL " in line:
            sslc += 1
        elif " SOCK " in line:
            sockc += 1
        elif " CLASS " in line:
            classc += 1
say("    协议 %d：CIPHER=%d  SSL=%d  SOCK=%d  CLASS=%d" % (tot, cif, sslc, sockc, classc))
say("    捕到过的进程: %s" % list(seen))

say("\n[8] prefs=%d  dna=%s" % (
    prefs_n(),
    su("grep -o 'device_id\">[^<]*' /data/data/%s/shared_prefs/%s_dna.xml 2>/dev/null" % (PKG, PKG)) or "(无)"))
MSG_F.close()
LOG.close()
