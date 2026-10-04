#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""spawn_capture.py — spawn+gating：从第 0 毫秒起抓，目标拿到 mdna 明文

★★★ 用户的关键推理（本轮的实验依据）：
     pm clear 后本地零状态 → libdu 必须把「能标识本机」的信息放进请求
     ⇒ 请求里必然存在【本地可重算】的设备标识
   要验证它，需要【同一设备跨两次 pm clear 注册】的 mdna 明文做 diff

★★★ 为什么必须用 spawn：
     之前 attach 要等 frida-server 起（4-5 秒），szlm 上报就在这个窗口里发出去了
     ⇒ spawn+gating 在 JVM 起来前装钩子，从第 0 毫秒抓起

★ 本脚本做一次完整注册，抓全量数据，落盘供离线 diff
"""
import base64
import io
import os
import re
import subprocess
import sys
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
RUN = sys.argv[3] if len(sys.argv) > 3 else "r1"
TAG = serial.replace(":", "_").replace(".", "_")
LOG = open(os.path.join(REV, "dev2", "SPAWN_%s_%s.txt" % (TAG, RUN)), "w", encoding="utf-8")


def raw(c, timeout=60):
    r = subprocess.run([ADB, "-s", serial, "shell", c], capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode(errors="replace").strip()


def su(c, timeout=90):
    b = base64.b64encode(c.encode()).decode()
    return raw('echo %s | base64 -d > /data/local/tmp/.s.sh; su -c "sh /data/local/tmp/.s.sh"' % b, timeout)


def say(s):
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
say("  spawn+gating 抓注册全量   %s   run=%s   %.0f 分钟" % (serial, RUN, minutes))
say("=" * 96)

# ── ① 起 frida-server ──
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

# ── ② 清数据 ──
say("\n[2] 清数据")
raw("am force-stop " + PKG)
time.sleep(1)
say("    " + raw("pm clear " + PKG))
say("    prefs=%d" % prefs_n())

# ── ③ spawn（挂起）──
say("\n[3] spawn + gating（进程挂起，先装钩子）")
pid = None
try:
    pid = dev.spawn([PKG])
    say("    ✓ spawn 成功 pid=%s（已挂起）" % pid)
except Exception as e:
    say("    ✗ spawn 失败: " + str(e)[:160])
    sys.exit(1)

js = open(os.path.join(REV, "spawn_hook.js"), encoding="utf-8").read()
msgs = []


def on_msg(m, d):
    try:
        if m.get("type") == "error":
            say("      [JS错误] " + str(m.get("description", ""))[:160])
            return
        if m.get("type") != "send":
            return
        p = str(m.get("payload", ""))
        msgs.append(p)
        if p.startswith(("★", "[ok]", "[x]", "[--]", "DONE", "[心跳]", "===", "    ", "[doFinal")):
            say("      " + p[:190])
    except Exception:
        pass


sess = None
for k in range(5):
    try:
        s = dev.attach(pid)
        sc = s.create_script(js)
        sc.on("message", on_msg)
        sc.load()
        sess = (s, sc)
        say("    ✓✓✓ 钩子已装（JVM 起来之前）")
        break
    except Exception as e:
        say("    ✗ 第 %d 次: %s" % (k + 1, str(e)[:100]))
        time.sleep(2)
if not sess:
    try:
        dev.kill(pid)
    except Exception:
        pass
    sys.exit(1)

# ── ④ resume ──
say("\n[4] resume，让 app 跑起来")
dev.resume(pid)
time.sleep(4)

# ── ⑤ 点按（adb input tap 优先，失败则用 JS performClick）──
say("\n[5] 走到协议页并点同意")
btn = None
for i in range(20):
    time.sleep(3)
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
use_js_click = False
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
    if btn and PKG in f and p <= 8 and tapped < 30 and not use_js_click:
        raw("input tap %d %d" % ((btn[0] + btn[2]) // 2, btn[1] + 14))
        tapped += 1
        time.sleep(0.8)
        p2 = prefs_n()
        if tapped >= 3 and p2 <= 8:
            # adb tap 没效果 → 改用 JS performClick
            use_js_click = True
            say("    ⚠ adb tap 无效（第 %d 次后 prefs 仍 %d）→ 改用 JS performClick" % (tapped, p2))
    if use_js_click and btn and p <= 8:
        try:
            sc.post({"cmd": "click"})
        except Exception:
            pass

    if p != last_p:
        last_p = p
        say("    [%3ds] prefs=%-4d tap=%-3d jsclick=%s 消息=%d"
            % (el, p, tapped, use_js_click, len(msgs)))
    time.sleep(2)

# ── ⑥ 强制落盘 + 取回 ──
say("\n[6] 强制落盘 + 取回")
try:
    sc.post({"cmd": "dump"})
    time.sleep(3)
except Exception as e:
    say("    dump 失败: " + str(e)[:90])

files = []
for d in ["/data/data/%s/files" % PKG, TMPD]:
    for n in [x for x in su("ls %s 2>/dev/null" % d).split() if x.startswith("SP_")]:
        t = su("cat %s/%s 2>/dev/null" % (d, n))
        if not t:
            continue
        pth = os.path.join(REV, "devout", "SPAWN_%s_%s" % (RUN, n))
        with open(pth, "w", encoding="utf-8") as fh:
            fh.write(t)
        files.append(pth)
say("    取回 %d 个文件" % len(files))

# ── ⑦ 统计 ──
say("\n[7] 统计")
tot = dofinal = sslc = sockc = classc = 0
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
            dofinal += 1
        elif " SSL " in line:
            sslc += 1
        elif " SOCK " in line:
            sockc += 1
        elif " CLASS " in line:
            classc += 1
say("    协议总数 %d：CIPHER=%d  SSL=%d  SOCK=%d  CLASS=%d" % (tot, dofinal, sslc, sockc, classc))

say("\n[8] prefs=%d  dna=%s  进程=%s" % (
    prefs_n(),
    su("grep -o 'device_id\">[^<]*' /data/data/%s/shared_prefs/%s_dna.xml 2>/dev/null" % (PKG, PKG)) or "(无)",
    raw("pgrep -f '^%s' 2>/dev/null | head -1" % PKG) or "(无)"))
try:
    sess[0].detach()
except Exception:
    pass
LOG.close()
