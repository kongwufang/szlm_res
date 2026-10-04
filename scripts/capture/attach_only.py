#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""attach_only.py — ★ 干净模板：只 attach，不做任何破坏性操作

★★★ 这个文件是【只读类任务的标准起点】。以后所有"attach 上去看点什么"
     的任务都从这个文件派生，不要从别的脚本派生。

★ 本模板保证【不含】以下破坏性操作：
    ✗ pm clear
    ✗ am force-stop
    ✗ rm -f / rm -rf
    ✗ iptables
    ✗ input tap / am start（不改 UI 状态）

★ 只做：
    ✓ 起 frida-server（隐藏名 + 非默认端口）
    ✓ 找一个目标进程并 attach
    ✓ load 指定 js
    ✓ 收集消息、定时落盘、最后取回产物

用法：
    python attach_only.py <serial> <js文件名> [分钟] [--all]
      --all   不按 libdu 过滤，直接取包名主进程
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
JSNAME = sys.argv[2] if len(sys.argv) > 2 else "grab_key.js"
MINUTES = float(sys.argv[3]) if len(sys.argv) > 3 else 2
WANT_ALL = "--all" in sys.argv

TAG = serial.replace(":", "_").replace(".", "_")
PREFIX = os.path.splitext(JSNAME)[0].upper()[:6]
LOG = open(os.path.join(REV, "dev2", "AO_%s_%s.txt" % (TAG, PREFIX)), "w", encoding="utf-8")


def raw(c, timeout=70):
    r = subprocess.run([ADB, "-s", serial, "shell", c], capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode(errors="replace").strip()


def su(c, timeout=80):
    b = base64.b64encode(c.encode()).decode()
    return raw('echo %s | base64 -d > /data/local/tmp/.s.sh; su -c "sh /data/local/tmp/.s.sh"' % b, timeout)


def say(s):
    print(s)
    LOG.write(s + "\n")
    LOG.flush()


def target_pid():
    """优先取 libdu 已加载的那个主进程；否则取包名主进程"""
    if not WANT_ALL:
        out = su("grep -l 'libdu\\.so' /proc/[0-9]*/maps 2>/dev/null")
        for l in out.split("\n"):
            m = re.match(r"/proc/(\d+)/maps", l.strip())
            if not m:
                continue
            p = m.group(1)
            r = subprocess.run([ADB, "-s", serial, "shell", "cat /proc/%s/cmdline" % p],
                               capture_output=True, timeout=20)
            c = r.stdout.split(b"\x00")[0].decode(errors="replace").strip()
            if c == PKG:
                return p, "libdu已加载"
    p = raw("pgrep -f '^%s' 2>/dev/null | head -1" % PKG).strip().split("\n")[0]
    return (p if p else None), "主进程"


say("=" * 92)
say("  attach_only   %s   js=%s   %s 分钟   %s"
    % (serial, JSNAME, MINUTES, "(--all)" if WANT_ALL else ""))
say("  ★ 本脚本不做 pm clear / force-stop / rm / iptables / input tap")
say("=" * 92)

# 0) 先看状态（只读）
say("\n[0] 只读状态")
say("    prefs : %s" % su("ls /data/data/%s/shared_prefs 2>/dev/null | wc -l" % PKG))
say("    dna   : %s" % (su("grep -o 'device_id\">[^<]*' /data/data/%s/shared_prefs/%s_dna.xml 2>/dev/null" % (PKG, PKG)) or "(无)"))
say("    进程  : %s" % (raw("pgrep -l -f '^%s' 2>/dev/null | tr '\\n' '|'" % PKG) or "(未运行)"))
say("    libdu : %s" % (su("grep -l libdu.so /proc/[0-9]*/maps 2>/dev/null | tr '\\n' '|'") or "(未加载)"))

pid, how = target_pid()
say("\n[1] 目标进程: pid=%s (%s)" % (pid or "-", how))
if not pid:
    say("    ✗ 无目标进程。本模板【不会】帮你启动 app（避免副作用）")
    say("      请手动启动酷安后重跑，或另写带启动流程的专用脚本")
    sys.exit(1)

# 2) frida
say("\n[2] 起 frida-server")
su("pkill -f frida; pkill -f re.frida; sleep 1; echo ok")
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
    except Exception as e:
        say("    ... 重试 %d: %s" % (i + 1, str(e)[:60]))
        time.sleep(4)
if dev is None:
    say("    ✗ frida 不可用")
    sys.exit(1)

# 3) attach
say("\n[3] attach + load %s" % JSNAME)
js = open(os.path.join(REV, JSNAME), encoding="utf-8").read()
msgs = []


def on_msg(m, d):
    try:
        if m.get("type") == "error":
            say("      [JS错误] " + str(m.get("description", ""))[:180])
            return
        if m.get("type") != "send":
            return
        p = str(m.get("payload", ""))
        msgs.append(p)
        say("      " + p[:185])
    except Exception:
        pass


sess = None
for k in range(6):
    try:
        s = dev.attach(int(pid))
        sc = s.create_script(js)
        sc.on("message", on_msg)
        sc.load()
        sess = (s, sc)
        say("    ✓✓✓ attach 成功（第 %d 次）" % (k + 1))
        break
    except Exception as e:
        say("    ✗ 第 %d 次: %s" % (k + 1, str(e)[:95]))
        time.sleep(4)
if not sess:
    say("    ✗ attach 失败")
    sys.exit(1)
s, sc = sess

say("\n[4] 保持 %.1f 分钟" % MINUTES)
t0 = time.time()
while time.time() - t0 < MINUTES * 60:
    time.sleep(10)

# 5) 取回（只读）
say("\n[5] 取回产物（只读）")
for d in ["/data/data/%s/files" % PKG, TMPD]:
    try:
        names = su("ls %s 2>/dev/null" % d).split()
    except Exception:
        continue
    for n in [x for x in names if x.endswith(".txt")]:
        if not (n.startswith(("GK_", "FI_", "VT_", "S6_", "S3_", "S4_", "AO_"))):
            continue
        t = su("cat %s/%s 2>/dev/null" % (d, n))
        if not t:
            continue
        p = os.path.join(REV, "dev2", "AO_%s_%s" % (TAG, n))
        with open(p, "w", encoding="utf-8") as f:
            f.write(t)
        say("    %s (%d 行)" % (n, t.count("\n")))
try:
    s.detach()
except Exception:
    pass
LOG.close()
