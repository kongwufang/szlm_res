#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""shrink2.py -- baksmali -> 只留 cn/shuzilm -> 重新组装 smali -> dex
"""
import io
import os
import shutil
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
EXP = os.path.join(REV, "exp_app")
BUILD = os.path.join(EXP, "build")
D2J = r"C:\Users\Admin\CodeBuddy\c001apk\_tools\apk\dex2jar\dex-tools-v2.4"
JAVA_HOME = r"C:\Program Files\Eclipse Adoptium\jdk-25.0.4.7-hotspot"

ENV = dict(os.environ)
ENV["JAVA_HOME"] = JAVA_HOME
ENV["PATH"] = os.path.join(JAVA_HOME, "bin") + ";" + ENV.get("PATH", "")

SRC = [
    ("d1", os.path.join(REV, "szlm_dex", "shuzilm01.dex")),
    ("d2", os.path.join(REV, "szlm_dex", "shuzilm10.dex")),
    ("d3", os.path.join(REV, "szlm_dex", "shuzilm09.dex")),
]

WORK = os.path.join(BUILD, "smali")
if os.path.isdir(WORK):
    shutil.rmtree(WORK)
os.makedirs(WORK, exist_ok=True)


def run(cmd, label):
    print("  $ " + label)
    r = subprocess.run(cmd, env=ENV, cwd=D2J, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    if out:
        for line in out.splitlines()[:8]:
            print("    " + line)
    return r.returncode


print("=" * 90)
print("  1) baksmali 三个 dex")
print("=" * 90)
for tag, p in SRC:
    od = os.path.join(WORK, tag)
    os.makedirs(od, exist_ok=True)
    rc = run([os.path.join(D2J, "d2j-dex2smali.bat"), "--force", "-o", od, p],
             "d2j-dex2smali %s" % os.path.basename(p))
    n = sum(1 for dp, dn, fn in os.walk(od) for f in fn if f.endswith(".smali"))
    print("    → %d 个 smali 文件%s" % (n, "" if rc == 0 else "  (rc=%d)" % rc))

print()
print("=" * 90)
print("  2) 只保留 cn/shuzilm/**")
print("=" * 90)
KEEP = os.path.join(WORK, "keep")
if os.path.isdir(KEEP):
    shutil.rmtree(KEEP)
os.makedirs(KEEP, exist_ok=True)

kept = 0
kept_bytes = 0
for tag, _ in SRC:
    src = os.path.join(WORK, tag, "cn", "shuzilm")
    if not os.path.isdir(src):
        print("  [%s] 无 cn/shuzilm" % tag)
        continue
    for dp, dn, fn in os.walk(src):
        rel = os.path.relpath(dp, os.path.join(WORK, tag))
        dst = os.path.join(KEEP, rel)
        os.makedirs(dst, exist_ok=True)
        for f in fn:
            if not f.endswith(".smali"):
                continue
            s = os.path.join(dp, f)
            shutil.copy2(s, os.path.join(dst, f))
            kept += 1
            kept_bytes += os.path.getsize(s)
    print("  [%s] 已复制" % tag)

print()
print("  共保留 %d 个 smali，%.1f KB" % (kept, kept_bytes / 1024.0))
print()
print("  文件清单：")
for dp, dn, fn in os.walk(KEEP):
    for f in sorted(fn):
        if f.endswith(".smali"):
            rel = os.path.relpath(os.path.join(dp, f), KEEP)
            print("    %-56s %6d B" % (rel, os.path.getsize(os.path.join(dp, f))))
