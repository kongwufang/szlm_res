#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_min.py -- 打最小 APK（SDK 120KB + so 1.35MB）
"""
import io
import os
import shutil
import subprocess
import sys
import zipfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
EXP = os.path.join(REV, "exp_app")
BUILD = os.path.join(EXP, "build")
APK = os.path.join(EXP, "apk")
BT = r"C:\Android\Sdk\build-tools\35.0.0"
JAVA_HOME = r"C:\Program Files\Eclipse Adoptium\jdk-25.0.4.7-hotspot"

ENV = dict(os.environ)
ENV["JAVA_HOME"] = JAVA_HOME
ENV["PATH"] = os.path.join(JAVA_HOME, "bin") + ";" + ENV.get("PATH", "")

SDKDEX = os.path.join(BUILD, "smali_out", "classes.dex")
MYDEX = os.path.join(BUILD, "classes.dex")
SO = os.path.join(REV, "native", "libdu.so")
CFG = os.path.join(APK, "assets", "cn.shuzilm.config.json")
BASE = os.path.join(APK, "base.apk")

print("=" * 90)
print("  1) 组装最小 APK")
print("=" * 90)

out = os.path.join(APK, "probe-min.apk")
if os.path.exists(out):
    os.remove(out)

# 读 base.apk 的 manifest / arsc
zin = zipfile.ZipFile(BASE, "r")
meta = {}
for n in zin.namelist():
    if n.startswith("classes") and n.endswith(".dex"):
        continue
    if n.startswith("lib/") or n.startswith("assets/"):
        continue          # 这些单独加，避免重复条目
    meta[n] = zin.read(n)
zin.close()

zout = zipfile.ZipFile(out, "w")
STORED = {"resources.arsc", "AndroidManifest.xml"}
for n, data in meta.items():
    zi = zipfile.ZipInfo(n)
    zi.compress_type = zipfile.ZIP_STORED if n in STORED else zipfile.ZIP_DEFLATED
    zout.writestr(zi, data)
    print("  = %-34s %10d B" % (n, len(data)))

items = [
    ("assets/cn.shuzilm.config.json", CFG, zipfile.ZIP_DEFLATED),
    ("classes.dex",  SDKDEX, zipfile.ZIP_STORED),
    ("classes2.dex", MYDEX,  zipfile.ZIP_STORED),
    ("lib/arm64-v8a/libdu.so", SO, zipfile.ZIP_STORED),
]
for name, src, comp in items:
    if not os.path.exists(src):
        print("  ✗ 缺: " + src)
        continue
    data = open(src, "rb").read()
    zi = zipfile.ZipInfo(name)
    zi.compress_type = comp
    zout.writestr(zi, data)
    print("  + %-34s %10d B" % (name, len(data)))
zout.close()

sz = os.path.getsize(out)
print()
print("  probe-min.apk = %d B (%.2f MB)" % (sz, sz / 1048576.0))

print()
print("=" * 90)
print("  2) zipalign + 签名")
print("=" * 90)
aligned = os.path.join(APK, "min-aligned.apk")
if os.path.exists(aligned):
    os.remove(aligned)
r = subprocess.run([os.path.join(BT, "zipalign.exe"), "-f", "-p", "4", out, aligned],
                   env=ENV, capture_output=True, text=True)
if r.returncode != 0:
    print("  zipalign 失败: " + (r.stderr or ""))
print("  aligned %d B" % (os.path.getsize(aligned) if os.path.exists(aligned) else 0))

signed = os.path.join(APK, "probe-min-signed.apk")
if os.path.exists(signed):
    os.remove(signed)
r = subprocess.run([os.path.join(BT, "apksigner.bat"), "sign",
                    "--ks", os.path.join(EXP, "probe.keystore"),
                    "--ks-key-alias", "probe",
                    "--ks-pass", "pass:probe123", "--key-pass", "pass:probe123",
                    "--out", signed, aligned],
                   env=ENV, capture_output=True, text=True)
for line in ((r.stdout or "") + (r.stderr or "")).splitlines():
    if "ERROR" in line or "error" in line:
        print("  " + line)
if os.path.exists(signed):
    print("  ★ probe-min-signed.apk = %d B (%.2f MB)"
          % (os.path.getsize(signed), os.path.getsize(signed) / 1048576.0))
else:
    print("  ✗ 签名失败")
    sys.exit(1)

print()
print("=" * 90)
print("  3) 安装 + 运行")
print("=" * 90)
subprocess.run(["adb", "uninstall", "com.coolapk.market"], env=ENV,
               capture_output=True, text=True)
r = subprocess.run(["adb", "install", "-r", "-g", signed], env=ENV,
                   capture_output=True, text=True, encoding="utf-8", errors="replace")
print("  install: " + ((r.stdout or "") + (r.stderr or "")).strip())
subprocess.run(["adb", "logcat", "-c"], env=ENV, capture_output=True)
subprocess.run(["adb", "shell", "am", "start", "-n",
                "com.coolapk.market/.MainActivity"], env=ENV, capture_output=True)
print("  已启动，等待 30 秒...")
import time
time.sleep(30)
r = subprocess.run(["adb", "logcat", "-d", "-s", "DUID-PROBE:*"], env=ENV,
                   capture_output=True, text=True, encoding="utf-8", errors="replace")
for line in (r.stdout or "").splitlines()[-22:]:
    print("  " + line)
