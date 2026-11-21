#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_probe2.py -- 用多 dex 组装 probe APK"""
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
AJAR = r"C:\Android\Sdk\platforms\android-36\android.jar"
JAVA_HOME = r"C:\Program Files\Eclipse Adoptium\jdk-25.0.4.7-hotspot"

ENV = dict(os.environ)
ENV["JAVA_HOME"] = JAVA_HOME
ENV["PATH"] = os.path.join(JAVA_HOME, "bin") + ";" + ENV.get("PATH", "")


def run(cmd, cwd=None):
    print("  $ " + " ".join(cmd))
    r = subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines()[:12]:
        print("    " + line)
    return r.returncode, out


print("=" * 88)
print("  1) 编译 MainActivity")
print("=" * 88)
clsd = os.path.join(BUILD, "classes")
if os.path.isdir(clsd):
    shutil.rmtree(clsd)
os.makedirs(clsd, exist_ok=True)
rc, out = run(["javac", "-source", "8", "-target", "8",
               "-bootclasspath", AJAR, "-d", clsd,
               os.path.join(EXP, "src", "com", "coolapk", "market", "MainActivity.java")])
classes = []
for dp, dn, fn in os.walk(clsd):
    for f in fn:
        if f.endswith(".class"):
            classes.append(os.path.join(dp, f))
            print("    + " + f)

print()
print("=" * 88)
print("  2) d8")
print("=" * 88)
mydex = os.path.join(BUILD, "classes.dex")
if os.path.exists(mydex):
    os.remove(mydex)
rc, out = run([os.path.join(BT, "d8.bat"), "--lib", AJAR, "--min-api", "24",
               "--output", BUILD] + classes)
if not os.path.exists(mydex):
    print("  ✗ d8 失败")
    sys.exit(1)
print("  my classes.dex %d B" % os.path.getsize(mydex))

print()
print("=" * 88)
print("  3) 组装多 dex APK")
print("=" * 88)
out_apk = os.path.join(APK, "probe-multi.apk")
shutil.copy2(os.path.join(APK, "base.apk"), out_apk)

DEXES = [
    ("classes.dex",  os.path.join(REV, "szlm_dex", "shuzilm01.dex")),
    ("classes2.dex", os.path.join(REV, "szlm_dex", "shuzilm10.dex")),
    ("classes3.dex", os.path.join(REV, "szlm_dex", "shuzilm09.dex")),
    ("classes4.dex", mydex),
]
EXTRA = [
    ("lib/arm64-v8a/libdu.so", os.path.join(REV, "native", "libdu.so")),  # 1,417,064 B, md5=97313e29... = ne8
    ("assets/cn.shuzilm.config.json", os.path.join(APK, "assets", "cn.shuzilm.config.json")),
]

zin = zipfile.ZipFile(out_apk, "r")
existing = {n: zin.read(n) for n in zin.namelist()}
zin.close()

zout = zipfile.ZipFile(out_apk, "w")
kept = 0
# resources.arsc 必须 STORED（Android R+ 要求不压缩 + 4 字节对齐）
STORED_NAMES = {"resources.arsc", "AndroidManifest.xml"}
for n, data in existing.items():
    if n.startswith("classes") and n.endswith(".dex"):
        continue
    if n.startswith("lib/") or n.startswith("assets/"):
        continue
    zi = zipfile.ZipInfo(n)
    zi.compress_type = zipfile.ZIP_STORED if n in STORED_NAMES else zipfile.ZIP_DEFLATED
    zout.writestr(zi, data)
    kept += 1
    print("  = %-24s %10d B  %s" % (n, len(data), "STORED" if n in STORED_NAMES else "DEFLATE"))
print("  保留 %d 个原始条目（manifest/arsc 等）" % kept)

for name, src in DEXES + EXTRA:
    if not os.path.exists(src):
        print("  ✗ 缺文件: " + src)
        continue
    data = open(src, "rb").read()
    zi = zipfile.ZipInfo(name)
    zi.compress_type = zipfile.ZIP_STORED if name.endswith(".so") or name.endswith(".dex") else zipfile.ZIP_DEFLATED
    zout.writestr(zi, data)
    print("  + %-34s %12d B" % (name, len(data)))
zout.close()

print()
print("=" * 88)
print("  4) zipalign")
print("=" * 88)
aligned = os.path.join(APK, "a4.apk")
if os.path.exists(aligned):
    os.remove(aligned)
run([os.path.join(BT, "zipalign.exe"), "-f", "-p", "4", out_apk, aligned])
print("  aligned %d B" % (os.path.getsize(aligned) if os.path.exists(aligned) else 0))

print()
print("=" * 88)
print("  5) 签名")
print("=" * 88)
signed = os.path.join(APK, "probe-signed.apk")
if os.path.exists(signed):
    os.remove(signed)
run([os.path.join(BT, "apksigner.bat"), "sign",
     "--ks", os.path.join(EXP, "probe.keystore"),
     "--ks-key-alias", "probe",
     "--ks-pass", "pass:probe123", "--key-pass", "pass:probe123",
     "--out", signed, aligned])
print("  signed %d B" % (os.path.getsize(signed) if os.path.exists(signed) else 0))

print()
print("=" * 88)
print("  6) 重装")
print("=" * 88)
run(["adb", "uninstall", "com.coolapk.market"])
run(["adb", "install", "-r", "-g", signed])

print()
print("=" * 88)
print("  7) 启动")
print("=" * 88)
run(["adb", "logcat", "-c"])
run(["adb", "shell", "am", "start", "-n", "com.coolapk.market/.MainActivity"])
