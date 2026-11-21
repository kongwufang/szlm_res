#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pkg_swap.py -- 改 probe APK 的包名，实测服务端是否按包名拒绝
"""
import io
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
EXP = os.path.join(REV, "exp_app")
APK = os.path.join(EXP, "apk")
BT = r"C:\Android\Sdk\build-tools\35.0.0"
AJAR = r"C:\Android\Sdk\platforms\android-36\android.jar"
JAVA_HOME = r"C:\Program Files\Eclipse Adoptium\jdk-25.0.4.7-hotspot"

ENV = dict(os.environ)
ENV["JAVA_HOME"] = JAVA_HOME
ENV["PATH"] = os.path.join(JAVA_HOME, "bin") + ";" + ENV.get("PATH", "")

SDKDEX = os.path.join(EXP, "build", "smali_out", "classes.dex")
MYSRC = os.path.join(EXP, "src", "com", "coolapk", "market", "MainActivity.java")
SO = os.path.join(REV, "native", "libdu.so")
CFG = os.path.join(APK, "assets", "cn.shuzilm.config.json")

TARGET = sys.argv[1] if len(sys.argv) > 1 else "com.tencent.mm"

print("=" * 92)
print("  改包名 → %s" % TARGET)
print("=" * 92)
print()


def build_manifest(pkg):
    return '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="%s"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />

    <application
        android:label="DUID Probe"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">

        <activity
            android:name="com.coolapk.market.MainActivity"
            android:exported="true"
            android:label="DUID Probe">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

    </application>
</manifest>
''' % pkg


work = os.path.join(EXP, "swap")
if os.path.isdir(work):
    shutil.rmtree(work)
os.makedirs(work, exist_ok=True)

mpath = os.path.join(work, "AndroidManifest.xml")
open(mpath, "w", encoding="utf-8").write(build_manifest(TARGET))

print("  1) aapt2 link")
base = os.path.join(work, "base.apk")
r = subprocess.run([os.path.join(BT, "aapt2.exe"), "link", "-o", base,
                    "-I", AJAR, "--manifest", mpath,
                    "--min-sdk-version", "24", "--target-sdk-version", "34"],
                   env=ENV, capture_output=True, text=True)
if r.returncode != 0:
    print("    失败: " + (r.stderr or "")[:400])
    sys.exit(1)
print("    base.apk %d B" % os.path.getsize(base))

print()
print("  2) 编译 MainActivity（包路径不变，仍是 com.coolapk.market）")
clsd = os.path.join(work, "classes")
os.makedirs(clsd, exist_ok=True)
subprocess.run(["javac", "-source", "8", "-target", "8", "-bootclasspath", AJAR,
                "-d", clsd, MYSRC], env=ENV, capture_output=True, text=True)
cls = []
for dp, dn, fn in os.walk(clsd):
    for f in fn:
        if f.endswith(".class"):
            cls.append(os.path.join(dp, f))
mydex = os.path.join(work, "classes.dex")
r = subprocess.run([os.path.join(BT, "d8.bat"), "--lib", AJAR, "--min-api", "24",
                    "--output", work] + cls, env=ENV, capture_output=True, text=True)
# d8 输出固定叫 classes.dex
if os.path.exists(os.path.join(work, "classes.dex")):
    mydex = os.path.join(work, "classes.dex")
print("    my dex %d B" % os.path.getsize(mydex))

print()
print("  3) 组装")
out = os.path.join(work, "probe.apk")
zin = zipfile.ZipFile(base, "r")
meta = {}
for n in zin.namelist():
    meta[n] = zin.read(n)
zin.close()

zout = zipfile.ZipFile(out, "w")
STORED = {"resources.arsc", "AndroidManifest.xml"}
for n, data in meta.items():
    zi = zipfile.ZipInfo(n)
    zi.compress_type = zipfile.ZIP_STORED if n in STORED else zipfile.ZIP_DEFLATED
    zout.writestr(zi, data)
for name, src, comp in [
    ("assets/cn.shuzilm.config.json", CFG, zipfile.ZIP_DEFLATED),
    ("classes.dex", SDKDEX, zipfile.ZIP_STORED),
    ("classes2.dex", mydex, zipfile.ZIP_STORED),
    ("lib/arm64-v8a/libdu.so", SO, zipfile.ZIP_STORED),
]:
    data = open(src, "rb").read()
    zi = zipfile.ZipInfo(name)
    zi.compress_type = comp
    zout.writestr(zi, data)
    print("    + %-32s %10d B" % (name, len(data)))
zout.close()

print()
print("  4) zipalign + 签名")
aligned = os.path.join(work, "a.apk")
subprocess.run([os.path.join(BT, "zipalign.exe"), "-f", "-p", "4", out, aligned],
               env=ENV, capture_output=True)
signed = os.path.join(work, "signed.apk")
r = subprocess.run([os.path.join(BT, "apksigner.bat"), "sign",
                    "--ks", os.path.join(EXP, "probe.keystore"),
                    "--ks-key-alias", "probe",
                    "--ks-pass", "pass:probe123", "--key-pass", "pass:probe123",
                    "--out", signed, aligned],
                   env=ENV, capture_output=True, text=True)
print("    signed %d B" % (os.path.getsize(signed) if os.path.exists(signed) else 0))

print()
print("  5) 安装并运行")
subprocess.run(["adb", "uninstall", TARGET], env=ENV, capture_output=True)
r = subprocess.run(["adb", "install", "-r", "-g", signed], env=ENV,
                   capture_output=True, text=True, encoding="utf-8", errors="replace")
print("    " + ((r.stdout or "") + (r.stderr or "")).strip()[:200])

subprocess.run(["adb", "logcat", "-c"], env=ENV, capture_output=True)
subprocess.run(["adb", "shell", "am", "start", "-n",
                TARGET + "/com.coolapk.market.MainActivity"], env=ENV, capture_output=True)
print("    已启动，等 35 秒...")
time.sleep(35)
r = subprocess.run(["adb", "logcat", "-d", "-s", "DUID-PROBE:*"], env=ENV,
                   capture_output=True, text=True, encoding="utf-8", errors="replace")
for line in (r.stdout or "").splitlines()[-18:]:
    print("    " + line)
