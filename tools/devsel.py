#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备选择模块 —— 自动在 USB 与 WiFi 两条通道间选择可用的那一个。

用途：
    from devsel import ADB, PKG, DEV, shd, su, out, fg, pick_device
    DEV 会在 import 时自动解析（USB 在线优先，否则用 WiFi）。

WiFi ADB 由设备上的 Magisk 模块 wifiadb 开机自动开启（监听 5555）。
"""
import os
import re
import subprocess
import sys
import time

ADB = r"C:\tool\adb-fastboot\adb.exe"
PKG = "com.coolapk.market"
ACT = "com.coolapk.market/.view.main.MainActivity"

# 候选设备：USB 序列号 与 WiFi 地址
USB_SERIAL = "74584773985655"
WIFI_ADDR = "10.0.0.7:5555"
REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"

# 允许用环境变量强制指定
_FORCE = os.environ.get("DSH_ANDROID_DEV", "").strip()


def _list_devices():
    try:
        r = subprocess.run([ADB, "devices"], capture_output=True, timeout=20)
        txt = (r.stdout + r.stderr).decode(errors="replace")
    except Exception:
        return []
    out = []
    for line in txt.split("\n")[1:]:
        line = line.strip()
        if not line or "\t" not in line:
            continue
        serial, state = line.split("\t", 1)
        if state.strip() == "device":
            out.append(serial.strip())
    return out


def _try_connect(addr, timeout=6):
    try:
        subprocess.run([ADB, "connect", addr], capture_output=True, timeout=timeout)
    except Exception:
        return False
    time.sleep(1.5)
    return addr in _list_devices()


def pick_device(verbose=True):
    """返回可用设备 id。优先 USB，其次 WiFi。"""
    if _FORCE:
        if verbose:
            print("[dev] 使用环境变量指定: %s" % _FORCE)
        return _FORCE

    devs = _list_devices()
    if USB_SERIAL in devs:
        if verbose:
            print("[dev] USB 通道: %s" % USB_SERIAL)
        return USB_SERIAL

    if WIFI_ADDR in devs:
        if verbose:
            print("[dev] WiFi 通道: %s" % WIFI_ADDR)
        return WIFI_ADDR

    # 都没有 -> 尝试连 WiFi
    if verbose:
        print("[dev] 未发现设备，尝试连接 WiFi %s ..." % WIFI_ADDR)
    if _try_connect(WIFI_ADDR):
        if verbose:
            print("[dev] WiFi 连接成功: %s" % WIFI_ADDR)
        return WIFI_ADDR

    # 最后兜底：返回 USB 序列号（让调用方报错时能看到它）
    if verbose:
        print("[dev] !! 无可用设备，回退到 %s" % USB_SERIAL)
    return USB_SERIAL


DEV = pick_device()


def sh(args, timeout=60):
    return subprocess.run([ADB, "-s", DEV] + args, capture_output=True, timeout=timeout)


def shd(cmd, timeout=60):
    return sh(["shell", cmd], timeout=timeout)


def su(cmd, timeout=60):
    return shd("su -c '" + cmd.replace("'", "'\\''") + "'", timeout=timeout)


def out(r):
    return (r.stdout + r.stderr).decode(errors="replace").strip()


def stdout_only(r):
    """只要 stdout —— pidof 之类的命令，stderr 混进来会污染解析"""
    return r.stdout.decode(errors="replace").strip()


def get_pid(pkg=PKG):
    """健壮取 pid：只认纯数字，失败返回 None"""
    for _ in range(3):
        v = stdout_only(shd("pidof " + pkg))
        for tok in v.split():
            if tok.isdigit():
                return int(tok)
        time.sleep(1)
    return None


def fg():
    """当前前台包名"""
    r = out(shd("dumpsys activity activities | grep -E 'ResumedActivity' | head -1"))
    i = r.find("u0 ")
    return r[i + 3:].split("/")[0].strip() if i >= 0 else ""


def battery():
    r = out(shd("dumpsys battery"))
    d = {}
    for line in r.split("\n"):
        line = line.strip()
        m = re.match(r"^(level|status|voltage|temperature)\s*:\s*(.+)$", line)
        if m:
            d[m.group(1)] = m.group(2).strip()
    try:
        d["level"] = int(d.get("level", "0"))
    except Exception:
        d["level"] = 0
    d["charging"] = d.get("status") == "2"
    return d


def ensure_battery(min_level=25, verbose=True):
    """电量不足时返回 False，调用方应中止测试"""
    b = battery()
    if verbose:
        print("[dev] 电量 %d%%  %s" % (b["level"], "充电中" if b["charging"] else "未充电"))
    return b["level"] >= min_level


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print("设备列表: %s" % _list_devices())
    print("选用: %s" % pick_device())
    print("前台: %s" % fg())
    b = battery()
    print("电量: %d%%  充电中=%s  电压=%s" % (b["level"], b["charging"], b.get("voltage")))
    print("pkgs root 测试: %s" % (out(su("id"))[:60] or "(失败)"))
