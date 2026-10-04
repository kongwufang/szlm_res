import io
import re
import subprocess
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ADB = r"C:\tool\adb-fastboot\adb.exe"
S = "10.0.0.7:5555"
PKG = "com.coolapk.market"
REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"


def raw(c, t=60):
    try:
        r = subprocess.run([ADB, "-s", S, "shell", c], capture_output=True, timeout=t)
        return (r.stdout + r.stderr).decode(errors="replace").strip()
    except Exception:
        return "(超时)"


def shot(name):
    raw("screencap -p /sdcard/.sc.png", t=45)
    subprocess.run([ADB, "-s", S, "pull", "/sdcard/.sc.png",
                    REV + r"\devout\SHOT\%s.png" % name], capture_output=True, timeout=60)
    print("  截图: %s.png" % name)


def nodes():
    raw("rm -f /sdcard/u.xml")
    raw("uiautomator dump /sdcard/u.xml", t=45)
    x = raw("cat /sdcard/u.xml", t=45)
    out = []
    for m in re.finditer(r"<node[^>]*>", x):
        s = m.group(0)
        t = re.search(r'text="([^"]*)"', s)
        bo = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', s)
        if bo:
            out.append((t.group(1) if t else "", tuple(map(int, bo.groups()))))
    return out


print("=" * 80)
print("  当前显示参数")
print("=" * 80)
print("  size   :", raw("wm size"))
print("  density:", raw("wm density"))

# ★ 降密度：180 -> 140（约缩小 22%），让协议页按钮能进入可视区
print("\n  ★ 降密度 180 -> 140")
print("  ", raw("wm density 140"))
time.sleep(3)
print("  新 density:", raw("wm density"))

# 重启酷安
raw("am force-stop " + PKG)
time.sleep(2)
raw("input keyevent KEYCODE_WAKEUP")
raw("am start -n %s/.view.main.MainActivity" % PKG)
time.sleep(9)
print("\n  前台:", raw("dumpsys window 2>/dev/null | grep -m1 mCurrentFocus")[:110])

print("\n=== 屏幕上的带文本节点 ===")
for t, b in nodes():
    if t:
        print("  %-34s bounds=%s" % (t[:34], b))

shot("dpi140")
print("\n  ★ 若要恢复：adb shell wm density reset")
