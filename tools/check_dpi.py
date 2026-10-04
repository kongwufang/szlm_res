import io
import re
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ADB = r"C:\tool\adb-fastboot\adb.exe"
S = "10.0.0.7:5555"
PKG = "com.coolapk.market"


def raw(c, t=60):
    try:
        r = subprocess.run([ADB, "-s", S, "shell", c], capture_output=True, timeout=t)
        return (r.stdout + r.stderr).decode(errors="replace").strip()
    except Exception:
        return "(超时)"


print("  屏幕尺寸:", raw("wm size"))
print("  屏幕密度:", raw("wm density"))
print("  LCD 密度:", raw("getprop ro.sf.lcd_density"))
print("  前台:", raw("dumpsys window 2>/dev/null | grep -m1 mCurrentFocus")[:120])
print()

raw("rm -f /sdcard/u.xml")
raw("uiautomator dump /sdcard/u.xml", t=45)
x = raw("cat /sdcard/u.xml", t=45)
print("=== 屏幕上的所有带文本节点 ===")
for m in re.finditer(r"<node[^>]*>", x):
    s = m.group(0)
    t = re.search(r'text="([^"]*)"', s)
    bo = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', s)
    cl = re.search(r'clickable="(\w+)"', s)
    if bo and t and t.group(1):
        b = tuple(map(int, bo.groups()))
        print("  %-34s bounds=%-28s clickable=%s" % (t.group(1)[:34], str(b), cl.group(1) if cl else "?"))

print()
print("=== 屏幕上的所有可点节点（不限文本）===")
n = 0
for m in re.finditer(r"<node[^>]*>", x):
    s = m.group(0)
    cl = re.search(r'clickable="true"', s)
    bo = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', s)
    t = re.search(r'text="([^"]*)"', s)
    if cl and bo:
        n += 1
        b = tuple(map(int, bo.groups()))
        if n <= 20:
            print("  bounds=%-28s text=%r" % (str(b), t.group(1) if t else ""))

subprocess.run([ADB, "-s", S, "shell", "screencap -p /sdcard/.sc.png"], capture_output=True, timeout=45)
subprocess.run([ADB, "-s", S, "pull", "/sdcard/.sc.png",
                r"C:\Users\Admin\CodeBuddy\c001apk\_rev\devout\SHOT\dpi_now.png"],
               capture_output=True, timeout=60)
print("\n  截图已存 devout/SHOT/dpi_now.png")
