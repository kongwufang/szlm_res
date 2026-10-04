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


print("=" * 84)
print("  清数据 → 走协议页（密度已降到 140）")
print("=" * 84)
print("  density:", raw("wm density"))
print("  size   :", raw("wm size"))
print()
print("  清数据…")
raw("am force-stop " + PKG)
time.sleep(2)
print("   ", raw("pm clear " + PKG))
time.sleep(3) if False else time.sleep(3)
print("  清后 prefs:", raw("su -c 'ls /data/data/%s/shared_prefs 2>/dev/null | wc -l'" % PKG))

raw("input keyevent KEYCODE_WAKEUP")
raw("am start -n %s/.view.main.MainActivity" % PKG)
print("\n  已启动，等待协议页…")

for i in range(8):
    time.sleep(5)
    ns = nodes()
    withtext = [(t, b) for t, b in ns if t]
    found = [x for x in withtext if ("协议" in x[0] or "同意" in x[0])]
    print("[%2ds] 文本节点 %d 个" % ((i + 1) * 5, len(withtext)))
    if found:
        print("   ★★★ 协议页出现！相关节点：")
        for t, b in withtext[:16]:
            print("        %-38s %s" % (t[:38], b))
        shot("agree140")
        break
    for t, b in withtext[:8]:
        print("        %-38s %s" % (t[:38], b))
else:
    shot("agree140_timeout")

print()
print("  最终密度:", raw("wm density"))
print("  ★ 恢复命令：adb -s %s shell wm density reset" % S)
