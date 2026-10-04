import base64
import io
import os
import re
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ADB = r"C:\tool\adb-fastboot\adb.exe"
S = "10.0.0.37:5555"
PKG = "com.coolapk.market"
DST = r"C:\Users\Admin\CodeBuddy\c001apk\_rev\devout\D1C"
os.makedirs(DST, exist_ok=True)


def sh(*a, t=200):
    r = subprocess.run([ADB, "-s", S] + list(a), capture_output=True, timeout=t)
    return (r.stdout + r.stderr).decode(errors="replace")


print("=== forced 文件 ===")
lst = sh("shell", "su", "-c", "ls -l /data/data/%s/files/HS2_forced_* 2>/dev/null" % PKG)
print(lst)

names = [x.split()[-1] for x in lst.split("\n") if "HS2_forced_" in x]
for n in names:
    n = os.path.basename(n)
    if not re.match(r"^HS2_forced_p\d+\.txt$", n):
        continue
    r = subprocess.run([ADB, "-s", S, "shell", "su", "-c",
                        "base64 -w 0 /data/data/%s/files/%s" % (PKG, n)],
                       capture_output=True, timeout=280)
    b64 = re.sub(r"[^A-Za-z0-9+/=]", "", (r.stdout + r.stderr).decode(errors="replace"))
    if len(b64) < 40:
        print("  ✗ %s" % n)
        continue
    data = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    with open(os.path.join(DST, n), "wb") as fh:
        fh.write(data)
    print("  ✓ %-32s %d 字节" % (n, len(data)))

# 分析
txt = ""
for f in os.listdir(DST):
    if f.startswith("HS2_forced_"):
        txt += open(os.path.join(DST, f), encoding="utf-8", errors="replace").read()

allrec = [l for l in txt.split("\n") if l.startswith("REC") or l.startswith("KEEP")]
uniq = {}
for ln in allrec:
    m = re.match(r"(REC|KEEP) p(\d+) t=(\d+) (\S+) (\S+) n=(\d+) hex=(.*)$", ln)
    if m:
        uniq.setdefault((m.group(1), m.group(3), m.group(4), m.group(5), m.group(6)), m)

print("\n  记录 %d 行，去重 %d 条" % (len(allrec), len(uniq)))
k = len([1 for m in uniq.values() if m.group(1) == "KEEP"])
print("  ★ KEEP 记录 %d 条" % k)

print("\n" + "=" * 100)
print("  ★★★ szlm 明文请求")
print("=" * 100)
hosts = {}
n = 0
mdna = []
for m in uniq.values():
    h = m.group(7)
    if not h or len(h) < 64:
        continue
    try:
        b = bytes.fromhex(h)
    except Exception:
        continue
    if b[:4] not in (b"POST", b"GET ", b"HTTP"):
        continue
    t = b.decode("latin1")
    hm = re.search(r"Host: ([^\r\n]+)", t)
    host = hm.group(1) if hm else "?"
    hosts[host] = hosts.get(host, 0) + 1
    if "telecome" in t or "yumao" in t or "umeng" in t:
        n += 1
        print("\n  [%s] t=%s n=%s" % (m.group(1), m.group(3), m.group(6)))
        print("  %s" % t.split("\r\n")[0][:170])
        if "mdna" in t:
            mdna.append((m, b))

print("\n  ★ Host 汇总:")
for kk, v in sorted(hosts.items(), key=lambda x: -x[1]):
    print("     %-44s %d" % (kk, v))
print("\n  szlm 请求 %d 条；其中 mdna %d 条" % (n, len(mdna)))

if mdna:
    print("\n" + "=" * 100)
    print("  ★★★★★★ mdna 请求详情")
    print("=" * 100)
    for m, b in mdna:
        i = b.find(b"\r\n\r\n")
        print("\n  %s" % b[:i].decode("latin1").replace("\r\n", " / ")[:400])
        print("  body(%d): %s" % (len(b) - i - 4, b[i + 4: i + 4 + 80].hex()))
