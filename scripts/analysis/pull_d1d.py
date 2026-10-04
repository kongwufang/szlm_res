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
DST = r"C:\Users\Admin\CodeBuddy\c001apk\_rev\devout\D1A"
os.makedirs(DST, exist_ok=True)


def sh(*a, t=200):
    r = subprocess.run([ADB, "-s", S] + list(a), capture_output=True, timeout=t)
    return (r.stdout + r.stderr).decode(errors="replace")


print("=== forced 文件 ===")
print(sh("shell", "su", "-c", "ls -l /data/data/%s/files/HS2_forced_* 2>&1" % PKG))

print("=== 按大小排前 6 ===")
big = sh("shell", "su", "-c", "ls -S /data/data/%s/files/HS2_* 2>/dev/null | head -6" % PKG)
bignames = [x.strip() for x in big.split("\n") if x.strip().startswith("HS2_")]
print("  ", bignames)

# ★ 逐个用 base64 传输（每文件单独一次，避免超时）
targets = ["HS2_forced_p31877.txt", "HS2_forced_p6999.txt"] + bignames
targets = list(dict.fromkeys(targets))

ok = 0
for n in targets:
    if not re.match(r"^HS2_[A-Za-z0-9_.]+$", n):
        continue
    r = subprocess.run([ADB, "-s", S, "shell", "su", "-c",
                        "base64 -w 0 /data/data/%s/files/%s" % (PKG, n)],
                       capture_output=True, timeout=200)
    b64 = (r.stdout + r.stderr).decode(errors="replace").replace("\n", "").strip()
    b64 = re.sub(r"[^A-Za-z0-9+/=]", "", b64)
    if len(b64) < 40:
        print("  ✗ %s（%d 字符）" % (n, len(b64)))
        continue
    try:
        data = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception as e:
        print("  ✗ %s 解码失败 %s" % (n, str(e)[:40]))
        continue
    with open(os.path.join(DST, n), "wb") as fh:
        fh.write(data)
    ok += 1
    print("  ✓ %-32s %d 字节" % (n, len(data)))

print("\n  拉回 %d 个文件" % ok)

# 分析
lines = []
for f in sorted(os.listdir(DST)):
    if not f.startswith("HS2_"):
        continue
    try:
        for ln in open(os.path.join(DST, f), encoding="utf-8", errors="replace").read().split("\n"):
            if ln.startswith("REC"):
                lines.append(ln)
    except Exception:
        pass

uniq = {}
for ln in lines:
    m = re.match(r"REC p(\d+) t=(\d+) (\S+) (\S+) n=(\d+) hex=(.*)$", ln)
    if m:
        uniq.setdefault((m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)), m)

print("\n  REC %d 行，去重 %d 条" % (len(lines), len(uniq)))
srcs = {}
for m in uniq.values():
    srcs[m.group(3)] = srcs.get(m.group(3), 0) + 1
print("  来源:", srcs)

if uniq:
    print("\n" + "=" * 96)
    print("  ★★★ 明文 HTTP")
    print("=" * 96)
    hosts = {}
    n = 0
    mdna = []
    for m in uniq.values():
        h = m.group(6)
        if not h or len(h) < 32:
            continue
        try:
            b = bytes.fromhex(h)
        except Exception:
            continue
        if b[:4] in (b"POST", b"GET ", b"HTTP"):
            n += 1
            t = b.decode("latin1")
            hm = re.search(r"Host: ([^\r\n]+)", t)
            host = hm.group(1) if hm else "?"
            hosts[host] = hosts.get(host, 0) + 1
            if n <= 25:
                print("  t=%-7s %-5s n=%-6s %-26s %s" % (m.group(2), m.group(3), m.group(5), host,
                                                          t.split("\r\n")[0][:105]))
            if any(k in t for k in ("mdna", "telecome", "auni", "yumao", "puata")):
                mdna.append((m, b))
    print("  共 %d 条" % n)
    print("\n  ★ Host 汇总:")
    for k, v in sorted(hosts.items(), key=lambda x: -x[1]):
        print("     %-42s %d" % (k, v))

    print("\n" + "=" * 96)
    print("  ★★★ mdna 明文")
    print("=" * 96)
    for m, b in mdna[:3]:
        print("  t=%s %s n=%s" % (m.group(2), m.group(3), m.group(5)))
        print("  %s" % b[:2000].decode("latin1").replace("\r\n", " / ")[:2000])
        print()
    if not mdna:
        for kw in ("mdna", "telecome", "auni", "sfOo", "foO", "yumao"):
            c = sum(1 for m in uniq.values() if kw in m.group(6))
            print("     含 %-10s : %d" % (kw, c))
