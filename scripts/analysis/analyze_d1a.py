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


def su(c, t=200):
    b64 = __import__("base64").b64encode(c.encode()).decode()
    r = subprocess.run([ADB, "-s", S, "shell",
                        'echo %s | base64 -d > /data/local/tmp/.s.sh; su -c "sh /data/local/tmp/.s.sh"' % b64],
                       capture_output=True, timeout=t)
    return (r.stdout + r.stderr).decode(errors="replace")


print("=== 设备上文件数 ===")
print(" ", su("ls /data/data/%s/files 2>/dev/null | grep -c '^HS2_'" % PKG).strip())

# 逐个文件拉回（用 base64 传输避免二进制/换行问题）
names = [x for x in su("ls /data/data/%s/files 2>/dev/null | grep '^HS2_'" % PKG).split("\n") if x.strip()]
print("  文件清单 %d 个" % len(names))
ok = 0
tot = 0
for n in names:
    n = n.strip()
    if not re.match(r"^HS2_[A-Za-z0-9_.]+$", n):
        continue
    t = su("cat /data/data/%s/files/%s 2>/dev/null" % (PKG, n))
    if t and t.startswith("#"):
        with open(os.path.join(DST, n), "w", encoding="utf-8") as fh:
            fh.write(t)
        ok += 1
        tot += t.count("\n")
print("  拉回 %d 个，%d 行" % (ok, tot))

# 分析
fs = [f for f in os.listdir(DST) if f.startswith("HS2_")]
lines = []
for f in fs:
    for ln in open(os.path.join(DST, f), encoding="utf-8", errors="replace").read().split("\n"):
        if ln.startswith("REC"):
            lines.append(ln)

# 去重
seen = set()
uniq = []
for ln in lines:
    m = re.match(r"REC p(\d+) t=(\d+) (\S+) (\S+) n=(\d+) hex=(.*)$", ln)
    if not m:
        continue
    k = (m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)[:64])
    if k in seen:
        continue
    seen.add(k)
    uniq.append(m)

print("\n  REC 去重 %d 条" % len(uniq))
srcs = {}
for m in uniq:
    srcs[m.group(3)] = srcs.get(m.group(3), 0) + 1
print("  来源分布:", srcs)

print("\n" + "=" * 96)
print("  ★★★ 找明文 HTTP 请求")
print("=" * 96)
n = 0
found_mdna = []
for m in uniq:
    h = m.group(6)
    if not h or len(h) < 32:
        continue
    try:
        head = bytes.fromhex(h[:64])
    except Exception:
        continue
    if head[:4] in (b"POST", b"GET ", b"HTTP") or head[:5] == b"POST ":
        n += 1
        b = bytes.fromhex(h)
        txt = b.decode("latin1")
        first = txt.split("\r\n")[0][:140]
        hm = re.search(r"Host: ([^\r\n]+)", txt)
        host = hm.group(1) if hm else "?"
        if n <= 25:
            print("  t=%-7s %-4s n=%-6s %-26s %s" % (m.group(2), m.group(3), m.group(5), host, first))
        if "mdna" in txt or "telecome" in txt or "auni" in txt:
            found_mdna.append((m, b))
print("  明文 HTTP 共 %d 条" % n)

print("\n" + "=" * 96)
print("  ★★★ mdna 请求")
print("=" * 96)
for m, b in found_mdna[:5]:
    print("  t=%s %s n=%s" % (m.group(2), m.group(3), m.group(5)))
    print("  %s" % b[:900].decode("latin1").replace("\r\n", " / ")[:900])
    print()

if not found_mdna:
    print("  （未找到 mdna）")
    # 搜关键词
    for kw in ("mdna", "telecome", "auni", "sfOo", "foO", "yumao", "puata"):
        c = sum(1 for m in uniq if kw in m.group(6))
        print("    含 %-10s : %d 条" % (kw, c))
    # 打印所有 Host
    hosts = {}
    for m in uniq:
        h = m.group(6)
        if not h or len(h) < 40:
            continue
        try:
            b = bytes.fromhex(h)
        except Exception:
            continue
        hm = re.search(rb"Host: ([^\r\n]+)", b)
        if hm:
            k = hm.group(1).decode("latin1")
            hosts[k] = hosts.get(k, 0) + 1
    print("\n  ★ 所有出现过的 Host:")
    for k, v in sorted(hosts.items(), key=lambda x: -x[1]):
        print("     %-40s %d" % (k, v))
