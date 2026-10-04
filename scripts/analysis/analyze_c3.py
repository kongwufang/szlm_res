#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze_c3.py — 分析 c3 采集的 CIPHER + SSL 数据，还原明文，找 mIS

★ 数据：devout/C3/HS2_*.txt
★ 记录格式：REC p<pid> t=<ms> <SRC> <DIR> n=<len> hex=<hex>
★ 思路：
   · CIPHER IN  = doFinal 的输入（加密前 = gzip(JSON) 明文）
   · CIPHER OUT = doFinal 的输出（解密后 = 明文）
   · 两个方向都试 gunzip / zlib
"""
import gzip
import io
import json
import os
import re
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DEV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev\devout\C3"
DST = r"C:\Users\Admin\CodeBuddy\c001apk\_rev\devout\C3_PLAIN"
os.makedirs(DST, exist_ok=True)

files = [f for f in os.listdir(DEV) if f.startswith("HS2_") and f.endswith(".txt")]
print("=" * 100)
print("  分析 c3 采集  文件 %d 个" % len(files))
print("=" * 100)

recs = []
seen = set()
for f in files:
    t = open(os.path.join(DEV, f), encoding="utf-8", errors="replace").read()
    for line in t.split("\n"):
        m = re.match(r'REC p(\d+) t=(\d+) (\S+) (\S+) n=(\d+) hex=(.*)$', line)
        if not m:
            continue
        key = (m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)[:64])
        if key in seen:
            continue
        seen.add(key)
        recs.append({"pid": m.group(1), "t": int(m.group(2)), "src": m.group(3),
                     "dir": m.group(4), "n": int(m.group(5)), "hex": m.group(6)})

cif = [r for r in recs if r["src"] == "CIPHER" and r["hex"]]
ssl = [r for r in recs if r["src"] == "SSL" and r["hex"]]
print("  去重后记录 %d 条：CIPHER=%d（有hex）  SSL=%d（有hex）" % (len(recs), len(cif), len(ssl)))

# ── CIPHER 解密 ──
plain = []
for r in cif:
    try:
        b = bytes.fromhex(r["hex"])
    except Exception:
        continue
    got = None
    for off in (0, 1, 2, 4, 8):
        for nm, fn in (("gzip", lambda x: gzip.decompress(x)),
                       ("zlib", lambda x: zlib.decompress(x)),
                       ("raw", lambda x: zlib.decompress(x, -15))):
            try:
                d = fn(b[off:])
                got = ("%s@%d" % (nm, off), d)
                break
            except Exception:
                pass
        if got:
            break
    if got:
        try:
            s = got[1].decode("utf-8")
        except Exception:
            continue
        plain.append({"pid": r["pid"], "t": r["t"], "dir": r["dir"], "n": r["n"],
                      "how": got[0], "json": s})
        with open(os.path.join(DST, "Cp%s_t%d_%s_%d.json" % (r["pid"], r["t"], r["dir"], r["n"])),
                  "w", encoding="utf-8") as fh:
            fh.write(s)

print("\n  ★ CIPHER 还原出明文 %d 条" % len(plain))

# 去重（同内容只留一条）
uniq = {}
for p in plain:
    uniq.setdefault(p["json"], p)
print("  去重后 %d 条不同明文\n" % len(uniq))

for s, p in list(uniq.items())[:15]:
    print("-" * 100)
    print("  p%s t=%d %s n=%d [%s]" % (p["pid"], p["t"], p["dir"], p["n"], p["how"]))
    print("  %s" % s[:900])

# ── 找 mIS ──
print("\n" + "=" * 100)
print("  ★★★ 找 mIS")
print("=" * 100)
n = 0
for s, p in uniq.items():
    if '"mIS"' in s:
        n += 1
        mm = re.search(r'"mIS"\s*:\s*"([^"]*)"', s)
        print("  ★ p%s t=%d  mIS = %r" % (p["pid"], p["t"], mm.group(1) if mm else "?"))
        i = s.find('"mIS"')
        print("     上下文: %s" % s[max(0, i - 250):i + 150])
print("  含 mIS 的明文 %d / %d" % (n, len(uniq)))

# ── 所有字段 ──
print("\n" + "=" * 100)
print("  所有明文里出现过的字段")
print("=" * 100)
freq = {}
for s in uniq:
    try:
        j = json.loads(s)
    except Exception:
        continue
    if isinstance(j, dict):
        for k in j:
            freq[k] = freq.get(k, 0) + 1
for k, c in sorted(freq.items(), key=lambda x: -x[1])[:70]:
    print("    %-14s %d" % (k, c))
print("  共 %d 个字段" % len(freq))

# ── SSL 里找 HTTP 明文（可能含 mdna 请求） ──
print("\n" + "=" * 100)
print("  SSL 记录里像 HTTP 的")
print("=" * 100)
cnt = 0
for r in ssl:
    try:
        b = bytes.fromhex(r["hex"])
    except Exception:
        continue
    if b[:1] in (b"G", b"P", b"H", b"p", b"g"):
        cnt += 1
        if cnt <= 15:
            head = b[:220].decode("latin1")
            print("\n  p%s t=%d n=%d" % (r["pid"], r["t"], r["n"]))
            print("      %s" % head.replace("\r\n", " / ")[:200])
print("  共 %d 条" % cnt)
