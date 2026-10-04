#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dump_d2c_cipher.py — 解 D2C 里所有 CIPHER 记录，找 sfOo / foO / 新格式明文

★★★ 关键：CIPHER 的 hex 是能解出来的（IN = doFinal 输入 = 明文）
     而且发现了一种【未压缩的明文 JSON】格式：
     {"#vt":0,"#sv":"9.9.1","#prv":"1.0.0","atm":"1","#$prv":"0",
      "#uda":"2026-10-04","st":"1","#av":"16.6.2","#vc":"2609151"}
"""
import gzip
import io
import json
import os
import re
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DEV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev\devout\D2C"
DST = r"C:\Users\Admin\CodeBuddy\c001apk\_rev\devout\D2C_PLAIN"
os.makedirs(DST, exist_ok=True)

OLD = {"sfOo": "4A213D3", "foO": "W***]TZTYX**X(W"}

fs = [f for f in os.listdir(DEV) if f.startswith("HS2_")]
print("=" * 100)
print("  解 %d 个文件里的 CIPHER 记录" % len(fs))
print("=" * 100)

recs = []
seen = set()
for f in fs:
    for line in open(os.path.join(DEV, f), encoding="utf-8", errors="replace").read().split("\n"):
        m = re.match(r'REC p(\d+) t=(\d+) CIPHER (\S+) n=(\d+) hex=(.*)$', line)
        if not m:
            continue
        hx = m.group(5).strip()
        if not hx:
            continue
        key = (m.group(1), m.group(2), m.group(4), hx[:64])
        if key in seen:
            continue
        seen.add(key)
        recs.append({"pid": m.group(1), "t": int(m.group(2)), "dir": m.group(3),
                     "n": int(m.group(4)), "hex": hx})

print("  CIPHER 记录（去重）%d 条" % len(recs))

# ── 逐条尝试解 ──
plain = []
for r in recs:
    try:
        b = bytes.fromhex(r["hex"])
    except Exception:
        continue
    got = None
    # ① 直接是 JSON 明文
    if b[:1] == b"{" or b[:1] == b"[":
        try:
            s = b.decode("utf-8")
            json.loads(s)
            got = ("明文JSON", s)
        except Exception:
            pass
    # ② gzip / zlib
    if not got:
        for off in (0, 1, 2, 4, 8):
            for nm, fn in (("gzip", lambda x: gzip.decompress(x)),
                           ("zlib", lambda x: zlib.decompress(x)),
                           ("raw", lambda x: zlib.decompress(x, -15))):
                try:
                    d = fn(b[off:])
                    s = d.decode("utf-8")
                    got = ("%s@%d" % (nm, off), s)
                    break
                except Exception:
                    pass
            if got:
                break
    if got:
        plain.append({**r, "how": got[0], "json": got[1]})

uniq = {}
for p in plain:
    uniq.setdefault(p["json"], p)
print("  解出 %d 条，去重 %d 条\n" % (len(plain), len(uniq)))

for s, p in list(uniq.items()):
    fn = "Cp%s_t%d_%s_%d.json" % (p["pid"], p["t"], p["dir"], p["n"])
    with open(os.path.join(DST, fn), "w", encoding="utf-8") as fh:
        fh.write(s)

# ── 打印 ──
for s, p in list(uniq.items())[:25]:
    print("-" * 100)
    print("  p%s t=%d %s n=%d [%s]" % (p["pid"], p["t"], p["dir"], p["n"], p["how"]))
    print("  %s" % s[:600])

# ── 找 sfOo / foO ──
print("\n" + "=" * 100)
print("  ★★★ 找 sfOo / foO")
print("=" * 100)
n = 0
for s, p in uniq.items():
    if '"sfOo"' in s or '"foO"' in s:
        n += 1
        print("\n  --- p%s t=%d ---" % (p["pid"], p["t"]))
        for key in ("sfOo", "foO", "2cO", "mIS"):
            mm = re.search(r'"%s"\s*:\s*"([^"]*)"' % key, s)
            if mm:
                v = mm.group(1)
                old = OLD.get(key)
                mark = ("  ★ 与上次相同" if v == old else "  ✗ 不同（上次=%r）" % old) if old else ""
                print("      %-6s = %r%s" % (key, v, mark))
        if n >= 5:
            break
print("\n  含 sfOo/foO 的明文 %d / %d" % (n, len(uniq)))

# ── 所有字段 ──
print("\n" + "=" * 100)
print("  所有明文里的字段")
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
for k, c in sorted(freq.items(), key=lambda x: -x[1])[:50]:
    print("    %-14s %d" % (k, c))
print("  共 %d 字段" % len(freq))
