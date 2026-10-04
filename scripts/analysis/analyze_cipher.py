#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze_cipher.py — 分析 CIPHER 记录，还原明文 JSON，找 mIS

★ 数据：devout/EARLY_e3_HM_*_p*.txt（CIPHER=216 条）
★ 思路：
   · ENCRYPT 方向：doFinal 的【输入】= gzip(JSON) 明文（未压缩前的 JSON 就是我们要的）
   · DECRYPT 方向：doFinal 的【输出】= 明文
   ⇒ 两个方向都试 gunzip → JSON
"""
import gzip
import io
import json
import os
import re
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
DEV = os.path.join(REV, "devout")
DST = os.path.join(DEV, "CIPHER")
os.makedirs(DST, exist_ok=True)

files = [f for f in os.listdir(DEV) if f.startswith("EARLY_e3_HM_") and f.endswith(".txt")]
print("=" * 100)
print("  分析 CIPHER 记录   文件 %d 个" % len(files))
print("=" * 100)

recs = []
for f in files:
    t = open(os.path.join(DEV, f), encoding="utf-8", errors="replace").read()
    for line in t.split("\n"):
        m = re.match(r'REC p(\d+) t=(\d+) (\S+) (\S+) n=(\d+) hex=(.*)$', line)
        if not m:
            continue
        recs.append({"pid": m.group(1), "t": int(m.group(2)), "src": m.group(3),
                     "dir": m.group(4), "n": int(m.group(5)), "hex": m.group(6)})

print("  记录 %d 条" % len(recs))
cif = [r for r in recs if r["src"] == "CIPHER" and r["hex"]]
print("  其中带 hex 的 CIPHER %d 条" % len(cif))

# ── 逐条尝试还原 ──
plain = []
for r in cif:
    try:
        b = bytes.fromhex(r["hex"])
    except Exception:
        continue
    got = None
    # ① 直接 gunzip / zlib
    for nm, fn in (("gzip", lambda x: gzip.decompress(x)),
                   ("zlib", lambda x: zlib.decompress(x)),
                   ("raw", lambda x: zlib.decompress(x, -15))):
        try:
            d = fn(b)
            got = (nm, d)
            break
        except Exception:
            pass
    # ② 去掉前 4 字节再试
    if not got:
        for off in (1, 2, 4, 8):
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
        s = got[1].decode("utf-8", "replace")
        plain.append({"pid": r["pid"], "t": r["t"], "dir": r["dir"], "n": r["n"],
                      "how": got[0], "json": s, "raw": b})
        fn = "Cp%s_t%d_%s_%d.json" % (r["pid"], r["t"], r["dir"], r["n"])
        with open(os.path.join(DST, fn), "w", encoding="utf-8") as fh:
            fh.write(s)

print("\n  ★ 还原出明文 %d 条" % len(plain))

# ── 打印 ──
print("\n" + "=" * 100)
print("  还原的明文")
print("=" * 100)
for p in plain[:20]:
    print("\n  --- p%s t=%d %s n=%d [%s] ---" % (p["pid"], p["t"], p["dir"], p["n"], p["how"]))
    print("      %s" % p["json"][:800])

# ── 找 mIS ──
print("\n" + "=" * 100)
print("  ★★★ 找 mIS")
print("=" * 100)
found = 0
for p in plain:
    for m in re.finditer(r'"mIS"\s*:\s*"([^"]*)"', p["json"]):
        found += 1
        print("  ★ p%s t=%d  mIS = %r" % (p["pid"], p["t"], m.group(1)))
    if '"mIS"' in p["json"]:
        idx = p["json"].find('"mIS"')
        print("     上下文: %s" % p["json"][max(0, idx - 200):idx + 120])
print("  含 mIS 的明文: %d / %d" % (found, len(plain)))

# ── 所有出现的字段 ──
print("\n" + "=" * 100)
print("  所有明文里出现过的字段")
print("=" * 100)
freq = {}
for p in plain:
    try:
        j = json.loads(p["json"])
        if isinstance(j, dict):
            for k in j:
                freq[k] = freq.get(k, 0) + 1
    except Exception:
        pass
for k, c in sorted(freq.items(), key=lambda x: -x[1])[:60]:
    print("    %-12s %d" % (k, c))
print("  共 %d 个字段" % len(freq))
