#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hunt_sfOo.py — 零成本追查 sfOo=4A213D3 与 foO 的来源

★ 假设 (a)：它们是【设备指纹】的哈希/编码
   ⇒ 在已知字段里找：是否某个字段（或组合）的 MD5/SHA 前 7 位 == 4A213D3

★ 假设 (b)：设备指纹 + 签名

★ 本脚本穷举：
   · 78 个字段值本身
   · 两两/三三组合（常见分隔符）
   · 已知的设备指纹常量（包名 / suffix / p / DUID / MAC / 机型 / android_id / boot_uuid …）
   · 各种哈希（MD5 / SHA1 / SHA256 / CRC32 / 各种截断）
"""
import hashlib
import io
import itertools
import json
import os
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
sys.path.insert(0, REV)
import szlm_id as S  # noqa: E402

POOL = 0x110DC8
SRC = os.path.join(REV, "dump", "wire_m58_REQ_9_len1745.bin")

SF = "4A213D3"
FO = "W***]TZTYX**X(W"

d = open(SRC, "rb").read()
i = d.find(b"\r\n\r\n")
k = S.KEY_BY_ADDR[POOL]
obj = json.loads(zlib.decompress(bytes(d[i + 4 + j] ^ k[j % len(k)]
                                       for j in range(len(d) - i - 4))).decode())

# 已知的外部常量（D2 = XTQ_Watch）
EXTRA = {
    "pkg": "com.coolapk.market",
    "suffix": "37be8a1ee106979a",
    "p": "F9BD0FBDACFE80FCF34370FBCFEE1A98",
    "duid": "DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9",
    "h": "F7AAD8CD5824603F7F2200731D8C045D",
    "apiKey": "11e7b222083a4b732b4b14811f6fc05995a01415eb",
    "model": "XTQ_Watch",
    "brand": "sprd",
    "mac": "6F824D:502156:160A84",
    "api": "28",
    "ver": "9",
}

# 收集所有候选字符串
cands = {}
for kk, v in obj.items():
    if isinstance(v, str):
        cands["body." + kk] = v
    elif isinstance(v, (int, float)):
        cands["body." + kk] = str(v)
    elif isinstance(v, dict):
        for k2, v2 in v.items():
            if isinstance(v2, str):
                cands["body.%s.%s" % (kk, k2)] = v2
for kk, v in EXTRA.items():
    cands["ext." + kk] = v

print("=" * 100)
print("  追查 sfOo = %s" % SF)
print("=" * 100)
print("  候选字符串 %d 个" % len(cands))

HASHES = {
    "md5": lambda b: hashlib.md5(b).hexdigest(),
    "sha1": lambda b: hashlib.sha1(b).hexdigest(),
    "sha256": lambda b: hashlib.sha256(b).hexdigest(),
    "sha512": lambda b: hashlib.sha512(b).hexdigest(),
}

hits = []

# ── ① 单个字段的各种哈希 ──
for name, val in cands.items():
    for hn, hf in HASHES.items():
        for form, b in (("raw", val.encode()),
                        ("upper", val.upper().encode()),
                        ("lower", val.lower().encode())):
            h = hf(b).upper()
            if SF in h[:7] or h[:7] == SF or SF in h:
                hits.append(("单字段 %s %s(%s)" % (name, hn, form), h, SF in h, h[:7] == SF))

print("\n  ① 单字段哈希: %d 命中" % len(hits))
for h in hits[:10]:
    print("     %s -> %s  含=%s 前7位=%s" % h)

# ── ② 常见组合（2 个 / 3 个，几种分隔符）──
if not hits:
    names = list(cands.keys())
    SEPS = [b".", b"", b",", b"|", b"-", b"_", b":"]
    print("\n  ② 试两两组合（%d 对 × %d 分隔符 × %d 哈希）…" % (
        len(names) * (len(names) - 1) // 2, len(SEPS), len(HASHES)))
    n = 0
    for a, b in itertools.combinations(names, 2):
        for sep in SEPS:
            for order in ((a, b), (b, a)):
                s = cands[order[0]].encode() + sep + cands[order[1]].encode()
                for hn, hf in HASHES.items():
                    h = hf(s).upper()
                    n += 1
                    if h[:7] == SF or SF in h:
                        hits.append(("二组合 %s%s%s %s" % (order[0], sep.decode(), order[1], hn), h,
                                     SF in h, h[:7] == SF))
                        if len(hits) < 6:
                            print("     ★ %s -> %s" % (hits[-1][0], h))
    print("     共试 %d 次，命中 %d" % (n, len(hits)))

# ── ③ 整数解释 ──
print("\n  ③ 其它解释")
try:
    v = int(SF, 16)
    print("     0x%s = %d (十进制)" % (SF, v))
    for mod in (1000, 10000, 100000, 1000000):
        print("       mod %d = %d" % (mod, v % mod))
except Exception:
    pass

# ── ④ foO 单独看 ──
print("\n" + "=" * 100)
print("  追查 foO = %r" % FO)
print("=" * 100)
print("  长度 %d，字符集 %s" % (len(FO), "".join(sorted(set(FO)))))
# 与 mIS 逐位置比较
mIS = obj.get("mIS", "")
print("  mIS(36) = %r" % mIS)
print("  foO(15) = %r" % FO)
print()
print("  逐位置对照（前 15 位）：")
print("     pos  foO  mIS  XOR")
for j in range(min(len(FO), len(mIS))):
    x = ord(FO[j]) ^ ord(mIS[j])
    print("     %3d   %r   %r   0x%02X %s" % (j, FO[j], mIS[j], x,
                                             "★ 相同" if x == 0 else ""))

# ── ⑤ 其它混淆串是否互相有关系（同一密钥流？）──
print("\n" + "=" * 100)
print("  ⑤ 混淆串之间的关系（是否同一密钥流加密）")
print("=" * 100)
OBF = ["mIS", "foO", "yzW", "zvW", "5Tv", "52J", "Bos", "IJK", "ibF", "IAI",
       "aFw", "KyU", "UOv", "dLH", "90P", "LAh"]
pairs = [o for o in OBF if o in obj and isinstance(obj[o], str)]
print("  候选 %d 个: %s" % (len(pairs), pairs))
# 看两两 XOR 的前缀是否有规律（若同一密钥流且明文相近，XOR 会稀疏）
print()
print("  %-6s %-6s %s" % ("A", "B", "共同前缀长度 / 首字符是否相同"))
for a, b in itertools.combinations(pairs, 2):
    sa, sb = obj[a], obj[b]
    same = 0
    for x, y in zip(sa, sb):
        if x == y:
            same += 1
        else:
            break
    if same > 0:
        print("  %-6s %-6s 共同前缀 %d 字符: %r" % (a, b, same, sa[:same]))
