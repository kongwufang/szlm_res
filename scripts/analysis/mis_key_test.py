#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mis_key_test.py — 用已知配对推 mIS 的 36 字节 XOR key

★★★ 已知（来自项目文档 + 本轮实测）：
    · mIS = XOR( base64url(27字节), key36 )       ← 文档：字母表是 base64url
    · DUID = base64url(27字节) = 36 字符           ← 本轮 4 设备实测
    · mIS 长 36 字符；位 4 恒定 ⇒ key 固定

★★★ 本脚本要回答：key 是不是【常数】？
    如果是，那么 (DUID XOR mIS) 在多个样本里应当相同。

  配对素材：
    S07/XTQ_Watch 的 DUID：DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9
    XTQ_Watch 的两次 mIS（不同注册轮次）：
       JQyPE~yLLEKIMMKHL{~}OHQJEy}P}E{HI|~|   (2cO 子秒 291441780)
       BrBrGppp?uGEtsBpG<?tE?Cq<G?<tCqspp<s   (2cO 子秒 17322914)
    wire_m58_REQ_9 里的 mIS：W(W(\\&&&T+\\Z*)W&\\QT*ZTX'Q\\TQ*X')&&Q)
"""
import base64
import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DUID_S07 = "DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9"
DUID_S38 = "DU8N1bbZfcNSfbmsBFOhsJslrOSOR3dL6eg5"

MIS = [
    ("XTQ_Watch#1", "JQyPE~yLLEKIMMKHL{~}OHQJEy}P}E{HI|~|", 291441780),
    ("XTQ_Watch#2", "BrBrGppp?uGEtsBpG<?tE?Cq<G?<tCqspp<s", 17322914),
    ("wire_m58_9", 'W(W(\\&&&T+\\Z*)W&\\QT*ZTX\'Q\\TQ*X\')&&Q)', None),
    ("NX809J", "W[\\Y''(X%S%%U'W&ZP)UXYU(PW[P*WSY&XP&", 380034934),
    ("?", 'TMP"OU"Q#JM#P"VRNQ"JQVTNJ~VUNS#~UVJ!', None),
    ("?", "-\\1c21`/\\]d]`./10X[^c]b\\X-`Xb_0/-_Xa", None),
]

B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
B64S = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

print("=" * 100)
print("  mIS 的 36 字节 XOR key —— 配对推演")
print("=" * 100)


def xor_str(a, b):
    return bytes(ord(x) ^ ord(y) for x, y in zip(a, b))


print("\n[1] 素材")
print("    S07 DUID : %s" % DUID_S07)
for n, m, s in MIS:
    print("    mIS %-12s : %s   (%s)" % (n, m, ("2cO子秒=%d" % s) if s else "无 2cO"))

# ── ① key = DUID_text XOR mIS ──
print("\n" + "=" * 100)
print("  ① 假设 key = DUID_text XOR mIS（key 是否常数？）")
print("=" * 100)
keys1 = []
for n, m, s in MIS:
    k = xor_str(DUID_S07, m)
    keys1.append((n, k))
    printable = all(32 <= c < 127 for c in k)
    print("    %-12s key = %s   可打印=%s" % (n, k.hex(), printable))
uniq1 = set(k for _, k in keys1)
print("    ⇒ 去重后 %d 种 key %s" % (len(uniq1), "★ 常数！" if len(uniq1) == 1 else "✗ 非常数"))

# ── ② key = base64_std(27字节) XOR mIS ──
print("\n" + "=" * 100)
print("  ② 假设 key = base64_std(DUID的27字节) XOR mIS")
print("=" * 100)
raw27 = base64.urlsafe_b64decode(DUID_S07 + "=" * (-len(DUID_S07) % 4))
print("    DUID -> 27 字节: %s" % raw27.hex())
b64s = base64.b64encode(raw27).decode()      # 标准表
b64u = base64.urlsafe_b64encode(raw27).decode()  # url 表
print("    base64_std(27) = %s" % b64s)
print("    base64_url(27) = %s   (= DUID 本身? %s)" % (b64u, b64u == DUID_S07))
keys2 = []
for n, m, s in MIS:
    k = xor_str(b64s, m)
    keys2.append((n, k))
    print("    %-12s key = %s" % (n, k.hex()))
uniq2 = set(k for _, k in keys2)
print("    ⇒ 去重后 %d 种 %s" % (len(uniq2), "★ 常数！" if len(uniq2) == 1 else "✗ 非常数"))

# ── ③ 用 S38 的 DUID 试 ──
print("\n" + "=" * 100)
print("  ③ 换 S38 的 DUID（排除偶然）")
print("=" * 100)
keys3 = []
for n, m, s in MIS:
    k = xor_str(DUID_S38, m)
    keys3.append((n, k))
uniq3 = set(k for _, k in keys3)
print("    ⇒ 去重后 %d 种 %s" % (len(uniq3), "★ 常数" if len(uniq3) == 1 else "✗ 非常数"))

# ── ④ 关键判定：任意两个 mIS 之间的 XOR 是否 = 两个 base64 之间的 XOR ──
print("\n" + "=" * 100)
print("  ④ ★ 关键判定：mIS_i XOR mIS_j 是否等于 b64_i XOR b64_j")
print("=" * 100)
print("    （若 mIS = b64 XOR key 且 key 固定，则两边必须相等）")
print("    但同一台设备的 DUID 只有一个 —— 所以先看：同一设备两次注册的 mIS 是否相同")
same_dev = [m for n, m, s in MIS if n.startswith("XTQ_Watch")]
print("    XTQ_Watch 两次 mIS:")
for m in same_dev:
    print("      %s" % m)
if len(same_dev) >= 2:
    if same_dev[0] == same_dev[1]:
        print("    ⇒ 相同 → mIS 只依赖 DUID，与注册轮次无关")
    else:
        print("    ⇒ ★ 不同！→ mIS 不只依赖 DUID（还依赖别的，如 2cO 子秒/轮次）")
        print("       ⇒ mIS = XOR(b64(27字节), key) 中，要么 27 字节每次不同，要么 key 每次不同")

# ── ⑤ 用 base64url 表把 mIS 反解（看能否得到合法结构）──
print("\n" + "=" * 100)
print("  ⑤ 检查 mIS 字符集与两张表的关系")
print("=" * 100)
allc = set("".join(m for _, m, _ in MIS))
print("    mIS 用到的字符数: %d" % len(allc))
print("    其中 base64url 之外的: %s" % sorted(c for c in allc if c not in B64U))
print("    其中 base64std 之外的: %s" % sorted(c for c in allc if c not in B64S))
print("""
    ⇒ mIS 用了大量两张表都没有的字符（~ { } | " # % & ' ( ) * 等）
      ⇒ 一定有 XOR 层，且 key 把字符推到了 0x21..0x7e 的任意位置
""")

# ── ⑥ 统计：mIS 各位置的字符码范围（看 key 的形态）──
print("=" * 100)
print("  ⑥ mIS 逐位置的字符码（若有样本共享同一 27 字节，可反推 key）")
print("=" * 100)
for i in range(36):
    codes = [ord(m[i]) for _, m, _ in MIS if len(m) > i]
    if not codes:
        continue
    print("    pos %2d  码=%s  min=0x%02X max=0x%02X 跨=%d"
          % (i, " ".join("%02X" % c for c in codes), min(codes), max(codes), max(codes) - min(codes)))
