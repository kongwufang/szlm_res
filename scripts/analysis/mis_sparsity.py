#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mis_sparsity.py — 诊断 mIS 的「明文差分稀疏度」，判定它的构造方式

★★★ 逻辑：
   若 mIS = XOR( P, K )  其中 P = 明文(27字节的 base64)，K = 固定 key
   则   mIS_i XOR mIS_j = P_i XOR P_j        （K 消掉）
   ⇒ 观测 mIS 两两 XOR 的【汉明距离分布】就能判断 P 的性质：

     P 完全相同        -> XOR 全 0
     P 大部分相同+小nonce -> XOR 稀疏（少数位为 1，且集中在几处）
     P 完全不同        -> XOR 稠密（≈半数位为 1，均匀分布）

★ 样本：
    · XTQ_Watch 同设备两次注册（2cO 子秒不同）
    · 其它设备的样本
    · wire_m58_REQ_9 的 mIS
"""
import base64
import io
import itertools
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

MIS = [
    ("XTQ#1", "JQyPE~yLLEKIMMKHL{~}OHQJEy}P}E{HI|~|", "S07"),
    ("XTQ#2", "BrBrGppp?uGEtsBpG<?tE?Cq<G?<tCqspp<s", "S07"),
    ("wire9", 'W(W(\\&&&T+\\Z*)W&\\QT*ZTX\'Q\\TQ*X\')&&Q)', "S07"),
    ("NX809", "W[\\Y''(X%S%%U'W&ZP)UXYU(PW[P*WSY&XP&", "?NX809J"),
    ("s5", 'TMP"OU"Q#JM#P"VRNQ"JQVTNJ~VUNS#~UVJ!', "?"),
    ("s6", "-\\1c21`/\\]d]`./10X[^c]b\\X-`Xb_0/-_Xa", "?"),
]

print("=" * 100)
print("  mIS 明文差分稀疏度诊断")
print("=" * 100)

print("\n[1] 样本")
for n, m, d in MIS:
    print("    %-8s dev=%-8s %s" % (n, d, m))


def bits(x):
    n = 0
    while x:
        n += x & 1
        x >>= 1
    return n


print("\n" + "=" * 100)
print("  ② 两两 XOR：汉明距离（位）+ 不同字节数")
print("=" * 100)
print("    %-10s %-10s %5s %6s  说明" % ("A", "B", "位", "字节"))
rows = []
for (n1, m1, d1), (n2, m2, d2) in itertools.combinations(MIS, 2):
    x = bytes(ord(a) ^ ord(b) for a, b in zip(m1, m2))
    hb = sum(bits(b) for b in x)
    db = sum(1 for b in x if b)
    same_dev = (d1 == d2 and d1 not in ("?",))
    rows.append((n1, n2, hb, db, same_dev))
    mark = ""
    if same_dev:
        mark = "  ← 同设备！"
    if hb == 0:
        mark += "  ★ 完全相同"
    print("    %-10s %-10s %5d %6d /36%s" % (n1, n2, hb, db, mark))

print("\n" + "=" * 100)
print("  ③ 统计（重点看【同设备】那一对）")
print("=" * 100)
same = [r for r in rows if r[4]]
if same:
    for n1, n2, hb, db, _ in same:
        tot = 36 * 8
        print("    同设备 %s vs %s :  %d/%d 位不同 (%.0f%%),  %d/36 字节不同"
              % (n1, n2, hb, tot, 100.0 * hb / tot, db))
        print("    " + ("⇒ XOR 稀疏 ⇒ 明文 P 大部分相同，只有少数位置不同（像『同 27 字节 + 小 nonce』）"
                        if hb < tot * 0.25 else
                        "⇒ XOR 稠密 ⇒ 明文 P 完全不同（每次注册的 27 字节整体不同）"))

alldiff = [r[2] for r in rows if not r[4]]
if alldiff:
    avg = sum(alldiff) / len(alldiff)
    print("\n    不同设备之间的平均汉明距离: %.1f / 288 位 (%.0f%%)" % (avg, 100.0 * avg / 288))
    print("    随机基线 ≈ 144/288 (50%%)")

print("\n" + "=" * 100)
print("  ④ 若 mIS = XOR(base64url(27字节), K) 且 K 固定，")
print("     那么把 mIS 用 K 解回后应得到【合法 base64url 字符集】")
print("=" * 100)
print("""
    我们可以不依赖 K 来验证这一点：对任意两个样本，
    用一个「共同的偏移」去试 —— 但更直接的是：

    ★ 检查 mIS 的每个字符是否能通过【固定单个字节 XOR】变回 base64url 字符集
      （若 K 固定且按位，则每个位置应有各自的偏移；本节只做粗筛）
""")
B64U = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
for i in range(36):
    codes = [ord(m[i]) for _, m, _ in MIS]
    # 每个位置单独求「让该位置所有样本都落回 base64url」的 delta 集合
    cand = None
    for c in codes:
        s = set(d for d in range(256) if (c ^ d) in [ord(x) for x in B64U])
        cand = s if cand is None else (cand & s)
        if not cand:
            break
    if cand is None:
        cand = set()
    if i < 12 or len(cand) > 0:
        print("    pos %2d  可行 delta 数=%2d  %s" % (i, len(cand), sorted("0x%02X" % d for d in cand)[:8]))
