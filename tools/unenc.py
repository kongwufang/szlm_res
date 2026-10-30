#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  unenc.py — 解开数字联盟 libdu 的字段编码
#
#  ★ 来源与归属（重要）
#      「字段编码 = 字符码位偏移 + 重排」这个思路，以及可用的解码函数骨架，
#      来自 People-11 的公开分析（https://github.com/People-11）。
#      本项目在此基础上发现：真实规则是 mod-95 环上的偏移、且 K 逐报文变化，
#      并实现了自动定位 K 的方法。详见仓库根目录 CREDITS.md。
#
#  ★ 规则
#      e[i] = chr(((ord(p[i]) - 0x20 + K) % 95) + 0x20)   然后按 shuffle 重排
#      解码 = 先反重排，再 chr(((ord(e[i]) - 0x20 - K) % 95) + 0x20)
#      95 = 可打印 ASCII 字符数（0x20..0x7E），K 每份报文不同（实测 5..56）
#
#  ★ 用法
#      python3 unenc.py 'DEo?qBmCp=DoDq>'                  # 自动找 K
#      python3 unenc.py --k 12 'DEo?qBmCp=DoDq>'           # 指定 K
#      python3 unenc.py --json data/decoded/D1H__MDNA_63185.json
#      python3 unenc.py --shuffle 'xxx'                    # 反过来解
#
#  ★ 只依赖 Python 3 标准库
# ============================================================================

from __future__ import print_function

import argparse
import glob
import hashlib
import io
import json
import os
import sys

try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
except Exception:
    pass

LO, HI = 0x20, 0x7E
MOD = HI - LO + 1                      # 95
HEX = set("0123456789abcdefABCDEF")


# ── 重排 ────────────────────────────────────────────────────────────────────
def shuffle(s):
    """编码方向：奇数长度先取中间字符，之后交替取首尾"""
    n = len(s)
    m = n // 2
    out = [s[m]] if n % 2 else []
    for i in range(m):
        out += [s[n - 1 - i], s[m - 1 - i]]
    return "".join(out)


def unshuffle(e):
    """shuffle 的逆"""
    n = len(e)
    m = n // 2
    s = [""] * n
    k = 0
    if n % 2:
        s[m] = e[0]
        k = 1
    for i in range(m):
        s[n - 1 - i] = e[k]
        s[m - 1 - i] = e[k + 1]
        k += 2
    return "".join(s)


# ── mod-95 偏移 ────────────────────────────────────────────────────────────
def dec(s, K):
    """解码：每个字符在 95 个可打印 ASCII 的环上反向偏移 K"""
    out = []
    for c in s:
        o = ord(c)
        if not (LO <= o <= HI):
            return None
        out.append(chr(((o - LO - K) % MOD) + LO))
    return "".join(out)


def enc(s, K):
    """编码"""
    out = []
    for c in s:
        o = ord(c)
        if not (LO <= o <= HI):
            return None
        out.append(chr(((o - LO + K) % MOD) + LO))
    return "".join(out)


# ── 校验器 ──────────────────────────────────────────────────────────────────
def is_uuid(s):
    if not s or len(s) != 36:
        return False
    if [s[8], s[13], s[18], s[23]] != ["-"] * 4:
        return False
    rest = s.replace("-", "")
    return len(rest) == 32 and all(c in HEX for c in rest)


def is_hexish(s):
    return bool(s) and len(s) >= 8 and all(c in HEX for c in s)


def is_hex15(s):
    """ANDROID_ID 的前 15 位（mode 10 会去掉最后一位）"""
    return bool(s) and len(s) == 15 and all(c in HEX for c in s)


def is_textual(s):
    if not s:
        return False
    ok = sum(1 for c in s if c.islower() or c.isdigit() or c in ".:,_-/ ")
    return ok / len(s) >= 0.95


def is_ipish(s):
    if not s:
        return False
    return all(c.isdigit() or c in ".:," for c in s)


def checksum(s):
    return hashlib.md5(str(sum(ord(c) for c in s)).encode()).hexdigest().upper()[:7]


# 权重高的排前面；命中即停（同一结果只归类一次）
VALIDATORS = [
    ("uuid", is_uuid, 100),
    ("hex15", is_hex15, 90),
    ("hexish", is_hexish, 70),
    ("textual", is_textual, 50),
    ("ipish", is_ipish, 30),
]


def best_attempt(value, only_K=None, only_dir=None):
    """返回 (分数, 方向, K, 明文, 命中的校验器名)"""
    best = (-1, None, None, None, None)
    dirs = [("unshuffle", unshuffle), ("shuffle", shuffle)]
    if only_dir == "unshuffle":
        dirs = dirs[:1]
    elif only_dir == "shuffle":
        dirs = dirs[1:]

    for dname, df in dirs:
        base = df(value)
        ks = [only_K] if only_K is not None else range(MOD)
        for K in ks:
            r = dec(base, K)
            if not r:
                continue
            for vname, vf, weight in VALIDATORS:
                if vf(r):
                    if weight > best[0]:
                        best = (weight, dname, K, r, vname)
                    break
    return best


def try_android_id(fo, sf):
    """用 sfOo 校验值确认 ANDROID_ID"""
    if not isinstance(fo, str) or not isinstance(sf, str):
        return None
    for dname, df in (("unshuffle", unshuffle), ("shuffle", shuffle)):
        base = df(fo)
        for K in range(MOD):
            r = dec(base, K)
            if not r or not all(c in HEX for c in r):
                continue
            for c in "0123456789abcdef":
                cand = r + c
                if checksum(cand) == sf:
                    return (dname, K, cand)
    return None


# ── 主流程 ──────────────────────────────────────────────────────────────────
def show_value(value, args):
    print("  输入 (%d 字符): %r" % (len(value), value))
    print()
    for dname in ("unshuffle", "shuffle"):
        df = unshuffle if dname == "unshuffle" else shuffle
        print("  [%s]" % dname)
        base = df(value)
        rows = []
        for K in range(MOD):
            r = dec(base, K)
            if not r:
                continue
            for vname, vf, weight in VALIDATORS:
                if vf(r):
                    rows.append((weight, K, r, vname))
                    break
        if not rows:
            print("    (无通过的偏移)")
        else:
            rows.sort(reverse=True)
            for weight, K, r, vname in rows[:5]:
                print("    K=%-2d  %-8s %r" % (K, vname, r))
        print()


def looks_plaintext(key, val):
    """判断这个字段是不是本来就是明文，不需要解"""
    # 已知的 raw 字段
    RAW_FIELDS = {"sfOo", "DUv", "EV2", "3mS", "AAA", "BBB", "GVp", "h6Z",
                  "2cO", "UOv", "ne8", "w91", "gEd", "6yY", "K5f", "AYk",
                  "P1J", "wSK", "zpA", "fPV", "R37", "R3d", "R41", "R63",
                  "Ra", "YWu", "mIS", "ubF", "75c", "za7", "90P", "LAh"}
    if key in RAW_FIELDS:
        return True
    # 形如包名 / 版本号 / 纯数字 / 纯 UUID / IPv4 的，也是明文
    if val.startswith(("com.", "android", "/", "v")):
        return True
    if all(c.isdigit() or c in ".:-" for c in val):
        return True
    if is_uuid(val):
        return True
    return False


def find_global_K(j, prefer=None):
    """在同一份报文里定出统一的 K

    优先用这些"格式明确"的字段当锚：
        dLH  → 合法 UUID
        OW2  → 可读文本
        foO  → 15 位 hex + sfOo 校验
    同一个 K 必须同时解对多项，才认。
    """
    candidates = []

    for dname, df in (("unshuffle", unshuffle), ("shuffle", shuffle)):
        for K in range(MOD):
            votes = 0
            proofs = []

            # dLH → UUID（最强证据）
            dlh = j.get("dLH")
            if isinstance(dlh, str) and len(dlh) >= 30:
                r = dec(df(dlh), K)
                if is_uuid(r):
                    votes += 5
                    proofs.append("dLH=UUID")

            # foO + sfOo
            fo, sf = j.get("foO"), j.get("sfOo")
            if isinstance(fo, str) and isinstance(sf, str):
                r = dec(df(fo), K)
                if r and all(c in HEX for c in r):
                    for c in "0123456789abcdef":
                        if checksum(r + c) == sf:
                            votes += 5
                            proofs.append("foO 校验命中")
                            break

            # OW2 → 文本
            ow = j.get("OW2")
            if isinstance(ow, str) and len(ow) >= 10:
                r = dec(df(ow), K)
                if is_textual(r):
                    votes += 3
                    proofs.append("OW2 可读")

            # mIS → UUID（boot_id）
            mis = j.get("mIS")
            if isinstance(mis, str) and len(mis) >= 30:
                r = dec(df(mis), K)
                if is_uuid(r):
                    votes += 4
                    proofs.append("mIS=UUID")

            if votes:
                candidates.append((votes, dname, K, proofs))

    if not candidates:
        return None
    candidates.sort(reverse=True)
    votes, dname, K, proofs = candidates[0]
    return (dname, K, proofs, votes)


def show_json(path, args):
    try:
        j = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        print("  读不了 %s: %s" % (path, e))
        return
    if not isinstance(j, dict):
        print("  不是 JSON 对象")
        return

    print("=" * 78)
    print("  %s   (%d 字段)" % (os.path.basename(path), len(j)))
    print("=" * 78)

    # ① 先还原 ANDROID_ID
    aid = try_android_id(j.get("foO"), j.get("sfOo"))
    if aid:
        print()
        print("  ★★ ANDROID_ID = %s" % aid[2])
        print("     方向 %s, K=%d, 校验值 sfOo=%r 命中" % (aid[0], aid[1], j.get("sfOo")))

    # ② 定全局 K
    gk = find_global_K(j)
    if not gk:
        print()
        print("  定不出统一的 K（可能没有可校验的字段）")
        return
    dname, K, proofs, votes = gk
    df = unshuffle if dname == "unshuffle" else shuffle

    print()
    print("  ★ 统一 K = %d  （方向 %s，证据 %s）" % (K, dname, " + ".join(proofs)))
    print()
    print("  用这个 K 解全部字段:")
    print()

    RAW_FIELDS = {"sfOo", "DUv", "EV2", "3mS", "AAA", "BBB", "GVp", "h6Z",
                  "2cO", "R41", "R37", "R3d", "R63", "Ra", "75c", "wSK",
                  "zpA", "fPV", "ubF", "ne8", "w91", "gEd", "6yY", "K5f",
                  "AYk", "P1J", "UOv", "YWu", "90P", "LAh", "za7"}
    shown = 0
    for key, val in j.items():
        if not isinstance(val, str) or len(val) < 6:
            continue
        if key in RAW_FIELDS:
            continue
        r = dec(df(val), K)
        if not r or r == val:
            continue
        # 只显示解出来是「可打印且像有意义」的
        if not all(LO <= ord(c) <= HI for c in r):
            continue
        shown += 1
        print("    %-6s → %s" % (key, r))

    if not shown:
        print("    (没有可解的字段)")


def main():
    ap = argparse.ArgumentParser(
        description="解开数字联盟 libdu 的字段编码（mod-95 + shuffle）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 unenc.py 'DEo?qBmCp=DoDq>'
  python3 unenc.py --k 12 --unshuffle 'DEo?qBmCp=DoDq>'
  python3 unenc.py --json data/decoded/D1H__MDNA_63185.json
""")
    ap.add_argument("value", nargs="?", help="要解的值")
    ap.add_argument("--json", help="从 JSON 文件里解全部字段")
    ap.add_argument("--k", type=int, help="指定 K（不指定则自动搜索 0..94）")
    ap.add_argument("--unshuffle", action="store_true", help="只用 unshuffle 方向")
    ap.add_argument("--shuffle", action="store_true", help="只用 shuffle 方向")
    a = ap.parse_args()

    if a.json:
        paths = glob.glob(a.json)
        if not paths:
            print("找不到文件: %s" % a.json)
            return 1
        for p in paths:
            show_json(p, a)
            print()
        return 0

    if a.value:
        show_value(a.value, a)
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
