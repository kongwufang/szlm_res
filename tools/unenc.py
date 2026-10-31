#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  unenc.py — 解开数字联盟 libdu 的字段编码
#
#  ★ 来源与归属（重要）
#
#    编码参数 P 的推导方式 ——「P 取自本次上报的 2cO 末三位」、四种重排的定义、
#    mode 10 的 checksum 偏移 —— 由 People-11 解出（https://github.com/People-11）。
#    详见仓库根目录 CREDITS.md。
#
#    本项目补的是：在真机数据上的交叉验证、非标准设备上的回退定位、
#    以及把解码结果与 DUID 锚点机制打通。
#
#  ★ 规则
#      P = 2cO 最后 3 个字符去掉 '.' 后 atoi
#          （2cO 是 clock_gettime(CLOCK_REALTIME) 的 "%ld.%ld"，纳秒不补零）
#          ★ 同一次 query 的所有上报、所有字段共用同一个 P
#
#      mode 2/3：
#          K       = P % 100 % 57 + 1               在 0x20..0x7E 内循环右移
#          variant = (P // 100) % 4                 四种重排
#          编码 = shuffle(shift(value, K), variant)
#          解码 = shift(unshuffle(value, variant), -K)
#
#      mode 10：
#          去掉第 (n-1-P%10) 个字符（长度 ≤ 9 时去掉最后一个），再按 mode 2 编码
#          另在 "s"+键名 下放校验值 MD5_UPPER(str(码位和 + P%100//10))[:7]
#
#  ★ 用法
#      python3 unenc.py --json data/decoded/D1H__MDNA_63185.json
#      python3 unenc.py --p 281 'RP|Q|zQKOJ~I~}Q'          # 指定 P
#      python3 unenc.py 'DEo?qBmCp=DoDq>'                  # 不给 P 时自动猜
#      python3 unenc.py --enc --p 281 'WIFI'
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


# ── 重排（四种，variant 由 P 决定）──────────────────────────────────────────
def shuffle(s, v):
    n, m = len(s), len(s) // 2
    if v == 0:
        # ① 奇数长度先放中间字符，再依次放 s[n-1-i]、s[m-1-i]
        return (s[m] if n % 2 else "") + "".join(
            s[n - 1 - i] + s[m - 1 - i] for i in range(m))
    if v == 1:
        # ② 依次放 s[n-1-i]、s[i]，中间字符最后
        return "".join(s[n - 1 - i] + s[i] for i in range(m)) + (s[m] if n % 2 else "")
    if v == 2:
        # ③ 从末尾起隔一个取一个，再从倒数第二个起隔一个取一个
        return s[n - 1::-2] + s[n - 2::-2]
    # ④ 先取偶数位，再取奇数位
    return s[0::2] + s[1::2]


def unshuffle(e, v):
    n = len(e)
    idx = shuffle("".join(chr(0x100 + i) for i in range(n)), v)
    out = [""] * n
    for pos, c in enumerate(idx):
        out[ord(c) - 0x100] = e[pos]
    return "".join(out)


# ── 偏移（mod 95 环）────────────────────────────────────────────────────────
def shift(s, k):
    return "".join(chr((ord(c) - LO + k) % MOD + LO) for c in s)


# ── P 与编解码 ──────────────────────────────────────────────────────────────
def p_of(two_co):
    """从 2cO 取 P：最后 3 个字符去掉 '.' 后 atoi"""
    if not two_co:
        return None
    tail = two_co[-3:].replace(".", "")
    return int(tail) if tail.isdigit() else None


def K_of(p):
    return p % 100 % 57 + 1


def V_of(p):
    return p // 100 % 4


def enc(value, p):
    return shuffle(shift(value, K_of(p)), V_of(p))


def dec(value, p):
    return shift(unshuffle(value, V_of(p)), -K_of(p))


def checksum(value, p):
    """mode 10 的校验值"""
    return hashlib.md5(
        str(sum(map(ord, value)) + p % 100 // 10).encode()
    ).hexdigest().upper()[:7]


# ── 回退：P 未知时自动猜（用于非标准设备 / 2cO 缺失）────────────────────────
def guess_p(value, validator):
    """穷举 P 的 (K, variant) 组合，返回所有通过 validator 的候选"""
    out = []
    for v in range(4):
        base = unshuffle(value, v)
        for k in range(1, 58):
            r = shift(base, -k)
            if validator(r):
                p_low = (k - 1) % 57
                for p_high in (0, 100, 200, 300):
                    p = p_high + p_low
                    if K_of(p) == k and V_of(p) == v:
                        out.append((p, k, v, r))
                        break
    return out


def is_uuid(s):
    if not s or len(s) != 36:
        return False
    if [s[8], s[13], s[18], s[23]] != ["-"] * 4:
        return False
    return all(c in HEX for c in s.replace("-", ""))


def is_hexish(s):
    return bool(s) and len(s) >= 8 and all(c in HEX for c in s)


def is_textual(s):
    if not s:
        return False
    return sum(1 for c in s if c.islower() or c.isdigit() or c in ".:,_-/ ") / len(s) >= 0.95


# ── 展示 ────────────────────────────────────────────────────────────────────
def show_value(value, args):
    print("  输入 (%d 字符): %r" % (len(value), value))
    print()

    if args.enc:
        if args.p is None:
            print("  --enc 需要 --p")
            return
        r = enc(value, args.p)
        print("  P=%d  K=%d  variant=%d" % (args.p, K_of(args.p), V_of(args.p)))
        print("  编码 → %r" % r)
        return

    if args.p is not None:
        p = args.p
        print("  P=%d  K=%d  variant=%d" % (p, K_of(p), V_of(p)))
        print("  解码 → %r" % dec(value, p))
        return

    # 未给 P：自动猜
    print("  未给 --p，自动搜索（4 种重排 × K=1..57）：")
    print()
    for name, vf in (("uuid", is_uuid), ("hexish", is_hexish), ("textual", is_textual)):
        hits = guess_p(value, vf)
        if hits:
            print("  [%s]" % name)
            for p, k, v, r in hits[:8]:
                print("    P=%-3d K=%-2d variant=%d → %r" % (p, k, v, r))
            print()


def show_json(path, args):
    try:
        j = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        print("  读不了 %s: %s" % (path, e))
        return
    if not isinstance(j, dict):
        print("  不是 JSON 对象")
        return

    print("=" * 80)
    print("  %s   (%d 字段)" % (os.path.basename(path), len(j)))
    print("=" * 80)

    two_co = j.get("2cO")
    p = args.p if args.p is not None else p_of(two_co)

    if p is None:
        print("  没有 2cO，且未给 --p —— 无法确定编码参数")
        return

    print()
    print("  2cO = %r" % two_co)
    print("  P = %d    →  K = %d,  variant = %d" % (p, K_of(p), V_of(p)))

    # ANDROID_ID：mode 10，用 sfOo 校验
    fo, sf = j.get("foO"), j.get("sfOo")
    if isinstance(fo, str) and isinstance(sf, str):
        base = dec(fo, p)
        if base and all(c in HEX for c in base):
            for c in "0123456789abcdef":
                cand = base + c
                if checksum(cand, p) == sf:
                    print()
                    print("  ★★ ANDROID_ID = %s" % cand)
                    print("     （foO 解出 %r，补 '%s' 后校验命中 sfOo=%r）" % (base, c, sf))
                    break
            else:
                print()
                print("  ⚠ foO 解出 %r，但 16 个候选都对不上 sfOo=%r" % (base, sf))

    # GUID 类
    dlh = j.get("dLH")
    if isinstance(dlh, str):
        r = dec(dlh, p)
        if is_uuid(r):
            print("  boot_uuid (dLH) = %s" % r)

    print()
    print("  其余可解字段:")

    RAW = {"sfOo", "DUv", "EV2", "3mS", "AAA", "BBB", "GVp", "h6Z", "2cO",
           "R41", "R37", "R3d", "R63", "Ra", "75c", "wSK", "zpA", "fPV",
           "ubF", "ne8", "w91", "gEd", "6yY", "K5f", "AYk", "P1J", "UOv",
           "YWu", "90P", "LAh", "za7", "foO", "dLH"}
    shown = 0
    for key, val in j.items():
        if not isinstance(val, str) or len(val) < 6 or key in RAW:
            continue
        r = dec(val, p)
        if not r or r == val:
            continue
        if any(not (LO <= ord(c) <= HI) for c in r):
            continue
        shown += 1
        print("    %-6s → %s" % (key, r))
    if not shown:
        print("    (无)")

    print()
    print("  ⚠ 注意")
    print("    · 若解开的内容看着像乱码，可能是该字段用别的 P（mode 1/7 尚未核清）")
    print("    · K 与 variant 由 2cO 决定，所以不同报文的值不能互相套用")


def main():
    ap = argparse.ArgumentParser(
        description="解开数字联盟 libdu 的字段编码（P 取自 2cO）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 unenc.py --json data/decoded/D1H__MDNA_63185.json
  python3 unenc.py --p 281 'RP|Q|zQKOJ~I~}Q'
  python3 unenc.py 'DEo?qBmCp=DoDq>'          # 不给 P，自动猜
  python3 unenc.py --enc --p 281 'WIFI'
""")
    ap.add_argument("value", nargs="?", help="要解的值")
    ap.add_argument("--json", help="从 JSON 文件里解全部字段")
    ap.add_argument("--p", type=int, help="编码参数 P（不给则从 2cO 取，或自动猜）")
    ap.add_argument("--enc", action="store_true", help="反向：编码")
    a = ap.parse_args()

    if a.json:
        for p in glob.glob(a.json):
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
