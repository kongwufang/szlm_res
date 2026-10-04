#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_getduid.py — 生成自包含的 getduid.py（把模板内嵌进去）"""
import io
import json
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
tpl = open(os.path.join(REV, "mdna_template.json"), encoding="utf-8").read().strip()

BODY = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  getduid.py — 从数字联盟取 DUID（单文件、零依赖、可直接在安卓上跑）
#
#  ★ 用法：
#      python3 getduid.py                # 固定三值 → 应稳定返回同一个 DUID
#      python3 getduid.py -n 3           # 固定三值跑 3 次
#      python3 getduid.py -r             # 随机三值 → 每次拿一个新 DUID
#      python3 getduid.py -r -n 5        # 连拿 5 个新 DUID
#      python3 getduid.py -f             # 打印完整响应 JSON
#      python3 getduid.py --sf 801C14F --fo 'RP|Q|zQKOJ~I~}Q' --ts 1791105420.764024281
#      python3 getduid.py -h             # 帮助
#
#  ★ 跨网络测试（你的目的）：
#      网络 A：python3 getduid.py -n 3     记下 DUID
#      网络 B：python3 getduid.py -n 3     对比
#         · 两次 DUID 相同 → 服务器不依赖出口 IP
#         · 两次 DUID 不同 → 出口 IP 参与了设备识别
#      脚本会自动打印出口 IP 便于确认网络已切换
#
#  ★ 只依赖 Python 3 标准库（json / zlib / ssl / urllib）
#  ★ 无需任何配套文件
# ============================================================================

from __future__ import print_function

import argparse
import json
import os
import random
import ssl
import sys
import time
import zlib

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError


# ── 常量 ────────────────────────────────────────────────────────────────────
HOST = "auni.telecome.cn"
URLPATH = ("/a/mdna/report?v=8.7&t=m"
           "&p=F9BD0FBDACFE80FCF34370FBCFEE1A98"
           "&r=5bb7efdd4c794f0e9563317b7802b995&n=0&l=2&h=0")
UA = "Dalvik/2.1.0 (Linux; U; Android 8.1; TK Watch Build/OPM2.171019.012)"

# ★ 池常量 0x110DC8（48 字节周期）
KEY = b"xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}"

ALPHA = ("!#$%&'()*+,-./0123456789:;<=>?@"
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`"
         "abcdefghijklmnopqrstuvwxyz{|}~")

REAL_DUID = "DUaVFlbAMrmH2Z57PEhm_N9EO4RoUdvNstg5"

DEFAULT_SF = "801C14F"
DEFAULT_FO = "RP|Q|zQKOJ~I~}Q"
DEFAULT_TS = "1791105420.764024281"

# ── 内嵌的 79 字段完整报文模板 ──────────────────────────────────────────────
TEMPLATE_JSON = r"""__TEMPLATE__"""
TEMPLATE = json.loads(TEMPLATE_JSON)


def dump_json(obj):
    # libdu 风格：紧凑 JSON + 把 / 转义成 反斜杠+/
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return s.replace("/", "\\\\/").encode("utf-8")


def xor(data):
    n = len(KEY)
    return bytes(bytearray(data[i] ^ KEY[i % n] for i in range(len(data))))


def encode_body(obj):
    return xor(zlib.compress(dump_json(obj), 6))


def decode_resp(raw):
    """尝试解出响应 JSON"""
    try:
        d = xor(raw)
    except Exception:
        return None
    for fn in (zlib.decompress, lambda x: x):
        try:
            return json.loads(fn(d).decode("utf-8"))
        except Exception:
            pass
    return None


def get_exit_ip():
    """取出口 IP（用于确认网络环境）"""
    for site in ("https://api.ipify.org", "https://ifconfig.me/ip",
                 "https://ipinfo.io/ip"):
        try:
            ctx = ssl._create_unverified_context()
            r = Request(site, headers={"User-Agent": "curl/8"})
            return urlopen(r, timeout=8, context=ctx).read().decode().strip()
        except Exception:
            continue
    return "(取不到)"


def post(body):
    hdrs = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
    }
    ctx = ssl._create_unverified_context()
    r = Request("https://" + HOST + URLPATH, data=body, headers=hdrs)
    try:
        return urlopen(r, timeout=30, context=ctx).read(), "ok"
    except HTTPError as e:
        try:
            return e.read(), "http%d" % e.code
        except Exception:
            return b"", "http%d" % e.code
    except Exception as e:
        return b"", str(e)[:70]


def make_random():
    sf = "%07X" % random.randint(0, 0xFFFFFFF)
    fo = "".join(random.choice(ALPHA) for _ in range(15))
    ts = "%.0f.%09d" % (time.time(), random.randint(1, 999999999))
    o = dict(TEMPLATE)
    o["sfOo"], o["foO"], o["2cO"] = sf, fo, ts
    # ★ 只改三值会被判「不自洽」→ 全 0；必须连三指纹一起改才会签发新 DUID
    o["w91"] = "".join(random.choice("0123456789ABCDEF") for _ in range(32))
    o["gEd"] = "".join(random.choice("0123456789abcdef") for _ in range(32))
    o["6yY"] = "".join(random.choice("0123456789abcdef") for _ in range(64))
    return o, sf, fo, ts


def make_fixed(sf, fo, ts):
    o = dict(TEMPLATE)
    o["sfOo"], o["foO"], o["2cO"] = sf, fo, ts
    return o, sf, fo, ts


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("-n", "--count", type=int, default=1)
    ap.add_argument("-r", "--random", action="store_true")
    ap.add_argument("-f", "--full", action="store_true")
    ap.add_argument("--no-ip", action="store_true")
    ap.add_argument("--sf", default=DEFAULT_SF)
    ap.add_argument("--fo", default=DEFAULT_FO)
    ap.add_argument("--ts", default=DEFAULT_TS)
    ap.add_argument("-h", "--help", action="store_true")
    a = ap.parse_args()

    if a.help:
        print(__doc__ or "见文件头注释")
        return 0

    print("=" * 62)
    print("  数字联盟 DUID 获取")
    print("=" * 62)
    if not a.no_ip:
        print("  出口 IP  : %s" % get_exit_ip())
    print("  模式     : %s" % ("random（拿新 DUID）" if a.random else "fixed（固定三值）"))
    print("  次数     : %d" % a.count)
    if not a.random:
        print("  固定三值 : sfOo=%s" % a.sf)
        print("             foO=%s" % a.fo)
        print("             2cO=%s" % a.ts)
        print("  ★ 正常应返回: %s" % REAL_DUID)
    print("-" * 62)

    seen = []
    for i in range(a.count):
        if a.random:
            o, sf, fo, ts = make_random()
        else:
            o, sf, fo, ts = make_fixed(a.sf, a.fo, a.ts)
        body = encode_body(o)
        raw, how = post(body)
        j = decode_resp(raw) if raw else None

        na = ""
        err = ""
        if isinstance(j, dict):
            na = str(j.get("n_a", ""))
            err = str(j.get("err", ""))
        seen.append(na)

        tag = ("[%d/%d] " % (i + 1, a.count)) if a.count > 1 else ""
        if i == 0:
            print("  body: %d 字节 / %d 字段" % (len(body), len(o)))
        print("  %s%-9s %-20s %s" % (tag, sf, fo, ts))
        if na == REAL_DUID:
            print("        -> %s   <<< D1 真 DUID" % na)
        elif na and set(na) == {"0"}:
            print("        -> %s   (全 0，被拒)" % na)
        elif na:
            print("        -> %s   <<< 新 DUID" % na)
        else:
            print("        -> (空)  %s" % how)
        if err and err not in ("0", ""):
            print("           err=%s" % err)
        if a.full and isinstance(j, dict):
            print("           %s" % json.dumps(j, ensure_ascii=False))
        if i + 1 < a.count:
            time.sleep(1.5)

    print()
    print("-" * 62)
    uniq = []
    for x in seen:
        if x not in uniq:
            uniq.append(x)
    print("  %d 次 -> %d 个不同的 DUID" % (a.count, len(uniq)))
    for x in uniq:
        print("     %-46s x%d" % (x or "(空)", seen.count(x)))
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

out = BODY.replace("__TEMPLATE__", tpl)
p = os.path.join(REV, "getduid.py")
open(p, "w", encoding="utf-8").write(out)
print("已生成 getduid.py  (%d 字节)" % len(out))
print("模板内嵌 %d 字节" % len(tpl))
