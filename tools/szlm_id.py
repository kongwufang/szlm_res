#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""szlm_id.py — 数盟 DUID 获取（/a/mdna/report）的完全自写、离线构造器 ★最终版

算法（全部经样本自证）：
    协议层  p = MD5(包名 + "." + "37be8a1ee106979a").upper()
            h = MD5(DUID + "." + "889e0b01").upper()   （首次无 DUID ⇒ h = "0"）
            r = 32 位小写十六进制
            URL  = <path>&p=…&r=…&n=…&l=…&h=…
    body    body = zlib.compress(JSON) XOR cyclic_key
            cyclic_key 取自 libdu 池常量表（已确认 5 个）
    序列化  JSON 紧凑格式，'/' 转义为 '\\/'

端点差异：
    /a/mdna/report   Content-Type: application/x-www-form-urlencoded   池 0x110dc8
    /a/adt/report    Content-Type: application/json                     池 0x109cf0
    /a/daa/report    Content-Type: application/json                     池 0x10924c

用法：
    python szlm_id.py show                 查看池常量与字段
    python szlm_id.py mdna                 用真实字段构造「要 ID」请求
    python szlm_id.py mdna --random        用随机指纹构造「要 ID」请求
    python szlm_id.py tpl                  输出 mdna 的 JSON 模板
    python szlm_id.py selftest             用已抓样本做双向自证
"""
import argparse
import glob
import hashlib
import json
import os
import random
import re
import sys
import time
import uuid
import zlib

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SALT_PKG = "37be8a1ee106979a"
SALT_DUID = "889e0b01"
HOST = "auni.telecome.cn"

# ---------------------------------------------------------------------------
# 池常量表（5 个，全部已逐字符溯源到 libdu 池地址）
# ---------------------------------------------------------------------------
POOL_KEYS = [
    (0x109CF0, 46, "2425763254577d706d6e5d3b696f2c5e402142262b3d3837667179753c3e3f3a5b277c7b2e2a602d303928747362"),
    (0x10924C, 53, "4064616c7364666b53444653657361214023746261664024256624254b3d5e2a26303931387e57657261723d2d2b5e253339283021"),
    (0x1090F8, 45, "372e6634393879753c3e3f3a5b277c545771262f3537667175403776362e616a6c236574757b2e6a7176326673"),
    (0x0FEC5C, 46, "4b6e5d3b2874733c3e3562763254573f3a5b277c256624254b36256f2c3d5e657261723d38376634422631387e57"),
    (0x110DC8, 48, "7870376a40262176355d326b232b337a7b6e3924715e72255b3866312a6434653a633e306c3f6d2f362979622d3d777d"),
]
KEY_BY_ADDR = {a: bytes.fromhex(h) for a, n, h in POOL_KEYS}

# 端点配置：路径、n、l、Content-Type、用哪个池常量
ENDPOINTS = {
    "mdna": ("/a/mdna/report?v=8.7&t=m", 0, 2,
             "application/x-www-form-urlencoded", 0x110DC8),
    "adt":  ("/a/adt/report?v=5.0&c=1&e=1&t=adt", 1, -1,
             "application/json", 0x109CF0),
    "daa":  ("/a/daa/report?v=1.1&c=1&e=1", 1, -1,
             "application/json", 0x10924C),
    "dai":  ("/a/dai/report?v=2.2&c=1&e=1", 0, 2,
             "application/x-www-form-urlencoded", 0x10924C),
    "dcc2": ("/a/dcc2/request?v=2.0&c=1&e=1", 0, 2,
             "application/x-www-form-urlencoded", 0x109CF0),
    "audd1": ("/a/audd/valid?v=1.0&t=uid1", 0, 2,
              "application/x-www-form-urlencoded", 0x1090F8),
    "d2api": ("/a/d2api/report?v=8.7&t=a&e=2", 0, 2,
              "application/x-www-form-urlencoded", None),
}


# ---------------------------------------------------------------------------
# 协议层
# ---------------------------------------------------------------------------
def make_p(pkg):
    return hashlib.md5(f"{pkg}.{SALT_PKG}".encode()).hexdigest().upper()


def make_h(duid):
    return hashlib.md5(f"{duid}.{SALT_DUID}".encode()).hexdigest().upper() if duid else "0"


# ---------------------------------------------------------------------------
# body 层
# ---------------------------------------------------------------------------
def dump_json(obj):
    """libdu 风格：紧凑 + '/' 转义为 '\\/'"""
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return s.replace("/", "\\/").encode("utf-8")


def encode_body(obj, key):
    z = zlib.compress(dump_json(obj))
    return bytes(z[i] ^ key[i % len(key)] for i in range(len(z)))


def decode_raw(body, key):
    z = bytes(body[i] ^ key[i % len(key)] for i in range(len(body)))
    return zlib.decompress(z)


def decode_body(body, key):
    return json.loads(decode_raw(body, key).decode("utf-8"))


# ---------------------------------------------------------------------------
# JSON 模板
# ---------------------------------------------------------------------------
# mdna（要 ID）用的模板：应用信息为主
MDNA_TEMPLATE = {
    "DUv": "com.coolapk.market",       # 包名
    "Qg1": 0,                           # 时间戳（ms）
    "LMi": 0,                           # 时间戳（ms）
    "Zrs": 2609151,                     # versionCode
    "EV2": "16.6.2",                    # versionName
    "SAN": 28,                          # SDK_INT
    "h6Z": "酷安",                       # App 名
    "R41": "9", "R5a": "46011", "R53": "0", "R63": "running",
    "QgA": 1, "qH9": "0", "iZS": 0, "ZZA": 0, "S6e": 1, "90P": "TU",
    "YWu": "127.0.0.1+localhost;::1+ip6-localhost;",
    "bzt": "0000", "5mZ": 0, "0KQ": 0, "Chh": 0,
    "Xl9": "0000", "D32": 4, "LAh": "67666666",
}

# adt/daa 用的模板：设备信息 + DUID + 应用列表
DEV_TEMPLATE = {
    "v5q": "0", "nAt": "2", "ubF": "",
    "AYk": "6F824D:502156:160A84", "P1J": "6F824D:502156:160A84",
    "R37": "sprd", "R3d": "XTQ_Watch",
    "DUv": "com.coolapk.market", "SAN": 28, "Zrs": 2609151, "EV2": "16.6.2",
    "AAA": "v1.0", "BBB": "v1.0", "3mS": "v9.0.1",
    "R41": "9", "R53": "0", "R63": "running",
    "QgA": 1, "qH9": "0", "w5v": 0, "iZS": 0, "ZZA": 0,
    "S6e": 1, "90P": "67",
    "YWu": "127.0.0.1+localhost;::1+ip6-localhost;",
    "bzt": "0000", "5mZ": 0, "0KQ": 0, "Chh": 0,
    "Xl9": "0000", "D32": 4, "LAh": "67666666",
    "GVp": "coolapk", "9qW": 0, "tcc": {"zdH": 0},
}

# 随机指纹时可选的真实 SoC/型号搭配
SOC_MODEL = [
    ("sprd", "XTQ_Watch"), ("sprd", "SC9863A"), ("sprd", "UMS512"),
    ("qcom", "Pixel 6"), ("qcom", "SM-G998B"), ("qcom", "2201123C"),
    ("mtk", "Redmi Note 11"), ("mtk", "CPH2451"), ("mtk", "V2164A"),
    ("kirin", "ELS-AN00"), ("kirin", "JSN-AL00"),
]


def build_mdna_json(pkg="com.coolapk.market", **over):
    now_ms = int(time.time() * 1000)
    j = dict(MDNA_TEMPLATE)
    j["DUv"] = pkg
    j["Qg1"] = now_ms
    j["LMi"] = now_ms
    j.update(over)
    return j


def randomize(dev, rng):
    """把设备相关字段换成随机的（保持自洽）"""
    soc, model = rng.choice(SOC_MODEL)
    d = dict(dev)
    tri = lambda: "%06X" % rng.randrange(0x100000, 0xFFFFFF)
    d["AYk"] = f"{tri()}:{tri()}:{tri()}"
    d["P1J"] = d["AYk"]
    d["R37"] = soc
    d["R3d"] = model
    d["R41"] = str(rng.choice([9, 10, 13]))
    d["R53"] = str(rng.choice([0, 1]))
    d["R63"] = rng.choice(["running", "idle"])
    d["LAh"] = "%08X" % rng.randrange(0x10000000, 0xFFFFFFFF)
    d["D32"] = rng.choice([4, 8])
    return d


# ---------------------------------------------------------------------------
# 组装
# ---------------------------------------------------------------------------
def build(endpoint, obj, pkg="com.coolapk.market", duid="", key=None):
    path, n, l, ctype, pool_addr = ENDPOINTS[endpoint]
    if key is None:
        key = KEY_BY_ADDR[pool_addr]
    url = "%s&p=%s&r=%s&n=%d&l=%d&h=%s" % (
        path, make_p(pkg), uuid.uuid4().hex, n, l, make_h(duid))
    body = encode_body(obj, key)
    head = ("POST %s HTTP/1.1\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: %s\r\n"
            "User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; %s Build/%s)\r\n"
            "Host: %s\r\n"
            "Connection: Keep-Alive\r\n"
            "Accept-Encoding: gzip\r\n\r\n") % (
        url, len(body), ctype, obj.get("R3d", "XTQ_Watch"),
        "PPR1.180610.011", HOST)
    return (head.encode("latin1") + body), url, body, key


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
def cmd_show():
    print("=" * 94)
    print("  池常量表（5 个，全部已溯源）")
    print("=" * 94)
    for addr, plen, hx in POOL_KEYS:
        raw = bytes.fromhex(hx)
        print(f"  0x{addr:06x}  周期 {plen:>2}  {raw.decode('latin1')!r}")
    print()
    print("=" * 94)
    print("  端点配置")
    print("=" * 94)
    print(f"  {'端点':<8} {'n':>3} {'l':>3}  池常量       Content-Type")
    for k, (path, n, l, ct, pa) in ENDPOINTS.items():
        pas = f"0x{pa:06x}" if pa else "（未确认）"
        print(f"  {k:<8} {n:>3} {l:>3}  {pas:<12} {ct}")
    print()
    print("  ★ 「要 ID」用 mdna：池 0x110dc8（周期 48）")


def cmd_mdna(randomize_dev):
    rng = random.Random() if randomize_dev else None
    obj = build_mdna_json()
    if rng:
        # mdna 模板里设备相关字段较少，主要随机化 90P/R5a 等可变项
        obj["90P"] = "%02X" % rng.randrange(0x10, 0x7F)
        obj["R5a"] = str(rng.randrange(40000, 50000))
        obj["R63"] = rng.choice(["running", "idle"])
    req, url, body, key = build("mdna", obj)
    print("=" * 94)
    print("  「要 ID」请求（/a/mdna/report）" + ("  【随机指纹】" if rng else "  【真实字段】"))
    print("=" * 94)
    print()
    print(f"  p = {make_p('com.coolapk.market')}")
    print(f"  h = {make_h('')}   （首次获取，无 DUID ⇒ h=0）")
    print(f"  池常量 = 0x110DC8  周期 {len(key)}")
    print()
    head, _, _ = req.partition(b"\r\n\r\n")
    for line in head.decode("latin1").split("\r\n"):
        print(f"     {line}")
    print(f"  [body] {len(body)} 字节  {body[:40].hex()}…")
    print()
    print("  ── 反解验证 ──")
    back = decode_body(body, key)
    print(f"     DUv={back['DUv']}  EV2={back['EV2']}  h6Z={back['h6Z']}")
    print()
    print("  ── JSON 全量 ──")
    print("     " + json.dumps(back, ensure_ascii=False, separators=(",", ":"))[:400])


def cmd_tpl():
    obj = build_mdna_json()
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def cmd_selftest(dump):
    jsons, bodies = {}, {}
    for pat, dic in (("wire_m55_JSONHEX_*.bin", jsons),
                     ("wire_m55_BODY_*.bin", bodies)):
        for f in sorted(glob.glob(os.path.join(dump, pat))):
            m = re.search(r"_(\d+)_len", os.path.basename(f))
            if m:
                dic[int(m.group(1))] = open(f, "rb").read()
    print("=" * 94)
    print("  自证：adt/daa 的 4 个样本（反解 + 序列化 + 重建）")
    print("=" * 94)
    jmap = {hashlib.md5(v).hexdigest(): (k, v) for k, v in jsons.items()}
    passed = tested = 0
    for f, bb in sorted(bodies.items()):
        got = None
        used = None
        for addr, key in KEY_BY_ADDR.items():
            try:
                raw = zlib.decompress(bytes(bb[i] ^ key[i % len(key)] for i in range(len(bb))))
                got, used = raw, key
                break
            except Exception:
                continue
        if got is None:
            continue
        h = hashlib.md5(got).hexdigest()
        if h not in jmap:
            continue
        k, jb = jmap[h]
        tested += 1
        obj = json.loads(got.decode("utf-8"))
        strict = (dump_json(obj) == got)
        fwd = (encode_body(obj, used) == bb)
        if strict and fwd:
            passed += 1
        print(f"  body#{f} ←→ json#{k}  反解={got == jb}  序列化一致={strict}  重建={fwd}")
    print()
    print(f"  结果：{passed}/{tested} 通过")
    return 0 if passed == tested and tested > 0 else 1


def main():
    ap = argparse.ArgumentParser(description="数盟 DUID 获取的离线构造器")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("show")
    p1 = sub.add_parser("mdna")
    p1.add_argument("--random", action="store_true")
    sub.add_parser("tpl")
    p2 = sub.add_parser("selftest")
    p2.add_argument("--dump", default=os.path.join(os.path.dirname(__file__), "dump"))
    args = ap.parse_args()

    if args.cmd == "show":
        cmd_show()
    elif args.cmd == "mdna":
        cmd_mdna(args.random)
    elif args.cmd == "tpl":
        cmd_tpl()
    elif args.cmd == "selftest":
        return cmd_selftest(args.dump)
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
