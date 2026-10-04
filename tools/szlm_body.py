#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""szlm_body.py — 数盟(cn.shuzilm) body 编解码器【完全离线、纯自写实现】

算法（已通过 4/4 双向验证）：
    body = zlib.compress(JSON) XOR cyclic_key
    cyclic_key = libdu 池中的硬编码常量字符串，按周期循环

依赖：仅 Python 标准库（zlib）。
不依赖设备、不依赖运行时数据、不依赖任何 SDK。

用法：
    python szlm_body.py selftest
        用已抓取的样本做双向自证（需要 _rev/dump 下的样本）
    python szlm_body.py encode <json文件>
        把 JSON 编码成 body（十六进制输出）
    python szlm_body.py decode <body文件> --key <索引0..3>
        把 body 解回 JSON
"""
import argparse
import glob
import json
import os
import re
import sys
import zlib

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# libdu 池中的硬编码常量密钥表（已从样本逐一确认）
# 每个元素是 (池地址, 密钥字节)
# ---------------------------------------------------------------------------
POOL_KEYS = [
    (0x109CF0, b"$%v2TW}pmn];io,^@!B&+=87fqyu<>?:['|{.*`-09(tsb"),                 # 周期 46
    (0x10924C, b"@dalsdfkSDFSesa!@#tbaf@$%f$%K=^*&0918~Werar=-+^%39(0!"),         # 周期 53
    (0x1090F8, b"7.f498yu<>?:['|TWq&/57fqu@7v6.ajl#etu{.jqv2fs"),                 # 周期 45
    (0x0FEC5C, b"Kn];(ts<>5bv2TW?:['|%f$%K6%o,=^erar=87f4B&18~W"),                 # 周期 46
]

# 已知的 type -> 曾观察到的密钥索引（仅作参考；未观察到固定规律，推测随机）
TYPE_HINT = {
    0x01: 1,
    0x04: 0,
    0x05: 3,
    0x0D: 2,
}


def encode_body(json_text: str, key: bytes, level: int = -1) -> bytes:
    """JSON 字符串 -> body 密文

    level = -1 表示用 zlib 默认等级（libdu 实测就是这个）
    """
    raw = json_text.encode("utf-8")
    z = zlib.compress(raw) if level < 0 else zlib.compress(raw, level)
    return bytes(z[i] ^ key[i % len(key)] for i in range(len(z)))


def decode_body(body: bytes, key: bytes) -> str:
    """body 密文 -> JSON 字符串"""
    z = bytes(body[i] ^ key[i % len(key)] for i in range(len(body)))
    return zlib.decompress(z).decode("utf-8")


def guess_key(body: bytes):
    """在不知道密钥时，用池常量逐个试，返回能成功解压的那个"""
    for addr, key in POOL_KEYS:
        try:
            t = decode_body(body, key)
            if t.lstrip().startswith("{"):
                return addr, key, t
        except Exception:
            continue
    return None, None, None


# ---------------------------------------------------------------------------
# 自证：用已抓取的样本做双向验证
# ---------------------------------------------------------------------------
def selftest(dump_dir: str) -> int:
    jsons, bodies = {}, {}
    for pat, dic in (("wire_m55_JSONHEX_*.bin", jsons),
                     ("wire_m55_BODY_*.bin", bodies)):
        for f in sorted(glob.glob(os.path.join(dump_dir, pat))):
            m = re.search(r"_(\d+)_len", os.path.basename(f))
            if m:
                dic[int(m.group(1))] = open(f, "rb").read()

    # 日志里记录的实际输入长度（用于识别被截断的样本）
    log_in = {1: 2290, 2: 6803, 3: 851, 4: 3402, 5: 1123, 6: 6979, 7: 1546, 8: 6990}

    print("=" * 90)
    print("  数盟 body 编解码器 —— 双向自证")
    print("=" * 90)
    print()
    print("  算法：body = zlib.compress(JSON) XOR cyclic_key")
    print("       cyclic_key = libdu 池常量（周期循环）")
    print()

    passed = 0
    tested = 0
    for k in sorted(jsons):
        if k not in bodies:
            continue
        jb, bb = jsons[k], bodies[k]
        full = (len(jb) == log_in.get(k, len(jb)))
        if not full:
            print(f"  #{k}  跳过（JSON 落盘被截断：{len(jb)}/{log_in.get(k)}）")
            continue
        tested += 1
        # 反解：用池常量逐个试，找出正确密钥
        addr, key, text = guess_key(bb)
        if key is None:
            print(f"  #{k}  反解失败")
            continue
        # 正向：用同一密钥重建
        rec = encode_body(text, key)
        fwd = (rec == bb)
        # 反解出的 JSON 是否与原 JSON 一致
        back = (text.encode("utf-8") == jb)
        ok = fwd and back
        if ok:
            passed += 1
        print(f"  #{k}  池地址 0x{addr:06x}  周期 {len(key):>2}  "
              f"正向重建一致={fwd}  反解回原 JSON={back}")

    print()
    print("=" * 90)
    print(f"  结果：{passed}/{tested} 通过")
    print("=" * 90)
    return 0 if passed == tested and tested > 0 else 1


def read_bytes(path: str) -> bytes:
    b = open(path, "rb").read()
    # 若是纯 hex 文本（且长度为偶数、全是 hex 字符），按 hex 解析
    if len(b) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F\r\n \t]+", b):
        return bytes.fromhex(re.sub(rb"[\r\n \t]", b"", b).decode("ascii"))
    return b


def main() -> int:
    ap = argparse.ArgumentParser(description="数盟 body 编解码器（纯离线实现）")
    sub = ap.add_subparsers(dest="cmd")

    p1 = sub.add_parser("selftest", help="用已抓样本做双向自证")
    p1.add_argument("--dump", default=os.path.join(os.path.dirname(__file__), "dump"))

    p2 = sub.add_parser("encode", help="JSON -> body")
    p2.add_argument("json_file")
    p2.add_argument("--key", type=int, default=0, choices=range(len(POOL_KEYS)),
                    help="用池常量表的第几个（默认 0）")

    p3 = sub.add_parser("decode", help="body -> JSON")
    p3.add_argument("body_file")
    p3.add_argument("--key", type=int, default=-1, help="池常量索引；-1 表示自动尝试")

    args = ap.parse_args()

    if args.cmd == "selftest":
        return selftest(args.dump)

    if args.cmd == "encode":
        text = open(args.json_file, encoding="utf-8").read()
        addr, key = POOL_KEYS[args.key]
        out = encode_body(text, key)
        print(f"# 池地址 0x{addr:06x}  周期 {len(key)}")
        print(f"# 输入 {len(text.encode('utf-8'))} 字节 -> 输出 {len(out)} 字节")
        print(out.hex())
        return 0

    if args.cmd == "decode":
        body = read_bytes(args.body_file)
        if args.key >= 0:
            addr, key = POOL_KEYS[args.key]
            print(decode_body(body, key))
            return 0
        addr, key, text = guess_key(body)
        if key is None:
            print("所有池常量都解不开", file=sys.stderr)
            return 1
        print(f"# 命中池地址 0x{addr:06x}  周期 {len(key)}", file=sys.stderr)
        print(text)
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
