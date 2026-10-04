#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_adler.py — ★ 测服务器是否校验 zlib 校验和（决定能否写纯 shell 版）

★★★ 动机：安卓第三方设备大多没有 python3。
     若能把 body 编码改成【纯 shell】实现，脚本就能在任何安卓上跑。
     纯 shell 的难点是 zlib 的 adler32 校验和 —— 但如果服务器根本不校验，
     就可以用一个常量/错误的 adler32 糊过去。

★ 本实验：拿正确 body，故意破坏 adler32（zlib 流的最后 4 字节），看服务器认不认
   变体 1：adler32 置零
   变体 2：adler32 随机
   变体 3：adler32 用 adler32(全零数据)
   变体 4：整个 zlib 头也改（0x7801 → 存块模式头）
"""
import io
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.request
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
sys.path.insert(0, REV)
import szlm_id as S  # noqa: E402

CTX = ssl._create_unverified_context()
POOL = 0x110DC8
URL = ("/a/mdna/report?v=8.7&t=m"
       "&p=F9BD0FBDACFE80FCF34370FBCFEE1A98"
       "&r=5bb7efdd4c794f0e9563317b7802b995&n=0&l=2&h=0")
REAL = "DUaVFlbAMrmH2Z57PEhm_N9EO4RoUdvNstg5"
KEY = S.KEY_BY_ADDR[POOL]

TPL = json.load(open(os.path.join(REV, "mdna_template.json"), encoding="utf-8"))


def dump_json(o):
    s = json.dumps(o, ensure_ascii=False, separators=(",", ":"))
    return s.replace("/", "\\/").encode("utf-8")


def xor(bs):
    return bytes(bs[i] ^ KEY[i % len(KEY)] for i in range(len(bs)))


def unxor(bs):
    return bytes(bs[i] ^ KEY[i % len(KEY)] for i in range(len(bs)))


def send(body):
    h = {"Content-Type": "application/x-www-form-urlencoded",
         "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 8.1; TK Watch Build/OPM2.171019.012)",
         "Accept": "*/*", "Accept-Encoding": "identity"}
    try:
        r = urllib.request.Request("https://%s%s" % (S.HOST, URL), data=body,
                                   method="POST", headers=h)
        raw = urllib.request.urlopen(r, timeout=25, context=CTX).read()
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
    except Exception as e:
        return None, str(e)[:60]
    for fn in (zlib.decompress, lambda x: x):
        try:
            return json.loads(fn(unxor(raw)).decode("utf-8")), "ok"
        except Exception:
            pass
    return None, "raw:%s" % unxor(raw)[:40].hex()


raw_json = dump_json(TPL)
print("=" * 100)
print("  测服务器是否校验 zlib 的 adler32")
print("=" * 100)
print("  JSON 明文 %d 字节" % len(raw_json))
print("  真实 adler32 = %08X" % (zlib.adler32(raw_json) & 0xFFFFFFFF))
print()

variants = []

# 基线
z0 = zlib.compress(raw_json)
variants.append(("基线：正常 zlib", z0, ""))

# 1: adler32 置零
z1 = z0[:-4] + b"\x00\x00\x00\x00"
variants.append(("① adler32 置零", z1, ""))

# 2: adler32 随机
z2 = z0[:-4] + bytes(random.randint(0, 255) for _ in range(4))
variants.append(("② adler32 随机", z2, ""))

# 3: adler32 算错的对象（用全零数据的 adler）
z3 = z0[:-4] + (zlib.adler32(b"\x00" * len(raw_json)) & 0xFFFFFFFF).to_bytes(4, "big")
variants.append(("③ adler32 算错数据", z3, ""))

# 4: 存块模式（无压缩）—— 纯 shell 最容易构造的形式
def zlib_stored(data):
    out = b"\x78\x01"
    i = 0
    while i < len(data):
        chunk = data[i:i + 65535]
        i += len(chunk)
        bfinal = 1 if i >= len(data) else 0
        out += bytes([bfinal])
        n = len(chunk)
        out += n.to_bytes(2, "little") + (0xFFFF ^ n).to_bytes(2, "little")
        out += chunk
    out += (zlib.adler32(data) & 0xFFFFFFFF).to_bytes(4, "big")
    return out


z4 = zlib_stored(raw_json)
variants.append(("④ 存块模式（未压缩 deflate）", z4, "★ 纯 shell 可构造"))

# 5: 存块模式 + adler32 置零
z5 = z4[:-4] + b"\x00\x00\x00\x00"
variants.append(("⑤ 存块模式 + adler32 置零", z5, "★ 纯 shell 零校验和"))

print("  %-34s %-10s %-30s %s" % ("变体", "zlib 长度", "响应 n_a", "判定"))
print("  " + "-" * 96)
for name, z, note in variants:
    body = xor(z)
    j, how = send(body)
    na = str(j.get("n_a", "")) if isinstance(j, dict) else ""
    err = str(j.get("err", "")) if isinstance(j, dict) else ""
    if not isinstance(j, dict):
        vd = "无响应 (%s)" % how
    elif na == REAL:
        vd = "★★★ 真 DUID → 服务器【不校验】该校验和"
    elif na and set(na) == {"0"}:
        vd = "全 0 → 被拒"
    elif na:
        vd = "→ 新 DUID"
    else:
        vd = "空 (err=%s)" % err
    print("  %-34s %-10d %-30s %s" % (name, len(z), (na or "(空)")[:30], vd))
    if note:
        print("      %s" % note)
    time.sleep(2)

print("\n" + "=" * 100)
print("  结论")
print("=" * 100)
print("""
  若 ① ② ③ 都返回真 DUID
     ⇒ 服务器【不校验 adler32】⇒ 纯 shell 版只需构造 deflate 数据 + 任意 4 字节
  若 ④（存块模式）也返回真 DUID
     ⇒ 纯 shell 版可以【完全不压缩】⇒ 实现极简单
  若 ⑤ 也通过
     ⇒ 连校验和都能写常数 ⇒ 脚本最简单
""")
