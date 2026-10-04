#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""anchor_verify.py — 区分「真锚点」与「只是类型敏感」

★★★ 上一轮的哨兵化有个混淆项：
     字符串字段改成 "ZZSENTINELZZ"、数字改成 424242
     ⇒ 全 0 可能是【格式/类型不符】导致，而不是因为它真是设备锚点
     （文档 FIELD_TYPES_AND_MIS.md 明确记录过：87 个叶节点里 76 个【类型敏感】）

★ 本实验用【同类型的合法值】替换，才能区分：
     · 换成合法值仍返回真 DUID   -> 无关字段
     · 换成合法值就全 0 / 换 DUID -> ★ 真锚点

★ 重点测 6 个嫌疑字段：
     DUv  (包名)        – 已知必需
     3mS  (SDK 版本)     – 已知必需（且值有格式要求）
     2cO  (时间戳)       – 需合法格式
     sfOo (7 位 hex)
     foO  (14 字符混淆)
     mIS  (36 字符)      – 已知换成合法值仍返回真 DUID
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
SRC = os.path.join(REV, "dump", "wire_m58_REQ_9_len1745.bin")
REAL_DUID = "DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9"
ALPHA = ("!#$%&'()*+,-./0123456789:;<=>?@"
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
         "abcdefghijklmnopqrstuvwxyz{|}~")


def load_real():
    d = open(SRC, "rb").read()
    i = d.find(b"\r\n\r\n")
    lines = d[:i].decode("latin1").split("\r\n")
    url = lines[0].split(" ")[1]
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip()] = v.strip()
    k = S.KEY_BY_ADDR[POOL]
    body = d[i + 4:]
    obj = json.loads(zlib.decompress(
        bytes(body[j] ^ k[j % len(k)] for j in range(len(body)))).decode())
    return url, hdrs, obj


def enc(obj):
    k = S.KEY_BY_ADDR[POOL]
    z = zlib.compress(S.dump_json(obj))
    return bytes(z[i] ^ k[i % len(k)] for i in range(len(z)))


def send(url, hdrs, body):
    h = {"Content-Type": hdrs.get("Content-Type", "application/x-www-form-urlencoded"),
         "User-Agent": hdrs.get("User-Agent", ""), "Accept": "*/*",
         "Accept-Encoding": "identity"}
    try:
        req = urllib.request.Request("https://%s%s" % (S.HOST, url), data=body,
                                     method="POST", headers=h)
        raw = urllib.request.urlopen(req, timeout=25, context=CTX).read()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
        except Exception:
            raw = b""
    except Exception:
        return None
    for addr, k in S.KEY_BY_ADDR.items():
        try:
            d = bytes(raw[j] ^ k[j % len(k)] for j in range(len(raw)))
            for fn in (lambda x: zlib.decompress(x), lambda x: x):
                try:
                    return json.loads(fn(d).decode("utf-8"))
                except Exception:
                    pass
        except Exception:
            pass
    return None


url, hdrs, base = load_real()
RAND = "".join(random.choice(ALPHA) for _ in range(36))

print("=" * 100)
print("  ★ 用【同类型合法值】区分真锚点 vs 类型敏感")
print("=" * 100)
print("  基线：mIS=随机 + ubF 清空")
for k in ("sfOo", "foO", "2cO", "3mS", "DUv"):
    print("     %-6s = %r" % (k, base.get(k)))
print()

# 基线
b = dict(base)
b["mIS"] = RAND
b["ubF"] = ""
jb = send(url, hdrs, enc(b))
BASE_NA = str(jb.get("n_a", "")) if isinstance(jb, dict) else "(失败)"
print("  基线 n_a = %s" % BASE_NA)
print()

CASES = [
    ("sfOo → 另一个 7 位 hex", "sfOo", "ABCDEF1"),
    ("sfOo → 原值（对照）", "sfOo", base.get("sfOo", "")),
    ("foO → 另一个 14 字符混淆", "foO", "".join(random.choice(ALPHA) for _ in range(14))),
    ("foO → 原值（对照）", "foO", base.get("foO", "")),
    ("2cO → 另一个合法秒.纳秒", "2cO", "1790969200.123456789"),
    ("2cO → 原值（对照）", "2cO", base.get("2cO", "")),
    ("3mS → v9.0.2（合法版本）", "3mS", "v9.0.2"),
    ("3mS → 原值（对照）", "3mS", base.get("3mS", "")),
    ("DUv → 另一个包名", "DUv", "com.tencent.mm"),
    ("mIS → 另一个 36 字符（对照）", "mIS", RAND),
]

print("  %-34s %-30s %s" % ("用例", "n_a", "判定"))
print("  " + "-" * 96)
verdicts = {}
for name, key, val in CASES:
    v = dict(base)
    v["mIS"] = RAND
    v["ubF"] = ""
    v[key] = val
    try:
        body = enc(v)
    except Exception:
        print("  %-34s %-30s ✗ 编码失败" % (name, "-"))
        continue
    j = send(url, hdrs, body)
    na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无响应)"
    if na == BASE_NA and na == REAL_DUID:
        vd = "无关（仍真 DUID）"
    elif na in ("000000000000000000000000000000000000", ""):
        vd = "★★★ 全 0 —— 真锚点！"
    else:
        vd = "→ 换成了 %s" % na[:20]
    verdicts[name] = vd
    print("  %-34s %-30s %s" % (name, na[:30], vd))
    time.sleep(1.5)

print("\n" + "=" * 100)
print("  结论")
print("=" * 100)
real_anchor = [n for n, v in verdicts.items() if "真锚点" in v]
print("  真锚点候选：")
for n in real_anchor:
    print("     ★ %s" % n)
print()
print("  基线 DUID = %s" % BASE_NA)
print("  真实 ubF  = (原 body 里没有 ubF 字段)")
print("  随机 mIS  = %s" % RAND)
