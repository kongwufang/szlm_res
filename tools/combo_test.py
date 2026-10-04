#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""combo_test.py — ★ 回答「除锚点外还有没有别的字段参与设备识别」

★★★ 为什么必须做这个实验：
     我的单字段扫描（逐字段换合法值）有【组合盲区】——
     如果服务器用的是「N 个字段组合校验」，单独改一个看不出来。

★ 做法：从「全真」出发，逐步【只保留锚点】，其余全部随机化
     变体 1：保留 6 个锚点，其余全随机                 -> ?
     变体 2：保留 5 个（去掉 75c），其余全随机          -> ?
     变体 3：只保留 DUv+3mS+2cO+sfOo+foO，其余全随机   -> ?
     变体 4：只保留 2cO+sfOo+foO（设备三元组）          -> ?
     变体 5：保留 2cO+sfOo+foO+DUv，其余全随机          -> ?

★ 判读：
     · 若某变体仍返回【真 DUID】=> 该变体保留的字段就是全部所需
     · 若全 0                  => 还有别的字段参与
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


def rnd_like(v):
    """按原值的类型和形态生成一个【同类型合法】的随机值"""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return random.randint(1, 999999)
    if isinstance(v, float):
        return round(random.uniform(0, 100), 3)
    if isinstance(v, dict):
        return {k: rnd_like(x) for k, x in v.items()}
    if isinstance(v, list):
        return []
    if isinstance(v, str):
        n = len(v)
        if n == 0:
            return ""
        # 尽量保持字符集形态
        if all(c in "0123456789abcdefABCDEF" for c in v) and n >= 7:
            pool = "0123456789ABCDEF"
        elif any(c in "*]()&\\'~" for c in v):
            pool = "*]()&\\'~WXZQT"
        else:
            pool = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(random.choice(pool) for _ in range(min(n, 40)))
    return v


url, hdrs, base = load_real()

print("=" * 104)
print("  ★ 组合盲区测试：只保留锚点，其余全部随机化")
print("=" * 104)
print("  真实 DUID = %s" % REAL_DUID)
print()

# 基线：全真
jb = send(url, hdrs, enc(dict(base)))
print("  [基线:全真] n_a = %s" % (str(jb.get("n_a", "?")) if isinstance(jb, dict) else "(失败)"))
print()

KEEP_SETS = [
    ("只留 6 锚点 DUv+3mS+2cO+sfOo+foO+75c",
     {"DUv", "3mS", "2cO", "sfOo", "foO", "75c"}),
    ("只留 5 个（去 75c）",
     {"DUv", "3mS", "2cO", "sfOo", "foO"}),
    ("只留 4 个（去 75c/3mS）",
     {"DUv", "2cO", "sfOo", "foO"}),
    ("只留 3 个设备三元组 2cO+sfOo+foO",
     {"2cO", "sfOo", "foO"}),
    ("只留 2cO+sfOo（去 foO）",
     {"2cO", "sfOo"}),
    ("只留 2cO+foO（去 sfOo）",
     {"2cO", "foO"}),
    ("只留 sfOo+foO（去 2cO）",
     {"sfOo", "foO"}),
]

for name, keep in KEEP_SETS:
    v = {}
    for k, val in base.items():
        v[k] = val if k in keep else rnd_like(val)
    # ubF 原 body 里没有，跳过
    try:
        body = enc(v)
    except Exception as e:
        print("  %-44s ✗ 编码失败 %s" % (name, str(e)[:40]))
        continue
    j = send(url, hdrs, body)
    na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无响应)"
    if na == REAL_DUID:
        vd = "★★★ 真 DUID —— 这些字段就够了！"
    elif na in ("0" * 36, ""):
        vd = "全 0"
    else:
        vd = "→ %s" % na[:24]
    print("  %-44s %-26s %s" % (name, na[:26], vd))
    time.sleep(2)

print("\n" + "=" * 104)
print("  反向对照：全随机（一个真值都不留）")
print("=" * 104)
v = {k: rnd_like(val) for k, val in base.items()}
j = send(url, hdrs, enc(v))
print("  全随机  n_a = %s" % (str(j.get("n_a", "?"))[:40] if isinstance(j, dict) else "(失败)"))

print("\n" + "=" * 104)
print("  排除法：从「全真」出发，把【某几类】字段整体随机化")
print("=" * 104)
GROUPS = [
    ("把所有 hex 哈希字段随机化 K5f/ne8/w91/gEd/6yY",
     ["K5f", "ne8", "w91", "gEd", "6yY"]),
    ("把所有混淆串随机化（除 mIS/foO）",
     ["yzW", "zvW", "5Tv", "52J", "Bos", "IJK", "ura", "ibF", "IAI", "aFw", "KyU", "UOv", "dLH", "90P", "LAh"]),
    ("把嵌套对象全清空 iYB/7S2/G8U/msg",
     ["iYB", "7S2", "G8U", "msg"]),
    ("把设备属性随机化 AYk/P1J/R3d/R37/wSK/YWu",
     ["AYk", "P1J", "R3d", "R37", "wSK", "YWu"]),
    ("把时间戳随机化 Qg1/LMi/za7",
     ["Qg1", "LMi", "za7"]),
]
for name, ks in GROUPS:
    v = dict(base)
    for k in ks:
        if k in v:
            v[k] = rnd_like(v[k])
    j = send(url, hdrs, enc(v))
    na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无响应)"
    vd = ("★★★ 仍真 DUID（这些与设备识别无关）" if na == REAL_DUID
          else ("全 0（★ 这里面有参与者！）" if na in ("0" * 36, "") else "→ " + na[:24]))
    print("  %-48s %s" % (name, vd))
    time.sleep(2)
