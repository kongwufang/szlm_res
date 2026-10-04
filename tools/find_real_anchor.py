#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""find_real_anchor.py — ★ 找出真正的设备标识字段

★★★ 上一实验的决定性发现：
     mIS 换成随机值 → 服务器【照样返回真 DUID】
     ⇒ mIS 不是设备标识！

★★★ 为什么文档的扫描测不出来：
     文档的 87 字段扫描【一直保持 mIS 为真值】——
     那个真值足以命中记录，所以别的字段改什么都看不出效果。
     ★ 这是典型的「观测设计缺陷」：被观测的量掩盖了要找的量。

★★★ 本实验的正确设计：
     基线 = mIS=随机 + ubF 清空  （已实测能拿到真 DUID）
     然后【逐个】把其它字段改成哨兵值，看 n_a 何时变成全 0
     ⇒ 变全 0 的那个字段 = 真正的设备标识之一

★ 哨兵值选择：
     字符串 -> "ZZSENTINELZZ"
     数字   -> 424242
     嵌套   -> {}
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
ALPHA = ("!#$%&'()*+,-./0123456789:;<=>?@"
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
         "abcdefghijklmnopqrstuvwxyz{|}~")
ZERO = "0" * 36


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
    except Exception as e:
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


def sentinel(v):
    if isinstance(v, dict):
        return {}
    if isinstance(v, list):
        return []
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return 424242
    if isinstance(v, str):
        return "ZZSENTINELZZ"
    return v


url, hdrs, base = load_real()
REAL_DUID = "DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9"
RAND = "".join(random.choice(ALPHA) for _ in range(36))

print("=" * 100)
print("  ★ 找真正的设备标识字段")
print("=" * 100)
print("  方法：基线 = mIS 随机 + ubF 清空（已知能拿真 DUID）")
print("        逐字段改哨兵值，看 n_a 何时变全 0")
print()

# 基线
b = dict(base)
b["mIS"] = RAND
b["ubF"] = ""
print("  [基线] 发送中…")
jb = send(url, hdrs, enc(b))
if not jb:
    print("  ✗ 基线失败，无法继续"); sys.exit(1)
na0 = str(jb.get("n_a", ""))
print("     基线 n_a = %s" % na0)
if na0 != REAL_DUID:
    print("     ⚠ 基线没拿到真 DUID，结果可能不可信")
print()

# 逐字段
keys = [k for k in base if k not in ("mIS", "ubF")]
print("  逐字段扫描 %d 个字段（每个间隔 1.5 秒）" % len(keys))
print("  " + "-" * 94)
print("  %-10s %-30s %s" % ("字段", "改后 n_a", "判定"))
hits = []
for k in keys:
    v = dict(base)
    v["mIS"] = RAND
    v["ubF"] = ""
    v[k] = sentinel(base[k])
    try:
        body = enc(v)
    except Exception:
        print("  %-10s %-30s ✗ 编码失败" % (k, "-"))
        continue
    j = send(url, hdrs, body)
    na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无响应)"
    if na == ZERO or na in ("", "000000000000000000000000000000000000"):
        verdict = "★★★ 全 0 —— 该字段是设备标识！"
        hits.append(k)
    elif na == REAL_DUID:
        verdict = "仍返回真 DUID（无关）"
    else:
        verdict = "→ %s" % na[:24]
    print("  %-10s %-30s %s" % (k, na[:30], verdict))
    time.sleep(1.5)

print("\n" + "=" * 100)
print("  命中：真正参与设备识别的字段")
print("=" * 100)
if hits:
    for k in hits:
        print("  ★ %s  =  %r" % (k, str(base[k])[:90]))
else:
    print("  （没有单个字段能单独让结果变全 0 ⇒ 可能是多字段组合）")
print("\n  基线 DUID = %s" % na0)
print("  随机 mIS  = %s" % RAND)
