#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mis_random_matrix.py — ★ 用户的实验：mIS 随机时服务器认不认

★★★ 用户提出的关键问题：
     mIS 如果是随机的，服务器认不认？

★ 已知（文档 mis_2co_matrix.py 做过）：
     mIS=原值      -> 真 DUID
     mIS=自造      -> 全 0（三个随机合法值 + 36 个 X/0/! 全部全 0）

★ 但有一个组合【从没测过】，而这才是问题的关键：
     文档的扫描都是「保持 mIS 为真值、只改别的字段」——
     那样 mIS 单独就能命中记录，别的字段改什么都看不出来
     ⇒ 那个扫描【发现不了「除 mIS 外还有谁在标识设备」】

   ★ 关键变体：
     A. mIS=随机 + ubF(DUID) 保持原值   → 文档说全 0（复核）
     B. mIS=随机 + ubF 清空             → ★ 返回【新 DUID】？【老 DUID】？全 0？
     C. mIS=随机 + ubF 清空 + 2cO 挖空   → ?
     D. mIS=真值 + ubF 清空             → 服务器是否仍认
     E. mIS=随机 + 只保留 6 个必需字段    → 最小体

   ⇒ 若 B 返回【老 DUID】：说明服务器靠别的字段认设备 → 目标不必解 mIS
   ⇒ 若 B 返回【新 DUID】：服务器把它当新设备 → mIS 是唯一标识
   ⇒ 若 B 全 0：body 内字段必须自洽

★ 发送：本机 urllib（已实测 HTTP 200 可用）
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

# mIS 的字符集（从样本统计得出）
ALPHA = ("!#$%&'()*+,-./0123456789:;<=>?@"
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
         "abcdefghijklmnopqrstuvwxyz{|}~")


def load_real():
    """从真实 HTTP 请求里解出 URL / headers / JSON"""
    d = open(SRC, "rb").read()
    i = d.find(b"\r\n\r\n")
    if i < 0:
        raise SystemExit("找不到 header 结束")
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


def rand_mis():
    return "".join(random.choice(ALPHA) for _ in range(36))


def send(url, hdrs, body):
    h = {"Content-Type": hdrs.get("Content-Type", "application/x-www-form-urlencoded"),
         "User-Agent": hdrs.get("User-Agent", ""), "Accept": "*/*",
         "Accept-Encoding": "identity"}
    full = "https://%s%s" % (S.HOST, url)
    try:
        req = urllib.request.Request(full, data=body, method="POST", headers=h)
        raw = urllib.request.urlopen(req, timeout=25, context=CTX).read()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
        except Exception:
            raw = b""
    except Exception as e:
        return None, "network:%s" % str(e)[:60]
    # 用池常量解
    for addr, k in S.KEY_BY_ADDR.items():
        try:
            d = bytes(raw[j] ^ k[j % len(k)] for j in range(len(raw)))
            for nm, fn in (("xor+zlib", lambda x: zlib.decompress(x)), ("xor", lambda x: x)):
                try:
                    dd = fn(d)
                    j = json.loads(dd.decode("utf-8"))
                    return j, "池0x%06X/%s" % (addr, nm)
                except Exception:
                    pass
        except Exception:
            pass
    return None, "raw:%s" % raw[:60].hex()


url, hdrs, base = load_real()

print("=" * 100)
print("  ★ mIS 随机时服务器认不认 —— 真实 mdna 请求矩阵实验")
print("=" * 100)
print("  源: %s" % os.path.basename(SRC))
print("  URL: %s" % url[:110])
print("  真实 body 里的关键字段：")
for k in ("mIS", "2cO", "ubF", "DUv", "AAA", "BBB", "3mS", "75c", "ne8", "w91"):
    if k in base:
        v = str(base[k])
        print("     %-6s = %s" % (k, v[:60]))
print("  字段总数: %d" % len(base))

# ── 构造各变体 ──
R = rand_mis()
variants = []

v = dict(base)
variants.append(("基线：原样重放", v, True))

v = dict(base)
v["mIS"] = R
variants.append(("A: mIS=随机（保留真 ubF）", v, False))

v = dict(base)
v["mIS"] = R
v["ubF"] = ""
variants.append(("B: ★ mIS=随机 + ubF 清空", v, False))

v = dict(base)
v["mIS"] = R
v["ubF"] = ""
if "2cO" in v:
    a = str(v["2cO"]).split(".")
    v["2cO"] = (a[0] + ".0") if len(a) == 2 else v["2cO"]
variants.append(("C: mIS=随机 + ubF 空 + 2cO 子秒挖空", v, False))

v = dict(base)
v["ubF"] = ""
variants.append(("D: mIS=真值 + ubF 清空", v, False))

v = dict(base)
v["mIS"] = R
v["ubF"] = ""
drop = [k for k in v if k not in ("AAA", "BBB", "3mS", "DUv", "2cO", "mIS")]
for k in drop:
    v.pop(k, None)
variants.append(("E: mIS=随机 + 只留 6 个必需字段", v, False))

print("\n" + "=" * 100)
print("  开始发送（每个变体之间睡 2 秒）")
print("=" * 100)

results = []
for name, obj, is_base in variants:
    try:
        body = enc(obj)
    except Exception as e:
        print("\n  %-40s ✗ 编码失败: %s" % (name, str(e)[:60]))
        continue
    j, how = send(url, hdrs, body)
    na = ""
    err = ""
    if isinstance(j, dict):
        na = str(j.get("n_a", ""))
        err = str(j.get("err", ""))
    tag = ""
    if na:
        if na == str(base.get("ubF", "")):
            tag = " ★★★ 与真实 DUID 相同！"
        else:
            tag = " ← 另一个 DUID"
    results.append((name, na, err, how, j))
    print("\n  %s" % name)
    print("    发送 %d 字节  →  %s" % (len(body), how))
    print("    err=%s   n_a=%r%s" % (err, na, tag))
    if isinstance(j, dict):
        print("    完整响应: %s" % json.dumps(j, ensure_ascii=False)[:260])
    time.sleep(2)

print("\n" + "=" * 100)
print("  汇总")
print("=" * 100)
print("  真实 ubF(DUID) = %s" % str(base.get("ubF", "(无)")))
print("  真实 mIS       = %s" % str(base.get("mIS", "(无)")))
print()
print("  %-40s %-28s %s" % ("变体", "n_a (返回的 DUID)", "err"))
for name, na, err, how, j in results:
    mark = ""
    if na and na == str(base.get("ubF", "")):
        mark = "  ★★★ 命中真 DUID"
    print("  %-40s %-28s %s%s" % (name[:40], (na or "(空)")[:28], err, mark))

print("""
  判读：
    · B 返回【真 DUID】 => 服务器靠别的字段认设备 => 目标不必解 mIS ★
    · B 返回【另一个 DUID】=> 服务器当成新设备 => mIS 是唯一标识
    · B 返回空/err 非 0    => body 内字段必须自洽
""")
