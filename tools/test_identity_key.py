#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_identity_key.py — ★★★ 找出「服务器凭什么认出这台设备」

★★★ 上一实验的结论：
     · 随机化 w91/gEd/6yY/ne8/MAC/机型/内网IP → 服务器【照样返回 D1 真 DUID】
     · 只有动 (sfOo,foO,2cO) 才改变结果 → 且返回【另一个有效 DUID】（不是全 0）
     ⇒ 服务器的设备识别键不在 body 里
     ⇒ 最大嫌疑：【出口 IP】

★ 本实验：
   Ⅰ 重复发送「随机三值」变体 3 次
        · 3 次返回【同一个】新 DUID  → 识别键是 IP（稳定的环境属性）
        · 3 次返回【不同】的 DUID    → 识别键是 (sfOo,foO,2cO) 本身
   Ⅱ 用真实 (sfOo,foO,2cO) 但清空其它一切 → 看是否仍返回真 DUID
   Ⅲ 把 URL 的 h 改成非 0 → 看路径是否切换
"""
import io
import json
import os
import random
import re
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
D1_DUID = "DUaVFlbAMrmH2Z57PEhm_N9EO4RoUdvNstg5"
ALPHA = ("!#$%&'()*+,-./0123456789:;<=>?@"
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
         "abcdefghijklmnopqrstuvwxyz{|}~")


def load_d1():
    d = os.path.join(REV, "devout", "D1C")
    for f in os.listdir(d):
        if not f.startswith("HS2_forced_"):
            continue
        for ln in open(os.path.join(d, f), encoding="utf-8", errors="replace").read().split("\n"):
            if not (ln.startswith("KEEP") or ln.startswith("REC")):
                continue
            h = ln.split("hex=", 1)[-1] if "hex=" in ln else ""
            if not h or len(h) < 200:
                continue
            try:
                b = bytes.fromhex(h)
            except Exception:
                continue
            if b[:4] != b"POST" or b"mdna" not in b[:400]:
                continue
            i = b.find(b"\r\n\r\n")
            if i < 0:
                continue
            head = b[:i].decode("latin1")
            url = head.split("\r\n")[0].split(" ")[1]
            body = b[i + 4:]
            for addr, k in S.KEY_BY_ADDR.items():
                try:
                    x = bytes(body[j] ^ k[j % len(k)] for j in range(len(body)))
                    s = zlib.decompress(x).decode("utf-8")
                    if s.lstrip()[:1] == "{":
                        return url, head, json.loads(s)
                except Exception:
                    pass
    return None, None, None


def enc(obj):
    k = S.KEY_BY_ADDR[POOL]
    z = zlib.compress(S.dump_json(obj))
    return bytes(z[i] ^ k[i % len(k)] for i in range(len(z)))


def send(url, head, obj):
    hdrs = {}
    for ln in head.split("\r\n")[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip()] = v.strip()
    hdrs.pop("Content-Length", None)
    h = {"Content-Type": hdrs.get("Content-Type", "application/x-www-form-urlencoded"),
         "User-Agent": hdrs.get("User-Agent", ""), "Accept": "*/*",
         "Accept-Encoding": "identity"}
    body = enc(obj)
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


url, head, base = load_d1()
print("=" * 104)
print("  ★★★ 找出服务器的设备识别键")
print("=" * 104)
print("  D1 真 DUID = %s" % D1_DUID)
print()


def rmd5():
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def rob(n):
    return "".join(random.choice(ALPHA) for _ in range(n))


def rand_session(v):
    v["sfOo"] = "{:07X}".format(random.randint(0, 0xFFFFFFF))
    v["foO"] = rob(len(v.get("foO", "RP|Q|zQKOJ~I~}Q")))
    v["2cO"] = "%.0f.%09d" % (time.time(), random.randint(1, 999999999))
    return v


print("=" * 104)
print("  实验 Ⅰ：连续 3 次「随机三值」，看返回的 DUID 稳不稳定")
print("=" * 104)
outs = []
for i in range(3):
    v = dict(base)
    v["w91"] = rmd5()
    v["gEd"] = rmd5()
    v["6yY"] = "".join(random.choice("0123456789abcdef") for _ in range(64))
    rand_session(v)
    j = send(url, head, v)
    na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无)"
    outs.append(na)
    print("  第%d次  sfOo=%s foO=%r" % (i + 1, v["sfOo"], v["foO"][:16]))
    print("        → n_a = %s" % na)
    time.sleep(2)

print("\n  ★ 3 次结果：")
uniq = set(outs)
for x in uniq:
    print("     %s   (出现 %d 次)" % (x, outs.count(x)))
if len(uniq) == 1:
    print("\n  ⇒ ★★★ 3 次都返回同一个 DUID")
    print("     ⇒ 识别键是【稳定的环境属性】（最可能是出口 IP）")
    print("     ⇒ 而不是 (sfOo,foO,2cO)")
    print("     ⇒ ★ 这意味着：同一台设备发请求必然拿回同一个 DUID！")
elif len(uniq) == 3:
    print("\n  ⇒ 3 次返回 3 个不同 DUID ⇒ 识别键就是 (sfOo,foO,2cO) 本身")
else:
    print("\n  ⇒ 部分相同，需进一步分析")

print("\n" + "=" * 104)
print("  实验 Ⅱ：真实 (sfOo,foO,2cO) + 其余全随机 → 还认得出 D1 吗")
print("=" * 104)
v = {}
for k, val in base.items():
    v[k] = val
# 只保留三个会话值 + 6 个锚点，其余全随机/清空
KEEP = {"DUv", "3mS", "75c", "2cO", "sfOo", "foO", "AAA", "BBB"}
for k in list(v.keys()):
    if k in KEEP:
        continue
    val = v[k]
    if isinstance(val, str):
        v[k] = rmd5()[:max(1, len(val))]
    elif isinstance(val, int):
        v[k] = 0
    elif isinstance(val, dict):
        v[k] = {}
j = send(url, head, v)
na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无)"
print("  只剩 8 个字段（6 锚点 + AAA/BBB），其余全随机")
print("  → n_a = %s" % na)
print("  判定: %s" % ("★★★ 仍是 D1 真 DUID" if na == D1_DUID else
                      ("→ 另一个 DUID" if na and na != "0" * 36 else "全 0")))

print("\n" + "=" * 104)
print("  实验 Ⅲ：只发【8 个字段】的最小体（三个会话值 + 常量）")
print("=" * 104)
mini = {"DUv": base["DUv"], "3mS": base["3mS"], "75c": base["75c"],
        "2cO": base["2cO"], "sfOo": base["sfOo"], "foO": base["foO"],
        "AAA": "v1.0", "BBB": "v1.0"}
j = send(url, head, mini)
na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无)"
print("  字段: %s" % list(mini.keys()))
print("  → n_a = %s" % na)
print("  判定: %s" % ("★★★ 仍是 D1 真 DUID" if na == D1_DUID else
                      ("→ 另一个 DUID" if na and na != "0" * 36 else "全 0")))

print("\n" + "=" * 104)
print("  实验 Ⅳ：最小体 + 随机三个会话值")
print("=" * 104)
mini2 = dict(mini)
rand_session(mini2)
j = send(url, head, mini2)
na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无)"
print("  sfOo=%s foO=%r" % (mini2["sfOo"], mini2["foO"][:16]))
print("  → n_a = %s" % na)
print("  判定: %s" % ("★★★ 竟是 D1 真 DUID" if na == D1_DUID else
                      ("→ 另一个有效 DUID: %s" % na[:30] if na and na != "0" * 36 else "全 0 / 空")))

print("\n" + "=" * 104)
print("  实验 Ⅴ：最小体 + 随机三值 + 换 URL 的 h")
print("=" * 104)
for hv in ("0", "F7AAD8CD5824603F7F2200731D8C045D"):
    u2 = re.sub(r"h=[^&]*", "h=%s" % hv, url)
    m2 = dict(mini)
    rand_session(m2)
    j = send(u2, head, m2)
    na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无)"
    print("  h=%-34s → n_a = %s" % (hv[:34], na))
    time.sleep(2)
