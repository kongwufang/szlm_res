#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""random_fp_test.py — ★★★ 用户提出的关键实验：指纹哈希换成随机值，服务器认不认

★★★ 实验逻辑（用户提出）：
     如果 w91 / gEd / 6yY 换成随机值、服务器【仍然认出设备】→ 它不靠这三个认设备
     如果换成随机值【被拒/变成新设备】                      → 这三个参与识别，
                                                              且可能存在签名校验机制

★ 素材：D1 的真实 mdna 请求（h=0 首次注册），完整 79 字段 body，已解出
   URL: /a/mdna/report?v=8.7&t=m&p=…&r=…&n=0&l=2&h=0
   编码: zlib(JSON) XOR 池常量 0x110DC8

★ 变体矩阵：
   基线            原样重放                     → 期望 n_a = D1 真 DUID
   A  w91 换随机
   B  gEd 换随机
   C  6yY 换随机
   D  三个全换随机
   E  三个全换随机 + sfOo/foO/2cO 也换随机
   F  三个全换随机 + MAC 也换随机
   G  只保留 6 个锚点、其余全随机（对照）
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
    """从 D1C 的 dump 里取出真实的 mdna 请求"""
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


def send(url, head):
    hdrs = {}
    for ln in head.split("\r\n")[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip()] = v.strip()
    hdrs.pop("Content-Length", None)
    h = {"Content-Type": hdrs.get("Content-Type", "application/x-www-form-urlencoded"),
         "User-Agent": hdrs.get("User-Agent", ""), "Accept": "*/*",
         "Accept-Encoding": "identity"}
    body = enc(HEAD_BODY[0])
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
        return None, "网络错误:%s" % str(e)[:50]
    for addr, k in S.KEY_BY_ADDR.items():
        try:
            d = bytes(raw[j] ^ k[j % len(k)] for j in range(len(raw)))
            for fn in (lambda x: zlib.decompress(x), lambda x: x):
                try:
                    return json.loads(fn(d).decode("utf-8")), "池0x%06X" % addr
                except Exception:
                    pass
        except Exception:
            pass
    return None, "raw:%s" % raw[:48].hex()


url, head, base = load_d1()
if base is None:
    print("未找到 D1 的 mdna 样本")
    sys.exit(1)

HEAD_BODY = [base]

print("=" * 104)
print("  ★★★ 指纹哈希换随机 —— 服务器认不认？（用户的实验设计）")
print("=" * 104)
print("  源: D1 真实 mdna（h=0）")
print("  URL: %s" % url[:120])
print("  D1 真 DUID = %s" % D1_DUID)
print("  w91 = %s" % base.get("w91"))
print("  gEd = %s" % base.get("gEd"))
print("  6yY = %s" % base.get("6yY"))
print("  ne8 = %s   ← 跨设备常量" % base.get("ne8"))
print("  字段数 = %d" % len(base))


def rmd5():
    return "".join(random.choice("0123456789abcdefABCDEF") for _ in range(32))


def rsha256():
    return "".join(random.choice("0123456789abcdef") for _ in range(64))


def rob(size):
    return "".join(random.choice(ALPHA) for _ in range(size))


VARIANTS = []

v = dict(base)
VARIANTS.append(("基线：原样重放", v, "期望 = D1 真 DUID"))

v = dict(base)
v["w91"] = rmd5()
VARIANTS.append(("A: w91 → 随机 MD5", v, ""))

v = dict(base)
v["gEd"] = rmd5()
VARIANTS.append(("B: gEd → 随机 MD5", v, ""))

v = dict(base)
v["6yY"] = rsha256()
VARIANTS.append(("C: 6yY → 随机 SHA256", v, ""))

v = dict(base)
v["w91"] = rmd5()
v["gEd"] = rmd5()
v["6yY"] = rsha256()
VARIANTS.append(("D: 三个指纹全换随机", v, "★ 最关键"))

v = dict(base)
v["w91"] = rmd5()
v["gEd"] = rmd5()
v["6yY"] = rsha256()
v["ne8"] = rmd5()
VARIANTS.append(("E: 四个哈希全换随机（含 ne8）", v, ""))

v = dict(base)
v["w91"] = rmd5()
v["gEd"] = rmd5()
v["6yY"] = rsha256()
v["sfOo"] = "{:07X}".format(random.randint(0, 0xFFFFFFF))
v["foO"] = rob(len(base.get("foO", "RP|Q|zQKOJ~I~}Q")))
v["2cO"] = "%.0f.%09d" % (time.time(), random.randint(1, 999999999))
VARIANTS.append(("F: 三个指纹 + 三个会话值 全换随机", v, ""))

v = dict(base)
v["AYk"] = "AA:BB:CC:DD:EE:FF"
v["P1J"] = "AA:BB:CC:DD:EE:FF"
v["R3d"] = "FakeModel"
v["R37"] = "FakeBrand"
v["wSK"] = "192.168.1.1"
VARIANTS.append(("G: 设备属性(含MAC)全换", v, ""))

v = dict(base)
for k in ("w91", "gEd", "6yY", "ne8", "sfOo", "foO", "2cO", "AYk", "P1J", "R3d", "R37", "wSK", "K5f"):
    if k in v and isinstance(v[k], str):
        v[k] = "0" * len(v[k])
VARIANTS.append(("H: 全部换全 0", v, ""))

print("\n" + "=" * 104)
print("  开始发送")
print("=" * 104)

results = []
for name, obj, note in VARIANTS:
    HEAD_BODY[0] = obj
    j, how = send(url, head)
    na = str(j.get("n_a", "")) if isinstance(j, dict) else "(无响应)"
    err = str(j.get("err", "")) if isinstance(j, dict) else ""
    if na == D1_DUID:
        vd = "★★★ 真 DUID（服务器认出了 D1）"
    elif na in ("0" * 36, ""):
        vd = "全 0 / 空（被拒或未识别）"
    elif na:
        vd = "→ 另一个 DUID: %s" % na[:30]
    else:
        vd = "(无 n_a)"
    results.append((name, na, err, vd, note))
    print("\n  %s%s" % (name, ("   " + note) if note else ""))
    print("     → %s" % how)
    print("     err=%s  n_a=%r" % (err, na))
    print("     判定: %s" % vd)
    time.sleep(2)

print("\n" + "=" * 104)
print("  汇总")
print("=" * 104)
print("  %-42s %-38s %s" % ("变体", "n_a", "判定"))
for name, na, err, vd, note in results:
    print("  %-42s %-38s %s" % (name[:42], (na or "(空)")[:38], vd))

print("""
  判读：
    · D（三个指纹全随机）仍返回真 DUID
        ⇒ 服务器【不靠这三个】认设备 ⇒ 需要另找真正的识别键
        ⇒ 也说明【没有签名机制】（否则随机值会被拒）
    · D 返回全 0 / 空
        ⇒ 服务器校验它们 ⇒ 存在校验（可能是签名，也可能是语义检查）
    · D 返回另一个 DUID
        ⇒ 服务器当新设备处理 ⇒ 说明识别键在别处
""")
