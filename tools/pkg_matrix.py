#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pkg_matrix.py -- 包名 vs apiKey 的交叉矩阵，判定服务端到底校验什么
"""
import hashlib
import io
import itertools
import json
import socket
import ssl
import sys
import time
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

HOST = "auni.telecome.cn"
UA = "Dalvik/2.1.0 (Linux; U; Android 8.1; TK Watch Build/OPM2.171019.012)"
XOR_KEY = b"xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}"
TPL = r"C:\Users\Admin\CodeBuddy\c001apk\szlm-re\data\samples\mdna_template.json"
P_LO, P_MOD = 0x20, 95
BASE = json.load(open(TPL, encoding="utf-8"))
AID = "288daec08ec17639"
P = 0

COOLAPK_KEY = "11e7b222083a4b732b4b14811f6fc05995a01415eb"
ZERO_KEY = "0" * 42


def perm(case, n):
    if n <= 1: return [0] * n
    if case == 0:
        h = n // 2; o = []
        if n % 2 == 0:
            for i in range(h): o += [n - 1 - i, n - 1 - i - h]
        else:
            for i in range(h): o += [h - i, 2 * h - i]
            o.append(0)
        return o
    if case == 1:
        o = []
        for i in range(n // 2): o += [n - 1 - i, i]
        if n % 2: o.append(n // 2)
        return o
    if case == 2: return list(range(n - 1, -1, -2)) + list(range(n - 2, -1, -2))
    return list(range(0, n, 2)) + list(range(1, n, 2))


def enc(s, p):
    sh = (p % 100) % 57 + 1; ca = (p // 100) % 4
    x = "".join(chr((ord(c) - P_LO + sh) % P_MOD + P_LO) for c in s)
    pm = perm(ca, len(x))
    return "".join(x[pm[i]] for i in range(len(x)))


drop = 15 - (P % 10)
FOO = enc(AID[:drop] + AID[drop + 1:], P)


def query(pkg, key, drop_key=False):
    o = dict(BASE)
    o["DUv"] = pkg
    o["foO"] = FOO
    o["sfOo"] = "0000000"
    o["2cO"] = "%d.%03d" % (int(time.time()), P % 1000)
    if drop_key:
        o.pop("75c", None)
    else:
        o["75c"] = key
    js = json.dumps(o, ensure_ascii=False, separators=(",", ":")).replace("/", "\\/")
    comp = zlib.compress(js.encode("utf-8"), 6)
    body = bytes(comp[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(comp)))
    pv = hashlib.md5((pkg + ".37be8a1ee106979a").encode()).hexdigest().upper()
    path = "/a/mdna/report?v=8.7&t=m&p=%s&r=5bb7efdd4c794f0e9563317b7802b995&n=0&l=2&h=0" % pv
    ctx = ssl._create_unverified_context()
    s = socket.create_connection((HOST, 443), timeout=20)
    ss = ctx.wrap_socket(s, server_hostname=HOST)
    req = ("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           "User-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
           "Content-Length: %d\r\n\r\n" % (path, HOST, UA, len(body)))
    ss.sendall(req.encode() + body)
    ch = []
    while True:
        d = ss.recv(65536)
        if not d: break
        ch.append(d)
    ss.close()
    _, _, rb = b"".join(ch).partition(b"\r\n\r\n")
    de = bytes(rb[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(rb)))
    try:
        j = json.loads(zlib.decompress(de).decode("utf-8"))
    except Exception:
        try: j = json.loads(de.decode("utf-8", "replace"))
        except Exception: j = {}
    na = j.get("n_a", "")
    if na and set(na) != {"0"}:
        return ("OK", len(na), na)
    elif na:
        return ("ZERO", 0, na)
    return ("EMPTY", 0, "")


def fmt(r):
    st, ln, na = r
    if st == "OK":
        return "★ %d 字符" % ln
    if st == "ZERO":
        return "✗ 全0"
    return "空"


PKGS = [
    ("com.coolapk.market",   "酷安（接入方）"),
    ("com.zhihu.android",    "知乎（接入方）"),
    ("com.tencent.mm",       "微信"),
    ("com.taobao.taobao",    "淘宝"),
    ("com.jingdong.app.mall", "京东"),
    ("com.sina.weibo",       "微博"),
    ("com.ss.android.ugc.aweme", "抖音"),
    ("com.xingin.xhs",       "小红书"),
]

print("=" * 100)
print("  实验设计：固定 AID/P/foO/sfOo/2cO，只交叉变化 (包名 × apiKey)")
print("=" * 100)
print()
print("  AID = %s   P=0   foO = %r" % (AID, FOO))
print("  酷安 apiKey = %s…" % COOLAPK_KEY[:12])
print("  全0 apiKey  = %s…" % ZERO_KEY[:12])
print()

RESULTS = {}

# 第一轮：包名 × 酷安 key
print("-" * 100)
print("  第一轮：DUv 变化，75c 固定为【酷安的 apiKey】")
print("-" * 100)
print()
for pkg, note in PKGS:
    r = query(pkg, COOLAPK_KEY)
    RESULTS[(pkg, "coolapk_key")] = r
    print("  %-30s %-22s → %s" % (pkg, note, fmt(r)))
    time.sleep(2)

print()
print("-" * 100)
print("  第二轮：同样的包名，但把 75c 整个【删掉】")
print("-" * 100)
print()
for pkg, note in PKGS:
    r = query(pkg, "", drop_key=True)
    RESULTS[(pkg, "no_key")] = r
    print("  %-30s %-22s → %s" % (pkg, note, fmt(r)))
    time.sleep(2)

print()
print("=" * 100)
print("  对照表")
print("=" * 100)
print()
print("  %-30s %-22s %-14s %-14s" % ("包名", "说明", "75c=酷安key", "75c=删除"))
print("  " + "-" * 88)
for pkg, note in PKGS:
    a = fmt(RESULTS[(pkg, "coolapk_key")])
    b = fmt(RESULTS[(pkg, "no_key")])
    print("  %-30s %-22s %-14s %-14s" % (pkg, note, a, b))
