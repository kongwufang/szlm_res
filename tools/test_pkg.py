#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_pkg.py -- 测试任意包名能否签发出 DUID"""
import hashlib
import io
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
KEY_COOLAPK = "11e7b222083a4b732b4b14811f6fc05995a01415eb"


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


def query(pkg, key=KEY_COOLAPK, drop_key=False):
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
    path = ("/a/mdna/report?v=8.7&t=m&p=%s"
            "&r=5bb7efdd4c794f0e9563317b7802b995&n=0&l=2&h=0" % pv)
    ctx = ssl._create_unverified_context()
    s = socket.create_connection((HOST, 443), timeout=20)
    ss = ctx.wrap_socket(s, server_hostname=HOST)
    req = ("POST %s HTTP/1.1\r\nHost: %s\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           "User-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\n"
           "Connection: close\r\nContent-Length: %d\r\n\r\n"
           % (path, HOST, UA, len(body)))
    ss.sendall(req.encode() + body)
    ch = []
    while True:
        d = ss.recv(65536)
        if not d: break
        ch.append(d)
    ss.close()
    raw = b"".join(ch)
    head, _, rb = raw.partition(b"\r\n\r\n")
    de = bytes(rb[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(rb)))
    try:
        j = json.loads(zlib.decompress(de).decode("utf-8"))
    except Exception:
        try:
            j = json.loads(de.decode("utf-8", "replace"))
        except Exception:
            j = {}
    return j, len(rb), head.decode("latin-1").split("\r\n")[0]


print("=" * 96)
print("  测试包名：com.github.gavin.smid")
print("=" * 96)
print()
print("  AID = %s   P = %d   foO = %r" % (AID, P, FOO))
print()

CASES = [
    ("com.github.gavin.smid", "酷安 key", False),
    ("com.github.gavin.smid", "无 key",   True),
    ("com.coolapk.market",    "酷安 key", False),
    ("com.github.gavin",      "酷安 key", False),
]

for pkg, klabel, dropk in CASES:
    j, rlen, status = query(pkg, drop_key=dropk)
    na = j.get("n_a", "")
    err = j.get("err", "")
    if na and set(na) != {"0"}:
        res = "★ %d 字符" % len(na)
        detail = na
    elif na:
        res = "✗ 全 0"
        detail = ""
    elif j:
        res = "空 n_a (err=%r)" % err
        detail = ""
    else:
        res = "解析失败"
        detail = ""
    print("  %-26s %-10s  [%s, body %d B]" % (pkg, klabel, status, rlen))
    print("      → %s" % res)
    if detail:
        print("      %s" % detail)
    if j:
        print("      响应: %s" % json.dumps(j, ensure_ascii=False)[:150])
    print()
    time.sleep(3)
