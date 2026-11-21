#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""whitelist_probe.py -- 批量测包名，摸服务端白名单边界
"""
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
KEY = "11e7b222083a4b732b4b14811f6fc05995a01415eb"


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


def query(pkg):
    o = dict(BASE)
    o["DUv"] = pkg
    o["foO"] = FOO
    o["sfOo"] = "0000000"
    o["2cO"] = "%d.%03d" % (int(time.time()), P % 1000)
    o["75c"] = KEY
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
    _, _, rb = b"".join(ch).partition(b"\r\n\r\n")
    de = bytes(rb[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(rb)))
    try:
        j = json.loads(zlib.decompress(de).decode("utf-8"))
    except Exception:
        try:
            j = json.loads(de.decode("utf-8", "replace"))
        except Exception:
            j = {}
    return j.get("n_a", "")


PKGS = [
    # 数字联盟相关项目 / 学习项目
    ("com.github.gavin.smid",        "gavin 的 smid 项目"),
    ("com.github.tangbin.smid",      "tangbin 的 smid_project"),
    ("top.wrj.smid",                 "猜测"),
    # 已知成功
    ("com.coolapk.market",           "酷安"),
    ("com.zhihu.android",            "知乎"),
    ("com.sina.weibo",               "微博"),
    ("com.ss.android.ugc.aweme",     "抖音"),
    ("com.xingin.xhs",               "小红书"),
    # 已知失败
    ("com.tencent.mm",               "微信"),
    ("com.taobao.taobao",            "淘宝"),
    ("com.jingdong.app.mall",        "京东"),
    # 新探测
    ("com.eg.android.AlipayGphone",  "支付宝"),
    ("com.baidu.BaiduMap",           "百度地图"),
    ("com.autonavi.minimap",         "高德地图"),
    ("com.ctrip.hotel",              "携程"),
    ("com.dianping.v1",              "大众点评"),
    ("com.hupu.games",               "虎扑"),
    ("com.netease.cloudmusic",       "网易云音乐"),
    ("com.qiyi.video",               "爱奇艺"),
    ("tv.danmaku.bili",              "B站"),
    ("com.smile.gifmaker",           "快手"),
    ("com.UCMobile",                 "UC"),
    ("com.baidu.searchbox",          "百度"),
    ("com.sohu.newsclient",          "搜狐新闻"),
]

print("=" * 96)
print("  包名白名单探测（固定 AID / P=0 / foO / 75c）")
print("=" * 96)
print()

ok = []
bad = []
for pkg, note in PKGS:
    na = query(pkg)
    if na and set(na) != {"0"}:
        ok.append((pkg, note, len(na)))
        print("  ★ %-32s %-22s %d 字符" % (pkg, note, len(na)))
    else:
        bad.append((pkg, note))
        print("  ✗ %-32s %-22s 全0" % (pkg, note))
    time.sleep(2)

print()
print("=" * 96)
print("  汇总")
print("=" * 96)
print()
print("  通过 %d 个：%s" % (len(ok), ", ".join(p for p, n, l in ok)))
print()
print("  拒绝 %d 个：%s" % (len(bad), ", ".join(p for p, n in bad)))
print()
print("  通过的 ID 长度分布：")
from collections import Counter
c = Counter(l for p, n, l in ok)
for ln, cnt in sorted(c.items()):
    print("     %d 字符: %d 个  (%s)" % (ln, cnt,
          ", ".join(p for p, n, l in ok if l == ln)))
