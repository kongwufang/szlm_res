#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dex_packages.py -- 统计各 dex 里的包分布，看是什么占了空间
"""
import io
import os
import struct
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def uleb(b, i):
    r = 0; sh = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << sh
        if not (x & 0x80):
            break
        sh += 7
    return r, i


def stats(path):
    d = open(path, "rb").read()
    if d[:4] != b"dex\n":
        return None
    (ss, so, ts, to, ps, po, fs, fo, ms, mo, cs, co) = struct.unpack_from("<12I", d, 0x38)
    strs = []
    for k in range(ss):
        off = struct.unpack_from("<I", d, so + 4 * k)[0]
        ln, p = uleb(d, off)
        strs.append(d[p:p + ln].decode("utf-8", "replace"))
    types = []
    for k in range(ts):
        idx = struct.unpack_from("<I", d, to + 4 * k)[0]
        types.append(strs[idx] if idx < len(strs) else "")
    cls = []
    for k in range(cs):
        ci = struct.unpack_from("<I", d, co + 32 * k)[0]
        cls.append(types[ci] if ci < len(types) else "")
    return {
        "size": len(d),
        "n_strings": ss,
        "n_types": ts,
        "n_methods": ms,
        "n_classes": cs,
        "classes": cls,
    }


def top_pkg(classes, depth=3):
    c = Counter()
    for n in classes:
        full = n.lstrip("L").rstrip(";")
        parts = full.split("/")
        if len(parts) >= depth:
            key = "/".join(parts[:depth])
        elif len(parts) >= 2:
            key = "/".join(parts[:2])
        else:
            key = parts[0] if parts else "?"
        c[key] += 1
    return c


FILES = [
    ("classes.dex",  r"C:\Users\Admin\CodeBuddy\c001apk\_rev\szlm_dex\shuzilm01.dex"),
    ("classes2.dex", r"C:\Users\Admin\CodeBuddy\c001apk\_rev\szlm_dex\shuzilm10.dex"),
    ("classes3.dex", r"C:\Users\Admin\CodeBuddy\c001apk\_rev\szlm_dex\shuzilm09.dex"),
]

for name, p in FILES:
    s = stats(p)
    if not s:
        continue
    print("=" * 92)
    print("  %s   ← %s" % (name, os.path.basename(p)))
    print("=" * 92)
    print("  大小 %.2f MB   类 %d   方法 %d   字符串 %d"
          % (s["size"] / 1048576.0, s["n_classes"], s["n_methods"], s["n_strings"]))
    print()
    c = top_pkg(s["classes"])
    print("  包分布（前 18 名）:")
    for pkg, n in c.most_common(18):
        bar = "#" * min(40, int(40.0 * n / c.most_common(1)[0][1]))
        print("     %-44s %6d  %s" % (pkg, n, bar))
    shuzilm = sum(v for k, v in c.items() if k.startswith("cn/shuzilm"))
    print()
    print("  其中 cn/shuzilm 相关类: %d 个  (%.2f%%)"
          % (shuzilm, 100.0 * shuzilm / max(1, s["n_classes"])))
    print()
