#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""field_stability.py — 找出「跨注册恒定」的字段 = 设备身份候选

★★★ 用户的关键推理：
     pm clear 后本地零状态 → libdu 必须把所有「能标识本机」的信息放进请求
     → 服务端据此认出设备 → 返回同一个 DUID
     ⇒ 请求里必然存在【本地可重算】的设备标识

★ 本脚本：把已解出的 18 个明文按字段做恒定/变化分析
     恒定      -> 设备身份候选 ★
     每次都变  -> 时钟/随机/会话量
"""
import io
import json
import os
import re
import sys
from collections import OrderedDict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DST = r"C:\Users\Admin\CodeBuddy\c001apk\_rev\devout\PLAIN"

samples = []
for f in sorted(os.listdir(DST)):
    if not f.endswith(".json"):
        continue
    try:
        s = open(os.path.join(DST, f), encoding="utf-8").read()
        j = json.loads(s)
    except Exception:
        continue
    samples.append((f, j))

print("=" * 100)
print("  字段稳定性分析  样本 %d 个" % len(samples))
print("=" * 100)

# 收集所有字段
allkeys = OrderedDict()
for name, j in samples:
    for k in j:
        allkeys[k] = allkeys.get(k, 0) + 1

const, varying, partial = [], [], []
for k in allkeys:
    vals = []
    for name, j in samples:
        if k in j:
            vals.append(json.dumps(j[k], ensure_ascii=False, sort_keys=True))
    if not vals:
        continue
    uniq = set(vals)
    if len(vals) < len(samples):
        partial.append((k, len(vals), len(uniq), vals[0][:60]))
    elif len(uniq) == 1:
        const.append((k, len(vals), vals[0][:80]))
    else:
        varying.append((k, len(vals), len(uniq), list(uniq)[:3]))

print("\n" + "=" * 100)
print("  ★★★ 跨样本【恒定】的字段（%d 个）—— 设备身份候选" % len(const))
print("=" * 100)
for k, n, v in const:
    print("    %-8s  %d/%d   %s" % (k, n, len(samples), v))

print("\n" + "=" * 100)
print("  每次【都不同】的字段（%d 个）—— 时钟/随机/会话量" % len(varying))
print("=" * 100)
for k, n, u, ex in varying:
    print("    %-8s  %d/%d  唯一值 %-3d  例: %s" % (k, n, len(samples), u, str(ex)[:100]))

if partial:
    print("\n" + "=" * 100)
    print("  只在部分样本里出现的字段（%d 个）" % len(partial))
    print("=" * 100)
    for k, n, u, ex in partial:
        print("    %-8s  %d/%d  唯一值 %d  %s" % (k, n, len(samples), u, ex))

# ── 重点：36 字符 + 非 base64 字符集的混淆串 ──
print("\n" + "=" * 100)
print("  ★ 36 字符混淆串类字段（与 mIS 同形态）的稳定性")
print("=" * 100)
B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
for name, j in samples[:8]:
    line = []
    for k, v in j.items():
        if isinstance(v, str) and len(v) == 36 and any(c not in B64 for c in v):
            line.append("%s=%s" % (k, v[:34]))
    print("  %-14s %s" % (name, " | ".join(line)[:180]))

# 对每个这样的字段，统计唯一值数
print("\n  每个 36 字符混淆字段的唯一值数：")
cand = {}
for name, j in samples:
    for k, v in j.items():
        if isinstance(v, str) and len(v) == 36 and any(c not in B64 for c in v):
            cand.setdefault(k, set()).add(v)
for k, s in sorted(cand.items(), key=lambda x: len(x[1])):
    tag = "  ★ 恒定！设备身份候选" if len(s) == 1 else ""
    print("    %-8s 唯一值 %-3d / %d%s" % (k, len(s), len(samples), tag))
    if len(s) == 1:
        print("       值 = %s" % list(s)[0])
