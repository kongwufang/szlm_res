#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extract_szlm_har.py — 从原始 HAR 正确提取 szlm 请求/响应（含 base64 编码还原）

★★★ 为什么需要重做：
     har_out/*.json 是「HAR 响应体 → Python str → 写文件」的产物，
     二进制内容已在文本往返中被破坏。
     正确做法：读 HAR 的 content.encoding / content.text，
     若 encoding == "base64" 则先 base64 解码得到原始字节。

★★★ 同时提取：
     · 完整 URL（含全部参数，特别是 h 的完整 32 位值）
     · 请求头
     · 请求体原始字节 + hex
     · 响应体原始字节 + hex
"""
import base64
import io
import json
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DL = r"C:\Users\Admin\Downloads"
REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
OUT = os.path.join(REV, "devout")
os.makedirs(OUT, exist_ok=True)

# 先找出所有含 auni.telecome.cn 的 HAR
targets = []
for f in os.listdir(DL):
    if not f.endswith(".har"):
        continue
    p = os.path.join(DL, f)
    try:
        if os.path.getsize(p) > 40 * 1024 * 1024:
            continue
        t = open(p, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    if "telecome" in t.lower():
        targets.append(p)

print("=" * 100)
print("  含 auni.telecome.cn 的 HAR：%d 个" % len(targets))
print("=" * 100)
for p in targets:
    print("  %s (%d 字节)" % (os.path.basename(p), os.path.getsize(p)))

allrecs = []
for p in targets:
    try:
        har = json.load(open(p, encoding="utf-8", errors="replace"))
    except Exception as e:
        print("  ✗ 解析失败 %s: %s" % (os.path.basename(p), e))
        continue
    for i, e in enumerate(har.get("log", {}).get("entries", [])):
        req = e.get("request", {})
        res = e.get("response", {})
        url = req.get("url", "")
        if "telecome" not in url.lower():
            continue
        pd = req.get("postData") or {}
        if not isinstance(pd, dict): pd = {}
        body_text = pd.get("text", "") or ""
        # 请求体：可能是文本（base64 字符串）或需要编码还原
        req_bytes = None
        enc = pd.get("encoding")
        if enc == "base64":
            try:
                req_bytes = base64.b64decode(body_text)
            except Exception:
                pass
        else:
            req_bytes = body_text.encode("latin1", "replace") if body_text else b""

        rc = res.get("content") or {}
        if not isinstance(rc, dict): rc = {}
        rtext = rc.get("text", "") or ""
        renc = rc.get("encoding")
        resp_bytes = None
        if renc == "base64":
            try:
                resp_bytes = base64.b64decode(rtext)
            except Exception:
                pass
        if resp_bytes is None:
            resp_bytes = rtext.encode("latin1", "replace") if rtext else b""

        allrecs.append({
            "src": os.path.basename(p), "idx": i,
            "method": req.get("method"), "url": url,
            "req_mime": pd.get("mimeType"),
            "req_bytes": req_bytes, "req_text": body_text,
            "status": res.get("status"),
            "resp_mime": rc.get("mimeType"),
            "resp_bytes": resp_bytes, "resp_text": rtext,
            "req_headers": req.get("headers", []),
            "res_headers": res.get("headers", []),
            "renc": renc, "peenc": enc,
        })

print("\n  找到 szlm 条目 %d 个" % len(allrecs))

# ── 打印 ──
for r in allrecs:
    print("\n" + "=" * 100)
    print("  [%s #%d] %s %s" % (r["src"], r["idx"], r["method"], r["url"]))
    print("=" * 100)
    print("  状态: %s   req_mime=%s   resp_mime=%s (enc=%s)   req_enc=%s"
          % (r["status"], r["req_mime"], r["resp_mime"], r["renc"], r["peenc"]))
    for h in r["req_headers"]:
        if h.get("name", "").lower() in ("user-agent", "content-type", "host", "content-length",
                                         "accept-encoding", "connection", "cookie", "x-app-token"):
            print("   H %-18s %s" % (h["name"], str(h.get("value"))[:110]))
    b = r["req_bytes"] or b""
    print("  REQ body %d 字节" % len(b))
    if b:
        print("     hex : %s" % b.hex()[:400])
        print("     asc : %r" % b[:200])
    rb = r["resp_bytes"] or b""
    print("  RESP body %d 字节" % len(rb))
    if rb:
        print("     hex : %s" % rb.hex()[:400])
        print("     asc : %r" % rb[:200])

# ── 存原始字节 ──
import traceback
for k, r in enumerate(allrecs):
    d = os.path.join(OUT, "SZLMREC_%02d" % k)
    os.makedirs(d, exist_ok=True)
    if r["req_bytes"]:
        open(os.path.join(d, "req.bin"), "wb").write(r["req_bytes"])
    if r["resp_bytes"]:
        open(os.path.join(d, "resp.bin"), "wb").write(r["resp_bytes"])
    open(os.path.join(d, "meta.txt"), "w", encoding="utf-8").write(
        "%s\n%s\n" % (r["method"], r["url"]))
print("\n  原始字节已存到 %s" % OUT)
