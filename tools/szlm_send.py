#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""szlm_send.py — 用 szlm_id.py 构造真实请求并发往云端，观察服务端响应。

用法：
    python szlm_send.py                 # mdna「要 ID」，先 https 再 http
    python szlm_send.py --ep adt        # 换端点
    python szlm_send.py --scheme https  # 只试 https
    python szlm_send.py --random        # 随机指纹
    python szlm_send.py --duid <DUID>   # 带已有 DUID（h 非 0）
"""
import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

import szlm_id as S

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HOST = S.HOST


def pick_json(resp):
    """找出能把响应解成 JSON 的池常量。"""
    import zlib
    for addr, key in S.KEY_BY_ADDR.items():
        for name, fn in (("xor", lambda x: x), ("xor+zlib", zlib.decompress)):
            try:
                x = bytes(resp[i] ^ key[i % len(key)] for i in range(len(resp)))
                data = fn(x)
                j = json.loads(data.decode("utf-8"))
                return addr, name, j
            except Exception:
                continue
    return None, None, None


def analyze(resp, quiet=False):
    """对响应体做全面尝试：明文 / zlib / gzip / 各池异或+zlib。"""
    import base64
    import gzip
    import zlib
    addr, how, j = pick_json(resp)
    if j is not None:
        print("    ★ 响应解出（池 0x%06x，%s）：" % (addr, how))
        print("      " + json.dumps(j, ensure_ascii=False))
        if j.get("dlab"):
            raw = base64.b64decode(j["dlab"])
            print("      dlab: base64=%s" % j["dlab"])
            print("            raw(%d)=%s" % (len(raw), raw.hex()))
            print("            hexstr=%s" % raw.hex().upper())
    elif quiet:
        print("    (未解出 JSON) hex=%s…" % resp[:48].hex())
    if quiet:
        return
    print("    原始 hex (%d 字节):" % len(resp))
    for i in range(0, len(resp), 32):
        print("      %04x  %s" % (i, resp[i:i + 32].hex()))
    print("    ── 解码尝试 ──")
    cands = [("明文", resp)]
    for name, fn in (("zlib", zlib.decompress), ("gzip", gzip.decompress)):
        try:
            cands.append((name, fn(resp)))
        except Exception:
            pass
    for addr, key in S.KEY_BY_ADDR.items():
        x = bytes(resp[i] ^ key[i % len(key)] for i in range(len(resp)))
        cands.append(("xor 0x%06x" % addr, x))
        for name, fn in (("zlib", zlib.decompress), ("gzip", gzip.decompress)):
            try:
                cands.append(("xor 0x%06x + %s" % (addr, name), fn(x)))
            except Exception:
                pass
    hit = False
    for name, data in cands:
        if not data:
            continue
        try:
            txt = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in txt if c.isprintable() or c in "\r\n\t")
        if printable / max(len(txt), 1) < 0.75:
            continue
        hit = True
        print("    ✔ [%s] %d 字节可读:" % (name, len(data)))
        print("        " + txt[:600].replace("\n", "\n        "))
        try:
            j = json.loads(txt)
            print("      ── JSON 解析成功 ──")
            print("        " + json.dumps(j, ensure_ascii=False)[:800])
        except Exception:
            pass
    if not hit:
        print("    ✘ 全部候选均不可读")


def post(scheme, url, body, ctype, ua, timeout):
    full = "%s://%s%s" % (scheme, HOST, url)
    req = urllib.request.Request(
        full, data=body, method="POST",
        headers={
            "Content-Type": ctype,
            "User-Agent": ua,
            "Accept": "*/*",
            "Accept-Encoding": "identity",   # 不压缩，省得再解一层
            "Host": HOST,                    # 让 SNI/Host 都一致
        })
    ctx = ssl._create_unverified_context()
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()
    except Exception as e:
        return None, {}, repr(e).encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ep", default="mdna", choices=sorted(S.ENDPOINTS))
    ap.add_argument("--scheme", default="both", choices=["http", "https", "both"])
    ap.add_argument("--random", action="store_true")
    ap.add_argument("--duid", default="")
    ap.add_argument("--pkg", default="com.coolapk.market")
    ap.add_argument("--quiet", action="store_true", help="只打印解出的 JSON，不转储 hex")
    ap.add_argument("--json", default="", help="用 szlm_peek.py --save 导出的真实 JSON 作为 body")
    ap.add_argument("--timeout", type=float, default=15.0)
    a = ap.parse_args()

    if a.json:
        with open(a.json, "rb") as fp:
            obj = json.load(fp)
        for k in ("Qg1", "LMi"):
            if k in obj:
                obj[k] = int(time.time() * 1000)
        print("  载入真实 body: %s（%d 字段）" % (a.json, len(obj)))
    elif a.ep == "mdna":
        obj = S.build_mdna_json(a.pkg)
        if a.random:
            import random
            rng = random.Random()
            obj["90P"] = "%02X" % rng.randrange(0x10, 0x7F)
            obj["R5a"] = str(rng.randrange(40000, 50000))
            obj["R63"] = rng.choice(["running", "idle"])
    elif a.ep in ("adt", "daa"):
        obj = dict(S.DEV_TEMPLATE)
        obj["DUv"] = a.pkg
        if a.random:
            import random
            obj = S.randomize(obj, random.Random())
    else:
        obj = S.build_mdna_json(a.pkg)

    pool = S.ENDPOINTS[a.ep][4]
    if pool is None:
        print("  ! 端点 %s 的池常量未确认，暂用 0x109cf0 试发" % a.ep)
        req, url, body, key = S.build(a.ep, obj, pkg=a.pkg, duid=a.duid,
                                      key=S.KEY_BY_ADDR[0x109CF0])
    else:
        req, url, body, key = S.build(a.ep, obj, pkg=a.pkg, duid=a.duid)
    ctype = S.ENDPOINTS[a.ep][3]
    ua = "Dalvik/2.1.0 (Linux; U; Android 9; %s Build/PPR1.180610.011)" % obj.get("R3d", "XTQ_Watch")

    print("=" * 94)
    print("  发送 %s  →  %s" % (a.ep, HOST))
    print("=" * 94)
    print("  URL  : %s" % url)
    print("  CT   : %s" % ctype)
    print("  body : %d 字节  %s…" % (len(body), body[:32].hex()))
    print("  池   : 0x%06x 周期 %d" % (S.ENDPOINTS[a.ep][4] or 0, len(key)))
    print()

    schemes = ["https", "http"] if a.scheme == "both" else [a.scheme]
    for sc in schemes:
        print("-" * 94)
        print("  ▶ %s://%s%s" % (sc, HOST, url))
        st, hdr, resp = post(sc, url, body, ctype, ua, a.timeout)
        if st is None:
            print("    连接失败: %s" % resp.decode("utf-8", "replace"))
            continue
        print("    HTTP %s" % st)
        for k in ("Content-Type", "Content-Length", "Server", "Location", "Date"):
            if k in hdr:
                print("    %-15s: %s" % (k, hdr[k]))
        if not resp:
            print("    [空响应]")
            continue
        print("    响应 %d 字节" % len(resp))
        analyze(resp, a.quiet)
        try:
            import os
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "szlm_last_%s_%s.bin" % (a.ep, sc))
            with open(p, "wb") as fp:
                fp.write(resp)
            print("    已存 %s" % os.path.basename(p))
        except Exception as e:
            print("    存盘失败: %r" % e)
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
