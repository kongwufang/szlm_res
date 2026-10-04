#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""szlm_forge.py - 随机化设备指纹实测：服务端是否仍发放新 DUID

基线 = decoded/wire_m58_REQ_9_len1745.bin.json（真机「要 ID」78 字段 JSON）
L0 原样(只刷新请求级字段)  L1 +AYk/P1J  L2 +R37/R3d  L3 +其余设备字段

用法: python szlm_forge.py --all [--seed N] [--dry]
"""
import argparse, base64, gzip, json, os, random, ssl, sys, time, urllib.error, urllib.request, zlib
import szlm_id as S

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
BASE_JSON = os.path.join(HERE, "decoded", "wire_m58_REQ_9_len1745.bin.json")
OUTDIR = os.path.join(HERE, "forge_out")

LEVELS = {0: "原样重放", 1: "L0+AYk/P1J随机", 2: "L1+R37/R3d随机", 3: "L2+其余设备字段随机"}


def hx(rng, n, up=True):
    cs = "0123456789ABCDEF" if up else "0123456789abcdef"
    return "".join(rng.choice(cs) for _ in range(n))


def build_level(base, level, rng):
    o = dict(base)
    now = time.time()
    ms = int(now * 1000)
    o["Qg1"] = ms; o["LMi"] = ms
    o["2cO"] = "%d.%09d" % (int(now), rng.randrange(10 ** 9))
    o["za7"] = "1_%d_" % int(now)
    o["75c"] = hx(rng, 40, False)
    o["K5f"] = hx(rng, 32)
    if level >= 1:
        tri = lambda: "%06X" % rng.randrange(0x100000, 0xFFFFFF)
        o["AYk"] = "%s:%s:%s" % (tri(), tri(), tri()); o["P1J"] = o["AYk"]
    if level >= 2:
        o["R37"], o["R3d"] = rng.choice(S.SOC_MODEL)
    if level >= 3:
        o["LAh"] = hx(rng, 8); o["ne8"] = hx(rng, 32, False)
        o["w91"] = hx(rng, 32); o["gEd"] = hx(rng, 32, False)
        o["6yY"] = hx(rng, 64, False); o["sfOo"] = hx(rng, 7)
        o["fxb"] = rng.randrange(1000, 200000); o["B3k"] = rng.randrange(1000, 2000)
    return o


def try_json(b):
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return None


def decode_resp(resp):
    """返回 [(描述, dict)]，覆盖 raw/b64 × 池异或 × zlib/gzip"""
    hits, stages = [], [("raw", resp)]
    s = resp.strip()
    try:
        stages.append(("b64", base64.b64decode(s + b"=" * (-len(s) % 4))))
    except Exception:
        pass
    keychain = [(None, None)] + [(a, k) for a, k in S.KEY_BY_ADDR.items()]
    for nm, d in stages:
        for addr, key in keychain:
            x = d if key is None else bytes(d[i] ^ key[i % len(key)] for i in range(len(d)))
            tag = nm if key is None else "%s^0x%06x" % (nm, addr)
            for suf, fn in (("", lambda z: z), ("+zlib", zlib.decompress), ("+gzip", gzip.decompress)):
                try:
                    y = fn(x)
                except Exception:
                    continue
                j = try_json(y)
                if j is not None:
                    hits.append((tag + suf, j))
    return hits


def post(url, body, ctype, ua, timeout):
    req = urllib.request.Request(
        "https://%s%s" % (S.HOST, url), data=body, method="POST",
        headers={"Content-Type": ctype, "User-Agent": ua, "Accept": "*/*",
                 "Accept-Encoding": "identity", "Host": S.HOST})
    ctx = ssl._create_unverified_context()
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()
    except Exception as e:
        return None, {}, repr(e).encode()


def summarize(j):
    """从解出的响应 dict 里挑出关心的字段"""
    if not isinstance(j, dict):
        return ""
    keys = ("retCode", "code", "msg", "seq", "n_a", "o_a", "cdd", "ocdd",
            "nctl", "dlab", "token", "data")
    got = {k: j[k] for k in keys if k in j}
    if isinstance(got.get("data"), str) and len(got["data"]) > 80:
        got["data"] = got["data"][:80] + "…(%d)" % len(j["data"])
    if isinstance(got.get("dlab"), str) and len(got["dlab"]) > 60:
        got["dlab"] = got["dlab"][:60] + "…"
    return json.dumps(got, ensure_ascii=False)


def run(level, base, rng, timeout, dry):
    print("=" * 96)
    print("  L%d  %s" % (level, LEVELS[level]))
    print("=" * 96)
    obj = build_level(base, level, rng)
    req, url, body, key = S.build("mdna", obj)
    ctype = S.ENDPOINTS["mdna"][3]
    ua = "Dalvik/2.1.0 (Linux; U; Android 9; %s Build/PPR1.180610.011)" % obj.get("R3d", "XTQ_Watch")
    print("  URL : %s" % url)
    print("  body: %d 字节  池 0x110dc8" % len(body))
    for k in ("AYk", "P1J", "R37", "R3d", "LAh", "ne8", "w91", "gEd", "K5f"):
        print("    %-5s %s" % (k, obj.get(k)))
    if dry:
        print("  (dry-run，未发送)\n")
        return None
    st, hdr, resp = post(url, body, ctype, ua, timeout)
    if st is None:
        print("  ✘ 连接失败: %s\n" % resp.decode("utf-8", "replace"))
        return None
    print("  HTTP %s  响应 %d 字节" % (st, len(resp)))
    hits = decode_resp(resp)
    os.makedirs(OUTDIR, exist_ok=True)
    tag = "%d_%d" % (level, int(time.time()))
    open(os.path.join(OUTDIR, "L%s_resp.bin" % level), "wb").write(resp)
    json.dump(obj, open(os.path.join(OUTDIR, "L%s_req.json" % level), "w", encoding="utf-8"),
              ensure_ascii=False)
    if not hits:
        print("  ✘ 响应未能解出 JSON，原始前 96 字节:\n    %s\n" % resp[:96].hex())
        return None
    for desc, j in hits:
        print("  ✔ [%s] %s" % (desc, summarize(j)))
    print("  (原始响应与请求已存 forge_out/L%s_*)\n" % level)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", type=int, nargs="*", default=None)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    with open(BASE_JSON, "rb") as fp:
        base = json.load(fp)
    print("  基线 body: %s（%d 字段）" % (os.path.basename(BASE_JSON), len(base)))
    print("  目标: POST https://%s/a/mdna/report?v=8.7&t=m …\n" % S.HOST)
    levels = a.level if a.level is not None else ([0, 1, 2, 3] if a.all else [0])
    for lv in levels:
        run(lv, base, rng, a.timeout, a.dry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
