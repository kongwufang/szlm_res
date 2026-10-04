import io
import json
import os
import re
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
sys.path.insert(0, REV)
import szlm_id as S  # noqa: E402

DST = os.path.join(REV, "devout", "D1C")

body_hex = ("00ecea3f8d48fa30252327e9a489732ef8a5c671e15d5f7489d61446e30158b2"
            "84671c75b57901e4834c42f3693c4a9928d0de47eff642ac6e8dc502a1df1e40"
            "b8d648aed3d92c6e1ae0fbcef30b5212")

# 从抓到的文件里重新取完整 body
txt = ""
for f in os.listdir(DST):
    if f.startswith("HS2_forced_"):
        txt += open(os.path.join(DST, f), encoding="utf-8", errors="replace").read()

bodies = []
for ln in txt.split("\n"):
    m = re.match(r"(REC|KEEP) p(\d+) t=(\d+) (\S+) (\S+) n=(\d+) hex=(.*)$", ln)
    if not m:
        continue
    h = m.group(7)
    if not h:
        continue
    try:
        b = bytes.fromhex(h)
    except Exception:
        continue
    if b[:4] == b"POST" and b"mdna" in b[:400]:
        i = b.find(b"\r\n\r\n")
        if i > 0:
            bodies.append((m.group(3), b[i + 4:]))

uniq = {}
for t, b in bodies:
    uniq[b] = t

print("=" * 100)
print("  ★★★ 解密 mdna body（%d 个不同的）" % len(uniq))
print("=" * 100)

for body, t in uniq.items():
    print("\n  t=%s  长度 %d" % (t, len(body)))
    print("  前 32 字节: %s" % body[:32].hex())

    got = None
    for addr, k in S.KEY_BY_ADDR.items():
        try:
            d = bytes(body[j] ^ k[j % len(k)] for j in range(len(body)))
        except Exception:
            continue
        for nm, fn in (("zlib", lambda x: zlib.decompress(x)),
                       ("raw", lambda x: zlib.decompress(x, -15)),
                       ("gzip", lambda x: __import__("gzip").decompress(x)),
                       ("none", lambda x: x)):
            try:
                s = fn(d).decode("utf-8")
                if s.lstrip()[:1] in ("{", "["):
                    got = ("池0x%06X + %s" % (addr, nm), s)
                    break
            except Exception:
                pass
        if got:
            break

    if got:
        print("\n  ★★★★★★ 解密成功 [%s]" % got[0])
        print("  " + "-" * 96)
        print("  %s" % got[1])
        print("  " + "-" * 96)
        with open(os.path.join(DST, "MDNA_%s.json" % t), "w", encoding="utf-8") as fh:
            fh.write(got[1])

        # 关键字段对照
        OLD = {"sfOo": "4A213D3", "foO": "W***]TZTYX**X(W",
               "2cO": "1790969185.997397935",
               "mIS": "W(W(\\&&&T+\\Z*)W&\\QT*ZTX'Q\\TQ*X')&&Q)"}
        print("\n  ★★★ 关键字段（与 D2 样本对照）")
        print("  %-8s %-42s %s" % ("字段", "D1 的值", "vs D2"))
        for key in ("sfOo", "foO", "2cO", "mIS", "ubF", "DUv", "3mS", "AAA", "BBB",
                    "R3d", "R37", "AYk", "UOv", "75c"):
            mm = re.search(r'"%s"\s*:\s*"([^"]*)"' % key, got[1])
            if mm:
                v = mm.group(1)
                old = OLD.get(key)
                mark = ""
                if old:
                    mark = "★ 相同" if v == old else "✗ 不同"
                print("  %-8s %-42s %s" % (key, v[:42], mark))
        print()
        try:
            j = json.loads(got[1])
            print("  字段总数: %d" % len(j))
        except Exception:
            pass
        break
    else:
        print("\n  ✗ 未解密")
        for addr, k in list(S.KEY_BY_ADDR.items()):
            d = bytes(body[j] ^ k[j % len(k)] for j in range(min(len(body), 16)))
            print("     池0x%06X -> %s" % (addr, d.hex()))
