#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hunt_fp_hashes.py — 追查 w91 / gEd / 6yY 三个设备指纹哈希的输入

★★★ 已确证：
     w91 / gEd / 6yY  = 跨注册【恒定】+ 跨设备【不同】 ⇒ 真正的设备身份
     ne8              = 跨设备也相同                  ⇒ 常量，非指纹

★ 目标：找出这三个哈希的输入是什么设备属性
★ 方法：拿 D1 已知的设备属性 + 从 mdna body 里解出的字段值，
       穷举各种组合/编码/哈希，看能否命中原值
"""
import hashlib
import io
import itertools
import json
import os
import re
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
sys.path.insert(0, REV)
import szlm_id as S  # noqa: E402

# ── 载入 D1 两次注册的 body ──
def load(dirname):
    out = {}
    d = os.path.join(REV, "devout", dirname)
    if not os.path.isdir(d):
        return out
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
            body = b[i + 4:]
            for addr, k in S.KEY_BY_ADDR.items():
                try:
                    x = bytes(body[j] ^ k[j % len(k)] for j in range(len(body)))
                    s = zlib.decompress(x).decode("utf-8")
                    if s.lstrip()[:1] == "{":
                        out[ln.split(" t=")[1].split(" ")[0] if " t=" in ln else "?"] = s
                        break
                except Exception:
                    pass
    return out


R1 = load("D1C")
R2 = load("D1H")
if not R1 or not R2:
    print("样本不足")
    sys.exit(0)

t1 = list(R1.keys())[0]
j = json.loads(R1[t1])

W91 = j.get("w91")
GED = j.get("gEd")
S6Y = j.get("6yY")
NE8 = j.get("ne8")

print("=" * 100)
print("  追查三个设备指纹哈希")
print("=" * 100)
print("  w91 = %s   (MD5)" % W91)
print("  gEd = %s   (MD5)" % GED)
print("  6yY = %s   (SHA256)" % S6Y)
print("  ne8 = %s   ← 常量，不是指纹" % NE8)
print()

# ── 候选输入素材（D1 的已知设备属性） ──
CAND = {
    "DUv(pkg)": "com.coolapk.market",
    "pkg_no_dot": "comcoolapkmarket",
    "R3d/R37(model)": "TK Watch",
    "model_": "TK_Watch",
    "model_nospace": "TKWatch",
    "model_lower": "tk watch",
    "MAC(AYk)": j.get("AYk", ""),
    "MAC_nocolon": (j.get("AYk", "").replace(":", "")),
    "SAN": str(j.get("SAN", "")),
    "R41": str(j.get("R41", "")),
    "EV2": str(j.get("EV2", "")),
    "Zrs": str(j.get("Zrs", "")),
    "wSK(内网IP)": str(j.get("wSK", "")),
    "px(未知)": "21503",
    "Q23": str(j.get("Q23", "")),
    "YWu": str(j.get("YWu", "")),
    "3mS": str(j.get("3mS", "")),
    "75c": str(j.get("75c", "")),
    "GVp": str(j.get("GVp", "")),
    "h6Z": str(j.get("h6Z", "")),
    "fPV": str(j.get("fPV", "")),
    "zpA": str(j.get("zpA", "")),
    "D32": str(j.get("D32", "")),
    "wlM": str(j.get("wlM", "")),
    "R63": str(j.get("R63", "")),
    "Ra": str(j.get("Ra", "")),
    "Qg1": str(j.get("Qg1", "")),
    "boottime": "19701",
    "LCC": "1",
}

print("  候选输入 %d 个" % len(CAND))

HASHES = {
    "md5": lambda b: hashlib.md5(b).hexdigest(),
    "sha1": lambda b: hashlib.sha1(b).hexdigest(),
    "sha256": lambda b: hashlib.sha256(b).hexdigest(),
}

TARGETS = {"w91": W91, "gEd": GED, "6yY": S6Y}


def check(label, data):
    for hn, hf in HASHES.items():
        try:
            h = hf(data)
        except Exception:
            continue
        for tn, tv in TARGETS.items():
            if not tv:
                continue
            if h == tv or h.upper() == tv.upper():
                print("  ★★★★★ 命中！%s = %s(%s)" % (tn, hn, label))
                return (tn, hn, label)
    return None


hits = []

# ① 单值
for k, v in CAND.items():
    for enc in (lambda s: s.encode(), lambda s: s.upper().encode(),
                lambda s: s.lower().encode(), lambda s: s.encode() + b"\n"):
        try:
            r = check("单值[%s]" % k, enc(v))
            if r:
                hits.append(r)
        except Exception:
            pass

# ② 两值/三值组合
if not hits:
    names = list(CAND.keys())
    SEPS = [b"", b".", b",", b"|", b"-", b"_", b":", b";", b"&"]
    n = 0
    for cnt in (2, 3):
        for combo in itertools.combinations(names, cnt):
            for sep in SEPS:
                for order in (combo, tuple(reversed(combo))):
                    s = sep.join(CAND[x].encode() for x in order)
                    n += 1
                    r = check("组合[%s]" % "+".join(order), s)
                    if r:
                        hits.append(r)
                        print("     %s" % (s[:90],))
    print("\n  组合穷举完成，试了 %d 次" % n)

print("\n" + "=" * 100)
print("  结果")
print("=" * 100)
if hits:
    for tn, hn, label in hits:
        print("  ★ %s = %s(%s)" % (tn, hn, label))
else:
    print("  未命中（单值 + 两值/三值组合都没中）")
    print()
    print("  ⇒ 说明输入不是这些字段的简单拼接 —— 可能是：")
    print("     · libdu 采集的更底层属性（boot_uuid / 系统文件清单 / 签名证书等）")
    print("     · 或者哈希中带了固定盐（salt）")
    print()
    print("  ★ 参考 FINGERPRINT_REPORT.md：数盟采集的项包括")
    print("     boot_uuid / boot_times / 包名+签名后缀 / 签名证书 DER /")
    print("     boot classpath 清单 / 系统字体清单 / 固件驱动标识 / 已装应用列表")
    print()
    print("  ⇒ 下一步应该是：在真机上 hook libdu 的 MD5 调用，直接读它的输入")
    print("     （文档 FINGERPRINT_REPORT.md §二 已给出方法：x1 寄存器 = 输入数据）")
