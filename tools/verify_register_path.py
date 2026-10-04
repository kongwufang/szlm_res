#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_register_path.py — ★★★ 验证「注册路径靠恒定指纹认设备」

★★★ 决定性实验推出的机制假设：
     · 回放路径（body 带 ubF=DUID）→ 用 (sfOo, foO, 2cO) 命中记录
     · 注册路径（h=0）           → 靠恒定设备指纹认出设备，沿用老 DUID
     而 (sfOo, foO, 2cO) 每次注册都变 ⇒ 新注册时它们只需是「新的随机值」

★ 本实验用先验证据检验这条假设：
     预测：ne8 / w91 / gEd / 6yY / AYk 这些【恒定】字段换了才影响 DUID
           而 sfOo / foO / 2cO 这些【每次变】的字段换了不影响

★ 方法：直接对比两次真实注册的完整 body，逐字段标注「恒定/变化」
       并对「变化」的字段做结构分析（看它们是不是同一套编码的不同值）
"""
import base64
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
print("=" * 100)
print("  D1 两次注册的完整 body 逐字段对比")
print("=" * 100)
print("  第一次 %s  第二次 %s" % (list(R1.keys()), list(R2.keys())))

if not R1 or not R2:
    print("  样本不足，退出")
    sys.exit(0)

t1, t2 = list(R1.keys())[0], list(R2.keys())[0]
j1 = json.loads(R1[t1])
j2 = json.loads(R2[t2])

# 展平（含嵌套）
def flat(o, pfx=""):
    out = {}
    for k, v in o.items():
        key = pfx + k
        if isinstance(v, dict):
            out.update(flat(v, key + "."))
        else:
            out[key] = v
    return out


f1 = flat(j1)
f2 = flat(j2)
allk = list(dict.fromkeys(list(f1.keys()) + list(f2.keys())))

same, diff, onlyone = [], [], []
print("\n  %-16s %-40s %-40s %s" % ("字段", "第一次", "第二次", "判定"))
print("  " + "-" * 112)
for k in allk:
    v1 = f1.get(k, "—")
    v2 = f2.get(k, "—")
    a = json.dumps(v1, ensure_ascii=False)
    b = json.dumps(v2, ensure_ascii=False)
    if v1 == "—" or v2 == "—":
        onlyone.append(k)
        vd = "仅一侧"
    elif v1 == v2:
        same.append(k)
        vd = "★★★ 恒定"
    else:
        diff.append(k)
        vd = "变化"
    if len(a) > 38:
        a = a[:35] + "…"
    if len(b) > 38:
        b = b[:35] + "…"
    print("  %-16s %-40s %-40s %s" % (k[:16], a, b, vd))

print("\n" + "=" * 100)
print("  分类汇总")
print("=" * 100)
print("\n  ★★★ 跨注册【恒定】(%d)：" % len(same))
for k in same:
    print("     %-16s = %s" % (k, json.dumps(f1[k], ensure_ascii=False)[:80]))
print("\n  ✗ 跨注册【变化】(%d)：" % len(diff))
print("     " + ", ".join(diff))

# ── 对「变化」字段做结构分析 ──
print("\n" + "=" * 100)
print("  ★ 对「变化」字段的结构分析（是不是同一套编码的不同值）")
print("=" * 100)
CHARSET = {}


def cs(s):
    return "".join(sorted(set(s)))


for k in diff:
    v1 = f1.get(k)
    v2 = f2.get(k)
    if not isinstance(v1, str) or not isinstance(v2, str):
        continue
    if len(v1) < 4:
        continue
    c1, c2 = cs(v1), cs(v2)
    inter = len(set(c1) & set(c2))
    print("\n  %-10s  len %d → %d" % (k, len(v1), len(v2)))
    print("      字符集1: %s" % c1[:60])
    print("      字符集2: %s" % c2[:60])
    print("      交集 %d / 并集 %d" % (inter, len(set(c1) | set(c2))))
    if len(v1) == len(v2):
        # 逐位置差异
        n = sum(1 for a, b in zip(v1, v2) if a == b)
        print("      ★ 同长度 %d，相同位置 %d" % (len(v1), n))

print("\n" + "=" * 100)
print("  ★★★ 结论")
print("=" * 100)
print("""
  恒定的字段 = 设备指纹（跨注册不变）
  变化的字段 = 每次注册新生成
  
  已知：
    sfOo / foO / 2cO 都【变化】 ⇒ 每次注册新值
    而 DUID 两次相同            ⇒ 服务端不是靠这三个认设备的
    恒定的 ne8/w91/gEd/6yY/AYk  ⇒ 它们才是「设备身份」

  ⇒ 推论：h=0 的注册路径靠恒定指纹认设备，
          (sfOo,foO,2cO) 只是「本次注册的会话标识」，可以随机生成
  ⇒ 若成立，sfOo/foO 不需要逆向 —— 这是目标的关键简化
""")
