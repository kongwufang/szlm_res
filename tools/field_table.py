#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""field_table.py — mdna 报文 78 字段完整清单 + 语义推断 + 关系验证

★ 数据：dump/wire_m58_REQ_9_len1745.bin（D2 真机发过的 mdna 请求）
★ 结合：我实测的锚点结果（只有 DUv/3mS/2cO/sfOo/foO/75c 一换就全 0）
        + 值形态推断
"""
import io
import json
import os
import sys
import zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REV = r"C:\Users\Admin\CodeBuddy\c001apk\_rev"
sys.path.insert(0, REV)
import szlm_id as S  # noqa: E402

POOL = 0x110DC8
SRC = os.path.join(REV, "dump", "wire_m58_REQ_9_len1745.bin")

d = open(SRC, "rb").read()
i = d.find(b"\r\n\r\n")
k = S.KEY_BY_ADDR[POOL]
body = d[i + 4:]
obj = json.loads(zlib.decompress(bytes(body[j] ^ k[j % len(k)] for j in range(len(body)))).decode())

# ★ 我实测的锚点（换成合法值就全 0）
ANCHORS = {"DUv", "3mS", "2cO", "sfOo", "foO", "75c"}

# 语义推断表（依据：值形态 + 文档 + 常识）
MEAN = {
    "DUv": "★包名（应用身份）",
    "Qg1": "毫秒时间戳",
    "LMi": "毫秒时间戳（同 Qg1，疑为启动时刻）",
    "Zrs": "versionCode",
    "EV2": "versionName",
    "SAN": "Android API level",
    "h6Z": "应用名",
    "R41": "Android 主版本号",
    "R5a": "运营商 MCC+MNC",
    "R53": "未知(0)",
    "R63": "进程状态(running/stopped)",
    "QgA": "未知(1)",
    "qH9": "未知(0)",
    "iZS": "未知(0)",
    "ZZA": "未知(0)",
    "S6e": "未知(1)",
    "90P": "★混淆值(网络/屏幕状态?)",
    "YWu": "/etc/hosts 内容",
    "bzt": "未知(0000)",
    "5mZ": "未知(0)",
    "0KQ": "未知(0)",
    "Chh": "未知(0)",
    "Xl9": "未知(0000)",
    "D32": "CPU 核数",
    "LAh": "★混淆值(存储/屏幕?)",
    "wlM": "未知(3)",
    "nur": "未知(0)",
    "tth": "未知(1)",
    "c2O": "★混淆位(与 2cO 不同!)",
    "PV8": "未知(7)",
    "yzW": "★混淆值(存储空间?)",
    "AYk": "MAC 地址三元组",
    "P1J": "MAC 地址三元组(同 AYk)",
    "R37": "厂商(brand)",
    "R3d": "机型(model)",
    "AAA": "协议版本 v1.0",
    "BBB": "协议版本 v1.0",
    "3mS": "★SDK 版本 v9.x",
    "2cO": "★时间戳 秒.纳秒",
    "K5f": "MD5(32hex)",
    "GVp": "渠道(coolapk)",
    "iYB": "存储/内存详情(嵌套)",
    "7S2": "同上(索引 0)",
    "ne8": "MD5(32hex)",
    "mIS": "★混淆串 36 —— 【实测：与设备识别无关！】",
    "sfOo": "★7 位 hex —— 【实测：真锚点】",
    "foO": "★混淆串 14 —— 【实测：真锚点】",
    "w91": "MD5(32hex)",
    "G8U": "网络详情(嵌套)",
    "zvW": "混淆串 35",
    "gEd": "MD5(32hex)",
    "5Tv": "混淆串 33",
    "52J": "混淆串 96",
    "Bos": "混淆串 41",
    "IJK": "混淆串 41",
    "ura": "混淆串 41(同 IJK)",
    "ibF": "混淆串 35",
    "IAI": "混淆串 45",
    "aFw": "混淆串 39",
    "KyU": "混淆串 23",
    "6yY": "SHA256(64hex)",
    "UOv": "混淆串 23",
    "JPd": "未知(0)",
    "J7w": "未知(0)",
    "zpA": "网络类型(WIFI)",
    "bf7": "未知(0)",
    "wSK": "内网 IP",
    "fPV": "国家,语言",
    "Db2": "未知(2)",
    "QVn": "未知(0)",
    "msg": "自定义消息(空)",
    "dLH": "混淆串 35",
    "4VP": "未知(1)",
    "za7": "时间戳格式化 1_<秒>_",
    "75c": "★apiKey(常量)",
    "fxb": "未知(100068)",
    "B3k": "未知(1342)",
    "cHo": "未知(0)",
}

print("=" * 116)
print("  mdna 报文 78 字段完整清单")
print("=" * 116)
print("  %-6s %-6s %-20s %-42s %s" % ("键", "类型", "值", "语义推断", "角色"))
print("  " + "-" * 112)


def role(k, v):
    if k in ANCHORS:
        return "★★★ 锚点/必需"
    if k == "mIS":
        return "☆ 实测与设备识别【无关】"
    s = json.dumps(v, ensure_ascii=False)
    if len(set(s)) <= 2 or s in ("0", '"0"', "1", '"1"', "{}", '{"custom": ""}'):
        return "常量/占位"
    if isinstance(v, (dict, list)):
        return "嵌套"
    return ""


for kk, v in obj.items():
    t = type(v).__name__
    s = json.dumps(v, ensure_ascii=False)
    if len(s) > 40:
        s = s[:37] + "..."
    m = MEAN.get(kk, "?")
    if len(m) > 40:
        m = m[:37] + "..."
    print("  %-6s %-6s %-20s %-42s %s" % (kk, t, s, m, role(kk, v)))

# ── 统计 ──
anch = [k for k in obj if k in ANCHORS]
nested = [k for k, v in obj.items() if isinstance(v, (dict, list))]
consts = [k for k, v in obj.items() if json.dumps(v, ensure_ascii=False) in ("0", '"0"', "1", '"1"', "3", "4", '"0000"', "{}", '{"custom": ""}')]
hexf = []
for k, v in obj.items():
    if isinstance(v, str) and len(v) >= 16 and all(c in "0123456789abcdefABCDEF" for c in v):
        hexf.append((k, len(v)))

print("\n" + "=" * 116)
print("  分类统计")
print("=" * 116)
print("  总字段数        %d" % len(obj))
print("  ★ 锚点/必需     %d  %s" % (len(anch), anch))
print("  嵌套对象        %d  %s" % (len(nested), nested))
print("  常量/占位       %d  %s" % (len(consts), consts))
print("  纯 hex 字段     %d  %s" % (len(hexf), [(a, b) for a, b in hexf]))

# ── 关系验证：sfOo 是不是某个 hex 字段的前缀/子串 ──
print("\n" + "=" * 116)
print("  ★ 关系验证：sfOo = %s 与各 hex 字段" % obj.get("sfOo"))
print("=" * 116)
sf = str(obj.get("sfOo", "")).upper()
for k, ln in hexf:
    v = str(obj[k]).upper()
    if sf in v:
        print("    ★★★ sfOo 是 %s 的子串！位置 %d" % (k, v.find(sf)))
    else:
        # 比较前缀
        if v[:len(sf)] == sf:
            print("    ★★★ sfOo == %s 的前 %d 位" % (k, len(sf)))
    print("    %-6s(len=%2d) 前 7 = %-8s  ==sfOo? %s" % (k, ln, v[:7], v[:7] == sf))

# ── foO 与 mIS 的关系 ──
print("\n" + "=" * 116)
print("  ★ 关系验证：foO = %r 与 mIS = %r" % (obj.get("foO"), obj.get("mIS")))
print("=" * 116)
fo = str(obj.get("foO", ""))
mi = str(obj.get("mIS", ""))
print("    foO 长度 %d, mIS 长度 %d" % (len(fo), len(mi)))
print("    foO 是否 mIS 子串: %s" % (fo in mi))
print("    foO 是否 mIS 前缀: %s" % mi.startswith(fo))
print("    foO 字符集: %s" % "".join(sorted(set(fo))))
print("    mIS 字符集: %s" % "".join(sorted(set(mi))))
print("    mIS 前 14 字符: %r" % mi[:14])
# 逐字符 XOR
if len(fo) <= len(mi):
    x = bytes(ord(a) ^ ord(b) for a, b in zip(fo, mi))
    print("    foO XOR mIS[:%d] = %s" % (len(fo), x.hex()))
