#!/bin/sh
# =============================================================================
#  getduid.sh — 从数字联盟取 DUID（跨网络环境对比测试用）
#
#  ★ 两种模式：
#      --fixed   用固定的三值 (sfOo/foO/2cO) → 应稳定返回同一个 DUID
#      --random  随机三值 + 完整 79 字段模板 → 每次拿到一个【新 DUID】
#
#  ★ 跨网络测试（你的目的）：
#      在同一网络先跑 --fixed --n 3 记下 DUID
#      换到另一网络再跑 --fixed --n 3
#        · 结果相同 → 服务器不依赖出口 IP
#        · 结果不同 → 出口 IP 参与了设备识别
#
#  用法：
#      ./getduid.sh                       # 固定三值，1 次
#      ./getduid.sh --n 3                 # 固定三值，3 次
#      ./getduid.sh --random              # 随机三值（拿新 DUID）
#      ./getduid.sh --random --n 5        # 连拿 5 个新 DUID
#      ./getduid.sh --min                 # 用 8 字段最小体（体积小，但随机三值会被拒）
#      ./getduid.sh --full                # 打印完整响应 JSON
#      ./getduid.sh --sf 801C14F --fo 'RP|Q|zQKOJ~I~}Q' --ts 1791105420.764024281
#
#  依赖：python3（zlib + XOR + HTTPS 都在里面做）
#  模板：脚本同目录下的 mdna_template.json（79 字段完整报文，没有则用最小体）
# =============================================================================

set -e

MODE="fixed"
COUNT=1
SHOW_FULL=0
USE_MIN=0
SF="801C14F"
FO='RP|Q|zQKOJ~I~}Q'
TS="1791105420.764024281"

while [ $# -gt 0 ]; do
    case "$1" in
        --random) MODE="random"; shift ;;
        --fixed)  MODE="fixed";  shift ;;
        --min)    USE_MIN=1;     shift ;;
        --full)   SHOW_FULL=1;   shift ;;
        --n)      COUNT="$2";    shift 2 ;;
        --sf)     SF="$2";       shift 2 ;;
        --fo)     FO="$2";       shift 2 ;;
        --ts)     TS="$2";       shift 2 ;;
        -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "未知参数: $1（用 -h 看帮助）" >&2; exit 2 ;;
    esac
done

# ── 找可用的 python 解释器（避开 Windows Store 的假 python3 存根） ──
PY=""
for c in python3 python /usr/bin/python3 /usr/local/bin/python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c "import sys,zlib,ssl,json;assert sys.version_info[0]==3" >/dev/null 2>&1; then
        PY="$c"; break
    fi
done
# Windows 上再兜底找真实路径
if [ -z "$PY" ]; then
    for c in \
        "/c/Users/$USERNAME/AppData/Local/Programs/Python/Python312/python" \
        "/c/Users/$USERNAME/AppData/Local/Programs/Python/Python311/python" \
        "/c/Python312/python" "/c/Python311/python"; do
        if [ -x "$c" ] && "$c" -c "import zlib,ssl" >/dev/null 2>&1; then
            PY="$c"; break
        fi
    done
fi
if [ -z "$PY" ]; then
    echo "找不到可用的 python3（需要能 import zlib, ssl, json）" >&2
    exit 1
fi

# 模板路径 = 脚本所在目录
SELF_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || SELF_DIR="$(pwd)"
TEMPLATE="$SELF_DIR/mdna_template.json"
[ -f "$TEMPLATE" ] || TEMPLATE=""

# 取出口 IP（方便跨网络对比）
EIP="(取不到)"
if command -v curl >/dev/null 2>&1; then
    EIP=$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null || echo "(取不到)")
elif command -v wget >/dev/null 2>&1; then
    EIP=$(wget -qO- --timeout=8 https://api.ipify.org 2>/dev/null || echo "(取不到)")
fi

echo "======================================================================"
echo "  数字联盟 DUID 获取"
echo "======================================================================"
echo "  出口 IP  : $EIP"
echo "  模式     : $MODE$( [ "$USE_MIN" = "1" ] && echo " (8 字段最小体)" || echo " (完整模板)" )"
echo "  次数     : $COUNT"
if [ "$MODE" = "fixed" ]; then
    echo "  固定三值 : sfOo=$SF"
    echo "             foO=$FO"
    echo "             2cO=$TS"
    echo "  ★ 正常应返回: DUaVFlbAMrmH2Z57PEhm_N9EO4RoUdvNstg5"
fi
echo "----------------------------------------------------------------------"

MODE="$MODE" COUNT="$COUNT" SHOW_FULL="$SHOW_FULL" USE_MIN="$USE_MIN" \
TEMPLATE="$TEMPLATE" SF="$SF" FO="$FO" TS="$TS" "$PY" <<'PYEOF'
import json, os, random, ssl, sys, time
import urllib.error, urllib.request, zlib

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MODE = os.environ["MODE"]
COUNT = int(os.environ["COUNT"])
SHOW_FULL = os.environ["SHOW_FULL"] == "1"
USE_MIN = os.environ["USE_MIN"] == "1"
TEMPLATE = os.environ.get("TEMPLATE", "")

HOST = "auni.telecome.cn"
URL = ("/a/mdna/report?v=8.7&t=m"
       "&p=F9BD0FBDACFE80FCF34370FBCFEE1A98"
       "&r=5bb7efdd4c794f0e9563317b7802b995&n=0&l=2&h=0")
UA = "Dalvik/2.1.0 (Linux; U; Android 8.1; TK Watch Build/OPM2.171019.012)"

# ★ 池常量 0x110DC8（48 字节周期）
KEY = b'xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}'
assert len(KEY) == 48

ALPHA = ("!#$%&'()*+,-./0123456789:;<=>?@"
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
         "abcdefghijklmnopqrstuvwxyz{|}~")
REAL = "DUaVFlbAMrmH2Z57PEhm_N9EO4RoUdvNstg5"
CTX = ssl._create_unverified_context()


def dump_json(o):
    """libdu 风格：紧凑 + 把 / 转义成 \\/"""
    s = json.dumps(o, ensure_ascii=False, separators=(",", ":"))
    return s.replace("/", "\\/").encode("utf-8")


def encode(o):
    z = zlib.compress(dump_json(o))
    return bytes(z[i] ^ KEY[i % 48] for i in range(len(z)))


def decode(raw):
    for fn in (zlib.decompress, lambda x: x):
        try:
            d = bytes(raw[i] ^ KEY[i % 48] for i in range(len(raw)))
            return json.loads(fn(d).decode("utf-8"))
        except Exception:
            pass
    return None


def send(body):
    h = {"Content-Type": "application/x-www-form-urlencoded",
         "User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity"}
    try:
        r = urllib.request.Request("https://" + HOST + URL, data=body,
                                   method="POST", headers=h)
        raw = urllib.request.urlopen(r, timeout=25, context=CTX).read()
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
    except Exception as e:
        return None, str(e)[:70]
    return decode(raw), "ok"


# ── 模板 ──
TPL = None
if TEMPLATE and os.path.isfile(TEMPLATE):
    try:
        TPL = json.load(open(TEMPLATE, encoding="utf-8"))
    except Exception:
        TPL = None


def make():
    sf = os.environ["SF"]
    fo = os.environ["FO"]
    ts = os.environ["TS"]
    if USE_MIN or TPL is None:
        o = {"DUv": "com.coolapk.market", "3mS": "v9.0.1",
             "75c": "11e7b222083a4b732b4b14811f6fc05995a01415eb",
             "2cO": ts, "sfOo": sf, "foO": fo,
             "AAA": "v1.0", "BBB": "v1.0"}
    else:
        o = dict(TPL)
    if MODE == "random":
        sf = "{:07X}".format(random.randint(0, 0xFFFFFFF))
        fo = "".join(random.choice(ALPHA) for _ in range(15))
        ts = "%.0f.%09d" % (time.time(), random.randint(1, 999999999))
        o["sfOo"], o["foO"], o["2cO"] = sf, fo, ts
        # ★ 关键：只改三值会被判「不自洽」→ 全 0
        #   必须【连三指纹一起改】才会被当作新设备 → 签发新 DUID
        if len(o) > 8:
            o["w91"] = "".join(random.choice("0123456789ABCDEF") for _ in range(32))
            o["gEd"] = "".join(random.choice("0123456789abcdef") for _ in range(32))
            o["6yY"] = "".join(random.choice("0123456789abcdef") for _ in range(64))
    else:
        o["sfOo"], o["foO"], o["2cO"] = sf, fo, ts
    return o, sf, fo, ts


if TPL is None and not USE_MIN:
    print("  ⚠ 未找到 mdna_template.json，退回 8 字段最小体")
    print("    （随机三值 + 最小体会被服务端拒，--fixed 仍可用）")
    print()

seen = []
for i in range(COUNT):
    obj, sf, fo, ts = make()
    body = encode(obj)
    j, how = send(body)
    if i == 0:
        print("  body: %d 字节 / %d 字段" % (len(body), len(obj)))
    na = str(j.get("n_a", "")) if isinstance(j, dict) else ""
    err = str(j.get("err", "")) if isinstance(j, dict) else ""
    seen.append(na)
    if na == REAL:
        mark = "  ★★★ D1 真 DUID"
    elif na and set(na) == {"0"}:
        mark = "  ✗ 全 0（被拒）"
    elif na:
        mark = "  ← 新 DUID"
    else:
        mark = "  (%s)" % how if how != "ok" else ""
    tag = ("[%d/%d] " % (i + 1, COUNT)) if COUNT > 1 else ""
    print("  %s%-9s %-20s %s" % (tag, sf, fo, ts))
    print("        → %s%s" % (na or "(空)", mark))
    if err and err != "0":
        print("          err=%s" % err)
    if SHOW_FULL and isinstance(j, dict):
        print("          %s" % json.dumps(j, ensure_ascii=False))
    if i + 1 < COUNT:
        time.sleep(1.5)

print()
print("----------------------------------------------------------------------")
uniq = []
for x in seen:
    if x not in uniq:
        uniq.append(x)
print("  %d 次 → %d 个不同的 DUID" % (COUNT, len(uniq)))
for x in uniq:
    print("     %-46s ×%d" % (x or "(空)", seen.count(x)))
print("======================================================================")
PYEOF
