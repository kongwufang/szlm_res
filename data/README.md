# data/ — 数据

> 👈 回到 [主线文档](../mainline.md) ｜ 相关支线 [02-anchor](../docs/02-anchor/)

---

> ⚠️ **本目录含"曾经是真实设备数据"的样本。已做文本脱敏，但请先读
> [`../PRIVACY.md`](../PRIVACY.md) 再决定是否公开。**

---

## 一、`samples/` — 原始样本

| 文件 | 大小 | 说明 |
|---|---|---|
| **`mdna_template.json`** | ~2.3 KB | **★ 79 字段完整 mdna 报文模板**（已脱敏） |
| `wire_m58_REQ_9_len1745.bin` | 1745 B | 真实 mdna HTTP 请求原始字节（含请求头 + 加密 body） |
| `mdna_body.bin` | 1058 B | 其它抓到的 mdna body |
| `szlm_last_mdna_http.bin` | 204 B | 抓到的 mdna HTTP 记录 |
| `du_cap2_明文HTTP抓包.txt` | — | tcpdump 明文抓包记录（含完整请求/响应） |

### `mdna_template.json` 是什么

一份**结构完整、可发往服务端**的 mdna 报文（79 字段）。

```json
{"DUv":"com.coolapk.market","Qg1":1790980402778,"LMi":1790980402778,
 "Zrs":2609151,"EV2":"16.6.2","SAN":27,"h6Z":"酷安","R41":"8.1","Ra":"ABSENT",
 ...
 "sfOo":"801C14F","foO":"RP|Q|zQKOJ~I~}Q","2cO":"1791105420.764024281",
 "w91":"...","gEd":"...","6yY":"...","75c":"11e7b222...",...
}
```

**用途**：`tools/getduid.py` 靠它构造请求。

**为什么需要完整 79 字段**：

```
8 字段最小体 + 真三值   → 真 DUID ✓
8 字段最小体 + 随机三值 → 全 0
完整 79 字段 + 随机三值 → 新 DUID ✓
```

即：**拿新 DUID 必须用完整 body。**

### `.bin` 样本说明

这些是**加密后**的原始字节：

```
body = zlib.compress(JSON) XOR POOL_KEY
POOL_KEY = b"xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}"   (周期 48)
```

**用本仓库公开的池常量即可解密。** 解密后可见设备字段（DQ名、机型等）。

**⇒ 如果不希望样本里的设备信息被还原，建议删除 `*.bin`，只保留已脱敏的
`mdna_template.json`** —— 后者足以复现协议。

---

## 二、`decoded/` — 解出的明文

| 前缀 | 来源 | 用途 |
|---|---|---|
| `D1C__MDNA_*.json` | D1 第一次注册的 mdna 明文 | **★ 锚点对比的基准** |
| `D1H__MDNA_*.json` | D1 第二次注册的 mdna 明文 | **★ 与上面逐字段对比，得出"三值每次都变"** |
| `C3_PLAIN__Cp*.json` | 一批 `Cipher` 明文（含 szlm 与其它 SDK） | 验证 `Cipher` 解密链路 |
| `D2A_PLAIN__Cp*.json` | 同上 | — |

### ★ 最重要的两组：D1 两次注册

**这是本项目最关键的对照数据。**

```
第一次  sfOo = 801C14F              foO = RP|Q|zQKOJ~I~}Q   2cO = 1791105420.764024281
第二次  sfOo = FD2C5E4              foO = DEo?qBmCp=DoDq>   2cO = 1791108030.968315068
        ⇒ 三者【都不同】，但 DUID 相同

跨注册【恒定】55 个字段（DUv / MAC / 机型 / w91 / gEd / 6yY / ne8 / wSK / 75c / Qg1 …）
跨注册【变化】21 个字段（sfOo / foO / 2cO / K5f / UOv / dLH / zvW / 5Tv / 52J / Bos / IJK /
                          IAI / aFw / KyU / ibF / dJs / p1m / LAh / 90P / za7 / Zne）
```

**⇒ 由此推出：服务端能从"新的三值"认出同一设备 ⇒ 三值内部编码了设备信息。**

### 复现对比

```python
import json, glob

def load(p):
    return json.load(open(p, encoding="utf-8"))

a = load("decoded/D1C__MDNA_77537.json")
b = load("decoded/D1H__MDNA_63185.json")

const, changed = [], []
for k in set(a) | set(b):
    (const if a.get(k) == b.get(k) else changed).append(k)

print("恒定:", sorted(const))
print("变化:", sorted(changed))
```

---

## 三、样本的来源与可信度

| 样本 | 来源 | 可信度 |
|---|---|---|
| `wire_m58_REQ_9_len1745.bin` | 真机抓包的原始字节 | ★★★ 一手 |
| `D1C__/D1H__ MDNA_*.json` | 真机抓包 → 池常量解密 | ★★★ 一手 |
| `mdna_template.json` | 上述解密结果 → 已脱敏 | ★★★ 一手 |
| `C3_PLAIN__/D2A_PLAIN__*.json` | 真机 `Cipher` 钩子采集 | ★★ 含多 SDK 流量，需筛选 |

---

## 四、数据体积说明

本目录**刻意只保留小样本（< 3 MB）**。

原始工作目录里有约 **2 GB** 的采集数据（`devout/`、`dump/`、`szlm_dex/`、
APK 等），**未包含在本发布中**，因为它们：

- 体积过大，不适合 Git
- 含未脱敏的设备信息
- 大多是一次性中间产物

**如需要更完整的数据，请从你自己的设备重新采集** —— 采集脚本见
[`../scripts/`](../scripts/)。
