# ★★★ 完整突破：body 结构与明文全部还原 ★★★

## 一、决定性发现：body 没有盐

```
body = AES-128-ECB( key="GWL8jXHLnzp63QDH", gzip(JSON明文) )
```

**没有前缀盐。** 之前我一直假设「4 字节盐 + 密文」，那是错的方向 ——
`Cipher.doFinal` 的输出**直接就是完整可解的密文**。

### 证据

```
★ C8  (out=1264) 解密成功! 1869 字节
★ C12 (out=1760) 解密成功! 2861 字节
```

直接对 `doFinal` 的密文做 `AES-ECB-decrypt → unpad → gzip-decompress`，
一次成功，无需任何偏移调整。

（之前 `SSL_write` 里抠出来的 body 前面那 4 字节，是抓取位置算错导致的，
不是真实结构。）

---

## 二、完整明文结构（mdna 上报）

```json
{
  "protocolVersion": "2.0",
  "SDKVersion": "5.4.10.2",
  "SDKVersionCode": 5041002,
  "sdkApiVersion": "5.4.10.2",
  "sdkApiVersionCode": 5041002,
  "sdkType": 1,
  "appInfo": {
    "appId": "625000001",
    "name": "酷安",
    "packageName": "com.coolapk.market",
    "version": "16.6.2",
    "versionCode": 2609151,
    "sha1": "5F:8E:19:82:7C:85:7E:C8:86:FB:08:0F:34:A0:B1:BF:C0:B4:38:E9"
  },
  "tkVersion": "6.2.3",
  "adSdkVersion": "5.4.10.2",
  "networkInfo": {},
  "liveSupportMode": 0,
  "waynePlayerSupportMode": 0,
  "closureSupportMode": 0,
  "userInfo": {},
  "timestamp": 1790818140912,
  "geoInfo": { "latitude": 0, "longitude": 0, "type": 0 },
  "mediumDisableSensor": false,
  "kwaiMerchantSdkVersion": "1.1.0",
  "deviceInfo": {
    "romName": "SPRD",
    "osType": 1,
    "osApi": 28,
    "osVersion": "9",
    "language": "zh",
    "screenWidth": 368,
    "screenHeight": 448,
    "deviceWidth": 327,
    "deviceHeight": 398,
    "deviceId": "ANDROID_ad0c2b9d9caebc5b",
    "deviceVendor": "sprd",
    "platform": 3,
    "deviceModel": "XTQ_Watch",
    "deviceBrand": "XinTaiQi",
    "deviceSig": "2NnaJSIjIE0hlMtumv6ZGZxtjt6MtfqQNS9zIWeV%2BG5qsN1ZnGPZ%2FF57gWv%2F8duBCUWIfkpMDiOl%0AJmmB6qpOBj0vxFAL%2FUOKjzGsIGgIMyoGwImLCn30sQzTFd2D4CkEDhk3XiYO14NiHpUmabP88pK%0ANQEcGSzAyySSnG1cagSxWr%2BbtX5OMOOokpbrwtOXo86yRWBx2msxq4tuNLlqsY6oitxCWYaXUnY1%0A2VWOZEF4V6SmTBTNSGhPsTeGMaQmcatSz7ah1VOtAqVOdUTHSuE2ecoeHpY9W1KYadVb27d1iioy%0AO1HXEb5jgQv%2FRrdbesh3%2FVe2NlZDs2MBYhWuBG1pTFb1oWsxpRBngZINaMOqJ4ltIHP5i9gJEYF%2B%0AM%2Fwpg88rCqVfjoEPAS9Bmy6Ezxgm7m5aNTCHZNZcpWR%2BtyRd5hGbvomqC4e5mYg8O27hGc5mIJ1l%0AAA5LTvzcAiVMaI%2BvgStHGBwK%2BY7BMwTL1PGn6%2BGijqoBf%2B1j%2F51rIwpfHmae6ga4PKwkXapwsbd0%0A%2FX%2FSfqeQfD3qpKGE0ivU3neAC86KkIzZZryYnznTFbM82bYH0LvogEoB73%2FRX9iI7HUG3v2Vazdh%0AS6ASO8tkX4%2F%2BiAf4%2BYdBtDO9L9EU0TCy7AiCmaNzSqdAE4J4W07xWpjGy0BUC28OYCD6T0rS5diH%0AnjAi0HSLhYhdllddquSIFipKWdKQcVk%2B3qSl7EbmPU7bzGLoPVPFRFCSmkeu79TvhQL%2BUS1MO2JO%0AqrrGW4Olwuy2c26eQyHFvLM2DduFiSAVxyiW0TrZ%0A",
    "arch": "aarch64",
    "systemUpdateTime": "160.459999994"
  },
  "impInfo": [{}],
  "appTag": ""
}
```

---

## 三、两个关键细节

### 1. `deviceSig` 是 URL-encoded base64

```
2NnaJSIjIE0hlMtumv6ZGZxtjt6MtfqQNS9zIWeV%2BG5qsN1ZnGPZ%2FF57gWv%2F8duBCUWIfkpMDiOl%0A...
                                                  ↑ %2B = '+'
                                                              ↑ %2F = '/'
                                                                     ↑ %0A = 换行
```

之前我看到的「600 字节 base64 blob」就是这个 —— 只是没意识到它是 **URL 编码**过的
（`+` → `%2B`，`/` → `%2F`，换行 → `%0A`）。

### 2. `deviceId` 是会变的

| 抓取时间 | deviceId |
|---|---|
| 之前 | `ANDROID_1662da439d294722` |
| **本次** | **`ANDROID_ad0c2b9d9caebc5b`** |

**这个字段不是固定值。** 很可能就是服务端用来识别「新设备」的关键 ——
每次 `pm clear` 后重新生成。

---

## 四、现在具备的完整构造能力

```python
import gzip, json, hashlib, os, random, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"GWL8jXHLnzp63QDH"      # 请求加密 + 响应解密（同一个）
HOST    = "auni.telecome.cn"

def calc_p(package: str, suffix: str) -> str:
    """设备指纹 p"""
    return hashlib.md5(f"{package}.{suffix}".encode()).hexdigest().upper()

def build_body(plaintext: dict) -> bytes:
    """构造请求体：AES-ECB(gzip(JSON))，无需盐"""
    raw = json.dumps(plaintext, separators=(",", ":"), ensure_ascii=False).encode()
    return AES.new(AES_KEY, AES.MODE_ECB).encrypt(pad(gzip.compress(raw), 16))

def build_url(p: str, r: str, h: str = "0") -> str:
    return f"https://{HOST}/a/mdna/report?v=8.7&t=m&p={p}&r={r}&n=0&l=2&h={h}"

def decrypt_resp(body: bytes) -> str:
    """解密响应"""
    pt = unpad(AES.new(AES_KEY, AES.MODE_ECB).decrypt(body), 16)
    if pt[:2] == b"\x1f\x8b":
        pt = gzip.decompress(pt)
    return pt.decode("utf-8", "replace")
```

**验证**：

```python
assert calc_p("com.coolapk.market", "37be8a1ee106979a") == "F9BD0FBDACFE80FCF34370FBCFEE1A98"
# ✓ 通过
```

---

## 五、完整战果

| 项 | 状态 |
|---|---|
| 六个上报端点 | ✅ |
| 请求格式（URL/Header/CT/UA） | ✅ |
| **`p` 算法** | ✅ `MD5(包名 + "." + suffix)` |
| **`r` 的性质** | ✅ **完全自由**（12/12 测试，连空值/非hex都通过） |
| **请求加密 key** | ✅ `GWL8jXHLnzp63QDH` |
| **body 结构** | ✅ **`AES-ECB(gzip(JSON))`，无盐** |
| **body 明文结构** | ✅ **完整还原（本文件第二节）** |
| 响应解密 | ✅ |
| `h` 与端点映射 | ✅ `mdna`→`0`，其余→`F7AAD8CD5824603F7F2200731D8C045D` |
| **设备端发送 → 200** | ✅ 稳定复现 |
| `suffix` 派生算法 | ⬜ 未定位（设备固有常量） |
| `deviceId` 生成规则 | ⬜ 观察到的值会变，规则未知 |

---

## 六、待验证的最后一件事

现在 body 的构造方式已经完全明确，**可以构造一个全新的、自洽的 body 发出去看是否被接受**。

之前 B/D 两组（新 body → 400）失败，很可能就是因为**我加了错误的 4 字节盐**。
去掉盐之后，同样的明文应该能通过。

**这是下一个实验**：

```
A. 原样 body（doFinal 的密文直接发）  -> 预期 200（基准）
B. 自研构造 body（同样明文，无盐）      -> 若 200 则完全打通
C. 自研构造 body（改 timestamp）        -> 检验时间窗口
```

---

## 七、采集方法（可靠版）

**关键教训**：不要从 `SSL_write` 抠 body。

```
✗ SSL_write + indexOf('....') 定位 body    → 偏移算错，抓到的全是垃圾
✗ SSL_write + 字节级找 \r\n\r\n            → 好些，但仍受分片影响
✅ Cipher.doFinal 的 out 直接就是完整密文   → 长度必然 16 对齐，一次成功
```

**最终采用**：hook `Cipher.doFinal`，只过滤 `alg` 含 `ECB` 且 `in/out` 在
700~9000 范围的调用，把 `out` 原样回报。离线直接解密即可。

---

## 八、资产

| 文件 | 用途 |
|---|---|
| **`cap_all.js`** | **★ 可靠采集：doFinal 密文 + SSL_write body 全量回报** |
| **`cap_all.py`** | **★ 采集驱动 + 离线暴力分析** |
| `capture2/orig_plain.json` | **★ 完整明文（本文件第二节的原始数据）** |
| `capture2/c*.bin` | 各次 doFinal 的密文 |
| `szlm_client.py` | 纯自研实现（需更新：去掉盐） |
| `real_evp.js` | native 层 EVP hook（破解 p 用的） |
| `real_key.js` | 抓 Cipher.init 密钥 |
| `test_r_strict.py` | r 自由度的严格测试（12/12） |
| `P_CRACKED.md` / `FULL_BREAKTHROUGH.md` / `R_IS_FREE.md` | 各阶段报告 |
