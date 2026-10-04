# captures/ — 采集产物

> 👈 回到 [主线文档](../mainline.md) ｜ 方法见 [支线](../docs/03-stealth/)

这里是逆向过程中的**原始采集数据**，供对照与复现使用。

---

## 一、目录说明

| 目录 | 文件数 | 大小 | 内容 |
|---|---:|---:|---|
| `plain/` | 73 | ~250 KB | **解出的明文**（最有价值） |
| `dumps/forced/` | 9 | ~20 MB | **HS2 完整快照**（每次采集的最终状态） |
| `dumps/heartbeat/` | 9 | ~1.6 MB | 代表性的中途快照 |
| `wire/` | 585 | ~14 MB | 原始 wire 抓包（`wire_m58_*`） |
| `har/` | 330 | ~11 MB | 从 HAR 提取的 szlm 记录 |
| `szlmrec/` | 81 | ~130 KB | 34 组 szlm 请求/响应记录 |
| `sniff/` | 111 | ~1 MB | 早期嗅探输出 |
| `device/` | 45 | ~500 KB | 设备数据（prefs / DUID / 探测结果） |
| `screenshots/` | 5 | ~400 KB | 采集时的界面截图 |

**总计约 49 MB，1248 个文件。**

---

## 二、`plain/` —— 先看这个

解出的明文，全部是 JSON，可直接读。

| 子目录 | 内容 |
|---|---|
| `PLAIN/` | 18 个 adt/dcc2 上报的明文 |
| `C3_PLAIN/` | 8 个 `Cipher` 明文（含 szlm 与其它 SDK） |
| `D2A_PLAIN/` | 6 个 `Cipher` 明文 |
| `D2C_PLAIN/` | 17 个 `Cipher` 明文 |
| `CIPHER/` | 7 个原始 `Cipher` 记录 |
| `ENC/` | 17 个待解记录 |

**★ 解明文的方法**（见 [`../tools/`](../tools/)）：

```python
import zlib
KEY = b"xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}"   # 周期 48

def decode(raw):                      # raw = 抓到的 body 字节
    x = bytes(raw[i] ^ KEY[i % 48] for i in range(len(raw)))
    return zlib.decompress(x).decode("utf-8")
```

---

## 三、`dumps/forced/` —— 每次采集的完整状态

命名规则：`<run名>__HS2_forced_p<pid>.txt`

```
C3__HS2_forced_p27497.txt     281 KB    D3 一次完整注册
D1C__HS2_forced_p24474.txt    5.3 MB    ★ D1 第一次注册（锚点对比基准）
D1H__HS2_forced_p30318.txt    6.7 MB    ★ D1 第二次注册（对比用）
D1A__HS2_forced_p31877.txt    7.6 MB    D1 早期采集（含 dcc2/dai 明文）
D2C__HS2_forced_p19760.txt     68 KB    D2 采集
```

**文件内部格式**（每行一条记录）：

```
# p<pid> t=<毫秒> ssl=<计数> cipher=<计数> blocked=<计数> redirect=<计数> exit=<计数> sock=<计数> recs=<总数>
REC p<pid> t=<毫秒> <来源> <方向> n=<长度> hex=<十六进制>
KEEP p<pid> t=<毫秒> <来源> <方向> n=<长度> hex=<十六进制>
```

| 字段 | 含义 |
|---|---|
| 来源 | `SSL` / `CIPHER` / `SOCK` |
| 方向 | `IN`（入参 / 解密后）｜`OUT`（出参 / 加密后） |
| `hex` | 内容十六进制；**`KEEP` 行是 szlm 的 HTTP 请求，永不淘汰** |

**★ 找 szlm 请求**：

```sh
grep '^KEEP' D1C__HS2_forced_p24474.txt | while read -r _ _ t src dir n hex; do
    echo "$hex" | xxd -r -p | head -c 200; echo; echo "---"
done
```

**★ 找 mdna 明文**：

```sh
grep '^KEEP' D1C__HS2_forced_p24474.txt | grep -i '504f5354'   # POST
```

---

## 四、`wire/` —— 原始抓包

`wire_m58_REQ_<n>_len<size>.bin` / `wire_m58_RESP_<n>_len<size>.bin`

- **REQ** = 客户端发出的请求原始字节（含 HTTP 头 + 加密 body）
- **RESP** = 服务端响应原始字节

**★ 解一个请求**：

```python
raw = open("wire/cases... bin", "rb").read()   # 或 wire_m58_REQ_9_len1745.bin
i = raw.find(b"\r\n\r\n")
head, body = raw[:i].decode("latin1"), raw[i+4:]
print(head)                       # URL + 请求头
print(decode(body))               # 明文 JSON
```

**本仓库 `data/samples/wire_m58_REQ_9_len1745.bin` 就是其中一个**，可作为最小示例。

---

## 五、⚠️ 关于数据体积

原始的完整采集目录约 **1.2 GB**（含数千个重复的心跳快照）。本目录是**精选后的 49 MB**。

**想要全量数据** → 见 [Release](https://github.com/kongwufang/szlm_res/releases) 里的
`szlm-captures-full.tar.gz`（约 42 MB，压缩了完整的 HS2 心跳、全部 wire、HAR、设备数据）。

**为什么不全放进仓库**：

- 数千个心跳快照内容高度重复，只是时间点不同
- GitHub 仓库建议保持在 1 GB 以内，且不适合存大量小文件
- 精选后读取效率高得多

---

## 六、数据可信度

| 内容 | 来源 | 可信度 |
|---|---|---|
| `dumps/forced/` | 真机 Frida 钩子采集 | ★★★ 一手 |
| `wire/` | 真机抓包 / HAR 提取 | ★★★ 一手 |
| `plain/` | 上述数据解密 | ★★★ 一手 |
| `har/` | 浏览器 HAR 里的 szlm 记录 | ★★ 需筛选（含其它 SDK 流量） |
| `sniff/` | 早期版本脚本的输出 | ★★ 记录格式较旧 |

**所有数据来自几台闲置的测试用安卓手表**，详见 [`../PRIVACY.md`](../PRIVACY.md)。
