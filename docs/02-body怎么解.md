# ② body 怎么解

> 👈 回到 [主线](../mainline.md) ｜ 上一节 [① 请求长什么样](01-请求长什么样.md) ｜ 下一节 [③ 服务端看哪些字段](03-服务端看哪些字段.md)

---

## 踩过的坑：地址 ≠ 密钥

早期笔记里记着 `0x109CF0`、`0x110DC8` 这样的形式，一开始把它们当成了**密钥值**，
结果所有解密尝试全部失败。

> ⚠️ **那些是内存地址。真正的密钥是存放在该地址处的字符串。**

改对之后样本全部解开。**记笔记时地址与内容要写清楚，否则自己回头读都会误读。**

---

## 两套加密并存

实测发现 body 加密**不止一套**，不同调用路径走不同那套：

```
① Java 路径（libjavacrypto）
   body = AES-128-ECB(key = "GWL8jXHLnzp63QDH", gzip(JSON))     ← 无盐
   响应用同一个 key 解密

② native 路径（libdu 自身）
   body = zlib.compress(JSON) XOR POOL_KEY
   响应用同一个 POOL_KEY 解密
```

**★ 两套都要实现** —— 只做一套会漏掉一半的样本。

---

## 池常量

`POOL_KEY` 有 5 个，都是 libdu 内存里的字符串常量：

| 地址 | 字符串 | 周期 |
|---|---|---|
| **`0x110DC8`** | `xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}` | 48 |
| `0x109CF0` | `$%v2TW}pmn];io,^@!B&+=87fqyu<>?:['|{.*`-09(tsb` | 46 |
| `0x10924C` | `@dalsdfkSDFSesa!@#tbaf@$%f$%K=^*&0918~Werar=-+^%39(0!` | 53 |
| `0x1090F8` | `7.f498yu<>?:['|TWq&/57fqu@7v.ajl#etu{.jqv2fs` | 45 |
| `0x0FEC5C` | `Kn];(ts<>5bv2TW?:['|%f$%K6%o,=^erar=87f4B&18~W` | 46 |

**`mdna` / `dcc2` / `adt` 用 `0x110DC8`。**

异或是按周期重复的：

```python
def xor(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
```

---

## 关键细节：JSON 的序列化方式

libdu 用的是**紧凑 JSON + 把 `/` 转义成 `\/`**：

```python
def dump_json(obj):
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return s.replace("/", "\\/").encode("utf-8")
```

**这一步必须一致**，否则 zlib 压缩出来的字节不同，服务端解不开。

（注意 `ensure_ascii=False` —— 中文如 `"酷安"` 要按 UTF-8 原样写入，不能转成 `\uXXXX`。）

---

## 解码实现

```python
import json, zlib

KEY = b"xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}"

def xor(data):
    return bytes(data[i] ^ KEY[i % 48] for i in range(len(data)))

def decode_body(raw):
    """raw = 抓到的 body 字节 → 明文 JSON 字符串"""
    plain = zlib.decompress(xor(raw))
    return plain.decode("utf-8")
```

**响应解码同理**（同一个 KEY）：

```python
def decode_resp(raw):
    d = xor(raw)
    return json.loads(zlib.decompress(d).decode("utf-8"))
```

---

## 编码实现

```python
def dump_json(obj):
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return s.replace("/", "\\/").encode("utf-8")

def encode_body(obj):
    return xor(zlib.compress(dump_json(obj), 6))
```

---

## 验证方法

**自校验**：解出来再编回去，应当与原 body **逐字节相同**。

```python
raw = open("data/samples/wire_m58_REQ_9_len1745.bin", "rb").read()
i = raw.find(b"\r\n\r\n")
body = raw[i + 4:]

obj = json.loads(decode_body(body))
assert encode_body(obj) == body      # ← 必须通过
```

这一步是后续所有变体实验的前提 —— 否则"改了字段却不知道变了几处"，结论不成立。

---

## 关于 zlib 的两个实测细节

### 服务器会校验 adler32

```
正常 zlib             → 真 DUID ✓
adler32 置零 / 随机 / 算错 → 全部失败 ✗
```

**⇒ 校验和必须算对。**

### 但接受「未压缩的存块模式」

```
存储块模式（deflate stored blocks，完全不压缩）→ 真 DUID ✓
```

**⇒ 不需要真压缩。** 这让低配实现（如纯 shell）也能构造合法 body ——
只需按 zlib 格式手工拼存储块 + 算对 adler32。

格式：

```
78 01                          ← zlib 头（CMF/FLG，表示无压缩）
  00 | 01  <LEN:2> <NLEN:2> <原始数据>    ← 存储块（最后一块 BFINAL=1）
<adler32:4 大端>
```

---

## 备用线路的 body

`yumao.puata.info/anti_logs` 与 `ccs.umeng.com/ra` 的 body 前 10 字节固定为：

```
2aeb393b33373531693d
```

**未进一步分析** —— 这两条线路不是主流程，不影响取 DUID。
`ccs.umeng.com` 那条还带 `Content-Encoding: xgzip`。

---

## 相关代码

| 文件 | 说明 |
|---|---|
| [`tools/szlm_id.py`](../tools/README.md) | 协议核心库（池常量 + 编解码 + 请求构造） |
| [`tools/szlm_body.py`](../tools/README.md) | body 编解码参考实现 |
| [`tools/test_adler.py`](../tools/README.md) | adler32 / 存储块模式的实验脚本 |
| [`data/samples/`](../data/README.md) | 可用来验证编解码的原始样本 |
