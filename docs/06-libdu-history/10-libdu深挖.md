# 深入 libdu.so：核心函数与字段发现

## 一、发现：libdu.so + 0xedf64 是数盟的**系统调用统一封装**

这是本阶段最重要的发现。它不是看雪文章说的「字符串解密函数」，而是**数盟所有敏感操作的出口**。

### 实测调用记录

```
D1  | x0="/proc/meminfo"       | x3=999      | ret="4000692,670012"
D2  | x0="model"               | x3=999      | ret={...}
D3  | x0="/proc/net/tcp"       | x2="hex"    | ret="32"
D4  | x0="/proc/self/status"   | x3=999      | ret=0
D5  | x0="/proc/self/maps"     | x2="xposed" | ret=0
D6  | x0="/proc/meminfo"       | x3=999      | ret="4000692,498828"
D9  | x0="/storage/emulated/0/Android/data/com.coolapk.market/cache/ee02ad45"
```

### 函数签名（还原）

```
x0 = 采集目标（文件路径 / 命令 / 键名）
x1 = 加密的配置 blob
x2 = 参数（"hex" / "xposed" / 0 / ...）
x3 = 999（模式标识，固定 0x3e7）
ret = 采集结果（字符串或指针）
```

**涵盖能力**：读文件、执行命令、读系统属性、环境检测（root/xposed/tracer）。

### 反汇编确认

```
0x0edf64: a9bd7bfd    STP x29,x30,[sp,#-0x30]!   ← 函数序言
0x0edf70: 910003fd
0x0edf74: 2a0303f5    MOV w21, w3                ← 第4参数
0x0edf78: aa0203f4    MOV x20, x2                ← 第3参数
0x0edf7c: aa0103f3    MOV x19, x1                ← 第2参数
0x0edf80: 710f9c7f    CMP w3, #0x3e7             ← 比较 999（模式）
0x0edf84: aa0003f6    MOV x22, x0                ← 第1参数
0x0edf88: 54000060    B.EQ
0x0edf8c: 7101bebf    CMP w21, #0x6f             ← 比较 111
0x0edf90: 54000241    B.NE
```

---

## 二、发现：`soK` 字段 —— 疑似核心设备指纹

`x0="model"` 查询的返回：

```json
{
  "I1g": "0", "I1g": "1", "I1g": "2", "I1g": "3",
  "1Ns": "Unisoc UWS6152",
  "soK": "47e8d494b9ccab8165aece423cec503f5088dad4676caed659863cea499b8974"
}
```

- **`soK`** = 64 位小写 hex（32 字节）—— **最可能是 SHA-256**
- **`1Ns`** = `Unisoc UWS6152`（芯片型号，注意不是 `XTQ_Watch`）
- **`I1g`** ×4 = CPU 核心索引

**但 hook 全部 EVP 符号后，`soK` 零命中** —— 说明它**不是通过 OpenSSL 的 EVP 接口算的**。
可能是自研哈希实现，或用了别的密码库。

---

## 三、重要修正：`p` 的哈希在 `libcrypto.so` 里算

之前我判定 `p` 的哈希走 `libjavacrypto.so`，**这次实测发现是 `libcrypto.so`**：

```
[ok] hook libcrypto.so EVP  (upd=0x7f689091d8 fin=0x7f689091f8)
[心跳 libcrypto.so] update=18797 final=2319 soK命中=0 p命中=1
```

**`p命中=1`** —— 在 `libcrypto.so` 上命中了 `p` 的输入。

`update=18797` 次 / 130 秒 —— 高频但进程稳定，印证了 **native hook 是安全的路子**。

### 这对我们意味着什么

之前 `real_evp.js` hook 的是 `libjavacrypto.so`，能命中是因为 Java 层调用会经过它。
但 `libdu.so` 自己算哈希时用的是 **`libcrypto.so`**。

**所以要做纯 native 追踪，应该 hook `libcrypto.so`。**

---

## 四、看雪文章 vs 我们的进度

| 项 | 我们 | 文章 |
|---|---|---|
| `p = MD5(包名+"."+suffix)` | ✅ **破解+字节级验证** | ❌ 未涉及 |
| body 明文 21 字段 | ✅ **完整还原** | 部分片段 |
| 请求加密 key | ✅ **`GWL8jXHLnzp63QDH`** | ❌ 未涉及 |
| `r` 完全自由 | ✅ **12/12 严格验证** | ❌ 未涉及 |
| 6 个端点 | ✅ | 2 个 |
| HTTP 头精确格式 | ✅ **完整 dump** | ❌ |
| **libdu 核心函数定位** | ✅ **`0xedf64`（系统调用封装）** | `0xc5f28`（国际版偏移） |
| **字符串解密函数** | ⬜ | ✅ `0xefdc0`（国际版偏移） |
| **篡改 device id** | ⬜ | ✅ **成功** |

**我们的算法层进度明显超过这篇文章**（它完全没碰 `p`、没碰加密 key、没碰 `r`、没还原明文结构）。
它唯一的独特优势是**找到了字符串解密函数并实际篡改成功**。

**注意**：文章的偏移是**国际版** `libdu.so`（`global-auni.checktrustworthiness.com`），
我们的是国内版（`auni.telecome.cn`），**偏移不通用**。已验证：

```
我们的 libdu_real.so:
  0xc5f28  ->  BL 0x8cee8          （调用指令，非入口）
  0xefdc0  ->  54000221            （B.cond，非入口）
  全 .text 无 BL 指向这两处
```

---

## 五、数盟的检测行为（实测）

```
x0="/proc/self/maps"  x2="xposed"  -> ret=0     检测 Xposed
x0="/proc/self/status"             -> ret=0     检测 TracerPid
x0="/proc/net/tcp"    x2="hex"     -> ret="32"  检测网络连接
x0="/proc/meminfo"                 -> 内存信息
```

**这解释了为什么必须做 stealth hook** —— 它确实在读 `/proc/self/maps` 找 frida/xposed 痕迹。

---

## 六、当前完整状态

### 已攻克

| 项 | 值 |
|---|---|
| **`p` 算法** | `MD5(包名 + "." + suffix)`，字节级验证 |
| **`r`** | 完全自由，服务端不解析（12/12 验证） |
| **请求加密 key** | `GWL8jXHLnzp63QDH`（AES-128-ECB） |
| **body 结构** | `AES-ECB(gzip(JSON))`，无盐 |
| **body 明文** | 21 顶层字段完整还原 |
| **响应解密** | 同一 key |
| **`h` 映射** | `mdna`→`0`，其余→`F7AAD8CD5824603F7F2200731D8C045D` |
| **HTTP 头格式** | 完整 dump |
| **设备端发送 200** | ✅ 复现多次 |
| **libdu 核心函数** | `0xedf64`（系统调用封装） |

### 未攻克

| 项 | 状态 |
|---|---|
| **body 精确字节布局** | `SSL_write` 抓 1365 字节（含头？），`doFinal` 给纯密文 1264。两者发送结果矛盾，未定 |
| **`suffix` 派生算法** | 16 位 hex，设备恒定，不依赖 android_id/serialno/机型/MAC |
| **`deviceId` 生成规则** | `ANDROID_<16hex>`，每次 `pm clear` 变 |
| **`soK` 计算方式** | 32 字节哈希，不用 EVP |
| **`x1` 加密配置 blob** | 未解开 |

---

## 七、下一步（优先级排序）

### 1. 静态分析 `libdu+0xedf64` 内部（最高价值）

顺着 `x3=999` 的分支看，能列出数盟**完整的设备采集清单**。
从中可能直接看出 `suffix` 和 `soK` 的来源字段。

### 2. hook `libcrypto.so` 追 `soK`

既然 `p` 在 `libcrypto.so` 命中，说明数盟的哈希走这个库。
`soK` 未命中可能是因为用了**别的算法入口**（如 `SHA256_Update` 而非 `EVP_DigestUpdate`）。

试试 hook：

```
libcrypto.so 的 SHA256_Init / SHA256_Update / SHA256_Final
             SHA1_Init / SHA1_Update / SHA1_Final
             MD5_Init / MD5_Update / MD5_Final
```

### 3. 解开 `x1` 配置 blob

它有固定前缀 `7b f2 ...`（多个调用中前几字节相同），说明是加密的配置数据。
解开它 = 拿到数盟内部配置，可能包含 `suffix` 算法的线索。

---

## 八、资产

| 文件 | 用途 |
|---|---|
| **`hook_dec.js`** | **★ hook `libdu+0xedf64`，观察系统调用封装** |
| **`verify_dec.py`** | **★ 驱动 + 结果汇总** |
| **`trace_sok.js`** | 多库 EVP hook，追 `soK` |
| `trace_sok.py` | 驱动 |
| `check_offsets.py` | 看雪偏移验证（结论：不通用） |
| `find_decrypt.py` | 找高频被调用函数 |
| `real_evp.js` | 原 EVP hook（`p` 破解功臣） |
| `dec_out.txt` | **`0xedf64` 的完整调用日志** |
| `sok_out.txt` | `soK` 追踪日志 |
