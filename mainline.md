# 主线：从零到取回 DUID

> 这是项目的主线文档，按时间顺序讲完整过程。
> 每一段末尾有**支线指针**，指向更详细的专题文档。

---

## 结论速览

先给结论，细节在后面。

```
① 协议：HTTPS POST 到 auni.telecome.cn，body 经 zlib 压缩后与一段固定字符串异或
② 校验：87 个字段里，服务端【只用 6 个】
③ 识别：服务端按 (sfOo, foO, 2cO) 三元组查表决定返回哪个 DUID
④ 最小体：只要 8 个字段就能取回 DUID
⑤ 无签名：不存在需要私钥签出的字段
⑥ 一个 DUID 随手可得，但取回【某个特定设备】的 DUID 需要那台设备的锚点三元组
```

**可直接使用的工具**：`tools/getduid.py`（单文件、零依赖）。

---

## 第 0 段 · 目标

起点是一个很具体的需求：

> 能不能不依赖酷安 App，自己构造请求，让数字联盟返回**这台设备以前注册过的 DUID**？

要回答这个问题，得先搞清三件事：

1. 请求长什么样（端点、参数、加密）
2. 服务端校验什么（什么字段能被改）
3. 服务端靠什么认出"这是同一台设备"

---

## 第 1 段 · 抓包：协议长什么样

抓包得到的信息：

```
端点：auni.telecome.cn
路径：/a/mdna/report   ← 取 ID（首次注册 h=0）
      /a/adt/report    ← 后续上报
      /a/dcc2/request  /a/dai/report  /a/daa/report
参数：?v=8.7&t=m&p=<32hex>&r=<32hex>&n=0&l=2&h=<32hex>

还有两条备用线路：
  POST /anti_logs   → Host: yumao.puata.info   （带 appkey 头）
  POST /ra         → Host: ccs.umeng.com       （带 appkey 头，Content-Encoding: xgzip）
```

其中：

- `p = MD5(packageName + "." + suffix).upper()`（酷安为 `F9BD0FBDACFE80FCF34370FBCFEE1A98`）
- `h = MD5(DUID + ".889e0b01").upper()`，首次注册为 `"0"`

**支线** → [`docs/01-protocol/01-协议总览.md`](docs/01-protocol/01-协议总览.md)
　　　　[`03-h-算法.md`](docs/01-protocol/03-h-算法.md) ｜ [`04-p-构造.md`](docs/01-protocol/04-p-构造.md)

---

## 第 2 段 · 解加密：body 里是什么

body 是加密的，且**有两套并存**（不同调用路径走不同那套）：

```
① Java 路径（libjavacrypto）
   AES-128-ECB(key="GWL8jXHLnzp63QDH", gzip(JSON))    ← 无盐
   响应用同一个 key 解

② native 路径（libdu 自身）
   zlib.compress(JSON) XOR POOL_KEY
   响应用同一个 POOL_KEY 解
```

**关键坑**：`POOL_KEY` 是 libdu 内存里的**字符串常量**，不是地址。

```
✗ 一开始把文档里的「0x109CF0」当成了密钥值 → 所有解密都失败
✓ 实际密钥是【那个地址处的字符串】：
   0x110DC8  "xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}"   ← mdna 用这个
   0x109CF0  "$%v2TW}pmn];io,^@!B&+=87fqyu<>?:['|{.*`-09(tsb"
   （共 5 个，周期 45~53 字节）
```

换对之后，34 个样本全部解出。

**支线** → [`docs/01-protocol/02-body-加密.md`](docs/01-protocol/02-body-加密.md)

---

## 第 3 段 · 测边界：服务端到底看什么

方法：拿一份真实的 body，**每次只改一个字段**，看响应变化。

结论（约 100 次变体实测）：

```
【必须正确的只有 6 个】
  URL.v      与端点匹配
  body.DUv   精确 == "com.coolapk.market"
  body.3mS   "v9.x" 及以上
  body.2cO   "秒.纳秒"，纳秒非零
  body.AAA   "v1.0"
  body.75c   apiKey（可省略；给了就必须精确）

【完全不参与识别】
  其余 73 个字段：机型 / 厂商 / MAC / 内网 IP / 语言 / 5 个哈希 / 16 个混淆串 / 4 个嵌套对象
  URL 的 p / r / n / l / h / t
  全部 HTTP 头
```

**⇒ 服务端不看设备指纹。** 那它靠什么认设备？这是下一段的问题。

**支线** → [`docs/01-protocol/05-服务端校验边界.md`](docs/01-protocol/05-服务端校验边界.md)

---

## 第 4 段 · 找设备标识：第一次走弯路 ⚠️

**这一段是项目里最值得记录的。**

逻辑上，`pm clear` 之后本地零状态，但重新注册拿到的 DUID 不变
—— 所以请求里**必然存在本地可重算的设备标识**。

于是在 87 个字段里逐字段扫描，看哪个改了会让结果变。

**当时的结论**：`mIS` 是"唯一钥匙、判据种子"。

```
mIS 换成 dLH 的值  → 返回【另一个 DUID】（说明服务端按它查表）
mIS 自造          → 全 0
```

**这个结论是错的。**

### 错在哪

```
扫描时【一直保持 mIS 为真值】——
那个真值足以命中记录，遮蔽了其它所有字段的作用。

⇒ 典型的观测设计缺陷：被观测的量掩盖了要找的量
```

### 怎么发现是错的

先把 `mIS` **随机化**，再逐字段扫描。结果：

```
mIS 换成任意合法 36 字符串 → 服务器【照样返回真 DUID】
```

### 修正后的正确结论

真正的锚点是另三个字段：`sfOo` / `foO` / `2cO`。

**支线** → [`docs/05-mis-history/`](docs/05-mis-history/)（记录错误结论怎么来的）
　　　　[`docs/02-anchor/`](docs/02-anchor/)（正确结论）

---

## 第 5 段 · 工程攻坚：让抓包稳定下来

要拿到注册瞬间的请求，得在目标 App 进程里挂钩子。这段全是坑。

### 5.1 App 检测到注入

```
现象：提示「该应用被注入 so」然后闪退
原因：App 读 /proc/self/maps 扫 frida-agent
```

**错误解法**：挂钩 `read()` 过滤 maps 内容 → **`read` 是极高频函数** → App 直接 ANR

**正确解法（maps 重定向）**：

```
在 open/openat 层拦截对 /proc/*/maps 的访问 →
现场生成一份【滤掉 frida 行】的副本 →
把副本的真实 fd 返回给调用方
⇒ 完全不碰 read，零高频开销
```

### 5.2 反复 ANR

一共踩了五个坑，统一规律是：

```
热路径上的活越少越好。高频函数（read / write / 每次 SSL 记录）绝不挂重钩子。
必需的转换必须加条件筛选，不能无差别执行。
```

### 5.3 那个最隐蔽的 bug：`toHex`

```js
// ✗ 错
const b = new Uint8Array(arr);

// ✓ 对
if (arr && typeof arr.readByteArray === "function") {
    b = new Uint8Array(arr.readByteArray(n));   // NativePointer
} else {
    b = new Uint8Array(arr);                    // Java byte[]
}
```

```
Cipher 钩子传的是 Java byte[]  → 老写法能用
SSL / socket 钩子传的是 NativePointer → 老写法静默返回空

⇒ 结果：所有 SSL 与 socket 数据被【静默丢弃】
⇒ 表象是「抓不到包」，极易误判为过滤条件问题
```

**这个 bug 困扰了整个采集阶段。** 修复后立刻抓到了完整的明文 HTTP 请求。

### 5.4 其它改进

| 问题 | 解法 |
|---|---|
| attach 慢（10–21 秒），错过注册瞬间 | 用 `get_process()` 直查替代 `enumerate_processes()` → **2.4 秒** |
| 点按按钮时误跳浏览器 | 每次点按前重新 dump UI，确认按钮在场才点 |
| 更新弹窗挡住界面 | 白名单点【取消】，黑名单【立即更新】→ 按 BACK 回避 |
| 关键请求被环形缓冲淘汰 | 给 szlm 的 HTTP 请求做**永久保留**的独立数组 |

**支线** → [`docs/03-stealth/`](docs/03-stealth/)（隐身与反调试）
　　　　[`docs/04-devices/`](docs/04-devices/)（设备环境与踩坑）

---

## 第 6 段 · 抓到 mdna：机制澄清

链路修好之后，一次清数据注册就抓到了完整的 `mdna` 报文（79 字段）。

### 6.1 服务端按三元组查表

```
① 命中              → 返回该记录关联的 DUID（与其余 73 字段无关）
② 未命中 + body 完整 → 新建记录，签发【新 DUID】
③ 未命中 + body 精简 → 返回全 0

★ 最小可用 body = 8 个字段：
    DUv + 3mS + 75c + 2cO + sfOo + foO + AAA + BBB
```

### 6.2 三元组的性质

同一台设备**两次注册**的对比：

```
第一次  sfOo = 801C14F              foO = RP|Q|zQKOJ~I~}Q
第二次  sfOo = FD2C5E4              foO = DEo?qBmCp=DoDq>
        ⇒ 三者【都不同】，但 DUID 相同

跨注册【恒定】55 字段（MAC / 机型 / w91 / gEd / 6yY / ne8 …）
跨注册【变化】21 字段（sfOo / foO / 2cO / 及一批混淆串）
```

**⇒ 服务端能从"新的三元组"认出同一设备 ⇒ 三元组内部编码了设备信息。**

### 6.3 没有签名机制

```
把 w91 / gEd / 6yY / ne8 / MAC / 机型 / 内网IP 全部换成随机值
→ 服务器【照样返回真 DUID】

⇒ 不存在「必须由私钥签出」的字段
⇒ 三元组不是签名，而是【编码】
```

### 6.4 一个意外能力

```
完整 body + 随机三元组 → 每次都能拿到一个【有效新 DUID】

⇒ 说明协议本身是开放的：想注册新设备随时可以
```

**支线** → [`docs/02-anchor/`](docs/02-anchor/)（锚点机制 · 核心成果）
　　　　[`docs/02-anchor/02-78字段完整清单.md`](docs/02-anchor/02-78字段完整清单.md)

---

## 第 7 段 · 验证与工具化

### 7.1 实验族（按结论递进）

```
1. field_table.py        看清有哪些字段
2. combo_test.py         只留锚点、其余 72 字段全随机 → 仍返回真 DUID
3. find_real_anchor.py   逐字段哨兵化 → 定位锚点候选
4. anchor_verify.py      排除「类型敏感」的假象
5. random_fp_test.py     确认无签名机制
6. test_identity_key.py  锁定真正识别键 = (sfOo, foO, 2cO)
7. test_adler.py         搞清 body 编码的约束
```

### 7.2 工具

`tools/getduid.py` —— 单文件、零依赖、模板与密钥内嵌。

```sh
python3 tools/getduid.py -n 3      # 固定三值
python3 tools/getduid.py -r -n 5   # 随机三值
```

**跨网络环境对比**（同一请求在不同网络下跑）：

| 结果 | 含义 |
|---|---|
| DUID 相同 | 服务器不依赖出口 IP |
| DUID 不同 | 出口 IP 参与设备识别 |

**支线** → [`tools/`](tools/README.md)

---

## 结论与未解

### 已解答

```
✓ 协议完整解出（端点 / 参数 / 两套加密）
✓ 服务端校验边界测定（87 字段只用 3~6 个）
✓ 设备识别锚点定位（sfOo / foO / 2cO）
✓ 无签名机制
✓ 工具可离线构造有效请求
```

### 未解

```
✗ sfOo / foO 的生成算法
  · 已确认：每次注册都变；编码了设备信息（服务端可解码）
  · 已确认：7 位 hex + 15 字符混淆串，格式固定
  · 未解出：具体构造公式
  · 下一步建议：hook libdu 的 MD5（偏移 0xe23c4 / 0xe1de4），读 x1 寄存器看输入

✗ w91 / gEd / 6yY 三个哈希的输入
  · 已确认：跨注册恒定 + 跨设备不同 ⇒ 设备指纹
  · 已确认：不是 mdna 报文里任何字段的简单拼接（73080 次组合穷举零命中）
  · 下一步：同上，hook MD5 读输入

✗ 2cO 的纳秒部分为何必须是新值、如何参与匹配
```

**⇒ 这三条不影响使用**：取回某台设备的 DUID，只需要该设备的锚点三元组
（抓到一次即可，或者调用官方 SDK）。

**支线** → [`docs/02-anchor/03-缺口总表.md`](docs/02-anchor/03-缺口总表.md)

---

## 支线文档总表

| 主题 | 目录 | 内容 |
|---|---|---|
| 协议层 | [`docs/01-protocol/`](docs/01-protocol/) | 端点、加密、参数算法、校验边界、指纹采集项 |
| **锚点机制** | [`docs/02-anchor/`](docs/02-anchor/) | **核心成果**：mdna 抓取、字段清单、缺口 |
| 隐身与反调试 | [`docs/03-stealth/`](docs/03-stealth/) | maps 重定向、ANR 五坑、toHex bug |
| 设备环境 | [`docs/04-devices/`](docs/04-devices/) | 短命进程、多设备、观测铁律 |
| mIS 专题 | [`docs/05-mis-history/`](docs/05-mis-history/) | **含被推翻的结论**（建议对照第 4 段读） |
| libdu 逆向 | [`docs/06-libdu-history/`](docs/06-libdu-history/) | 静态/动态分析、token 表、编码器 |
| 会话记录 | [`docs/07-sessions/`](docs/07-sessions/) | 逐次记录（含完整命令与原始输出） |
| 工具 | [`tools/`](tools/README.md) | 可运行工具与实验脚本 |
| 采集脚本 | [`scripts/`](scripts/README.md) | Frida 钩子与采集驱动 |
| 数据 | [`data/`](data/README.md) | 样本与解出的明文 |
