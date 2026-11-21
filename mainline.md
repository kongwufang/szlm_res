# 主线：十二个问题，按解决顺序

> 本文按**时间顺序**记录整个逆向过程 —— 每一节都是一个具体问题，写清「怎么发现的 → 怎么试的 → 结果如何」。
>
> ⚠️ **过程里有若干中间结论后来被实验推翻**。这些地方都用醒目的框标出，
> 集中汇总见 [已推翻的结论](docs/99-已推翻的结论.md)。

---

## 起点

一个具体需求：

> 能不能不依赖酷安 App，自己构造请求，让数字联盟返回**这台设备以前注册过的 DUID**？

拆成四个可验证的子问题：

1. 请求长什么样
2. body 里是什么
3. 服务端校验哪些字段
4. 服务端靠什么认出"同一台设备"

后文按实际解决的顺序展开。

---

## 问题 ① 请求长什么样

**做法**：在测试设备上抓包。

**结果**：

```
主机：auni.telecome.cn
路径：/a/mdna/report?  ← 取 ID（首次注册 h=0）
      /a/adt/report?   ← 后续上报
      /a/dcc2/request? /a/dai/report? /a/daa/report?
参数：v=8.7 & t=m & p=<32hex> & r=<32hex> & n=0 & l=2 & h=<32hex>
```

另外还有两条备用线路（走别的域名，带 `appkey` 头）：

```
POST /anti_logs  →  Host: yumao.puata.info
POST /ra         →  Host: ccs.umeng.com     (Content-Encoding: xgzip)
```

**两个参数是可推导的**：

```
p = MD5(packageName + "." + 后缀).upper()
    酷安 → F9BD0FBDACFE80FCF34370FBCFEE1A98

h = MD5(DUID + ".889e0b01").upper()
    首次注册时为 "0"
```

**支线** → [docs/01-请求长什么样.md](docs/01-请求长什么样.md)

---

## 问题 ② body 里是什么

**做法**：解加密。请求 body 是一串二进制。

**第一次失败**：拿文档里记的 `0x109CF0` 当密钥，全部解不开。

**为什么错**：

```
✗ 把【地址】当成了密钥值
✓ 真正的密钥是【那个地址处存放的字符串】
```

**改对之后**，发现加密不止一套，而是**两套并存**（不同调用路径走不同那套）：

```
① Java 路径（libjavacrypto）
   body = AES-128-ECB(key="GWL8jXHLnzp63QDH", gzip(JSON))     ← 无盐
   响应用同一个 key 解

② native 路径（libdu 自身）
   body = zlib.compress(JSON) XOR POOL_KEY
   响应用同一个 POOL_KEY 解
```

**5 个池常量**（都是 libdu 内存里的字符串）：

```
0x110DC8  xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}   ← mdna 用这个
0x109CF0  $%v2TW}pmn];io,^@!B&+=87fqyu<>?:['|{.*`-09(tsb
0x10924C  @dalsdfkSDFSesa!@#tbaf@$%f$%K=^*&0918~Werar=-+^%39(0!
0x1090F8  7.f498yu<>?:['|TWq&/57fqu@7v.ajl#etu{.jqv2fs
0x0FEC5C  Kn];(ts<>5bv2TW?:['|%f$%K6%o,=^erar=87f4B&18~W
```

**结果**：34 个样本全部解出明文。

**支线** → [docs/02-body怎么解.md](docs/02-body怎么解.md)

---

## 问题 ③ 服务端校验哪些字段

**做法**：拿一份真实 body，**每次只改一个字段**，看响应变化。约 100 次变体。

**结果**：

```
【必须正确的只有 6 个】
  URL.v      与端点匹配
  body.DUv   精确 == "com.coolapk.market"
  body.3mS   "v9.x" 及以上
  body.2cO   "秒.纳秒"，纳秒非零
  body.AAA   "v1.0"
  body.75c   apiKey（可省略；给了就必须精确）

【完全不参与识别】
  其余 73 个字段：机型 / 厂商 / MAC / 内网 IP / 语言 /
                 5 个哈希 / 16 个混淆串 / 4 个嵌套对象
  URL 的 p / r / n / l / h / t
  全部 HTTP 头
```

**⇒ 服务端根本不看设备指纹。** 那它靠什么认设备？下一个问题。

**支线** → [docs/03-服务端看哪些字段.md](docs/03-服务端看哪些字段.md)

---

## 问题 ④ 服务端靠什么认出设备 ⟵ ⚠️ 走过一段弯路

这一段是整个项目里最值得记录的。

### 4.1 逻辑起点

```
pm clear 之后本地零状态，但重新注册拿到的 DUID 不变
⇒ 请求里必然存在【本地可重算的设备标识】
```

### 4.2 第一次尝试（错误）

在 87 个字段里**逐字段扫描**，看哪个改了会让结果变化。

**当时的结论**：

```
mIS 换成别的已知值  → 返回另一个 DUID（像在按它查表）
mIS 自造 36 字符串  → 全 0
⇒ 判断：mIS 是"唯一钥匙、判据种子"
```

> ⚠️ **这个结论是错的。** 它写进了当时的文档，并在此基础上做出了一系列错误推断。
> 详见 [已推翻的结论](docs/99-已推翻的结论.md#1-mis-是唯一钥匙)。

### 4.3 错在哪

```
扫描时【一直保持 mIS 为真值】——
那个真值足以命中记录，把其它所有字段的作用都遮蔽了。

⇒ 典型的观测设计缺陷：被观测的量掩盖了要找的量
```

### 4.4 修正做法

**先把 `mIS` 随机化，再逐字段扫描。**

**结果**：

```
mIS 换成任意合法 36 字符串 → 服务器照样返回真 DUID
⇒ mIS 与设备识别无关
```

### 4.5 正确结论

真正的锚点是另外三个字段：

```
sfOo   7 位大写十六进制        例 801C14F
foO    15 字符混淆串           例 RP|Q|zQKOJ~I~}Q
2cO    "秒.纳秒" 形式的时钟读数  例 1791105420.764024281
```

服务端按**这三元组查表**：

```
① 命中                → 返回该记录关联的 DUID（与其余 73 字段无关）
② 未命中 + body 完整   → 新建记录，签发【新 DUID】
③ 未命中 + body 精简   → 返回全 0

★ 最小可用 body = 8 个字段：
    DUv + 3mS + 75c + 2cO + sfOo + foO + AAA + BBB
```

### 4.6 三元组的性质

同一台设备**两次注册**的对比：

```
第一次  sfOo = 801C14F   foO = RP|Q|zQKOJ~I~}Q
第二次  sfOo = FD2C5E4   foO = DEo?qBmCp=DoDq>
        ⇒ 三者【都不同】，但 DUID 相同

跨注册【恒定】55 字段（MAC / 机型 / w91 / gEd / 6yY / ne8 …）
跨注册【变化】21 字段（sfOo / foO / 2cO 及一批混淆串）
```

**⇒ 服务端能从"新的三元组"认出同一设备 ⇒ 三元组内部编码了设备信息。**

### 4.7 有没有签名机制？

```
把 w91 / gEd / 6yY / ne8 / MAC / 机型 / 内网 IP 全部换成随机值
→ 服务器【照样返回真 DUID】

⇒ 不存在「必须由私钥签出」的字段
⇒ 三元组不是签名，而是【编码】
```

**支线** → [docs/04-怎么认出设备.md](docs/04-怎么认出设备.md)
　　　　[已推翻的结论](docs/99-已推翻的结论.md)

---

## 问题 ⑤ 怎么稳定抓到包

要拿到注册瞬间的请求，得在目标 App 进程里挂钩子。这段全是坑。

### 5.1 被检测到注入

```
现象：提示「该应用被注入 so」然后闪退
原因：App 读 /proc/self/maps 扫 frida-agent
```

**错误解法**：挂钩 `read()` 过滤 maps 内容
→ **`read` 是极高频函数，每次读都进 JS 回调** → App 直接 ANR

**正确解法 —— maps 重定向**：

```
在 open/openat 层拦截对 /proc/*/maps 的访问
  → 现场生成一份【滤掉 frida 行】的副本
  → 把副本的真实 fd 返回给调用方
⇒ 完全不碰 read，零高频开销
```

### 5.2 反复 ANR（一共五个坑）

```
① 无差别 hex 转换    每条 SSL 记录都转 16KB → 千万次 JS 操作
② read() 过滤 maps   read 极高频
③ 放宽 SSL 过滤      转 hex 的量暴涨
④ SOCK 一律 hex      又钩了 write（频率极高）
⑤ 缓存的按钮坐标点按  页面一变就点到《用户协议》链接 → 跳浏览器

【统一规律】
  热路径上的活越少越好。高频函数（read / write / 每次 SSL）绝不挂重钩子；
  必需的转换必须加条件筛选，不能无差别执行。
```

### 5.3 最隐蔽的一个 bug：`toHex`

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
Cipher 钩子传的是 Java byte[]        → 老写法能用
SSL / socket 钩子传的是 NativePointer → 老写法静默返回空

⇒ 结果：所有 SSL 与 socket 数据被【静默丢弃】
⇒ 表象是「抓不到包」，极易误判为过滤条件问题
```

**这个 bug 困扰了整个采集阶段**（当时误以为是过滤太严，去改过滤条件，反而引发 ANR）。
修复后立刻抓到了完整的明文 HTTP 请求。

### 5.4 其它改进

| 问题 | 解法 |
|---|---|
| attach 慢（10–21 秒），错过注册瞬间 | 用 `get_process()` 直查替代 `enumerate_processes()` → **2.4 秒** |
| 点按按钮时误跳浏览器 | 每次点按前重新 dump UI，确认按钮在场才点 |
| 更新弹窗挡住界面 | 白名单点【取消】，黑名单【立即更新】→ 按 BACK 回避 |
| 关键请求被环形缓冲淘汰 | 给 szlm 的 HTTP 请求做**永久保留**的独立数组 |

**支线** → [docs/05-怎么稳定抓包.md](docs/05-怎么稳定抓包.md)

---

## 问题 ⑥ 抓到了 mdna，然后呢

链路修好后，一次清数据注册就抓到了完整的 `mdna` 报文（79 字段），
验证了问题 ④ 的结论，也拿到了可直接使用的工具。

**支线** → [docs/06-字段参考.md](docs/06-字段参考.md)

---

## 问题 ⑦ 能不能拿一个全新 ID

```
完整 body + 随机三元组 → 每次都能拿到一个【有效新 DUID】
```

但有个前提：

```
只改三值(sfOo/foO/2cO)               → 全 0（服务器判「不自洽」）
三值 + w91/gEd/6yY 一起改             → 新 DUID ✓
```

**⇒ 协议本身是开放的：想注册新设备随时可以。**

工具：[`tools/getduid.py`](tools/README.md) 的 `-r` 模式已处理这个细节。

---

## 问题 ⑧ 换网络环境还成立吗

`tools/getduid.py` 固定三值模式下，同一请求在不同网络跑：

| 结果 | 含义 |
|---|---|
| DUID 相同 | 服务器不依赖出口 IP |
| DUID 不同 | 出口 IP 参与设备识别 |

**支线** → [tools/README.md](tools/README.md)

---

## 问题 ⑨ 字段到底是什么内容

解出编码后，才发现前面几节说的"混淆串"根本不是随机垃圾，而是**可读的设备档案**。

### 编码规则

```
P       = 2cO 最后 3 个字符去掉 '.' 后 atoi
K       = P % 100 % 57 + 1               在 0x20..0x7E 内循环右移
variant = P // 100 % 4                   四种重排之一

编码 = shuffle(shift(value, K), variant)
解码 = shift(unshuffle(value, variant), -K)
```

**★ 参数就藏在同一份报文自己的时间字段 `2cO` 里。**

**⇒ 一位逆向同行（[People-11](https://github.com/People-11)）先观察到「字符 +1 加重排」并给出了可用解码器；
我顺着他的思路独立发现了「不是裸 ASCII 偏移，而是 mod-95 环」，
但只覆盖了四种重排里的第一种。**
**完整的参数推导 —— `P` 取自 `2cO`、`K` 与 `variant` 的公式、四种重排的定义 —— 是他后来解出的。**
**详见 [CREDITS.md](CREDITS.md)。**

### 解出来是什么

一份报文完整解码（`P=68` → `K=12`, `variant=0`）：

```
foO  → 288daec8ec17639                     ANDROID_ID 前 15 位
dLH  → c009c04e-f985-42ba-b41a-f49d0345988b   boot_uuid
dJs  → 150100525831424d420751004057c400     eMMC CID
p1m  → 0x51004057                          eMMC 序列号
zvW  → 06fb5d9bd9d8921842811d8021d95c6c     Canvas 指纹 MD5
5Tv  → 72f3b7de3fac3ef63923efbaadd02cdc     libcutils.so MD5
52J  → 7754:1,11548:20,11938:20,…          10 个路径的 inode:dev
Bos  → 1735690118.109999897,…              目录访问/修改时间
```

**跨注册对比**：`dJs` / `p1m` / `zvW` / `5Tv` / `52J` / `Bos` **逐字节相同**，
只有 `dLH`（每次安装重生成）和带当前时间的字段变化。

**⇒ 这反证了解码正确 —— 参数若算错，不可能 6 个字段同时对齐。**

### `sfOo` 其实是校验值

```
foO  = ANDROID_ID 前 15 位的编码（mode 10，去掉了第 16 位）
sfOo = MD5_UPPER(str(全部 16 位码位之和 + P%100//10))[:7]
```

**⇒ 用 `sfOo` 可以确定被去掉的那一位（16 个 hex 候选里只有一个对得上）。**

**⇒ 所以「`sfOo` 是锚点字段」这个说法要修正：它是 `foO` 的校验值，
而 `foO` 编码的是 ANDROID_ID。**

### 顺带解开的两个老问题

```
w91 = /system/fonts 文件名列表的 MD5
gEd = libreference-ril.so 或 libc.so 的 MD5
6yY = Widevine deviceUniqueId
mIS = /proc/sys/kernel/random/boot_id（每次开机变）
```

**⇒ 这就是为什么当初做 73080 次字段组合穷举零命中 —— 输入根本不在报文里。**

**支线** → [docs/08-破解字段编码.md](docs/08-破解字段编码.md)

---

## 问题 ⑩ 到底有没有签名校验

前面九节全是「改报文」得出的结论。但改报文有个天然缺陷：

> **报文里没有的东西，你能证明它在服务端被校验吗？**

签名就是典型的例子。报文里从头到尾没有任何看起来像证书指纹的字段，
但 SDK 完全可能在本地校验完签名才发请求。

**⇒ 只有一条路能排除：造一个签名完全不同的 App，看它能不能拿到 DUID。**

### 10.1 摸清调用方式

从脱壳 DEX 里反编译出 `cn.shuzilm.core.Main`：

```java
Main.init(Context, String apiKey, boolean);
String duid = Main.getQueryID(Context, "", "", true);
```

`init()` 第一件事是校验 apiKey 格式，不合格直接
`Log.e("[shuzilm]", "apikey error.")` 然后 return。

### 10.2 apiKey 的格式（反汇编还原）

```
长度必须 42，以 "11" 开头，index 2 是校验位

i3 = Σ bitCount(hex[i])   for i in 3..9
i4 = Σ (i-2) * hex[i]     for i in 3..9
i5 = 索引 3..9 拼成的整数
check = ((i3 + i4 + (((i5>>>17)^((i5>>>7)^i5)) & 0xFF)) % 15) + 1
```

**而 `75c` 字段的值正好是这个格式** —— 它就是 apiKey。

### 10.3 三个坑

| 现象 | 根因 |
|---|---|
| `apikey error` | 传成了 config 里的 RSA 公钥（128 字符），不是 42 字符的 `75c` |
| `ClassNotFoundException: AIClient` | SDK 被拆成 3 个 DEX，只放了一个 |
| `JNI_ERR returned from JNI_OnLoad` | `libdu.so` 版本和 DEX 不配套 |

### 10.4 结果

自签名（`CN=DUID Probe`）、180 行 Activity、55 个 SDK 类、1.5 MB APK：

```
package = com.coolapk.market
★★★★★ 拿到 DUID: DU8N1bbZfcNSfbmsBFOhsJslrOSOR3dL6eg5
```

**同一个 APK 只改包名为 `com.tencent.mm`：**

```
★★★★★ 拿到 DUID: 000000000000000000000000000000000000
```

**⇒ 不校验签名，只校验包名。**

**支线** → [docs/10-自己造App验证.md](docs/10-自己造App验证.md)

---

## 问题 ⑪ 包名到底怎么校验

既然改包名会被拒，那规则是什么？

### 11.1 白名单探测（24 个包名）

固定 AID / P=0 / foO / 75c，只变 `DUv`：

```
通过 10 个：
  com.coolapk.market        ★ 36
  com.zhihu.android         ★ 88
  com.sina.weibo            ★ 88
  com.ss.android.ugc.aweme  ★ 36
  com.xingin.xhs            ★ 36
  com.netease.cloudmusic    ★ 36
  tv.danmaku.bili           ★ 36
  com.smile.gifmaker        ★ 36
  com.baidu.searchbox       ★ 36
  com.sohu.newsclient       ★ 36

拒绝 14 个：
  com.tencent.mm / com.taobao.taobao / com.jingdong.app.mall
  com.eg.android.AlipayGphone / com.baidu.BaiduMap / com.autonavi.minimap
  com.github.gavin.smid / com.github.tangbin.smid / …
```

### 11.2 三个推论

**① 按「具体 App」维护，不是按厂商**

```
com.baidu.searchbox   → ★ 36
com.baidu.BaiduMap    → ✗ 全 0
```

**② 不是「包名 ↔ apiKey 配对校验」**

`com.zhihu.android` + 酷安的 apiKey 照样成功。

**③ apiKey 完全不参与门控**

同一批包名，`75c` 保留 / 删除，两列结果完全一致。

### 11.3 36 vs 88 两种长度

88 = 36 + base64(36 + "shu")，自校验结构。
同一个服务端、同一份报文，只换包名就能拿到两种长度
**⇒ 长度是账户级配置，不是版本差异。**

**支线** → [docs/11-包名白名单.md](docs/11-包名白名单.md)

---

## 问题 ⑫ 官方说法和实测差多少

拿官方隐私政策的每一项声明，逐条对照解密出来的字段。

### 12.1 政策在哪

官网 `shuzilm.cn/privacy` 是纯 JS 渲染，抓不到正文。
用镜像站拿到全文（最新版 2026-04-04）。

### 12.2 政策主动删了什么

2026-04-04 版相比上一版：

| 条目 | 变化 |
|---|---|
| GPS 坐标（「设备大地坐标」） | **删除** |
| `ACCESS_FINE_LOCATION` | **删除** |
| MAC 处理方式 | 改为「仅检测可获取性，不存储原始值」 |
| 应用列表 | 升级为「默认关闭 + 双重同意」 |

**⇒ 政策方向明确收紧。**

### 12.3 但实测还有落差

**① GPS 坐标：政策已删，v9.0.1 仍在采**

```
"G8U": { "H4S": "25.474575,1.646057" }   ← 小数点后 6 位
```

政策只写「设备所在地区（如中国与美国）」。

**② 真实 MAC：政策说「不存储原始值」，v8.4.0 明文上报**

```
"LLS": "20:0E:3C:11:58:F7"
```

✅ 但 v9.0.1 已整改，只剩伪 MAC。

**③ 唯一标识符清单不完整**

政策只列 IDFV/IDFA/Android\ID/Boot\ID/OAID/UAID，
实测还有 Widevine DRM deviceUniqueId、eMMC CID、eMMC 序列号。

**④ 「Rijndael 256 位」的说法不准**

传输层实际是 **zlib + XOR**（密钥硬编码在 so 里），
AES 只用于本地落盘。

**支线** → [docs/12-合规对照.md](docs/12-合规对照.md)

---

## 剩下的未解问题

```
① 非标准设备上 P1J 与 ANDROID_ID 对不上
   · 标准机上 P1J = SHA1_UPPER(AID)[1:7]:[13:19]:[7:13] 成立
   · 我这台手表（TK Watch, Android 8.1）解出的 AID 反推不出 P1J
   · 两份报文算出的 AID 还不同
   · 下一步：换标准手机验证

② 2cO 纳秒部分的精确来源与服务端时间窗

③ mode 1 / 7 的变换（只有 hH1、9P6 等少数字段用）
```

**支线** → [docs/07-未解问题.md](docs/07-未解问题.md)

---

## 文档地图

| 主题 | 文档 |
|---|---|
| **问题① 协议形态** | [docs/01-请求长什么样.md](docs/01-请求长什么样.md) |
| **问题② body 加密** | [docs/02-body怎么解.md](docs/02-body怎么解.md) |
| **问题③ 校验边界** | [docs/03-服务端看哪些字段.md](docs/03-服务端看哪些字段.md) |
| **问题④ 设备识别** | [docs/04-怎么认出设备.md](docs/04-怎么认出设备.md) |
| **问题⑤ 抓取链路** | [docs/05-怎么稳定抓包.md](docs/05-怎么稳定抓包.md) |
| **问题⑥ 字段参考** | [docs/06-字段参考.md](docs/06-字段参考.md) |
| **问题⑦ 未解问题** | [docs/07-未解问题.md](docs/07-未解问题.md) |
| **问题⑨ 字段编码** | [docs/08-破解字段编码.md](docs/08-破解字段编码.md) |
| **问题⑩ 造 App 验证** | [docs/10-自己造App验证.md](docs/10-自己造App验证.md) |
| **问题⑪ 包名白名单** | [docs/11-包名白名单.md](docs/11-包名白名单.md) |
| **问题⑫ 合规对照** | [docs/12-合规对照.md](docs/12-合规对照.md) |
| ⚠️ **被推翻的结论** | [docs/99-已推翻的结论.md](docs/99-已推翻的结论.md) |
| 工具 | [tools/README.md](tools/README.md) |
| 采集脚本 | [scripts/README.md](scripts/README.md) |
| 数据样本 | [data/README.md](data/README.md) |
| 采集产物 | [captures/README.md](captures/README.md) |
| 历史文档归档 | [docs/_archive/](docs/_archive/) |
