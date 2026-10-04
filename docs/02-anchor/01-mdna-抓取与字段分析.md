# ★ 归档 · 2026-10-04 会话成果（mdna 抓取打通 + 字段分析）

> 设备：D1 `10.0.0.37:5555`（TK_Watch, SDK27）/ D2 `10.0.0.7:5555`（XTQ_Watch, SDK28）
> 状态：**mdna 报文已完整抓到并解出** —— 这是本会话的最终成果

---

## 一、★★★ 成果一：抓到了完整的 mdna 报文

```
POST /a/mdna/report?v=8.7&t=m&p=F9BD0FBDACFE80FCF34370FBCFEE1A98&r=5bb7efdd4c794f0e9563317b7802b995&n=0&l=2&h=0
Content-Length: 1371
Content-Type: application/x-www-form-urlencoded
User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.1; TK Watch Build/OPM2.171019.012)
Host: auni.telecome.cn

body: 00ecea3f8d48fa30252327e9a489732e…（1371 字节）
```

**解密路径：`池常量 0x110DC8 XOR` → `zlib` → JSON（79 字段）**

### 解出的完整报文（D1 首次注册）

```json
{"DUv":"com.coolapk.market","Qg1":1790980402778,"LMi":1790980402778,"Zrs":2609151,
 "EV2":"16.6.2","SAN":27,"h6Z":"酷安","R41":"8.1","Ra":"ABSENT","R53":"0","R63":"running",
 "QgA":1,"qH9":"0","iZS":0,"ZZA":0,"S6e":1,
 "90P":"IJ",
 "Q23":"user:e4e40166.0+CN=数据包捕获CA证书;user:87bc3517.0+OU=HttpCanary,O=HttpCanary,CN=HttpCanary Root CA;",
 "YWu":"127.0.0.1+localhost;::1+ip6-localhost;","bzt":"0000","5mZ":0,"0KQ":0,"Chh":0,
 "Xl9":"0000","D32":4,"LAh":"IIJIIIII","wlM":1,"nur":0,"tth":1,"c2O":"1","PV8":"7",
 "AYk":"13A365:CCAF40:AD4AA9","P1J":"13A365:CCAF40:AD4AA9","R37":"TK Watch","R3d":"TK Watch",
 "AAA":"v1.0","BBB":"v1.0","3mS":"v9.0.1",
 "2cO":"1791105420.764024281",                       ← ★ 锚点
 "K5f":"F8E4D9D1F967D773DFA6381BA10102E9","GVp":"coolapk",
 "iYB":{...},"7S2":{...},
 "ne8":"97313e29420c51d0d8cc6e3a3586889a",
 "sfOo":"801C14F",                                   ← ★★★ 设备锚点（7 位 hex）
 "foO":"RP|Q|zQKOJ~I~}Q",                            ← ★★★ 设备锚点（15 字符混淆）
 "dJs":"IMPIIJPK}KJQKIJNI|NMINIMMMLNNIIJ",
 "w91":"529D912CF3C16EC094E0AD57FFD19589",
 "G8U":{"MYA":"IOPOIOKMIEPRQ","H4S":"PIMGEPMMNNOOJNNPGK"},
 "zvW":"||RJI}JKQKQR{}{OON}KQJQMJR}}RN I",
 "gEd":"9e077ef78ef33b84b98eeb2615feacee",
 "5Tv":"||I}z LRO~| ~PLK}K}z{~KL LzL}{ P",
 "52J":"RLOJREKKKESEKMPELOSLEJIREKOSKEKQRJISMJESNPKOSRKRSRKIIJSIRJLOMNQSORRLOOMISLJEKQNJJMP",
 "p1m":"PIIJ2NMINI",
 "Bos":"PQRRJQJRNPERRRIGJIOLJRRRIGJIOLJPQRRJQJRNP",
 "IJK":"PRMILMMIJPERRROGJRPLJKJINGQNJRJLRRRJKKQNP",
 "ura":"PRMILMMIJPERRROGJRPLJKJINGQNJRJLRRRJKKQNP",
 "ibF":"IIIFFI",
 "IAI":"JPMIMILNNPERRRLGJIOLJOPIRGQOQOJOQRRNRJRNP",
 "aFw":"NRMIRJMIJPERRRKGIRPLJOJIRGLNJRJMRRRPRKQNP",
 "KyU":"JRMIPNLIJPRJIRGRNJRJ",
 "6yY":"0306f8ee3e9e99964ce29c62439d4e5f937e2f9189c18d6a8e844d27eb38b95b",
 "UOv":"NQQLRLRQJPKQRJGKNIRJ",
 "JPd":"0","J7w":0,"zpA":"WIFI","bf7":"0","wSK":"10.0.0.37","fPV":"CN,zh","Db2":2,"QVn":0,
 "msg":{"custom":""},
 "dLH":" NNzM~FRQKLFP{K| |JOLRONLQFKMzKFPOO{","4VP":1,
 "za7":"1_1791105420_",
 "75c":"11e7b222083a4b732b4b14811f6fc05995a01415eb",   ← apiKey 常量
 "fxb":100344,"B3k":67020,"cHo":0}
```

---

## 二、★★★ 成果二：找到并修复了「SSL/SOCK 数据被静默丢弃」的根本 bug

```js
// ✗ 修复前（从 c3 那次起一直在跑）
function toHex(arr, n) {
    const b = new Uint8Array(arr);     // ← NativePointer 不能用这个
    ...
}

// ✓ 修复后
function toHex(arr, n) {
    let b = null;
    try {
        if (arr && typeof arr.readByteArray === 'function') {
            const ab = arr.readByteArray(n);      // NativePointer 路径
            if (ab) b = new Uint8Array(ab);
        }
    } catch (e) { }
    if (!b || b.length === 0) {
        try { b = new Uint8Array(arr); } catch (e) { }   // Java byte[] 路径
    }
    if (!b || b.length === 0) return '';
    ...
}
```

**影响**：
```
CIPHER 的 arr = Java byte[]  → 老写法可用 → hex 正常
SSL/SOCK 的 arr = NativePointer → 老写法返回长度 0 → hex 恒空

⇒ c3 之后所有抓包中，SSL 与 SOCK 的数据【全部被静默丢弃】
⇒ 我误判为「SSL 过滤条件太严」，去改过滤条件 → 反而引发 ANR
⇒ mdna 一直就在 SSL 里，只是被这个 bug 吞掉了
```

**验证**：修复后立刻抓到
```
POST /service/2/app_log/?version_code=2609151&... HTTP/1.1
Host: log.zijieapi.com
User-Agent: …   Content-Length: 1590
```

---

## 三、★★★ 成果三：`KEEPS` 永久保留机制

```js
// 问题：recs 超过 2000 条会 splice 掉最老的 800 条
//      而 mdna 在注册最早期（t≈77s）发出 → 一直被冲掉
if (recs.length > 2000) recs.splice(0, 800);

// 解法：给 szlm 的 HTTP 请求单独存一份【永不淘汰】
const KEEPS = [];
...
if (rr.hex && (src === 'SSL' || src === 'SOCK')) {
    const h0 = rr.hex.slice(0, 8);
    if (h0 === '504f5354' || h0 === '47455420') {          // POST / GET
        if (rr.hex.indexOf('74656c65636f6d65') >= 0         // "telecome"
            || rr.hex.indexOf('6d646e61') >= 0              // "mdna"
            || rr.hex.indexOf('61756e69') >= 0) {           // "auni"
            KEEPS.push(Object.assign({}, rr));
        }
    }
}
// dump 时输出为 KEEP p<pid> t=… 行
```

**⇒ 加上这个之后，`mdna` 立刻就被抓到了。**

---

## 四、★★★ 成果四：78/79 字段分析 —— 只有 6 个有意义

### 4.1 ★ 推翻了文档三条旧结论

| 文档旧说法 | 实测 |
|---|---|
| `mIS` 是"唯一钥匙、判据种子" | ❌ **换成任意合法 36 字符串，服务器照样返回真 DUID** |
| `sfOo`/`foO` 是"可删的混淆串" | ❌ **它们是真正的设备锚点** |
| 必需字段含 `mIS` | ❌ 应为 `DUv/3mS/75c/2cO/sfOo/foO` |

**根因**：文档的 87 字段扫描**一直保持 `mIS` 为真值** —— 那个真值足以命中记录，
遮蔽了其它字段的作用（观测设计缺陷）。

### 4.2 ★ 组合盲区测试（决定性）

```
基线（全真）                                  → 真 DUID
只留 6 锚点，其余 72 字段【全部随机化】         → ★★★ 仍返回真 DUID
只留 5 个（去 75c）                            → 全 0
只留 2cO+sfOo+foO（去 DUv/3mS/75c）           → 全 0
全随机                                        → 空

排除法（从全真出发整类随机化，全部通过）：
  5 个 hex 哈希 K5f/ne8/w91/gEd/6yY            → 仍真 DUID
  15 个混淆串                                   → 仍真 DUID
  4 个嵌套对象 iYB/7S2/G8U/msg                  → 仍真 DUID
  设备属性 AYk/P1J(MAC)/R3d(机型)/R37/wSK       → 仍真 DUID
  时间戳 Qg1/LMi/za7                            → 仍真 DUID
```

**⇒ 整个 body 只有 6 个字段有意义，其余 72 个（含全部设备指纹）一个都不参与识别。**

### 4.3 最小可用 body

| # | 字段 | 值 | 性质 |
|---|---|---|---|
| 1 | `DUv` | `com.coolapk.market` | 常量 |
| 2 | `3mS` | `v9.0.1` | 常量 |
| 3 | `75c` | `11e7b222…15eb` | apiKey 常量（**跨设备相同已验证**） |
| 4 | `2cO` | 时间戳 秒.纳秒 | 锚点 |
| 5 | `sfOo` | 7 位 hex | **设备锚点** |
| 6 | `foO` | 15 字符混淆 | **设备锚点** |

### 4.4 ★★ `sfOo` / `foO` 跨设备对比（新证据）

```
D2 (XTQ_Watch) : sfOo = "4A213D3"          foO = "W***]TZTYX**X(W"
D1 (TK_Watch)  : sfOo = "801C14F"          foO = "RP|Q|zQKOJ~I~}Q"
                 ⇒ ✗ 完全不同  ⇒ 确认是设备相关的值

75c (apiKey)   : 两台设备完全相同  ⇒ 确认是常量
```

**⇒ 两者都是 7 位大写 hex（`sfOo`）和 15 字符混淆串（`foO`），格式固定、取值随设备变。**

---

## 五、★★★★ 成果五：机制完全讲通 —— 两条不同的路径（路线级发现）

### 5.1 决定性实验：D1 同设备两次注册的逐字段对比

```
第一次  sfOo = "801C14F"              foO = "RP|Q|zQKOJ~I~}Q"
第二次  sfOo = "FD2C5E4"              foO = "DEo?qBmCp=DoDq>"
        ⇒ ✗ 每次注册都【变化】

★ 跨注册【恒定】55 个字段，【变化】21 个
  恒定的包括：DUv / AYk(MAC) / R37 / R3d / w91 / gEd / 6yY / ne8 / wSK / 75c / Qg1 / LMi …
  变化的包括：sfOo / foO / 2cO / K5f / UOv / dLH / zvW / 5Tv / 52J / Bos / IJK / IAI /
             aFw / KyU / ibF / dJs / p1m / LAh / 90P / za7 / Zne / iYB.* / 7S2.* / G8U.*
```

### 5.2 ★★★ 两条路径（这解释了过去所有看似矛盾的实验）

```
① 回放路径（body 带 ubF=DUID）—— 我之前所有锚点实验走的都是这条
   服务端按 (sfOo, foO, 2cO) 三元组【命中已存记录】→ 返回 DUID
   ⇒ 改这三个 → 全 0；改别的恒定字段 → 无影响

② 注册路径（h=0，真实注册）—— D1 两次注册走的都是这条
   服务端按【恒定设备指纹】认出设备 → 沿用老 DUID
        （D1 两次都是 DUaVFlbAMrmH2Z57PEhm_N9EO4RoUdvNstg5）
   ⇒ (sfOo, foO, 2cO) 每次都是新的值，服务端照收
```

### 5.3 ★★★ 区分「设备指纹」与「常量」

| 字段 | D1 | D2 | 判定 |
|---|---|---|---|
| `ne8` | `97313e…889a` | `97313e…889a` | **两台相同 ⇒ 常量**（不是指纹） |
| **`w91`** | `529D912C…9589` | `922BD642…8897` | **跨注册恒定 + 跨设备不同 ⇒ ★ 设备指纹** |
| **`gEd`** | `9e077ef7…cee` | `7bee6511…572` | **同上 ⇒ ★ 设备指纹** |
| **`6yY`** | `0306f8ee…95b` | `c48ed04b…44f` | **同上 ⇒ ★ 设备指纹** |
| `AYk`(MAC) | `13A365:…` | `6F824D:…` | 设备指纹（但服务端不用） |
| `sfOo`/`foO`/`2cO` | 每次注册都变 | — | 每次注册新生成的会话标识 |

### 5.4 ★★★★★ 对目标的重大含义

```
若机制假设成立 ⇒ sfOo / foO 【不需要逆向】！
   它们在每次注册时都是新的值，服务端的【注册路径】不靠它们认设备

您的 app 只需：
   1. 复刻三个设备指纹哈希  w91 / gEd / 6yY      ← ★ 新的攻关点
   2. 生成随机的 (sfOo, foO, 2cO)
   3. 发 /a/mdna/report，h=0
   4. 服务端按指纹认出设备 → 返回老 DUID

⇒ ★ 攻关目标从「36 字符混淆串的算法」变成「三个哈希的输入是什么」
  而这三个都是标准 MD5/SHA256，且跨注册恒定、跨设备不同
  ⇒ 输入是稳定的设备属性
```

### 5.5 但简单组合穷举失败（已做）

```
把 D1 的 29 个已知设备属性做：
  · 单值 × 4 种编码 × 3 种哈希
  · 两值/三值组合 × 9 种分隔符 × 两种顺序 × 3 种哈希
  共 73080 次 —— 零命中

⇒ 输入不是这些字段的简单拼接，而是【更底层的设备属性】
```

### 5.6 ★ 下一步（明确）

```
在真机上 hook libdu 的 MD5，直接读它的输入：
   0xe23c4  MD5 包装（22 处调用）
   0xe1de4  MD5 实体
   寄存器约定（FINGERPRINT_REPORT.md §二 实测）：
     x0 = 输出缓冲（跨调用恒定）
     x1 = ★ 输入数据（每次变化，位于栈区）
     返回值 r = 字符串指针（不是 x0 缓冲）

文档已抓到的指纹项包括：
   boot_uuid / boot_times / 包名+签名后缀 / 签名证书 DER /
   boot classpath 清单 / 系统字体清单 / 固件驱动标识 / 已装应用列表
```

---

## 六、★ 当前假设（已由实验回答）

```
sfOo / foO 可能是：
  (a) 设备指纹             → ✗ 已被否掉（每次注册都变）
  (b) 设备指纹 + 签名        → ✗ 同上
  (c) 服务端下发的种子       → ✗ 同上
  ★ 实际：它们是【每次注册新生成的会话标识】，
          不参与注册路径的设备识别 ⇒ 【不需要逆向】
```

---

## 七、★★ 工程改进（本会话）

| 改进 | 效果 |
|---|---|
| **toHex 双路径修复** | ★★★ SSL/SOCK 数据从「全部丢弃」变为「完整抓到」 |
| **KEEPS 永久保留** | mdna 不再被 recs 淘汰 |
| **get_process 直查** | attach 从 10-21 秒降到 **2.4 秒** |
| **去掉 write 钩子** | 只留 send/sendto，避免高频 ANR |
| **SOCK 只对 HTTP 形态做 hex** | 避免 2986 条 × 4096 字节的转换 |
| **弹窗白名单/黑名单** | 自动回避「立即更新」 |
| **安全点按** | 每次重新 dump UI 确认按钮在场 |
| **降密度 140**（`wm density`）| 解决小屏「协议页按钮被挤出」 |

---

## 七、★ ANR 五坑（全部记下来）

```
① 无差别 hex（16384×N）→ 4221 条 ≈ 7000 万次 JS 操作
② read() 钩子过滤 maps → read 极高频
   ★ 正解：改在 open/openat 层做 maps 重定向
③ SSL 过滤「放宽」→ hex 转换量暴涨
④ SOCK 一律 hex + 钩 write → 2986 条 × 4096
   ★ 正解：SOCK 只对 HTTP 形态做 hex；去掉 write
⑤ 缓存的按钮坐标点按 → 点到《用户协议》链接 → 跳浏览器
   ★ 正解：每次点按前重新 dump UI

【统一规律】热路径上的活越少越好；高频函数（read/write/每次 SSL）绝不挂重钩子
```

---

## 八、★ 关键数字速查

```
解密池常量（4 个，都是地址处的【字符串】）：
  0x109CF0  "$%v2TW}pmn];io,^@!B&+=87fqyu<>?:['|{.*`-09(tsb"
  0x10924C  "@dalsdfkSDFSesa!@#tbaf@$%f$%K=^*&0918~Werar=-+^%39(0!"
  0x1090F8  "7.f498yu<>?:['|TWq&/57fqu@7v.ajl#etu{.jqv2fs"
  0x0FEC5C  "Kn];(ts<>5bv2TW?:['|%f$%K6%o,=^erar=87f4B&18~W"
  0x110DC8  ← mdna/dcc2/adt 用的（本次验证）

端点：
  /a/mdna/report?v=8.7&t=m&p=…&r=…&n=0&l=2&h=0   ← 拿 ID（首次注册 h=0）
  /a/adt/report?v=…    /a/daa/report?v=…    /a/dcc2/request?v=2.0
  /a/dai/report?v=2.2  /a/audd/report?v=…

p  = MD5("com.coolapk.market" + "." + "37be8a1ee106979a").upper() = F9BD0FBDACFE80FCF34370FBCFEE1A98
h  = MD5(DUID + "." + "889e0b01").upper()，首次为 "0"（服务端不校验）

设备 DUID：
  D1 TK_Watch  DUaVFlbAMrmH2Z57PEhm_N9EO4RoUdvNstg5
  D2 XTQ_Watch DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9
  D3 LineageOS DU8N1bbZfcNSfbmsBFOhsJslrOSOR3dL6eg5
  D4 Phh-Treble DU1pGU7EXcGo9LQWg8PIHk9uBFUqDjnlVJg6
```

---

## 九、★ 文件清单（本会话新增/关键）

| 文件 | 作用 |
|---|---|
| **`hook_stealth2.js`** | ★ 最终钩子：maps 重定向 + 完整反调试 + SSL/SOCK/Cipher 采集 + **toHex 修复** + **KEEPS** |
| **`early_capture2.py`** | ★ 采集驱动：设备端守望 + get_process 直查 + 安全点按 + 弹窗处理 + 截图 |
| `decode_mdna_final.py` | 解 mdna body |
| `mis_random_matrix.py` / `find_real_anchor.py` / `anchor_verify.py` / `combo_test.py` | 字段锚点实验族 |
| `field_table.py` | 78 字段完整清单生成 |
| `pull_d1c2.py` / `pull_d1d.py` | 拉取（base64 逐个文件，绕开 shell 陷阱） |
| `FIELDS_mdna_78.md` | 字段总表 |
| `GAPS_2026-10-04.md` | 缺口总表 |
| `STEP_2026-10-04f_TOHEX_BUG_AND_FIELD_ANALYSIS.md` | toHex bug 详解 |

---

## 十、★ 下一步

```
1. 【进行中】D1 第二次注册 → 对比 sfOo/foO → 判定假设 a/b/c
2. 若恒定（假设 a）→ 攻 sfOo（7 位 hex，穷举空间小）
3. 若变化（假设 b/c）→ 找 libdu 的混淆表 / 走"抓一次复用"退路
```
