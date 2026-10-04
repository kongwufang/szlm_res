# STEP_2026-10-04f · ★★★ 找到根本 bug：SSL/SOCK 数据一直被静默丢弃

> 日期：2026-10-04 ｜ 设备：D2 `10.0.0.7:5555`（XTQ_Watch）｜ 状态：链路已彻底打通

---

## 一、★★★ 本会话最重要的发现：`toHex()` 的转换 bug

```js
// ✗ 修复前（一直在跑）
function toHex(arr, n) {
    const b = new Uint8Array(arr);     // ← 这里
    ...
}
```

**`new Uint8Array(nativePointer)` 不读内存** —— 它只对 array-like 有效。

```
CIPHER 的 arr = Java byte[]     → new Uint8Array(arr) 可用 → hex 正常 ✓
SOCK 的 arr  = NativePointer    → 返回长度 0             → hex 恒为空 ✗
SSL 的 arr   = NativePointer    → 返回长度 0             → hex 恒为空 ✗
```

### 影响范围（严重）

**从 c3 那次开始，【所有 SSL 与 SOCK 的数据都被静默丢弃了】。**

```
表象：c3 那次「SSL=0（有hex）」、d2a「SSL=0（有hex）」、d2b「SOCK 带hex=0」
我误判为：「SSL 过滤条件太严」→ 去改过滤条件 → 反而引发 ANR
真实原因：toHex 对 NativePointer 返回空字符串

⇒ mdna 一直就在 SSL 里，只是被这个 bug 吞掉了
```

### 修复后（已验证）

```
REC p25185 t=24213 SSL n=1977 hex=504f5354202f736572766963...
= POST /service/2/app_log/?version_code=2609151&device_platform=android&... HTTP/1.1
  Host: log.zijieapi.com
  User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; XTQ_Watch Build/PPR1.180610.011)
  Content-Length: 1590

⇒ ★ 完整的请求行 + 请求头 + body 全部拿到
```

```js
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

---

## 二、★ 第二个突破：attach 速度从 10-21 秒降到 2.4 秒

```
之前：[守望+10.5s] / [直查+21.2s] / [守望+86.9s] 才装上钩子 → 注册期流量漏掉
现在：★★★ [轮询+2.4s] pid=5963 → 钩子已装

改法：frida 轮询线程改用 dev.get_process(PKG) 直查，
      不再 enumerate_processes()（后者慢得多）
      且轮询线程在 am start【之前】就启动
```

---

## 三、★ 78 字段分析（本会话的另一条主线）

### 3.1 推翻了文档三条结论

| 文档旧说法 | 本会话实测 |
|---|---|
| `mIS` 是"唯一钥匙、判据种子" | ❌ **换成任意合法 36 字符串，服务器照样返回真 DUID** |
| `sfOo`/`foO` 是"可删的混淆串" | ❌ **它们是真正的设备锚点** |
| 必需字段含 `mIS` | ❌ 应为 `DUv/3mS/75c/2cO/sfOo/foO` |

**根因**：文档的 87 字段扫描**一直保持 `mIS` 为真值** —— 那个真值足以命中记录，
遮蔽了其它字段的作用（观测设计缺陷）。

### 3.2 ★ 组合盲区测试（关键实验）

```
基线（全真）                                → 真 DUID
只留 6 锚点，其余 72 字段【全部随机化】       → ★★★ 仍返回真 DUID
只留 5 个（去 75c）                          → 全 0
只留 2cO+sfOo+foO（去 DUv/3mS/75c）         → 全 0
全随机                                      → 空

排除法（整类随机化，从全真出发）：
  5 个 hex 哈希 K5f/ne8/w91/gEd/6yY          → 仍真 DUID
  15 个混淆串                                 → 仍真 DUID
  4 个嵌套对象 iYB/7S2/G8U/msg                → 仍真 DUID
  设备属性 AYk/P1J(MAC)/R3d(机型)/R37/wSK     → 仍真 DUID
  时间戳 Qg1/LMi/za7                          → 仍真 DUID
```

**⇒ 整个 78 字段的 body，只有 6 个有意义，其余 72 个（含全部设备指纹）一个都不参与识别。**

### 3.3 最小可用 body

| # | 字段 | 值 | 性质 |
|---|---|---|---|
| 1 | `DUv` | `com.coolapk.market` | 常量 |
| 2 | `3mS` | `v9.0.1` | 常量 |
| 3 | `75c` | `11e7b222…15eb` | apiKey 常量 |
| 4 | `2cO` | `1790969185.997397935` | 时间戳 |
| 5 | `sfOo` | `4A213D3` | 7 位 hex |
| 6 | `foO` | `W***]TZTYX**X(W` | 混淆串 15 |

**⇒ 真正要"算"的只有 `2cO` / `sfOo` / `foO`。**

### 3.4 零成本追查失败

```
sfOo=4A213D3 不是任何单字段/两两组合的 MD5/SHA1/SHA256/SHA512 前缀
             （93 候选 × 7 分隔符 × 4 哈希 = 239568 次，零命中）
foO 与 mIS 无直接派生关系（foO ⊄ mIS；XOR 首字节为 0，仅首字符相同）
```

---

## 四、★ 当前假设（用户提出，待验证）

```
sfOo / foO 可能是：
  (a) 设备指纹                 → 只要能复刻指纹采集即可本地算出
  (b) 设备指纹 + 签名           → 还需从 libdu 提取签名密钥
  (c) 服务端下发的种子          → 本地算不出，只能"抓一次复用"

验证方法：抓【第二个 mdna 样本】，对比 sfOo/foO 是否跨注册恒定
```

---

## 五、★ 本会话踩过的 ANR 坑（全部记下来）

```
① 无差别 hex 转换（第一版）
   对每条 SSL 记录都 toHex(arr, 16384) → 4221 条 ≈ 7000 万次 JS 操作 → ANR

② read() 钩子过滤 maps
   read 是极高频函数 → 全 app 每次读都进 JS → ANR
   ★ 正解：改在 open/openat 层做【maps 重定向】（不碰 read）

③ SSL 过滤「放宽」（c5 那次）
   改成 keepHex = 非全零 → hex 转换量暴涨 → ANR

④ SOCK 一律 hex（d2e 那次，最新）
   SOCK 改成 keepHex=true + cap 4096，且钩了 write（频率极高）→ 2986 条 × 4096 → ANR
   ★ 正解：SOCK 只对【像 HTTP】的记录做 hex；去掉 write 钩子，只留 send/sendto

⑤ 缓存的按钮坐标点按 → 页面一变就点到《用户协议》链接 → 跳浏览器
   ★ 正解：每次点按前重新 dump UI 确认按钮在场

【统一规律】热路径上的活越少越好；高频函数（read/write/每次 SSL）绝不挂重钩子
```

---

## 六、★ 当前工具链状态（全部已验证）

| 能力 | 状态 |
|---|---|
| maps 重定向隐身 | ✅ 生效，不再被检测到注入 so |
| attach 速度 | ✅ 2.4 秒（get_process 直查） |
| SSL 明文 HTTP 抓取 | ✅ **本轮修复**（完整请求行+头+body） |
| CIPHER 明文抓取 | ✅ gzip（Java 路径）/ 明文 JSON（SDK init 路径） |
| native SOCK 抓取 | ✅ 已限定只抓 HTTP 形态 |
| 安全点按 | ✅ 不再误跳浏览器 |
| 弹窗处理 | ✅ 自动回避「立即更新」 |
| 截图辅助 | ✅ devout/SHOT/ |
| 双通道进程守望 | ✅ 设备端 watch.sh + frida 侧 get_process |

---

## 七、下一步（唯一剩的事）

```
跑一次 D2 的 pm clear 注册，用修好的钩子抓 mdna
  → 提取 sfOo / foO
    → 与已知样本（4A213D3 / W***]TZTYX**X(W）对比
      → 相同  ⇒ 设备固有指纹（假设 a）→ 本地必可算 → 目标路径明确
      → 不同  ⇒ 每次注册生成（假设 b/c）→ 转攻混淆表或走"抓一次复用"
```

**上一轮（d2e）已经跑完注册，但因为 toHex bug 未修，SSL 数据被丢；**
**本轮修复 + 修掉 SOCK 的 ANR 后，重跑一次即可。**

---

## 八、诚实记录

```
✅ 找到并修复 toHex bug（这是困扰 c3 之后所有抓包的根因）
✅ 修复 attach 速度（10-21s → 2.4s）
✅ 完成 78 字段分析：只有 6 个有意义，mIS 不是锚点
✅ 组合盲区测试通过：72 个字段全随机化仍返回真 DUID
✅ 验证 SSL 明文 HTTP 可完整抓取
❌ 仍未抓到 mdna（上一轮被 toHex bug 吞掉；新一轮已修待跑）
❌ 未验证 sfOo/foO 是否跨注册恒定
```
