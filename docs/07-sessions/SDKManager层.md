# `ShuzilmSDKManager` —— 酷安侧封装层（从没看过的那一层）

> `_rev` 以前一直直接看 `cn.shuzilm.*`，从没看过酷安自己包的这一层。
> 本轮用 frida 运行时反射把它读出来了（仓库里没有 jadx，反射比静态反编译更直接）。
>
> 日期：2026-10-03 ｜ 设备：XTQ_Watch（Android 9 / arm64 / Magisk）

---

## 一、它是什么

```
com.coolapk.market.manager.ShuzilmSDKManager
    extends com.coolapk.market.view.ad.DelayInitSDK       ← 酷安的延迟初始化基类
```

**不是一个静态工具类，而是一个带实例状态的管理器**（11 个实例字段，22 个方法）。

运行时反射出的字段（混淆名 → 结构）：

| 字段 | 类型 | 运行时值 | 推断 |
|---|---|---|---|
| `ԩ` | `ShuzilmSDKManager` | `ShuzilmSDKManager@6e70f86` | 单例自引用 |
| `Ԫ` | `KProperty[]` | 数组 | Kotlin 委托属性 |
| `ԫ` | `StateFlowImpl` | — | **状态流**（Kotlin Flow） |
| `Ԭ` | `boolean` | `true` | 标志 |
| **`ԭ`** | `int` | **`127470393`** | 版本号 / 间隔（`0x7995A39`） |
| `Ԯ` | Kotlin flow 类型 | `null` | 流句柄 |
| `ԯ` | `ShuzilmSDKManager$Ϳ` | 实例 | **Listener 实现**（见下） |
| `ՠ` | `boolean` | `true` | 标志 |
| `ֈ` | `boolean` | `true` | 标志 |
| `֏` | `toc` | 实例 | 某种回调/任务对象 |
| **`ׯ`** | `long` | **`1790989016261`** | **毫秒时间戳**（≈ 采集时刻） |

22 个方法里，带参数签名值得注意的：

```
Object  ԯ(ShuzilmSDKManager, boolean, Continuation)       ← 协程，带 boolean
Object  ՠ(ShuzilmSDKManager, String, Continuation)        ← 协程，带 String
Object  ԭ(Context, Continuation)                          ← 初始化入口
String  ނ(ShuzilmSDKManager, boolean, int, Object)
void    ވ(ShuzilmSDKManager, boolean, int, Object)
String  ހ()          String  ށ(boolean)      String  ރ(String)
boolean ބ()          boolean ޅ()
Object  ކ(boolean, Continuation)
void    އ(boolean)                      ← 疑似「设置某标志后重载」
Object  މ(String, Continuation)         ← 协程，带 String
void    ފ(String)
Object  ދ(Continuation)                 ← 无参协程
void    onLoginEvent(p99)                ← ★ 公开，登录事件
void    onWifiEvent(lwi)                 ← ★ 公开，WiFi 变化事件
```

### 1.1 ★ `onLoginEvent` / `onWifiEvent` —— 有事件上报通道

这两个是**非混淆可见名**的公开方法。它们对应 SDK 侧的：

```
cn.shuzilm.core.Main.onEvent(Context, String, String, int, Listener)
cn.shuzilm.core.DUHelper.onEvent(4) / onIEvent(4) / onIEvent(2)
cn.shuzilm.core.DUHelper.onSSChanged(2) / onSensorChanged(2)
```

⇒ **酷安把「登录」「WiFi 变化」这两类事件转给数盟**。
这解释了为什么请求里有一批看起来像环境快照的字段（网络类型 `zpA`、
SSID 列表 `YWu`、信号 `9qW` 之类），以及 `tra_stats` 这种累计状态键。

### 1.2 ★ `initID$validIdOrNull` —— 客户端自己会对 ID 做合法性校验

从类名就能读出来（Kotlin 内联 lambda 的名字保留）：

```
ShuzilmSDKManager$initID$validIdOrNull$1
ShuzilmSDKManager$initID$validIdOrNull$1$1
ShuzilmSDKManager$initID$validIdOrNull$1$1$Ϳ      ← 只有 1 个方法：void handler(String)
```

最后那个 `$Ϳ` 类是 **Listener 的匿名实现**：

```
super = java.lang.Object
fields = 1   (gsc Ϳ)
methods = 1  void handler(String)      ← cn.shuzilm.core.Listener.handler(String)
```

⇒ **`initID` 的流程是**：拿缓存 ID → `validIdOrNull` 判断是否合法 →
不合法就再向 SDK 要（回调 `handler(String)` 收新 ID）。

**这解释了一个此前的观察**：我们几次删掉 `dna.xml` 后 DUID 会在 10 秒内被写回 ——
客户端有「读缓存 → 校验 → 缺了就补」的完整逻辑，不是单纯读文件。

### 1.3 ★ `initSDKAndID` 带 `forceReloadID` 参数

```
ShuzilmSDKManager$initSDKAndID$1
    fields: boolean $forceReloadID  /  int label
```

⇒ **客户端有「强制重新取 ID」的代码路径**。
这对实验很有用：如果能调用它，就能在不 `pm clear`、不冷启动的前提下
让真机重新向服务端要一次 ID —— 这正是 D1 上一直卡住的那个问题（见 `dev2/TWO_DEVICES.md` §四）。

### 1.4 还有 `updateRetryJobStatus` / `getSessionSync` / `postEventAndGetSessionID`

```
$updateRetryJobStatus$2        ← 重试任务（日志里出现过 "try to reload did"）
$getSessionSync$1 / $1$1       ← 拉 session（字段 $path: String → 是个 HTTP 路径）
$postEventAndGetSessionID$2    ← 上报事件并取 session
```

`$getSessionSync$1` 的字段是 `$path`（String）—— 说明这里会**请求一个服务端路径**。
结合日志里的 `RequestSessionIDUpdater: shuzilm /v6/main/indexV8 不需要 token`，
这条链是和**酷安自己的 API**（`/v6/...`）打交道的，不是 szlm 上报端点。

---

## 二、★ 最重要的结论：这一层没有密钥材料

反射了 11 个实例字段 + 22 个方法 + 13 个嵌套类的全部静态字段，
**没有找到 apiKey、包名声明、任何常量字符串**。

回顾我们已知的三个候选位置：

| 候选 | 结果 |
|---|---|
| `ShuzilmSDKManager` 的静态常量 | ✗ 没有（本轮证实） |
| `app/src/probe/assets/cn.shuzilm.config.json` | 内容是 `{"store":"DUTest","apiKey":"MFwwDQYJ..."}` —— 与线上 apiKey 不符，是占位样本 |
| **`libdu.so` 的加密串池 / native** | ✓ 唯一剩下的地方 |

⇒ **`x12 = "com.coolapk.market"` 这个「包名声明」不是 Java 层的常量**，
它要么硬编码在 native，要么由 native 在运行时采集。
这与 `SZLM_SDK_SIGNING_VERDICT.md` 第七轮的结论一致：「包名与签名都来自
native 通过 JNI 调 `PackageManager.getPackageInfo(pkg, GET_SIGNATURES)`」。

**本轮把这条从「推断」变成了「排除了 Java 层实现」**。

---

## 三、与既有文档的关系

| 既有结论 | 本轮 |
|---|---|
| 「酷安直接把数盟 SDK 拿来用」（`_rev` 一直这么假设） | **不成立**。中间有一层 `ShuzilmSDKManager extends DelayInitSDK`，负责状态机 + 重试 + 事件转发 + ID 缓存校验 |
| 「数盟 SDK 只在进程启动时跑一次」 | 有 `updateRetryJobStatus` 重试任务、`onWifiEvent` / `onLoginEvent` 触发点 |
| 「删 dna.xml 被回填是 `prefs.xml` 干的」 | 是，但还有一层：`validIdOrNull` 会**主动校验并补取** |
| 「包名声明在 Java 层」 | **排除**。Java 层没有该常量 ⇒ 在 native |

---

## 四、新增脚本

| 脚本 | 作用 |
|---|---|
| `sdkmanager_probe.js` | 第一版：枚举全部 shuzilm 相关类 + 方法 |
| `sdkmanager4.js` | **可用的版本**：`setImmediate` 轮询 + 反射字段/方法（`setTimeout` 在 frida 16.7.19 上实测不触发） |
| `run_sdkmanager_probe.py` | attach 模式驱动（需先把 app 养稳再挂） |
| `run_sdkmanager_spawn.py` | spawn 模式驱动（⚠ 会注入到短命父进程，见 §五） |
| `run_sdkmanager_watch.py` | 盯新 pid 注入（用于「spawn 出孤儿父进程」的机型） |

### 五、本轮踩到的三个 frida 坑（都记下来）

```
① spawn 注入的是【短命父进程】
   frida.spawn 返回的 pid 与真正的 app 进程 pid 不同（本次 16279 → 16330）。
   注入父进程 ⇒ 钩子永不触发，脚本一声不响。
   ⇒ 对策：spawn 起头 + 盯 pidof 新出现的 pid 做 attach。

② setTimeout 在 frida 16.7.19 上不触发
   用 setTimeout(loop, 500) 的轮询版脚本装上了却毫无输出。
   ⇒ 对策：改 setImmediate 自轮询，并先发一条诊断日志确认脚本在跑。

③ attach 太早会 "connection is closed"
   app 冷启动期间注入必然失败（D1 上更严重，会直接把 app 拖成 ANR）。
   ⇒ 对策：先 am start 让 app 稳定 40 秒，再 attach，并做 3 次重试。
```
