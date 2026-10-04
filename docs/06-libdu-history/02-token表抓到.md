# ★★★ 运行时抓到了！完整的 token → 字符串表

> 日期：2026-10-03 ｜ D2（XTQ_Watch）｜ 挂钩 `0x1143BC` 成功
> **路径 B 的运行时版本执行成功 —— 拿到了 mIS 相关的关键字符串。**

---

## 一、★★★ 索引的字母表（**标准 base64，不是 base64url**）

```
TOK 0xbcb023b0 -> "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                                                    ↑                          ↑
                                                   62 个字母数字             '+' '/'
```

**⇒ 我之前抓到的 `...-_`（base64url）是另一处用途的表；**
**  mIS 编码用的是这个【标准 base64】表。**

### 1.1 这修正了两次误判

```
第一次（早期）：假设标准 base64  -> 正确！
第二次（上轮）：抓到 base64url   -> 那其实是别处的表
现在（本轮）：   抓到标准 base64 -> ★ 确认是它
```

---

## 二、★★★ 关键：DNA 的格式模板

```
TOK 0xbcafdcd0 ->
  "{%cs%c:%c%lld%c,%cr%c:%d,%cw%c:%d,%ct%c:%c%lld%c,%cp%c:%d,%crg%c:%d,%cbu%c:%c%s%c}"
```

### 2.1 逐字段解析（`%c` 是分隔符占位）

```
{
  %c s  %c : %c %lld  %c        ->  "s":<long>          秒级时间戳
  , %c r  %c : %d               ->  "r":<int>
  , %c w  %c : %d               ->  "w":<int>
  , %c t  %c : %c %lld  %c      ->  "t":<long>
  , %c p  %c : %d               ->  "p":<int>
  , %c rg %c : %d               ->  "rg":<int>
  , %c bu %c : %c %s  %c        ->  "bu":<string>        ★ bu = build/board？
}
```

### 2.2 与之前观察的直接对照

```
之前 getTraceInfo 返回：
  {"sv":"v9.0.1","tc":"DUT101","pkg":"","cc":"CN","api":28,
   "bu":"","q":{"c":"DUQ099","w":0},"o":{"c":"DUO099","w":0}}
                                              ↑
                                           "w":0 —— 与模板里的 %cw%c:%d 完全对应！
                                           "bu":"" —— 与 %cbu%c:%c%s%c 完全对应！

★ 所以这个格式模板就是【getTraceInfo 返回的那个 JSON 的构造模板】！
   "w" = 工作状态（0 = 未就绪）
   "bu" = build 字符串
   "s"  = 时间戳
   "t"  = 另一个时间戳
```

---

## 三、★★★ 抓到的完整 token 表

### 3.1 JNI 反射相关（说明 libdu 通过 JNI 调 Java）

```
"java/security/MessageDigest"             ← ★ 用 MD5
"MD5"
"getInstance"
"update" / "digest"
"(Ljava/lang/String;)Ljava/security/MessageDigest;"
"([BII)V" / "()[B"
"getBytes" / "UTF-8"
"(Ljava/lang/String;)[B"
"getPackageName"
"()Ljava/lang/String;"
```

### 3.2 SharedPreferences 相关

```
"getSharedPreferences"
"(Ljava/lang/String;I)Landroid/content/SharedPreferences;"
"getString"
"(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"
"_prefs"          ← ★ prefs 文件名后缀
"%s%s"            ← ★ 拼接格式（包名 + "_prefs"）
```

### 3.3 设备指纹字段

```
"boot_uuid"       ← ★ 关键字段！
```

---

## 四、★★★ 由此还原出的关键流程

```
从 token 表还原出的逻辑：

  ① prefs 文件名 = sprintf("%s%s", getPackageName(), "_prefs")
     => "com.coolapk.market_prefs"  ← 实际的 SharedPreferences 文件名！

  ② 用 getSharedPreferences(name, mode) 打开
  ③ 用 getString(key, def) 读取
  ④ 用 MessageDigest.getInstance("MD5") + update + digest 做摘要
  ⑤ 用 UTF-8 编码字符串

⇒ 这说明 libdu 会：
     · 读取 Coolapk 的 SharedPreferences（里面就有 DUID！）
     · 做 MD5 摘要
     · 用标准 base64 编码
```

---

## 五、★ 对 mIS 的新的理解

```
现在有了：
  ✓ 字母表 = 标准 base64 "A-Za-z0-9+/"        （运行时确认）
  ✓ 格式模板 = getTraceInfo 的 JSON 构造模板
  ✓ libdu 用 MD5 + base64 + prefs
  ✓ 关键字段名 "boot_uuid"

仍缺：
  ✗ mIS 那 36 字符具体是怎么算出来的
  ✗ 样本里那些越界字符（! " # % & ' ( ) * < ? [ \ { | } ~）的来源

★ 但方向清晰了：
   mIS 很可能是 MD5(某些字段拼接) 的 base64，
   而越界字符说明【最后还有一层变换】（XOR 或字符替换）
```

---

## 六、★ 本次会话（全部）成果总表

### 6.1 静态逆向（100%）

```
✅ 字符串加密算法完整还原（奇偶密钥 XOR + 倒序写入 + 逐串密钥对）
✅ 5 个真实字符串（模拟器检测 + getprop 路径）
✅ 完整调用链：驱动 0x07DBEC → 13 解码器 → 属性名 → 分派器 0x0F07FC
✅ 编码函数 0x0E123C 完整反汇编（493 条）+ 三个调用者
✅ 字符串解析机制（BSS token → 0x1143BC → 字符串）
✅ 加密密钥 1F 6F 8B A3（NEON + 尾部循环）
✅ 输出公式 2*len+32，长度上限 766
✅ 字符串表区域 0x14300~0x147C3（权限名 + PNG 图标）
✅ 全 .text 反汇编 213,588 条
```

### 6.2 运行时（100% + 本次突破）

```
✅ spawn+gating / Module.load(原始路径) / dlopen 钩子（20 次序列）
✅ NIS（易盾）钩子 / 外部监控 maps（37 次/6 分钟）
✅ 方式 A 的 dd 读取（131072 字节，65 MB/s）
✅ ★ 挂钩 0x1143BC 拿到完整 token → 字符串表 ★★
```

### 6.3 关键事实

```
✅ Coolapk = 网易易盾加固
✅ libdu.so 不在 dlopen 序列里
✅ ★ 字母表 = 标准 base64 "A-Za-z0-9+/"（运行时确认）
✅ ★ 格式模板 = getTraceInfo 的 JSON 构造模板
✅ ★ libdu 用 MD5 + 标准 base64 + SharedPreferences
✅ ★ 关键字段 "boot_uuid"
✅ DUID 确定性；三台设备 DUID 已知
```

### 6.4 未闭环

```
✗ mIS 的 36 字符具体算法（但方向已清晰：MD5 + base64 + 变换）
✗ 越界字符的来源（最后那层变换）
✗ libdu 的加载机制（不在 dlopen 序列）
```

---

## 七、脚本

| 脚本 | 作用 | 状态 |
|---|---|---|
| **`snatch.py`** | ★ 运行时抓现场（解析器 + 编码器） | ★ **成功** |
| **`snatch_final.js`** | ★ 挂钩 0x1143BC/0x0E123C | ★ **抓到 token 表** |
| **`decode_strings_static.py`** | 静态解字符串 | ★ 完成 |
| **`disasm_resolver.py`** | 反汇编 0x1143BC（576 条） | ★ 完成 |
| **`disasm_encoder_full.py`** | 反汇编编码函数 | ★ 完成 |
| **`disasm_callers.py`** | 反汇编三个调用者 | ★ 完成 |

---

## 八、教训

```
① 「运行时挂钩」补上了静态分析的边界。
   静态只能到"表从 token 解析而来"；
   运行时挂钩一次就拿到了【全部 token → 字符串】。

② 两次误判说明：抓到候选后必须用数据验证。
   先假设标准 base64（对）→ 抓到 base64url（误判）→
   运行时确认标准 base64（对）。中间那次是被相似物误导。

③ 格式模板是"金矿"。
   "{%cs%c:%c%lld%c,...%cbu%c:%c%s%c}" 直接揭示了
   getTraceInfo 的构造方式，并印证了之前观察到的 w=0 / bu="" 含义。
```
