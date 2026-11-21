# ⑩ 自己造一个 App，验证到底有没有签名校验

> 👈 回到 [主线](../mainline.md) ｜ 相关 [③ 服务端看哪些字段](03-服务端看哪些字段.md) ｜ [⑥ 字段参考](06-字段参考.md)
>
> 结论先行：**服务端只校验包名字符串，不校验 APK 签名、不校验包体完整性。**
> 下面是从零造一个 `com.coolapk.market` 的极简 App、成功拿到 DUID 的完整过程。

---

## 为什么非要做这个实验

前面几篇都是「改报文」得出结论。但改报文有个天然缺陷：

> **报文里没有的东西，你能证明它在服务端被校验吗？**

比如签名。报文里从头到尾没有任何看起来像证书指纹的字段，但你不能因此断定「服务端不校验签名」——
它完全可能是 SDK 在本地校验完才发请求。

要排除这种可能，只有一条路：**造一个签名完全不同的 App，看它能不能拿到 DUID。**

---

## 一、摸清 SDK 的调用方式

### 1.1 JNI 方法表

从 v8.4.0 样本拿到的 native 方法（地址为 unidbg 重定位后的值）：

```
aXZlZWNl(Context, Intent)V
c6M3YmYQ(Context, int, String)String
onIEvent(Context, String, String, String)String
query(Context, String, String, int)String
run(Context, String, String)String
onEvent(Context, String, String, String)String
onSensorChanged(Context, SensorEvent)V
onSSChanged(Context, SignalStrength)V
...
```

**注意**：方法名本身在 so 里是加密的，直接 grep 找不到。这些是从**已脱壳的 DEX** 里读出来的。

### 1.2 Java 侧入口：`cn.shuzilm.core.Main`

反编译 DEX 后得到的公开 API：

```java
public class Main {
    public static void init(Context context, String apiKey)
    public static void init(Context context, String apiKey, boolean z)
    public static String getQueryID(Context ctx, String a, String b)
    public static String getQueryID(Context ctx, String a, String b, boolean z)
    public static void   getQueryID(Context ctx, String a, String b, boolean z, Listener l)
    public static String getVersion()
    public static String getTraceInfo(Context ctx)
    public static int    setConfig(String k, String v)
    public static int    setData(String k, String v)
}

public interface Listener {
    void handler(String str);
}
```

典型用法：

```java
Main.init(context, apiKey, true);
String duid = Main.getQueryID(context, "", "", true);
```

**`init` 内部做三件事**（`DUHelper.init`）：

```java
String d2 = d(str);                 // ① 校验 apiKey 格式
if (d2 == null) {
    Log.e("[shuzilm]", "apikey error.");
    return;                          // ② 不合格直接 return，什么都不做
}
mContext = e(context);
E.execute(new n(context, z2));       // ③ 异步加载 so + 初始化
```

### 1.3 apiKey 的校验算法（反汇编还原）

jadx 反编译出来的版本把掩码猜成了 `PartialGapBuffer.BUF_SIZE`，值算错了。
用 `dexdump` 反汇编 `DUHelper.d(String)` 才拿到真相：

```
0075: and-int/lit16 v5, v5, #int 255 // #00ff      ← 掩码是 0xFF
0079: rem-int/lit8 v1, v1, #int 15
007b: add-int/2addr v1, v2                        ← v2 在 0014 处被设为 1
```

完整算法：

```java
private static String d(String s) {
    // ① 长度必须 42
    if (s == null || s.length() != 42) return null;
    // ② 必须以 "11" 开头
    if (s.charAt(0) != '1' || s.charAt(1) != '1') return null;

    int i3 = 0, i4 = 0, i5 = 0;
    for (int i6 = 2; i6 < s.length(); i6++) {
        int v = hexValue(s.charAt(i6));       // 非法字符直接 return null
        int i7 = i6 - 2;
        if (i7 >= 1 && i7 <= 7) {              // 只有索引 3..9 参与计算
            i5 = (i5 << 4) | v;
            i3 += Integer.bitCount(v);
            i4 += i7 * v;
        }
    }
    // ③ 校验位在 index 2
    int calc = (((i3 + i4) + (((i5 >>> 17) ^ ((i5 >>> 7) ^ i5)) & 0xFF)) % 15) + 1;
    return Character.digit(s.charAt(2), 16) == calc ? s.toLowerCase() : null;
}
```

**用酷安的 apiKey 验证**：

```
11e7b222083a4b732b4b14811f6fc05995a01415eb
  ↑↑ ↑
  ││ └─ index2 = 'e' = 14
  │└─── 固定 "11"
  └──── 长度 42

计算得 14 → 与 index2 一致 ✓
```

**这个值就是报文里 `75c` 字段的值。**

---

## 二、三个必须准备的东西

| 组件 | 来源 | 大小 | 说明 |
|---|---|---|---|
| `libdu.so` | 原版酷安 APK 的 `lib/arm64-v8a/` | 1,417,064 B | md5 = `97313e29420c51d0d8cc6e3a3586889a` |
| `cn/shuzilm/**` 的 class | 已脱壳的 DEX | 55 个类 / 120 KB | 主逻辑 |
| `assets/cn.shuzilm.config.json` | 原版 APK | 165 B | 含 RSA 公钥 |

### 2.1 `cn.shuzilm` 到底有多少类

把一个第三方客户端的三个 DEX 全部拆开后统计：

| DEX | 大小 | 总类数 | 其中 `cn/shuzilm/**` |
|---|---|---|---|
| classes.dex | 17.87 MB | 16,691 | **47** |
| classes2.dex | 8.90 MB | 10,554 | **6** |
| classes3.dex | 7.83 MB | 9,208 | **2** |
| **合计** | **34.6 MB** | **36,453** | **55（0.15%）** |

**⇒ 34.6 MB 的 DEX 里，数字联盟 SDK 只占 120 KB。**

其余是 Jetpack Compose（10,425 类）、快手广告（1,944 + 3,215 类）、腾讯 IM、网易易盾、华为 HMS、友盟……

所以「精简 SDK」只要按包名过滤即可，不需要 R8 剪枝。

### 2.2 `libdu.so` 的版本必须和 DEX 配套 ⚠️

我一开始用错了 so：

```
apk\extract\libdu.so   1,291,960 B   md5=ca8c021909ff2b0dc598f183348d3d82
native\libdu.so        1,417,064 B   md5=97313e29420c51d0d8cc6e3a3586889a
```

结果是：

```
Failed to register native method ... query(Context, String, String, int)
UnsatisfiedLinkError: JNI_ERR returned from JNI_OnLoad in ".../libdu.so"
```

**原因**：DEX 里声明的是 `query(Context, String, String, int, long, long, int[])`（7 参数），
而那个 so 注册的是 4 参数版本 —— **签名对不上，`RegisterNatives` 失败，`JNI_OnLoad` 返回 `JNI_ERR`。**

换成配套的 1.4 MB 版本后立刻正常。

**⇒ 顺带确认了 `ne8` 的含义**：`ne8` 就是 `libdu.so` 的 MD5，
所以用原版 so 时 `ne8` 天然匹配，这一项永远过关。

---

## 三、最小 App 的构造

### 3.1 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.coolapk.market"
    android:versionCode="1" android:versionName="1.0">

    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />

    <application android:label="DUID Probe" android:allowBackup="true">
        <activity android:name="com.coolapk.market.MainActivity"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

⚠️ **`android:name` 必须写完整类名**。写 `.MainActivity` 会被解析成 `<包名>.MainActivity`，
改包名后就和 DEX 里的类对不上，直接 `ClassNotFoundException`。

### 3.2 MainActivity（180 行，全反射）

不编译期依赖 `cn.shuzilm.core`，所以只需要 `android.jar`：

```java
public class MainActivity extends Activity {
    private void runProbe() {
        try {
            String apiKey = pickApiKey();                      // 取一个格式合法的 42 字符 key
            Class<?> mainCls = Class.forName("cn.shuzilm.core.Main");

            Method init = mainCls.getMethod("init",
                    Context.class, String.class, boolean.class);
            init.invoke(null, this, apiKey, Boolean.TRUE);

            Thread.sleep(10000);                               // 等异步初始化

            Method gq = mainCls.getMethod("getQueryID",
                    Context.class, String.class, String.class, boolean.class);
            String duid = (String) gq.invoke(null, this, "", "", Boolean.TRUE);
            Log.i("DUID-PROBE", "拿到 DUID: " + duid);
        } catch (Throwable t) { ... }
    }
}
```

### 3.3 打包产物

```
probe-min-signed.apk   1,573,462 B (1.50 MB)
├── lib/arm64-v8a/libdu.so        1,417,064 B   90.0%
├── classes.dex                     123,660 B    7.9%   ← SDK 全部 55 个类
├── classes2.dex                      8,420 B    0.5%   ← 我的 MainActivity
├── AndroidManifest.xml               2,788 B
├── assets/cn.shuzilm.config.json       165 B
└── resources.arsc + 签名               ~25 KB
```

---

## 四、四个坑

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 1 | `E [shuzilm]: apikey error.` | `init()` 要的不是 config 里的 RSA 公钥，而是 **42 字符、`11` 开头、带校验位的值** | 用 `75c` 的值 |
| 2 | `ClassNotFoundException: AIClient` | SDK 被拆成 3 个 DEX，`AIClient` 在另一个里 | 三个 DEX 全部放入 |
| 3 | `Failure [-124]: requires resources.arsc stored uncompressed` | Android R+ 强制要求 `resources.arsc` 不压缩 + 4 字节对齐 | zip 时用 `ZIP_STORED` |
| 4 | `JNI_ERR returned from JNI_OnLoad` | `libdu.so` 版本和 DEX 不配套 | 换配套版本 |

另外一个隐蔽坑：**`d2j-dex2smali` 必须在它自己的目录下运行**，否则静默产出 0 个文件。

以及 **Windows 文件名大小写不敏感**：SDK 里同时有 `cn/shuzilm/core/r`（小写）和
`cn/shuzilm/core/R`（大写），dex2jar 会把前者存成 `r_d2j6.smali` 避免冲突。
**不要去改它** —— 文件内部的 `.class` 声明本来就是 `Lcn/shuzilm/core/r;`，
文件名只是磁盘标识。改了反而会覆盖掉真正的 `R.smali`。

---

## 五、结果

### 5.1 包名 `com.coolapk.market`（自签名）

```
D/DUID-PROBE: package = com.coolapk.market
D/DUID-PROBE: version = v9.0.1
D/DUID-PROBE: 候选通过校验: 11e7b222083a4b732b4b14811f6fc05995a01415eb
D/DUID-PROBE: 调用 init(context, apiKey, true)
D/DUID-PROBE: 调用 getQueryID(context, "", "", true)
D/DUID-PROBE: ★★★★★ 拿到 DUID: DU8N1bbZfcNSfbmsBFOhsJslrOSOR3dL6eg5
D/DUID-PROBE: SharedPreferences 缓存 device_id = DU8N1bbZfcNSfbmsBFOhsJslrOSOR3dL6eg5
```

### 5.2 签名对比

| | DN | SHA-256 |
|---|---|---|
| 我的 probe | `CN=DUID Probe, OU=Test, O=Test, L=Test, ST=Test, C=CN` | `078fa36c2be94cf0fe3d704479e1cfcbff7d5d0b5116701c06358129af14bb4c` |
| 官方酷安 | `CN=CoolApk.com, OU=CoolApk.com, O=CoolApk.com, …` | `8037a13b154927d4a8e5649e294dab6c09a5296693578e2d5d02ece32a9678dc` |

**证书完全不同，照样拿到 DUID。**

### 5.3 换成 `com.tencent.mm`

```
D/DUID-PROBE: package = com.tencent.mm
D/DUID-PROBE: 调用 init(context, apiKey, true)
D/DUID-PROBE: 调用 getQueryID(context, "", "", true)
D/DUID-PROBE: ★★★★★ 拿到 DUID: 000000000000000000000000000000000000
```

**同一个 APK、同一个签名、同一台设备，只改包名 → 36 个 0。**

### 5.4 换成 `com.zhihu.android`

```
D/DUID-PROBE: 拿到 DUID: DU8N1bbZfcNSfbmsBFOhsJslrOSOR3dL6eg5
                            RFU4TjFiYlpmY05TZmJtc0JGT2hzSnNsck9TT1IzZEw2ZWc1c2h1
```

88 字符。后半段 base64 解码 = `DU8N1bbZfcNSfbmsBFOhsJslrOSOR3dL6eg5shu`。

**⇒ 前半段设备身份和酷安那次完全相同，只是包名不同导致格式不同。**

---

## 六、这组实验证明了什么

| 假设 | 判定 | 依据 |
|---|---|---|
| 服务端校验 APK 签名 | **否** | 自签名 APK 正常拿号 |
| 服务端校验 APK 完整性 | **否** | 180 行 Activity + 55 个 SDK 类就够 |
| 服务端校验 `libdu.so` 完整性 | **否（不阻断）** | `ne8` 上报后不校验，换 so 也能跑（版本对就行） |
| 服务端校验包名 | **是** | 换包名 → 36 个 0 |
| 校验是「白名单」还是「配对」 | **白名单** | `com.zhihu.android` + 酷安的 apiKey 照样成功 |
| apiKey 参与签发门控 | **否** | `75c` 保留 / 删除 / 换值，结果不变 |

---

## 七、完整脚本

| 文件 | 作用 |
|---|---|
| `build_probe2.py` | 编译 Activity + d8 + 组装多 dex APK + 签名 + 安装 |
| `build_min.py` | 精简版打包（只要 55 个类） |
| `pkg_swap.py` | 改 manifest 包名重建 APK（用于对照实验） |
| `shrink2.py` | baksmali 三个 DEX，只保留 `cn/shuzilm/**` |
| `shrink4.py` | smali 重新组装成 DEX |

---

## 相关

| 内容 | 位置 |
|---|---|
| 服务端到底校验哪几个字段 | [③ 服务端看哪些字段](03-服务端看哪些字段.md) |
| 包名白名单探测结果 | [⑪ 包名白名单](11-包名白名单.md) |
| `75c` / `ne8` 的字段含义 | [⑥ 字段参考](06-字段参考.md) |
| 官方隐私政策和实测的落差 | [⑫ 合规对照](12-合规对照.md) |
