# app-probe/ — 自建最小 App 验证签名校验

> 👈 回到 [主线](../mainline.md) ｜ 完整说明见 [⑩ 自己造 App 验证](../docs/10-自己造App验证.md)

这个目录是**从零写一个 `com.coolapk.market` 的极简 App、成功拿到 DUID** 的完整工程。

结论：**服务端不校验 APK 签名、不校验包体完整性，只校验包名字符串。**

---

## 文件

| 文件 | 作用 |
|---|---|
| `AndroidManifest.xml` | 最小清单，`package="com.coolapk.market"` |
| `MainActivity.java` | 180 行，全反射调用 `cn.shuzilm.core.Main` |
| `build_probe.py` | 完整版打包（含无关的第三方 DEX） |
| `build_min.py` | 精简版打包（只要 55 个 SDK 类，1.5 MB） |

---

## 前置条件

### 1. 需要的东西

| 组件 | 从哪来 | 大小 |
|---|---|---|
| `lib/arm64-v8a/libdu.so` | 原版酷安 APK | 1,417,064 B（md5 `97313e29420c51d0d8cc6e3a3586889a`） |
| `classes.dex`（SDK 部分） | 脱壳 DEX 里的 `cn/shuzilm/**` | 55 个类 / 120 KB |
| `assets/cn.shuzilm.config.json` | 原版 APK | 165 B |

⚠️ **`libdu.so` 的版本必须和 DEX 配套**。用错版本会报
`JNI_ERR returned from JNI_OnLoad`，因为 `RegisterNatives` 的方法签名对不上。

### 2. 工具链

```
JDK 17+                     javac / d8 / keytool
Android SDK build-tools      aapt2 / d8 / zipalign / apksigner
一个 arm64 真机或模拟器        adb 能连上
```

### 3. 从原始 DEX 提取 SDK

```sh
# 1) baksmali（dex2jar 的 d2j-dex2smali，必须在它自己的目录下运行）
cd /path/to/dex-tools
d2j-dex2smali.bat --force -o out/smali-d1 /path/to/shuzilm01.dex

# 2) 只保留 cn/shuzilm/**
mkdir -p keep
cp -r out/smali-d1/cn keep/

# 3) 重新组装
d2j-smali.bat -o sdk.dex keep/
# → 120 KB，55 个类
```

⚠️ Windows 文件名大小写不敏感：SDK 里同时有 `cn/shuzilm/core/r` 和 `cn/shuzilm/core/R`，
dex2jar 会把前者存成 `r_d2j6.smali`。**不要改它** —— 文件内部的 `.class` 声明是对的。

---

## 构建

```sh
# 精简版（推荐）
python3 build_min.py

# 完整版
python3 build_probe.py
```

产物：

```
probe-min-signed.apk   1.5 MB
├── lib/arm64-v8a/libdu.so    1,417,064 B   90.0%
├── classes.dex                 123,660 B    7.9%   ← SDK
├── classes2.dex                  8,420 B    0.5%   ← MainActivity
└── …
```

---

## 运行

```sh
adb install -r -g probe-min-signed.apk
adb logcat -c
adb shell am start -n com.coolapk.market/com.coolapk.market.MainActivity
adb logcat -s DUID-PROBE:*
```

预期输出：

```
D/DUID-PROBE: package = com.coolapk.market
D/DUID-PROBE: version = v9.0.1
D/DUID-PROBE: 候选通过校验: 11e7b222083a4b732b4b14811f6fc05995a01415eb
D/DUID-PROBE: 调用 init(context, apiKey, true)
D/DUID-PROBE: 调用 getQueryID(context, "", "", true)
D/DUID-PROBE: ★★★★★ 拿到 DUID: DU8N1bbZfcNSfbmsBFOhsJslrOSOR3dL6eg5
```

---

## 对照实验

改 `AndroidManifest.xml` 里的 `package` 属性，重新构建：

| 包名 | 预期结果 |
|---|---|
| `com.coolapk.market` | ★ 36 字符 DUID |
| `com.zhihu.android` | ★ 88 字符 DUID（前 36 与上面相同） |
| `com.tencent.mm` | ✗ 36 个 0 |
| 任意自造包名 | ✗ 36 个 0 |

⚠️ `android:name` 必须写完整类名（`com.coolapk.market.MainActivity`），
写 `.MainActivity` 会在改包名后 `ClassNotFoundException`。

也可以用现成脚本：

```sh
python3 ../tools/pkg_swap.py com.tencent.mm
```

---

## apiKey 格式

`Main.init()` 要的 `apiKey` 是 **42 字符、以 `11` 开头、index 2 是校验位**的串，
**不是** `cn.shuzilm.config.json` 里那个 RSA 公钥。

校验算法：

```java
if (s.length() != 42) return null;
if (s.charAt(0) != '1' || s.charAt(1) != '1') return null;

int i3 = 0, i4 = 0, i5 = 0;
for (int i6 = 2; i6 < s.length(); i6++) {
    int v = hexValue(s.charAt(i6));
    int i7 = i6 - 2;
    if (i7 >= 1 && i7 <= 7) {          // 索引 3..9
        i5 = (i5 << 4) | v;
        i3 += Integer.bitCount(v);
        i4 += i7 * v;
    }
}
int calc = (((i3 + i4) + (((i5 >>> 17) ^ ((i5 >>> 7) ^ i5)) & 0xFF)) % 15) + 1;
return Character.digit(s.charAt(2), 16) == calc;
```

**报文里 `75c` 字段的值就是这个 apiKey**（酷安的是
`11e7b222083a4b732b4b14811f6fc05995a01415eb`）。

不过它对签发结果**没有任何影响** —— 保留、删除、换成别的合法值都一样。

---

## 免责

仅用于协议互操作性研究，在自己持有的测试设备上进行。
