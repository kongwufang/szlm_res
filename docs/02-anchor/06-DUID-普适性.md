# DUID 普适性验证报告

设备: PinTaiQi XTQ_Watch / Android 9 / arm64 / Magisk root

---

## 一、实验设计

要回答的问题：**能否伪造一份设备信息，让数盟签发出一个酷安 API 认可的 DUID？**

三个递进实验：
1. 改 `ro.product.model / brand / manufacturer` → 清缓存 → 看 DUID
2. 改 `Settings.Secure.ANDROID_ID` → 清缓存 → 看 DUID
3. 定位 DUID 的所有本地落盘物，彻底清干净 → 看 DUID

---

## 二、实测结果

### 实验 1：篡改机型/品牌/厂商

```
基线(原设备)                 -> DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9
伪造 ThinkPad X1 Carbon      -> DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9
    ro.product.model        = ThinkPadX1Carbon
    ro.product.brand        = Lenovo
    ro.product.manufacturer = LENOVO
伪造 Xiaomi Mi 10            -> DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9
    ro.product.model = M2001J2E, brand/manufacturer = Xiaomi,
    name/device = umi
```

**DUID 完全不变。**

### 实验 2：篡改 Android ID

```
android_id = df9e3c7411278481 (原)  -> DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9
android_id = 0123456789abcdef (改)  -> DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9
```

**DUID 完全不变。**

### 实验 3：定位 DUID 的全部落盘物（**关键发现**）

```
/data/data/com.coolapk.market/shared_prefs/com.coolapk.market_dna.xml
    <string name="device_id">DUFPnec5dST2pTeImYGBClyhOnoUecHYyWg9</string>
    <string name="device_label">6KYDnLSlcHZQV83Yq2P63w==</string>

/data/data/com.coolapk.market/shared_prefs/coolapk_preferences_v7.xml
    ← 也含同一个 DUID 字符串！

/data/data/com.coolapk.market/files/du.lock        (0 字节，锁标记)
/data/data/com.coolapk.market/app_DUHOME/          (空目录，数盟工作目录)
```

**这是本项目最重要的踩坑点**：

> **酷安把 DUID 同时存在两处。只清 `dna.xml` 会被 `coolapk_preferences_v7.xml` 回填**，
> 导致"清缓存后 DUID 仍不变"的假象。此前多轮实验都因此得到错误结论。

**必须两处同时清**，才能观察真实行为。

---

## 三、结论

### 1. DUID 是**服务端签发**的，不是本地计算

证据链：
- 清除全部本地缓存（两处 prefs + du.lock）后重启，DUID 仍被服务端返回同一个值
- DUID 不随 `ro.product.*` 变化
- DUID 不随 Android ID 变化
- `getQueryID()` 是**同步**返回，无本地加密运算痕迹（对应链路的 `snprintf`/AES 只用于**上行 body**）

### 2. 服务端识别设备所依赖的**不是**这些表层属性

已排除：
- `ro.product.model` / `brand` / `manufacturer` / `name` / `device`
- `Settings.Secure.ANDROID_ID`

### 3. 服务端实际依赖的（据实测抓取推断）

数盟上行体里实测采集到的指纹项：
- **已安装应用列表**，格式 `{"包名":"是否系统应用,首装天数,签名MD5"}`
- **`ua`** — `Dalvik/2.1.0 (Linux; U; Android 9; zh-CN; XTQ_Watch Build/PPR1.180610.011)`
- **`device_model` / `vendor` / `os` / `ip`**
- **`imei_md5` / `oaid` / `applog_did`**
- **签名证书**（应用签名的稳定派生）

真正的锚点最可能是 **「签名证书 + 已安装应用集合 + 网络出口」的组合指纹**，
以及服务端侧的**首次上报记录**。

### 4. 对「伪造设备信息换 DUID」的可判定结论

- **只改表层属性（机型/品牌/Android ID）：无效** —— 实测 DUID 纹丝不动
- **完整伪造全部指纹项（含签名、应用列表、UA、出口 IP）：理论可行但工程量大**，
  且服务端可能有未知的风控规则（如"同 IP 短时间大量新设备"直接拒绝）
- **最实际的做法**：直接复用**已在服务端登记过的真机 DUID**，
  即 `getQueryID()` 的返回值 —— 它与设备绑定，不会因本地缓存清理而失效

---

## 四、可复现的验证脚本

| 脚本 | 作用 |
|---|---|
| `test_spoof.py` | 篡改机型/品牌/厂商，对比 DUID |
| `test_anchor.py` | 篡改 Android ID，对比 DUID；含设备属性恢复 |
| `test_clear_all.py` | **两处 prefs 同时清**（正确做法），观察 DUID 真实行为 |
| `find_anchor.py` | 扫出 DUID 的全部本地落盘物 |

**运行前提**：真机在线（`74584773985655`）+ Magisk root + frida-server 16.7.19。

---

## 五、踩坑记录（重要）

1. **`resetprop -p <key>` 不是"恢复"，是"从 persist 分区读取"** —— 用它恢复改坏的属性
   会失败（读回来还是篡改值）。正确做法是 `resetprop --delete <key>` 撤销覆盖，
   再用 `resetprop <key> <原值>` 设回。
2. **`dna.xml` 与 `coolapk_preferences_v7.xml` 双写** —— 只清一处必然被回填。
3. **`/data/data/<pkg>/app_DUHOME/`** 是数盟工作目录，实测为空（未落盘任何东西）。
4. **`device_id.vip.xml` 是腾讯 TPNS 的**，不是数盟的（key 为 MD5 样式、value 为 48B base64）。
