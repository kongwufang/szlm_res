# 突破：找到正确的 hook 点 —— Cipher.doFinal

## 一、决定性成果

`javax.crypto.Cipher.doFinal` 是**可用且安全**的 hook 点。

**实测数据（90 秒窗口）**：

```
### [# 1]  doFinal in=816   out=815   alg=AES/ECB/PKCS5Padding/null
### [# 2]  doFinal in=272   out=266   alg=AES/ECB/PKCS5Padding/null
### [# 3]  doFinal in=8000  out=7989  alg=AES/CBC/PKCS5Padding/<iv>
### [# 5]  doFinal in=2336  out=2332  alg=AES/ECB/PKCS5Padding/null
### [# 11] doFinal in=21680 out=21679 alg=AES/ECB/PKCS5Padding/null
### [# 25] doFinal in=21648 out=21647 alg=AES/ECB/PKCS5Padding/null

[频率] doFinal 已调用 20 次
[心跳] total=20 caught=0
```

**进程全程稳定，没有崩溃，没有 ANR。**

---

## 二、三次崩机与一次成功的分界线

| hook 点 | 调用频率 | 结果 |
|---|---|---|
| `memcpy` / `strcpy` / `strncpy` / `strcat` | 极热 | **酷安 5 秒 ANR** |
| `java.io.OutputStream.write` | 每秒上千次 | **所有应用崩** |
| `okhttp3.RequestBody.writeTo`（含递归 bug） | 中 | **所有应用卡退** |
| **`javax.crypto.Cipher.doFinal`** | **90 秒 20 次** | **稳定，且直接给出明文** |

**结论：选 hook 点的第一判据是调用频率，不是「能不能拿到数据」。**

---

## 三、抓到的明文内容

`OUT` 字段的 hex 解码后是**明文 JSON**：

```json
{"event":"sdk_init","params":{"device_info":{
    "os":1,
    "imei_md5":"",
    "oaid":"",
    "applog_did":"2468865544836580",
    "device_model":"XTQ_Watch",
    "vendor":"sprd",
    ...
```

**多种事件类型**（来自不同 `doFinal` 调用）：

```
{"event":"sdk_init",                     "params":{"device_info":{...}}}
{"event":"sdk_init_end",                 "params":{"device_info":{...}}}
{"event":"get_config_final",             "params":{"device_info":{...}}}
{"event":"init_adn_splash_info_request", "params":{"device_info":{...}}}
```

**还抓到 RSA 公钥明文**：

```
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuvdBJwbAoCuzm0bWQP2WdSZ5JniZwnfIjT5ULnrJ6
qojzAKJ3nmxClMaoE4x03BNhInfIvxTdcQpfgqL7l5o354hDfneODQ4+g+JAyaGvDvt6zPEmW9IVZ+PV
ra/WbVsuWVdiAoh73ACzAKh0Aytkk...
```

**这与之前静态分析得到的是同一个 2048 位公钥**，确认它被运行时使用。

---

## 四、数据方向判别

`doFinal` 同时用于加密与解密，靠 gzip 魔数区分：

```
IN  以 1f8b0800 开头  ->  IN 是压缩明文，OUT 是密文    => 加密
OUT 以 1f8b0800 开头  =>  IN 是密文，OUT 是压缩明文    => 解密
```

**算法栈**：`AES/ECB/PKCS5Padding`，IV 为 `null` —— 与响应解密完全一致。

---

## 五、hook 写法（关键）

```js
const Cipher = Java.use('javax.crypto.Cipher');
const df = Cipher.doFinal.overload('[B');
df.implementation = function (input) {
    // input = 明文或密文
    const out = df.call(this, input);   // ★ 必须用 .call，不能 this.doFinal()
    return out;
};
```

**`this.doFinal(input)` 会重入 hook 导致无限递归 —— 这是第 2 次崩机的直接原因。**

---

## 六、当前卡点

**不再是「不知道挂哪里」，而是「数盟不上报」。**

两种情形都试过：

| 方式 | 问题 |
|---|---|
| `--no-clear` | 数盟走缓存，不发请求 |
| 带 `pm clear` | 酷安在协议页阶段交互不稳定，最后 ANR |

**但这条链路本身验证过是通的** —— `capture_timing.py` + `real_plite.js` 那次成功抓到过完整 7 个上报。

**问题是设备状态**：今天重启 3 次、ANR 3 次、内存清过一轮，负载长期在 6–13 之间。

---

## 七、恢复后的完整流程

```bash
# 1. 清数据并启动到协议页
python attach_all.py 200 real_gzip.js

# 2. 脚本会自动点协议（若还在协议页）
# 3. 观察日志出现：
#      >>> URL: POST /a/mdna/report?...
#      ##### [加密上报?] #N in=xxxx out=xxxx
#      PLAIN_GZIP:N:<hex>
# 4. 提取 PLAIN_GZIP 的 hex，Python gunzip 得到完整明文 JSON
```

**预期在明文里能看到**：`p` 的输入字段、`device_label`、完整指纹数据。

---

## 八、资产

| 文件 | 用途 |
|---|---|
| **`real_gzip.js`** | **当前主武器：Cipher.doFinal + SSL_write 联合抓取** |
| `real_cipher.js` | 低压验证版（只记频率） |
| `attach_all.py` | 全进程 attach，支持 `--no-clear` |
| `real_backtrace.js` | SSL_write 调用栈探针 |
| `HOOK_LESSONS.md` | 三次崩机的教训 |
| `SUMMARY.md` | 整体进度 |
| `PROTOCOL_COMPLETE.md` | 协议全景 |
| `P_CONSTRUCTION.md` | p 构造链静态分析 |
