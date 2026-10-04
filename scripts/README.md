# scripts/ — 采集脚本

> 👈 回到 [主线文档](../mainline.md) ｜ 相关支线 [03-stealth](../docs/03-stealth/) · [04-devices](../docs/04-devices/)

---

三部分：`frida/`（JS 钩子）、`capture/`（采集驱动）、`analysis/`（数据分析）。

---

## 一、`frida/` — Frida 钩子（JavaScript）

### 主钩子

| 文件 | 说明 |
|---|---|
| **`★hook_stealth2.js`** | **★ 最终版**：maps 重定向隐身 + 完整反调试 + SSL/SOCK/Cipher 采集 |

**它做了五件事：**

```
① maps 重定向（隐身核心）
   拦截 open/openat 对 /proc/*/maps 的访问 → 现场生成滤掉 frida 行的副本
   → 返回副本 fd。完全不碰 read()（那是 ANR 的根源）

② 反调试绕过
   prctl(SVMA / DUMPABLE) / kill / tgkill / tkill / pthread_kill / raise
   拦 SIGTRAP(5) 与 SIGABRT(6) / strstr 命中关键词置 0 / ptrace 置 0
   Java 层：Process.killProcess / Process.exit / System.exit

③ SSL 采集（libssl.so + libjavacrypto.so 的 SSL_write / SSL_read）
   明文 HTTP 请求可见

④ Cipher 采集（javax.crypto.Cipher.doFinal 的单参数版与三参数版）
   明文 JSON / gzip(JSON) 可见

⑤ native socket 采集（send / sendto —— 刻意不钩 write / read）
   只对「像 HTTP」的记录做 hex，避免高频 ANR

★ 关键实现点：
   · toHex 必须区分 NativePointer 与 Java byte[]（见 docs/03-stealth/05-★toHex-根因bug.md）
   · 关键请求（szlm 的 HTTP）存入独立数组 KEEPS，不参与 recs 的淘汰
   · Cipher 钩子必须用 ov.call(this, input)，不能 this.doFinal(input)
```

### 其它钩子

| 文件 | 用途 |
|---|---|
| `hook_stealth.js` | 上一版（用 `read()` 过滤 maps，会 ANR，**仅存档**） |
| `hook_min.js` | 最小版（无 maps 过滤，会被检测到注入） |
| `anti_debug_v5.js` | 反调试绕过的**参考实现**（含四种防线） |
| `anti_debug_v4.js` / `anti_debug_bypass.js` | 早期版本 |
| `diag_ssl.js` | 诊断：验证 SSL 指针可读性（定位 toHex bug 就靠它） |
| `diag_sock.js` | 诊断：验证 native 指针可读性 |
| `cap_szlm.js` / `cap_ssl.js` | 定向抓包 |
| `dujni.js` | libdu JNI 层钩子 |

### 使用提示

```sh
# 钩子由采集驱动加载，也可手动挂：
frida -U -f com.coolapk.market -l scripts/frida/★hook_stealth2.js --no-pause

# ★ 注意：frida-server 的文件名与端口要伪装
#   （防线 1 会检测 "frida" 文件名与默认端口）
cp /data/local/tmp/frida-server /data/local/tmp/fs
chmod 777 /data/local/tmp/fs
setsid /data/local/tmp/fs -l 0.0.0.0:31337 &
```

---

## 二、`capture/` — 采集驱动

| 文件 | 说明 |
|---|---|
| **`★early_capture2.py`** | **★ 主驱动** |
| `early_capture.py` | 上一版 |
| `attach_only.py` | **零破坏性只读 attach 模板**（改脚本时从这里派生） |
| `watch.sh` | 设备端进程守望（30ms 轮询，精确匹配 cmdline 首 token） |
| `spawn_capture.py` / `watch_capture.py` | spawn 与守望方案 |
| `clear_and_agree.py` | 清数据并走完协议页 |
| `fix_dpi.py` | 小屏设备降密度（`wm density`） |

### `★early_capture2.py` 做了什么

```
① 起 frida-server（伪装名 + 非默认端口）
② 部署 watch.sh 到设备，清 app 数据
③ 双通道进程守望：
     · 设备端 watch.sh（30ms 轮询）
     · frida 侧 get_process() 直查（比 enumerate_processes 快得多）
④ am start 启动 App（轮询线程【已在跑】）
⑤ 进程一出现立刻 attach
⑥ 安全点按推进注册：
     · 每次点按前【重新 dump UI】，确认按钮在场才点
     · 绝不用缓存坐标（否则会点到《用户协议》链接 → 跳浏览器）
⑦ 弹窗处理：
     · 白名单点【取消 / 以后再说 / 关闭】
     · 黑名单【立即更新 / 下载 / 安装】→ 按 BACK 回避
⑧ 周期截图 → devout/SHOT/
⑨ 强制落盘 + 取回数据
```

### 关键改进（都是踩坑换来的）

| 改进 | 效果 |
|---|---|
| `get_process()` 直查替代 `enumerate_processes()` | attach 从 10–21 秒降到 **2.4 秒** |
| 每次点按前重新 dump UI | 不再误跳浏览器 |
| 弹窗白/黑名单 | 不再被「更新提示」挡住 |
| 周期截图 | 直接看到真实界面（正是靠它发现了更新弹窗） |

### ⚠️ 安全提醒

```sh
# 从既有脚本派生新脚本时，务必逐行检查破坏性操作：
#   pm clear / rm -rf / iptables / am force-stop / input tap
#
# 本项目就发生过：派生脚本继承了父脚本的 pm clear，误清了设备数据。
```

---

## 三、`analysis/` — 分析脚本

| 文件 | 说明 |
|---|---|
| `analyze_c3.py` / `analyze_d1a.py` | 采集数据解析（含 KEEPS 记录处理） |
| `analyze_cipher.py` | `Cipher` 明文还原（gzip / zlib / 明文多路尝试） |
| `dump_d2c_cipher.py` | 批量解 `Cipher` 记录 |
| `field_stability.py` | 字段跨样本稳定性统计 |
| `mis_sparsity.py` / `mis_key_test.py` | mIS 差分分析 |
| `extract_szlm_har.py` | 从 HAR 文件提取 szlm 记录 |
| `pull_d1c2.py` / `pull_d1d.py` | 设备数据拉取 |

### 拉取数据的坑

```
✗ 逐个 `cat` 大量文件 → WiFi ADB 超时
✗ 用 `ls` 输出做文件名解析 → 输出混入内容，文件名被拆碎
✗ `su -c "for f in ..."` 在部分设备上 shell 不支持

✓ 最可靠：su -c "base64 -w 0 <单个文件>"，Python 侧解码
✓ 或：adb pull（先 cp 到 /sdcard）
```

---

## 四、依赖

```
frida            16.x（版本要与设备上的 frida-server 一致）
python           3.6+（标准库）
adb              platform-tools
设备端            frida-server（arm64）
```

**⚠️ frida 客户端与服务端版本必须匹配**，否则 attach 会失败。
本项目用 16.7.19。

---

## 五、最小复现路径

```sh
# 1. 准备设备（root，开 WiFi ADB）
adb connect <device>:5555

# 2. 部署 frida-server（伪装名 + 非默认端口）
cp frida-server /data/local/tmp/fs && chmod 777 /data/local/tmp/fs
setsid /data/local/tmp/fs -l 0.0.0.0:31337 &

# 3. 跑采集（会清 app 数据 → 走完整注册流程）
python early_capture2.py <device>:5555 7 hook_stealth2.js myrun

# 4. 分析产物
python ../analysis/analyze_c3.py
```

**预期产物**：`HS2_forced_p<pid>.txt`，其中 `KEEP` 开头的行就是抓到的 szlm HTTP 请求。
