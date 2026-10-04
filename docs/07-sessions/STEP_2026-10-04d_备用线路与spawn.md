# STEP_2026-10-04d · ★ 发现数字联盟的第二/三条上报线 + spawn 自杀重启

> 日期：2026-10-04 ｜ 设备：D3 ｜ 状态：★ 新线发现 / ◐ mdna 仍未拿到

---

## 一、这一步的结果一句话

**找到了数字联盟除 `auni.telecome.cn` 之外的另两条上报线**，
并且用 `spawn+gating` 从第 0 毫秒装钩子成功 —— 但 **Coolapk 检测到后反复自杀重启**，mdna 仍未拿到。

---

## 二、★★★ 核心新发现：数字联盟的第二/三条线

从本会话 `mis_origin_test4` 抓到的日志里挖出：

```
POST /anti_logs HTTP/1.1
appkey: 5a387236a40fa374880002f4          ← ★ 数字联盟的 appkey
Content-Type: application/octet-stream
User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; LineageOS GSI on ARM64 Build/TQ3A.230901.001)
Host: yumao.puata.info                     ← ★★★ 新 Host
Connection: Keep-Alive
Accept-Encoding: gzip
Content-Length: 396

POST /ra HTTP/1.1
Content-Type: application/octet-stream
Content-Encoding: xgzip                    ← ★ 腾讯 xgzip
appkey: 5a387236a40fa374880002f4
Content-Length: 253
Host: ccs.umeng.com                        ← ★★★ 另一个 Host
```

**⇒ 数盟的上报不只走 `auni.telecome.cn`；还有带 `appkey` 请求头的另一组线路。**

### 2.1 两个 body 有相同的 10 字节固定头

```
/anti_logs(body 396B): 2a eb 39 3b 33 37 35 31 69 3d | 67 fd 22 4d ea 0b 38 ec ...
/ra      (body 253B): 2a eb 39 3b 33 37 35 31 69 3d | 1f 3d ac 50 ba 0b 3c d2 ...
```

**⇒ 固定头 + 加密数据。** 已试：池常量 XOR（4 个密钥 × 多偏移）、AES(GWL8jXHLnzp63QDH) —— 均未解出。

### 2.2 数据出处（可复现）

| 文件 | 说明 |
|---|---|
| `dev2/M4_10_0_0_38_5555_S8_n*_27175.txt.txt` | 含 `/anti_logs` 与 `/ra` 的完整记录（14 条） |
| `dev2/S2G_10_0_0_38_5555_S2_hb*_8339.txt.txt` | 另一次抓取（18 条） |

**★ 注意**：这是从 `mis_origin_test4.py` 那次抓包产物里挖出来的 —— 那次我用 `spawn` 之前的双路抓包，
**说明这条线在 attach 之后仍能抓到**（不像 mdna 那么早）。

---

## 三、spawn+gating 的结果：钩子装上了，但进程自杀

```
✓✓✓ 钩子已装（JVM 起来之前）
[ok] Cipher 钩子: init, init3, doFinal([B), doFinal([B,int,int)
[ok] SSL: libssl.so.SSL_write, SSL_read, libjavacrypto.so.SSL_write, SSL_read
[ok] SOCK: send,sendto,recv,recvfrom
[ok] ClassLoader.loadClass
```

**但注册过程中**：

```
[+10.20s] 捕捉到 pid=28270 → [-12.18s] 消失   （活 ~2.0s）
[+14.90s] 捕捉到 pid=28538 → [-16.28s] 消失   （活 ~1.4s）
[+18.42s] 捕捉到 pid=28735 → [-19.80s] 消失   （活 ~1.4s）
... 反复循环，prefs 卡在 33，注册从未完成
最终统计: CIPHER=0  SSL=0  SOCK=6  CLASS=0
```

**⇒ 装了 `Cipher`/`SSL`/`SOCK` 这些 `Interceptor.attach` 钩子之后，反调试就检测到了，
进程自杀并从 zygote 重启，钩子随之丢失。**

**★ 对照**：`minimal_antidbg.js`（只用 `Interceptor.replace` 改 libc 的 4 个函数）能让注册完整跑完
（prefs 306→375，抓到 481 条记录）。**差别在钩子类型与目标模块。**

---

## 四、★ 纠正一个我之前说错的结论

```
我此前说：「frida 挂着时 adb input tap 在 D3 上失效」
实测（本轮 spawn 那次）：
    [  0s] prefs=6    tap=1
    [  8s] prefs=306  tap=2      ← ★ 点按生效了
⇒ 该结论是错的。那是从被压缩的上下文里继承的错误信念，
   我后来几轮一直按它设计脚本（写了一大堆 performClick 后备逻辑），属于白费功夫。
```

---

## 五、对缺口清单的影响

| # | 缺口 | 之前 | 现在 |
|---|---|---|---|
| **1** | `mIS` 的算法 | ❌ 未解 | ❌ 未解（本轮没推进） |
| **2** | `suffix` 派生 | ⬜ | ⬜ |
| **3** | `deviceId` 规则 | ⬜ | ⬜ |
| **4** | 无 root 路径 | ❌ | ❌ |
| **5** | 谁触发 `Main.init` | 🔄 | 🔄 `ClassLoader.loadClass` 钩子已能装，但进程活不长抓不到 |
| **6** | ★ **数盟第二/三条线** | — | ★ **新发现**：`yumao.puata.info` / `ccs.umeng.com`，body 有 10 字节固定头 |
| **7** | ★ **app 自杀重启** | — | ★ **新阻塞点**：装了重钩子就被检测 |

---

## 六、下一步（按性价比）

```
1. ★ 解 `2aeb393b33373531693d` 这个 10 字节头
     它是两条新线共同的固定头；若解出，可能直接拿到一个明文通道

2. ★ 让钩子「不被检测」——这是 spawn 路线的前提
     思路：
       · 不 hook Cipher（Java 层），改 hook native 的 EVP_* （文档推荐，开销最低）
       · 或把钩子延迟到进程稳定后再装（但那会错过早期上报）
       · 或找出「是哪一个检测点导致自杀」—— 逐个钩子开/关做二分

3. 用「只 hook SSL」的最小集合重试 spawn（SSL 是文档列为安全的）
      先求「能活下来」，再逐步加钩子

4. 若 spawn 路线走不通 → 回到两段式 attach，
      但把抓包脚本压到只剩 SSL 一项，并把 attach 时机提前到 am start 之后 1 秒内
```

---

## 七、本轮新增脚本

| 脚本 | 作用 |
|---|---|
| **`spawn_hook.js`** | ★ spawn+gating 用的全量钩子（Cipher/SSL/SOCK/ClassLoader + 反调试） |
| **`spawn_capture.py`** | spawn+gating 采集驱动 |
| **`watch_capture.py`** | ★ **进程守望**：0.15s 扫一次，出现即 attach（覆盖自杀重启） |
| `field_stability.py` | 18 个明文的字段稳定性分析（找出恒定/变化字段） |
| `szlm_alt_line.py` / `alt_line_decode.py` | ★ 挖数字联盟第二/三条线 |
| `alt_prefix_probe.py` | 反推 10 字节固定头对应的密钥 |

---

## 八、诚实记录：本轮没做到的

```
✗ 没拿到 mdna 明文
✗ 没推进 mIS 的算法
✗ 没解开 10 字节固定头
✗ spawn 路线受阻于 app 自杀重启
```

**但新增了两条可追的线（`yumao.puata.info` / `ccs.umeng.com`），
以及一个明确的工程阻塞点（重钩子被检测 → 自杀重启）。**
