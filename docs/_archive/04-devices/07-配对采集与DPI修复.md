# 双设备抓包：DPI 适配 + 落盘权限 + 触发条件

> 承接 `PAIR_CAPTURE_RESULT.md`。本轮解决了三个具体卡点，并**第一次抓到多个端点的完整 body**。
>
> 日期：2026-10-03 ｜ 设备：D1 TK_Watch（USB）/ D2 XTQ_Watch（USB）

---

## 一、★★ 本轮最大的进展：抓到了完整 body（但落盘被权限挡住）

在 Q_D2 那一轮，管线**第一次完整抓到多个端点**：

```
★★ 端点: dcc2
      [chunk] id=2 本片=895  body片=513  累计=513/513     ← 收齐
★★ 端点: dai
      [chunk] id=6 本片=1817 body片=1436 累计=1436/1436   ← 收齐
★★ 端点: audd
      [chunk] id=8 本片=1019 body片=640  累计=640/640     ← 收齐
```

对比旧样本：

| 端点 | 旧样本 CL | 本轮抓到 | 池常量 |
|---|---|---|---|
| `dcc2` | 546 | **513** | `0x109CF0` |
| `dai` | 1420 | **1436** | `0x10924C` |
| `audd` | 655 | **640** | `0x1090F8` |

**⇒ 分片累积修好了**（`body片` + `累计=总/总` 都对）。

**但全部落盘失败**：

```
@@ SAVE_FAIL /data/local/tmp/cap/p11489_REQB_2.bin Error: Permission denied
```

### 1.1 原因与修法

```
frida-server 以【shell】身份运行
/data/local/tmp/cap 由 su( root ) 创建 → 默认 root:root，app/js 写不进去

修法：chmod 777 /data/local/tmp/cap
验证：以 shell 身份 echo test > /data/local/tmp/cap/perm_test.txt → 成功
```

已固化进 `cap_pair3.prepare_devdir()`（含「可写自检」一行）。

---

## 二、DPI 问题（你的观察是对的）

### 2.1 现象

```
D2 物理：368x448 @ density 180
协议页在 density 180 下：「同意协议并继续」bounds = [141,407][341,448]
                             → bottom=448 = 屏幕最后一行，实际已贴底/被顶出
```

在 density 140 下：

```
「同意协议并继续」bounds = [137,385][347,434]  → bottom=434，完整可见
中心 = (242, 409)
```

**⇒ 降 dpi 确实能把按钮拉回可视区。**

### 2.2 但有个坑：`wm density` 后如果 `pm clear`，override 可能丢

```
设了 wm density 140 → settings: display_density_forced=140   ✓
随后 pm clear + am start → 有时 wm density 又回到只有
   "Physical density: 180"（Override 行消失）
   → 协议页布局又变回 180 的，按钮 bottom 又变成 448
```

**⇒ 顺序要改：先 pm clear、启动 app、确认布局，再设 dpi；或者设完 dpi 后
不要立刻 pm clear，而是先 am start 让系统重新读取。**

### 2.3 ★ 但实测：两台的按钮**都在屏内**，点击其实有效

```
D1（不设 dpi，density 180）：「同意协议并继续」= [141,383][341,447]  bottom=447
                             → 我按 (241,415) 点击，**有效**（进程正常拉起）
D2（density 180）            ：= [141,407][341,448]  bottom=448
                             → 我按 (241,427) 点击，**同样有效**
```

**结论：按钮「贴底」不等于「点不到」。** 我前几轮把「点协议页失败」归因于
按钮出屏是**误判** —— 真正的问题在别处（见第三节）。

**不过 DPI 调整仍有价值**：让 uiautomator dump 更稳定、坐标更可靠。

---

## 三、★★ 真正的卡点：触发条件

连续跑了几轮（QD2 / R_D2 / S_D2）都是 **0 端点**，而 Q_D2 那轮有 3 个端点。
差异在这里：

| 轮次 | pm clear | 结果 |
|---|---|---|
| **Q_D2** | **否**（沿用上一轮已注册的状态）| **3 个端点 + 完整 body** |
| R_D2 / S_D2 | 是 | 0 端点 |

**⇒ `/a/` 上报的触发条件是【已注册状态的 app 重启后重新上报】，
不是【pm clear 后的冷启动】。**

这与 `CAPTURE_PIPELINE.md` 的观察一致：

```
· mdna     —— 删掉 dna.xml 就会触发
· dcc2/dai/audd/daa —— 只在【注册流程】里发
· 而「注册流程」是：协议页点同意 → SDK 初始化 → 逐个端点上报
```

**⇒ 正确顺序应该是**：

```
① 启动 app 到稳定（协议页点同意，等注册完成）
② 挂钩子（此时 app 已注册，钩子挂好）
③ 重启 app（am start）—— 这一次的重启会重跑上报序列，而钩子已在位
```

之前几轮都在 ①/② 之间反复切，导致要么钩子太晚、要么触发条件不对。

---

## 四、D1 的 watcher 问题（已修）

```
D1 上子进程 com.coolapk.market:xg_vip_service 会先出现，而且数量多（5~9 个），
抢占了 attach 配额 → 真正发上报的【主进程】挂不上。

实测主进程要 7 秒后才出现在 frida 的进程表里，且要与子进程竞争。
```

**修法**：watcher 里把进程按「主进程优先」排序：

```python
procs.sort(key=lambda p: (0 if p.name == PKG else 1, p.pid))
```

已固化进 `cap_pair3.watch()`，日志里主进程会标 `★主进程`。

---

## 五、脚本清单

| 脚本 | 作用 |
|---|---|
| `cap_file.js` | **钩子 + 设备内落盘**（绕开消息回传的所有坑） |
| `cap_pair3.py` | 完整驱动：DPI、清数据、点协议页、watcher（主进程优先）、落盘权限、pull 回本地并用池常量解 body |
| `cap_pair2.py` | 上一版（消息回传，保留作对照） |
| `agreement_probe.py` | 协议页判据与坐标探测（含 DPI 对比） |

---

## 六、下一轮的正确流程（已写进脚本，只差跑对顺序）

```
[1] 两台都：启动 app → 点协议页 → 等 60s 让注册完成
[2] watcher 挂上钩子（此时 app 状态是「已注册」）
[3] 确认 /data/local/tmp/cap 可写（脚本会自检）
[4] am force-stop + am start 重启 —— 触发上报序列
[5] 等 60s，然后 ls /data/local/tmp/cap 并 pull
[6] 用池常量解 body，取 mIS 做交叉比对
```

**关键判据**：只要 `ls /data/local/tmp/cap` 里出现 `p*_REQB_*.bin`，
就是抓到了；`p*_REQB_*.json` 出现就是解出了。

---

## 七、教训

```
① 把「按钮贴底」当成「点不到」是误判 —— 应该用「点了之后进程/状态有没有变」来验证，
   而不是靠 bounds 猜。
② frida-server 的身份（shell）决定它能写哪些目录；/data/local/tmp 下 su 建的目录
   默认写不进去，必须 chmod 777。
③ 触发条件是「已注册 + 重启」，不是「清数据 + 冷启动」——
   连续三轮把顺序搞反，浪费了时间。改触发方式前应该先确认
   「上一次成功时到底是什么状态」。
```
