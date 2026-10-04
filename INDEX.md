# 目录表 · INDEX

> 本文件列出发布目录下的全部文件与用途。
> 自动生成的部分见 [`_MANIFEST.txt`](_MANIFEST.txt)。

---

## 顶层

| 文件 | 说明 |
|---|---|
| [`README.md`](README.md) | 项目简介 + 免责声明 |
| [`mainline.md`](mainline.md) | **★ 主线文档**：从零到取回 DUID 的完整过程 |
| [`INDEX.md`](INDEX.md) | 本文件：目录表 |
| [`PRIVACY.md`](PRIVACY.md) | **数据与隐私说明**：仓库里有哪些真实值、哪些是公开常量、Fork 时如何替换 |
| [`_MANIFEST.txt`](_MANIFEST.txt) | 文件清单（大小 + 来源，自动生成） |

---

## docs/ — 支线文档

### `docs/01-protocol/` — 协议层

| 文件 | 内容 |
|---|---|
| `01-协议总览.md` | 端点、参数、整体流程 |
| `02-body-加密.md` | 两套 body 加密的完整推导 |
| `03-h-算法.md` | `h = MD5(DUID + ".889e0b01")` 的解法 |
| `04-p-构造.md` / `04b-p-构造过程.md` | `p` 的构造与推导过程 |
| `05-服务端校验边界.md` | **★ 87 字段扫描实验**：只有 6 个被使用 |
| `06-字段判据.md` | 各字段的判据与失败形态 |
| `07-压缩与落地测试.md` | zlib/gzip 相关实验 |
| `08-签名结论.md` / `09-签名链.md` | 是否存在签名机制的结论 |
| `10-r-是自由值.md` | `r` 参数不参与校验 |
| `11-端点探测.md` | 端点发现过程 |
| `12-设备指纹采集项.md` | **★ libdu 采集了哪些设备属性**（hook MD5 得到） |

### `docs/02-anchor/` — ★ 锚点机制（核心成果）

| 文件 | 内容 |
|---|---|
| `01-★mdna-抓取与字段分析.md` | **★ 本轮主成果**：抓到 mdna 报文 + 机制完全讲通 |
| `02-78字段完整清单.md` | 78 字段逐条语义与角色标注 |
| `03-缺口总表.md` | 距离目标还差什么 |
| `04-锚点调查.md` | 锚点定位过程 |
| `05-字段类型敏感.md` | 类型不符会导致 HTTP 400 |
| `06-DUID-普适性.md` | DUID 跨设备/跨环境的表现 |

### `docs/03-stealth/` — Frida 隐身与反调试

| 文件 | 内容 |
|---|---|
| `01-反调试绕过.md` | 四层反调试的识别与绕过 |
| `02-挂钩教训.md` | **★ 挂钩方法论**：先问三个问题，一次只挂一个 |
| `03-采集管线.md` | 采集流程演进与记录 |
| `04-隐身采集打通.md` | 本轮链路打通记录 |
| `05-★toHex-根因bug.md` | **★ 那个困扰整个采集阶段的 bug** |
| `06-网易易盾.md` | 酷安自身的加固（与本协议无关但干扰观测） |
| `07-Cipher-突破.md` | `Cipher.doFinal` 采集要点 |

### `docs/04-devices/` — 设备环境

| 文件 | 内容 |
|---|---|
| `01-设备踩坑与短命进程.md` | **★ 短命注册进程 + 观测铁律** |
| `02-真机报告.md` | 真机实测汇总 |
| `03-三设备环境.md` / `04-三设备交叉验证.md` | 多设备验证 |
| `05-多进程发现.md` | 多进程与消息 tag 冲突 |
| `06-代理客户端可行性.md` | 服务端对发送方的约束 |
| `07-配对采集与DPI修复.md` | 小屏设备 UI 适配 |

### `docs/05-mis-history/` — mIS 专题（**含已被推翻的结论**）

> ⚠️ **重要**：本目录内的早期结论（「mIS 是唯一钥匙」）**已被实验推翻**。
> 保留用于记录推理过程与错误来源。当前正确结论见 `docs/02-anchor/`。

| 文件 | 内容 |
|---|---|
| `01-mIS-算法结论.md` ~ `08-libdu编码搜索.md` | mIS 定性与穷举过程（历史） |

### `docs/06-libdu-history/` — libdu 逆向过程

| 文件 | 内容 |
|---|---|
| `01-逆向总结.md` | 整体总结 |
| `02-token表抓到.md` | 运行时抓到的 token → 字符串表 |
| `03-字母表找到.md` / `04-字母表抓取.md` | 编码字母表 |
| `05-编码器机制.md` / `06-编码器破解.md` | 编码器定位与结论 |
| `07-静态解码完成.md` ~ `11-加壳未加载.md` | 静态分析过程 |

### `docs/07-sessions/` — 会话记录

| 文件 | 内容 |
|---|---|
| `STEP_2026-10-04*.md` | 按步骤的详细记录（含命令与原始输出） |
| `会话总结与缺口.md` / `目标与缺口分析.md` / `缺口闭合审计.md` | 阶段总结 |
| `云端偏好解码.md` / `SDKManager层.md` | 相关组件 |

---

## tools/ — 可运行工具

| 文件 | 说明 |
|---|---|
| **`getduid.py`** | **★ 主工具**：单文件、零依赖，取 DUID（支持固定/随机三值） |
| `getduid.sh` | 同上的 shell 版（需要 Python） |
| `szlm_id.py` | 协议库：池常量、`p`/`h` 计算、body 编解码、请求构造 |
| `szlm_body.py` | body 编解码参考实现 |
| `szlm_send.py` / `szlm_forge.py` / `forge_mdna.py` | 请求构造与发送 |
| `decode_mdna_final.py` | 解 mdna 报文（池 `0x110DC8` + zlib） |
| `field_table.py` | 生成 78 字段完整清单 |
| `make_getduid.py` | 生成自包含的 `getduid.py` |
| **实验脚本** | |
| `random_fp_test.py` | 指纹哈希随机化 —— 测有无签名机制 |
| `combo_test.py` | 组合盲区测试 —— 只留锚点、其余全随机 |
| `anchor_verify.py` | 区分「真锚点」与「类型敏感」 |
| `find_real_anchor.py` | 逐字段哨兵化定位锚点 |
| `test_identity_key.py` | 找设备识别键 |
| `test_adler.py` | 测服务端是否校验 zlib 校验和 |
| `verify_register_path.py` | 验证注册路径假设 |
| `mis_random_matrix.py` | mIS×2cO 矩阵实验 |
| `hunt_sfOo.py` / `hunt_fp_hashes.py` | 追查锚点/指纹哈希来源 |
| `check_dpi.py` | 小屏设备 DPI 与 UI 元素检查 |

---

## scripts/ — 采集脚本

### `scripts/frida/` — Frida 钩子（JS）

| 文件 | 说明 |
|---|---|
| **`★hook_stealth2.js`** | **★ 最终钩子**：maps 重定向隐身 + 完整反调试 + SSL/SOCK/Cipher 采集 |
| `hook_stealth.js` | 上一版（用 read 过滤 maps，会 ANR，仅存档） |
| `hook_min.js` | 最小版（无 maps 过滤，会被检测） |
| `anti_debug_v5.js` | 反调试绕过参考实现 |
| `anti_debug_v4.js` / `anti_debug_bypass.js` | 早期版本 |
| `diag_ssl.js` / `diag_sock.js` | 诊断脚本（验证指针可读性） |
| `cap_szlm.js` / `cap_ssl.js` | 抓包钩子 |
| `dujni.js` | libdu JNI 层钩子 |

### `scripts/capture/` — 采集驱动

| 文件 | 说明 |
|---|---|
| **`★early_capture2.py`** | **★ 采集驱动**：设备端守望 + 快速 attach + 安全点按 + 弹窗处理 + 截图 |
| `early_capture.py` | 上一版 |
| `attach_only.py` | 零破坏性只读 attach 模板 |
| `watch.sh` | 设备端进程守望（30ms 轮询） |
| `spawn_capture.py` / `watch_capture.py` | spawn 与守望方案 |
| `clear_and_agree.py` | 清数据并走协议页 |
| `fix_dpi.py` | 小屏设备降密度 |

### `scripts/analysis/` — 分析脚本

| 文件 | 说明 |
|---|---|
| `analyze_c3.py` / `analyze_d1a.py` | 采集数据解析 |
| `analyze_cipher.py` / `dump_d2c_cipher.py` | `Cipher` 明文还原 |
| `field_stability.py` | 字段跨样本稳定性 |
| `mis_sparsity.py` / `mis_key_test.py` | mIS 差分分析 |
| `extract_szlm_har.py` | 从 HAR 提取 szlm 记录 |
| `pull_d1c2.py` / `pull_d1d.py` | 设备数据拉取（base64 逐个文件） |

---

## data/ — 数据

### `data/samples/` — 原始样本

| 文件 | 说明 |
|---|---|
| `mdna_template.json` | **★ 79 字段完整 mdna 报文模板**（工具靠它构造请求） |
| `wire_m58_REQ_9_len1745.bin` | 真实 mdna HTTP 请求原始字节 |
| `mdna_body.bin` / `szlm_last_mdna_http.bin` | 其它抓到的请求 |
| `du_cap2_明文HTTP抓包.txt` | tcpdump 明文抓包记录 |

### `data/decoded/` — 解出的明文

| 前缀 | 来源 |
|---|---|
| `D1C__MDNA_*.json` / `D1H__MDNA_*.json` | D1 两次注册的 mdna 明文（**锚点对比用**） |
| `C3_PLAIN__Cp*.json` | 一批 `Cipher` 明文 |
| `D2A_PLAIN__Cp*.json` | 同上 |

---

## 阅读建议（按目的）

| 想了解 | 从哪开始 |
|---|---|
| **完整过程（推荐）** | [`mainline.md`](mainline.md) |
| **整体结论** | [`README.md`](README.md) |
| **协议怎么走通** | `docs/01-protocol/01-协议总览.md` |
| **服务端校验边界** | `docs/01-protocol/05-服务端校验边界.md` |
| **★ 锚点机制** | `docs/02-anchor/01-★mdna-抓取与字段分析.md` |
| **★ 怎么抓到的** | `docs/03-stealth/05-★toHex-根因bug.md` |
| **自己动手试** | `tools/getduid.py` |
| **踩过的坑** | `docs/03-stealth/02-挂钩教训.md` + `docs/04-devices/01-*.md` |
| **错误结论怎么来的** | `docs/05-mis-history/`（对照 `docs/02-anchor/`） |
