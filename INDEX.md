# 文件清单 · INDEX

> 完整文件列表与用途。自动生成部分见 [`_MANIFEST.txt`](_MANIFEST.txt)。

---

## 顶层

| 文件 | 大小 | 说明 |
|---|---:|---|
| `.gitignore` | 361 B | Git 忽略规则 |
| `PRIVACY.md` | 4.6 KB | 数据与隐私说明 |
| `README.md` | 2.3 KB | 项目简介 + 免责 + 导航 |
| `_MANIFEST.txt` | 12.6 KB | 文件清单（自动生成） |
| `mainline.md` | 11.6 KB | ★ 主线：八个问题，按解决顺序 |

## 文档（新）

按问题组织的 7 篇专题 + 必读的错误结论清单。

| 文件 | 大小 | 说明 |
|---|---:|---|
| `docs/01-请求长什么样.md` | 3.6 KB | ① 端点 / 参数 / 请求与响应格式 |
| `docs/02-body怎么解.md` | 4.7 KB | ② 两套 body 加密 + 池常量 + 编解码实现 |
| `docs/03-服务端看哪些字段.md` | 5.2 KB | ③ 校验边界：79 字段只用 6 个 |
| `docs/04-怎么认出设备.md` | 6.4 KB | ④ ★ 锚点机制（含早期错误结论的说明） |
| `docs/05-怎么稳定抓包.md` | 8.4 KB | ⑤ Frida 隐身 / ANR / toHex bug / 采集链路 |
| `docs/06-字段参考.md` | 6.0 KB | ⑥ 79 字段完整表 |
| `docs/07-未解问题.md` | 4.9 KB | ⑦ 三条未解 + 下一步建议 |
| `docs/99-已推翻的结论.md` | 12.4 KB | ⚠️ 必读：12 个被推翻的中间结论 |
| `docs/README.md` | 3.1 KB | 支线文档索引 |

## 归档文档

原始工作记录。**⚠️ 中间结论未经修正，读前先看 [99-已推翻的结论](99-已推翻的结论.md)。**

| 文件 | 大小 | 说明 |
|---|---:|---|
| `docs/_archive/01-protocol/01-协议总览.md` | 6.4 KB |  |
| `docs/_archive/01-protocol/02-body-加密.md` | 7.3 KB |  |
| `docs/_archive/01-protocol/03-h-算法.md` | 9.1 KB |  |
| `docs/_archive/01-protocol/04-p-构造.md` | 6.3 KB |  |
| `docs/_archive/01-protocol/04b-p-构造过程.md` | 5.7 KB |  |
| `docs/_archive/01-protocol/05-服务端校验边界.md` | 7.0 KB |  |
| `docs/_archive/01-protocol/06-字段判据.md` | 17.4 KB |  |
| `docs/_archive/01-protocol/07-压缩与落地测试.md` | 7.0 KB |  |
| `docs/_archive/01-protocol/08-签名结论.md` | 18.7 KB |  |
| `docs/_archive/01-protocol/09-签名链.md` | 11.8 KB |  |
| `docs/_archive/01-protocol/10-r-是自由值.md` | 3.7 KB |  |
| `docs/_archive/01-protocol/11-端点探测.md` | 5.8 KB |  |

… 共 62 个文件

## 工具

| 文件 | 大小 | 说明 |
|---|---:|---|
| `tools/README.md` | 5.3 KB | 工具说明与参数 |
| `tools/anchor_verify.py` | 5.4 KB |  |
| `tools/check_dpi.py` | 2.0 KB |  |
| `tools/combo_test.py` | 7.0 KB |  |
| `tools/decode_mdna_final.py` | 3.6 KB |  |
| `tools/devsel.py` | 4.6 KB |  |
| `tools/field_table.py` | 6.3 KB |  |
| `tools/find_real_anchor.py` | 5.3 KB |  |
| `tools/forge_mdna.py` | 3.0 KB |  |
| `tools/getduid.py` | 10.4 KB |  |
| `tools/getduid.sh` | 9.2 KB |  |
| `tools/hunt_fp_hashes.py` | 6.2 KB |  |
| `tools/hunt_sfOo.py` | 5.7 KB |  |
| `tools/make_getduid.py` | 8.7 KB |  |
| `tools/mis_random_matrix.py` | 6.9 KB |  |
| `tools/random_fp_test.py` | 8.0 KB |  |
| `tools/szlm_body.py` | 6.7 KB |  |
| `tools/szlm_forge.py` | 6.4 KB |  |
| `tools/szlm_id.py` | 12.2 KB |  |
| `tools/szlm_send.py` | 7.7 KB |  |
| `tools/test_adler.py` | 5.2 KB |  |
| `tools/test_identity_key.py` | 8.1 KB |  |
| `tools/verify_register_path.py` | 5.5 KB |  |

## 采集脚本

| 文件 | 大小 | 说明 |
|---|---:|---|
| `scripts/README.md` | 6.4 KB | 采集脚本说明 |
| `scripts/analysis/analyze_c3.py` | 4.4 KB |  |
| `scripts/analysis/analyze_cipher.py` | 4.0 KB |  |
| `scripts/analysis/analyze_d1a.py` | 3.9 KB |  |
| `scripts/analysis/dump_d2c_cipher.py` | 4.2 KB |  |
| `scripts/analysis/extract_szlm_har.py` | 5.1 KB |  |
| `scripts/analysis/field_stability.py` | 3.5 KB |  |
| `scripts/analysis/mis_key_test.py` | 5.6 KB |  |
| `scripts/analysis/mis_sparsity.py` | 4.1 KB |  |
| `scripts/analysis/pull_d1c2.py` | 3.2 KB |  |
| `scripts/analysis/pull_d1d.py` | 4.0 KB |  |
| `scripts/capture/attach_only.py` | 6.2 KB |  |
| `scripts/capture/clear_and_agree.py` | 2.4 KB |  |
| `scripts/capture/early_capture.py` | 10.7 KB |  |
| `scripts/capture/early_capture2_MAIN.py` | 12.3 KB |  |
| `scripts/capture/fix_dpi.py` | 2.0 KB |  |
| `scripts/capture/spawn_capture.py` | 8.2 KB |  |
| `scripts/capture/watch.sh` | 1.5 KB |  |
| `scripts/capture/watch_capture.py` | 9.0 KB |  |
| `scripts/frida/anti_debug_bypass.js` | 12.4 KB |  |
| `scripts/frida/anti_debug_v4.js` | 14.9 KB |  |
| `scripts/frida/anti_debug_v5.js` | 17.4 KB |  |
| `scripts/frida/cap_ssl.js` | 3.6 KB |  |
| `scripts/frida/cap_szlm.js` | 6.1 KB |  |
| `scripts/frida/diag_sock.js` | 3.7 KB |  |
| `scripts/frida/diag_ssl.js` | 2.8 KB |  |
| `scripts/frida/dujni.js` | 7.2 KB |  |
| `scripts/frida/hook_min.js` | 8.4 KB |  |
| `scripts/frida/hook_stealth.js` | 14.3 KB |  |
| `scripts/frida/hook_stealth2_MAIN.js` | 19.0 KB |  |

## 数据

| 文件 | 大小 | 说明 |
|---|---:|---|
| `data/README.md` | 4.5 KB | 数据说明 |
| `data/decoded/C3_PLAIN__Cp27497_t165519_IN_3235.json` | 7.8 KB |  |
| `data/decoded/C3_PLAIN__Cp27497_t289090_IN_2127.json` | 3.6 KB |  |
| `data/decoded/C3_PLAIN__Cp27497_t52831_OUT_21623.json` | 61.4 KB |  |
| `data/decoded/C3_PLAIN__Cp27497_t62957_IN_1843.json` | 3.0 KB |  |
| `data/decoded/C3_PLAIN__Cp27497_t65618_OUT_81.json` | 64 B |  |
| `data/decoded/C3_PLAIN__Cp27497_t79224_IN_2.json` | 0 B |  |
| `data/decoded/C3_PLAIN__Cp27497_t85561_OUT_2500.json` | 9.4 KB |  |
| `data/decoded/C3_PLAIN__Cp27497_t91460_IN_1255.json` | 4.5 KB |  |
| `data/decoded/D1C__MDNA_77537.json` | 2.3 KB |  |
| `data/decoded/D1H__MDNA_63185.json` | 2.3 KB |  |
| `data/decoded/D1H__MDNA_77537.json` | 2.3 KB |  |
| `data/decoded/D2A_PLAIN__Cp28210_t10777_IN_300.json` | 449 B |  |
| `data/decoded/D2A_PLAIN__Cp28210_t125761_OUT_155.json` | 166 B |  |
| `data/decoded/D2A_PLAIN__Cp28210_t13054_OUT_110.json` | 102 B |  |
| `data/decoded/D2A_PLAIN__Cp28210_t162380_IN_16.json` | 0 B |  |
| `data/decoded/D2A_PLAIN__Cp28210_t17912_IN_429.json` | 549 B |  |
| `data/decoded/D2A_PLAIN__Cp28210_t268447_IN_2066.json` | 3.4 KB |  |
| `data/samples/du_cap2_明文HTTP抓包.txt` | 43.7 KB |  |
| `data/samples/mdna_body.bin` | 1.0 KB |  |
| `data/samples/mdna_template.json` | 2.3 KB |  |
| `data/samples/szlm_last_mdna_http.bin` | 204 B |  |
| `data/samples/wire_m58_REQ_9_len1745.bin` | 1.7 KB |  |

## 采集产物

| 文件 | 大小 | 说明 |
|---|---:|---|
| `captures/README.md` | 4.6 KB | 采集产物说明 |
| `captures/device/10_0_0_37_5555/INSTALLATION2` | 39 B |  |
| `captures/device/10_0_0_37_5555/LOCAL_APP_STATUS_RULES_JSON` | 372 B |  |
| `captures/device/10_0_0_37_5555/TE_libdu_1195.txt` | 129 B |  |
| `captures/device/10_0_0_37_5555/TE_main_getTraceInfo_1195.txt` | 1.9 KB |  |
| `captures/device/10_0_0_37_5555/android_setting_info_game198b3` | 3.5 KB |  |
| `captures/device/10_0_0_37_5555/exid.dat` | 98 B |  |
| `captures/device/10_0_0_37_5555/gameScreenServer1` | 66.7 KB |  |
| `captures/device/10_0_0_37_5555/ksadsdk_sdk_config_data` | 28.2 KB |  |
| `captures/device/10_0_0_37_5555/main_v8_list_cache.json` | 225.5 KB |  |

… 共 1249 个文件

---

## 总量

```
文件总数  1401
总体积    48.21 MB
```
