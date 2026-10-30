# szlm_res

> **致谢**：感谢 [**People-11**](https://github.com/People-11) 的公开分析 —— 他关于 `libdu.so` 字段编码与采集项的研究，为本项目最关键的突破提供了基础。

对**数字联盟（cn.shuzilm）设备标识协议**的逆向记录。

酷安（`com.coolapk.market`）集成了数字联盟 SDK（`libdu.so`），启动时会向
`auni.telecome.cn` 上报设备信息并取回一个 **DUID**（设备唯一 ID）。

本项目把这条链路走通了：抓到了完整协议、解出了 body 加密、测定了服务端的
校验边界、定位了设备识别的真正锚点、**破译了字段编码**，并做出了可离线构造请求的工具。

**👉 完整过程请看 → [主线文档](mainline.md)**

主线按时间顺序分八节，每节都是「问题是什么 → 怎么发现的 → 怎么试的 → 结果如何」。

---

## ⚠️ 先读这一份

逆向过程中产生过若干**中间结论**，后来被实验推翻。

**[已推翻的结论 →](docs/99-已推翻的结论.md)**

如果不先读它，在看归档文档时很容易被已作废的判断误导。

---

## 核心结论

```
① 设备识别的锚点 = (sfOo, foO, 2cO) 三元组
   sfOo 是校验值：MD5_UPPER(str(16 位码位之和))[:7]
   foO  是 ANDROID_ID 前 15 位的编码
   2cO  是本次上报时间

② 字段"编码"完全可逆
   e[i] = chr(((ord(p[i]) - 0x20 + K) % 95) + 0x20)，再按 shuffle 重排
   K 每份报文不同（实测 5~56），需自动定位

③ 服务端只校验 6 个字段，其余 73 个不参与识别
④ 无签名机制；完整 body + 随机三元组 = 有效新 DUID
```

详见 [字段编码破解](docs/08-破解字段编码.md)。

---

## 免责声明

- 本项目为**安全研究 / 互操作性研究**性质，用于理解设备标识协议的工作方式
- 所有测试均在**研究者自有的闲置测试设备**上进行
- 涉及的数字联盟、酷安等商标与协议归各自权利人所有
- 仓库中的设备标识为测试设备所有，与个人常用设备、账号均无关联
- **请勿将本项目用于未获授权的用途**

详见 [数据与隐私说明](PRIVACY.md)。

---

## 快速上手

```sh
# 取一个 DUID（单文件、零依赖）
python3 tools/getduid.py -n 3      # 固定三值，应稳定返回同一个 DUID
python3 tools/getduid.py -r -n 5   # 随机三值，每次拿一个新 DUID
python3 tools/getduid.py -h        # 帮助

# 解开报文里的编码字段（自动定位 K）
python3 tools/unenc.py --json data/decoded/D1H__MDNA_63185.json
```

参数说明见 [tools/README.md](tools/README.md)。

---

## 目录

| 路径 | 内容 |
|---|---|
| [`mainline.md`](mainline.md) | **★ 主线文档**：八个问题，按解决顺序 |
| [`docs/`](docs/README.md) | 支线文档（8 篇专题 + 未解问题） |
| [`docs/99-已推翻的结论.md`](docs/99-已推翻的结论.md) | **⚠️ 必读**：被推翻的中间结论 |
| [`docs/08-破解字段编码.md`](docs/08-破解字段编码.md) | **字段编码的完整解法** |
| [`tools/`](tools/README.md) | 可运行工具 |
| [`scripts/`](scripts/README.md) | Frida 钩子与采集驱动 |
| [`data/`](data/README.md) | 样本与解出的明文 |
| [`captures/`](captures/README.md) | 采集产物（dump / wire / 截图） |
| [`INDEX.md`](INDEX.md) | 完整文件清单 |
| [`PRIVACY.md`](PRIVACY.md) | 数据与隐私说明 |
