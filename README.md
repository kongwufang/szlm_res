# szlm-re

对**数字联盟（cn.shuzilm）设备标识协议**的逆向记录。

酷安（`com.coolapk.market`）集成了数字联盟 SDK（`libdu.so`），启动时会向
`auni.telecome.cn` 上报设备信息并取回一个 **DUID**（设备唯一 ID）。

本项目从零开始把这条链路走通了：抓到了完整的通信协议、解出了 body 加密、
测定了服务端的校验边界、定位了设备识别的真正锚点，并做出了可离线构造请求的工具。

**👉 完整过程请看 → [主线文档](mainline.md)**

---

## 免责声明

- 本项目为**安全研究 / 互操作性研究**性质，用于理解设备标识协议的工作方式
- 所有测试均在**研究者自有的闲置测试设备**（几台廉价安卓手表）上进行
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
```

---

## 目录

| 路径 | 内容 |
|---|---|
| [`mainline.md`](mainline.md) | **★ 主线文档**：从零到取回 DUID 的完整过程 |
| [`docs/`](docs/README.md) | 支线文档（按主题分类） |
| [`tools/`](tools/README.md) | 可运行工具 |
| [`scripts/`](scripts/README.md) | Frida 钩子与采集驱动 |
| [`data/`](data/README.md) | 样本与解出的明文 |
| [`INDEX.md`](INDEX.md) | 完整文件清单 |
| [`PRIVACY.md`](PRIVACY.md) | 数据与隐私说明 |
