## 数字联盟 DUID 获取工具

单文件、零依赖的 Python 脚本。直接从数字联盟取一个 DUID。

### 用法

```sh
python3 getduid.py              # 固定三值 → 每次都返回同一个 DUID
python3 getduid.py -n 3         # 跑 3 次
python3 getduid.py -r           # 随机三值 → 每次拿一个新 DUID
python3 getduid.py -r -n 5      # 连拿 5 个
python3 getduid.py -f           # 打印完整响应 JSON
python3 getduid.py -h           # 帮助
```

### 跨网络环境对比

```sh
网络 A：python3 getduid.py -n 3     记下 DUID
网络 B：python3 getduid.py -n 3     对比
```

| 结果 | 含义 |
|---|---|
| 两次 DUID 相同 | 服务器不依赖出口 IP |
| 两次 DUID 不同 | 出口 IP 参与设备识别 |

### 依赖

只需要 Python 3（标准库 `json` / `zlib` / `ssl` / `urllib`）。

模板与密钥已内嵌，**不需要仓库里的其它文件**，单独下载这一个脚本即可运行。

### 注意事项

- `-r` 随机模式会**同时随机化三个设备指纹哈希** —— 这是必需的。
  只改锚点三元组、不动指纹，会被服务端判为「不自洽」而返回全 0。

- 安卓设备上运行时，脚本**不要**放在 `/sdcard/Android/data/` 下
  （Android 11+ 的分区存储限制会导致 `Permission denied`），
  放到 `/sdcard/` 或 Termux 家目录即可。

- 需要 `python3`。安卓上可通过 Termux（`pkg install python`）安装。

### 原理

详见仓库的 [mainline.md](https://github.com/kongwufang/szlm_res/blob/main/mainline.md)。

核心结论：

- 服务端按 `(sfOo, foO, 2cO)` 三元组查表决定返回哪个 DUID
- 最小可用 body 只需 8 个字段
- 不存在签名机制
