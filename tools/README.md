# tools/ — 可运行工具

> 👈 回到 [主线文档](../mainline.md) ｜ 相关支线 [02-anchor](../docs/02-anchor/) · [03-stealth](../docs/03-stealth/)

---

全部为 Python 3，**只用标准库**（`json` / `zlib` / `ssl` / `urllib` / `hashlib`）。

---

## 一、主工具

### `getduid.py` ★

**从数字联盟取 DUID。单文件、零依赖、模板与密钥已内嵌。**

```sh
python3 getduid.py              # 固定三值 → 每次都返回同一个 DUID
python3 getduid.py -n 3         # 跑 3 次
python3 getduid.py -r           # 随机三值 → 每次拿一个新 DUID
python3 getduid.py -r -n 5      # 连拿 5 个
python3 getduid.py -f           # 打印完整响应 JSON
python3 getduid.py --no-ip      # 跳过出口 IP 查询（离线环境更快）
python3 getduid.py -h           # 帮助
python3 getduid.py --sf 801C14F --fo 'RP|Q|zQKOJ~I~}Q' --ts 1791105420.764024281
```

**跨网络环境对比：**

```sh
网络 A：python3 getduid.py -n 3     记下 DUID
网络 B：python3 getduid.py -n 3     对比
```

| 结果 | 含义 |
|---|---|
| 两次 DUID 相同 | 服务器不依赖出口 IP |
| 两次 DUID 不同 | 出口 IP 参与设备识别 |

**随机模式的注意事项：**

```
只改三值(sfOo/foO/2cO)              → 全 0（服务器判「不自洽」）
三值 + w91/gEd/6yY 一起改            → 新 DUID ✓
```

脚本的 `-r` 模式已自动把三指纹一起随机化。

**已实测：**

```
--fixed  → 稳定返回同一个 DUID
--random → DU2bsnftErmBbavMZyaI39VYWq6FP_cmCZg3
           DUDBLiCSMoayKoGFkDHfnEZ_wrLId1VLtBg2
           DUqdawkOfSYMrp39EEFQdOay47x4ACMhPOg1
```

### `getduid.sh`

同上的 shell 版（内部仍调用 Python）。支持 `sh` 环境。
自带解释器探测（会跳过 Windows Store 的假 `python3` 存根）。

### `make_getduid.py`

从 `data/samples/mdna_template.json` 重新生成自包含的 `getduid.py`。
改了模板后跑一次即可。

---

## 二、协议库

| 文件 | 说明 |
|---|---|
| `szlm_id.py` | **协议核心库**：5 个池常量、`p`/`h` 计算、body 编解码、请求构造、自校验 |
| `szlm_body.py` | body 编解码参考实现 |
| `szlm_send.py` | 构造并发送请求，观察服务端响应 |
| `szlm_forge.py` | 伪造请求 |
| `forge_mdna.py` | 构造 mdna 请求 |
| `devsel.py` | 设备选择与 adb 辅助 |

**`szlm_id.py` 关键常量：**

```python
HOST = "auni.telecome.cn"

# 池常量（libdu 内存里的字符串，不是地址）
KEY_BY_ADDR = {
    0x109CF0: b"$%v2TW}pmn];io,^@!B&+=87fqyu<>?:['|{.*`-09(tsb",
    0x10924C: b"@dalsdfkSDFSesa!@#tbaf@$%f$%K=^*&0918~Werar=-+^%39(0!",
    0x1090F8: b"7.f498yu<>?:['|TWq&/57fqu@7v.ajl#etu{.jqv2fs",
    0x0FEC5C: b"Kn];(ts<>5bv2TW?:['|%f$%K6%o,=^erar=87f4B&18~W",
    0x110DC8: b"xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}",   # mdna 用这个
}
```

---

## 三、解码

| 文件 | 说明 |
|---|---|
| `decode_mdna_final.py` | **解 mdna 报文**：池 `0x110DC8` XOR → zlib → JSON |
| `field_table.py` | 生成 78 字段完整清单（含语义推断与角色标注） |
| `check_dpi.py` | 小屏设备 DPI 与 UI 元素检查 |

---

## 四、实验脚本（复现论文级结论用）

| 文件 | 实验 | 结论 |
|---|---|---|
| **`random_fp_test.py`** | 指纹哈希随机化 | **服务器不靠指纹认设备，且无签名机制** |
| **`combo_test.py`** | 组合盲区测试：只留锚点、其余 72 字段全随机 | **仍返回真 DUID ⇒ 只有 6 个字段有意义** |
| **`find_real_anchor.py`** | 逐字段哨兵化 | 定位到 6 个锚点字段 |
| **`anchor_verify.py`** | 区分「真锚点」与「类型敏感」 | **确认 sfOo/foO/2cO/DUv 是真锚点** |
| **`test_identity_key.py`** | 找设备识别键 | **识别键就是 (sfOo, foO, 2cO)** |
| **`test_adler.py`** | 测 zlib 校验和是否被校验 | **adler32 必须对；但接受未压缩的存块模式** |
| **`verify_register_path.py`** | 验证注册路径假设 | 讲通「三值每次都变但 DUID 相同」 |
| `mis_random_matrix.py` | mIS × 2cO 矩阵 | 早期实验，后被修正 |
| `hunt_sfOo.py` | 追查 sfOo 来源 | 不是已知字段的哈希前缀（239568 次零命中） |
| `hunt_fp_hashes.py` | 追查三指纹哈希输入 | 不是已知字段的简单拼接（73080 次零命中） |

**建议复现顺序**（结论是层层递进的）：

```
1. field_table.py            → 先看清有哪些字段
2. combo_test.py             → 确认只有 6 个字段有意义
3. find_real_anchor.py       → 找出锚点候选
4. anchor_verify.py          → 排除「类型敏感」的假象
5. random_fp_test.py         → 确认无签名机制
6. test_identity_key.py      → 锁定真正识别键
7. test_adler.py             → 搞清 body 编码的约束
```

---

## 五、运行环境

```
Python 3.6+
标准库：json / zlib / ssl / urllib / hashlib / base64 / random / time

无需：requests、pycryptodome、frida（前四个实验脚本都对网络发请求，但不需要本地依赖）
```

**在安卓上跑**（如用 Termux）：

```sh
pkg install python
python getduid.py
```

**注意**：不要放在 `/sdcard/Android/data/` 下 —— 那是分区存储受限目录，
shell 连 `cd` 都进不去。放到 `/sdcard/` 或 Termux 家目录。
