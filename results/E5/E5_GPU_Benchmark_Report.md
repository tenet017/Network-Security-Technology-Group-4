# E5 — GPU 攻击侧基准测试交付报告（hashcat）

**实验编号：** E5（Offline GPU cracking benchmark）
**执行人：** R3
**测试日期：** 2026-11-25
**设备：** 本机物理机（插有 NVIDIA 独显），与 CPU 实验（E1–E4、E6、E7）不在同一台机器

---

## 1. 实验目的

E5 在攻击者视角下，用 hashcat 的内置基准（`-b`）测量三种口令哈希方案在同一张 NVIDIA 显卡上的破解速率（H/s，每秒可计算的哈希数），用于支撑“内存硬函数限制 GPU/ASIC 并行”这一结论。基准为 hashcat 自包含的标准算力测试，不依赖本组 Python 实现，也不需要真实哈希文件。

## 2. 硬件与软件环境

| 字段 | 内容 |
|---|---|
| GPU | NVIDIA GeForce RTX 5070 Laptop GPU |
| 显存 | 8150 MiB（单块可分配 2037 MiB），36 MCU，主频 1425 MHz |
| 显卡驱动 | 573.24 |
| 计算能力 | 12.0（Blackwell） |
| OpenCL 运行时 | OpenCL 3.0 CUDA 12.8.97（Platform #1, NVIDIA Corporation） |
| hashcat 版本 | v8.0.0（官方 Windows 包，解压于 `D:\hashcat\hashcat-8.0.0`） |
| 后端 | CUDA Toolkit / RTC 未安装，hashcat 回退到 OpenCL 运行时；基准通过 `-d 1` 仅选用 NVIDIA 设备 #01，AMD Radeon 610M 核显已跳过 |
| 内核 | 三个模式基准时均为 pure kernel（optimized kernel 不可用或非必需） |

设备枚举原始信息见各日志中的 `OpenCL Info` 段。

## 3. 执行命令

在 hashcat 解压目录内打开 PowerShell，依次运行：

```powershell
.\hashcat.exe -b -m 40024 -d 1   # PBKDF2-HMAC-SHA256
.\hashcat.exe -b -m 3200  -d 1   # bcrypt
.\hashcat.exe -b -m 34000 -d 1   # Argon2id
```

## 4. 基准结果

### 4.1 本轮复跑（2026-11-25 09:53，归档日志对应数据）

| 方案 | hashcat 模式号 | 基准参数 | 内核 | 破解速率 | 单次基准耗时 | 日志文件 |
|---|---|---|---|---|---|---|
| PBKDF2-HMAC-SHA256 | 40024 | iterations = 999 | pure | **1,395.4 kH/s（≈ 1,395,400 H/s）** | 86.57 ms | `e5_pbkdf2_40024.log` |
| bcrypt | 3200 | cost = 5 | pure | **24,314 H/s** | 110.61 ms | `e5_bcrypt_3200.log` |
| Argon2id | 34000 | m = 65536 KiB（64 MiB）, t = 3, p = 1 | pure | **383 H/s** | 93.00 ms | `e5_argon2id_34000.log` |

### 4.2 两轮对照（同机同卡，观察波动）

| 方案 | 首轮 H/s | 复跑 H/s | 说明 |
|---|---|---|---|
| PBKDF2-HMAC-SHA256 | 1,401,600 | 1,395,400 | 波动 <1% |
| bcrypt | 25,709 | 24,314 | 波动约 5% |
| Argon2id | 314 | 383 | 笔记本功耗/温度下波动较大，量级一致（数百 H/s） |

基准为单次 `hashcat -b` 采样，未做 Python 实验那样的 30 次重复；最终论文引用时建议取复跑值并注明波动区间。

## 5. 模式号核对（以本机 `--example-hashes` 当场核对为准）

| 方案 | 任务旧记 | 本机 8.0.0 实际模式号 | 核对依据 |
|---|---|---|---|
| PBKDF2-HMAC-SHA256 | 10900（本版本已不存在） | **40024** | Name: PBKDF2-HMAC-SHA256，Category: Generic KDF，格式 `sha256:<iterations>:<salt>:<dk>` |
| bcrypt | 3200 | **3200** | Name: bcrypt `$2*$`, Blowfish (Unix) |
| Argon2id | 需当场核对 | **34000** | Name: Argon2，示例哈希即 `$argon2id$v=19$m=65536,t=3,p=1$...`，内建 pure kernel |

备注：另有 `#70000` 为 Argon2id reference implementation bridged 模式，本次基准未采用，统一使用内建内核 #34000。

## 6. 口径与限制（写入论文 Results / Discussion 时必须保留）

1. **基准参数不一致**：三个模式使用 hashcat 各自的示例参数（迭代 999 / cost 5 / 64 MiB·t3），H/s 反映优化实现下的典型破解速率量级，**不是同一参数档位下的严格对照**。
2. **后端保守**：基准在 OpenCL 后端完成（CUDA RTC 缺失），Blackwell 架构下速率可能偏保守；未启用 hand-optimized kernel。
3. **跨机跨实现**：本组数据是攻击侧 GPU 速率，与 E4 的 CPU 多进程吞吐不在同一台机器、不是同一套实现，论文中只做数量级与趋势对比，不做绝对值归一。
4. **采样次数**：E5 为单次 `hashcat -b` 基准（两轮），不像 CPU 实验有 30 次重复与误差棒。
5. **数据如实记录**：未为趋势调参；Argon2id 两轮差异已如实列出。

## 7. 趋势结论

在同一张 RTX 5070 Laptop 上：

- **PBKDF2** 可达百万级 H/s，GPU 并行最友好；
- **bcrypt** 约 2.4 万 H/s，比 PBKDF2 慢约两个数量级；
- **Argon2id** 仅数百 H/s（314–383），受显存容量与带宽限制最慢。

该顺序与论文论点一致：PBKDF2 内存恒定、易被 GPU/ASIC 并行放大；bcrypt 有自适应成本但内存仍小；Argon2id 的内存硬设计直接抬高了攻击硬件的代价。

## 8. 交付文件清单

| 文件 | 内容 |
|---|---|
| `E5_GPU_Benchmark_Report.md` | 本汇总报告 |
| `e5_hashcat_gpu.csv` | 本轮结果结构化数据表 |
| `e5_pbkdf2_40024.log` | PBKDF2 基准原始输出日志 |
| `e5_bcrypt_3200.log` | bcrypt 基准原始输出日志 |
| `e5_argon2id_34000.log` | Argon2id 基准原始输出日志 |
