# Group 4 · Password Hashing Benchmarks

**网络安全技术课程实验** · PBKDF2-HMAC-SHA256 / bcrypt / Argon2id

在统一的 Python 框架下，把三种口令哈希方案校准到相同的登录延迟，比较它们的
内存开销、CPU 并发吞吐，以及在 GPU 上被离线破解的速率。论文在小组共享的
Overleaf 上协作，正式数据和图表在本仓库维护。

**入口**　[Python 脚本](hashing_benchmark.py) · [GPU 基准](gpu_bench.py) · [出图脚本](figures/make_figures.py) · [依赖](requirements.txt)

## 计时口径（重要）

全脚本统一用**登录延迟 = 一次 `verify()`**（即一次密钥派生）作为「延迟」。
注册耗时 `hash()`（生成盐 + 一次派生）单独记为 `hash_mean_ms` 列，绝不并入
登录延迟。参数扫描、等延迟校准、热力图、攻击吞吐、Anderson 全部用同一口径。

## 快速开始

Python 3.10+，在仓库根目录：

```bash
python -m pip install -r requirements.txt
python hashing_benchmark.py env                       # 机器与软件环境
python hashing_benchmark.py all --repeats 30 \
       --wordlist /path/to/common-passwords.txt       # 全部 CPU 实验
```

`all` 按顺序执行 CPU 实验，并把 E2 的 250 ms 档校准参数传给 E4 和 E7。
单独执行 `parallel` 或 `anderson` 时，脚本会从 `results/equal_latency.csv`
读取 250 ms 校准参数（找不到会报错退出），不再回退到默认参数。
`--repeats` 控制 E1/E2 的延迟测量次数，`--memory-repeats` 控制 E3，
`--parallel-repeats` 控制 E4/E7。正式运行请用 `--wordlist` 传入公开口令表
（如 SecLists 样本）并在论文注明来源；缺省的 24 词内置表仅供冒烟测试。

## GPU 实验（E5）

`gpu_bench.py` 在装有 NVIDIA 显卡的机器上用 **hashcat 8.0.0** 的内建内核测量攻击
速率，**在 CPU 端校准出的同一组参数下**生成真实哈希再攻击，因此可与 CPU 的
`verify` 速率逐档对照。需要先跑完 `calibrate`（或 `all`）得到 `equal_latency.csv`。

```bash
# 位置参数：<hashcat_dir> <输出目录> <cuda设备号> <重复次数> [which]
# which ∈ {all, calibrated, sweep, mt, sha, extra}，缺省 all
python gpu_bench.py tools/hashcat-8.0.0 results <cuda_device_ids> 3 all
```

**hashcat mode 映射（8.0.0 版）**：`-m 40024` = PBKDF2-HMAC-SHA256、`-m 3200` =
bcrypt、`-m 34000` = Argon2id、`-m 1400` = 裸 SHA-256。可用 `hashcat --hash-info -m 40024`
自行核对（注：旧版 PBKDF2-HMAC-SHA256 为 `10900`，v8 重新编号为 `40024`）。

产物：
- `gpu_calibrated.csv`——三算法在 100/250/500 ms 及 OWASP 参数下的 GPU H/s；
- `gpu_argon2_sweep.csv`——Argon2id 的 GPU 速率随内存 m 变化（含每点 CPU `verify_ms`，
  用于把绝对速率归一化到等延迟），支撑「内存抑制 GPU」主图；
- `gpu_mt_sweep.csv`——固定预算下 (m,t) 不同分配的 GPU 速率 + CPU 延迟；
- `gpu_sha256.csv`——单卡裸 SHA-256 基准（Intro 与对比基线）。

## 实验与产物

| 实验 | 内容 | 产物 |
| --- | --- | --- |
| env | 机器与库版本（CPU 型号、各依赖版本、OpenSSL） | `environment.csv`、`run_log.csv` |
| E1 | 参数扫描（1 维）+ Argon2id 的 m×t 热力图（**含数值 CSV**） | `latency_sweep.csv/.pdf`、`argon2_heatmap.csv/.pdf` |
| E2/E3 | 100/250/500 ms 校准与子进程峰值内存 | `equal_latency.csv` |
| E4 | CPU 多进程吞吐与扩展（公平计时，排除进程启动开销） | `parallel_scaling.csv/.pdf` |
| E5 | GPU 攻击速率（hashcat 8.0.0，校准参数下）+ 内存扫描 /(m,t) 分配 / 裸 SHA-256 | `gpu_calibrated.csv`、`gpu_argon2_sweep.csv`、`gpu_mt_sweep.csv`、`gpu_sha256.csv`、`gpu_RTX4090_logs/` 原始日志 |
| E6 | 加盐 m vs n×m（同时记哈希计算次数，不只计时） | `salting.csv/.pdf` |
| E7 | Anderson 公式下的最短口令长度（用攻击速率 G） | `anderson.csv` |

论文图由 `figures/make_figures.py` 直接读上述真值 CSV 生成，同时导出
每张图的 `PLOTTED_*.csv`（图中每个点的精确数值）。论文引用的 PDF 复制到
Overleaf 的 `results/` 目录，文件名与 `main.tex` 的 `\includegraphics` 对应。

## 测量方法要点

- **延迟**：`time.perf_counter()`，一次预热后测 `repeats` 次，报告均值与标准差。
- **内存**：每个配置在全新 spawn 的子进程里测峰值 RSS 减空闲基线，2 ms 轮询，
  取多次中位数与最大值。低于采样/页分辨率的差值（如 bcrypt 约 4 KiB 工作状态）
  读数约为 0，按测量下限解释，不当作「零内存」。
- **GPU**：hashcat CUDA 内核；若驱动与 nvrtc 版本不匹配需对齐（见 `gpu_bench.py` 注释）。
- **伦理**：仅使用合成账号、测试口令与公开口令表，不处理任何真实泄露的个人数据。

## 环境

CPU 正式实验机：Intel Xeon（统一核型，便于并发扩展测量）。
GPU：NVIDIA RTX 4090（CUDA 后端）。具体型号、核数、内存、驱动与库版本
由 `env` 命令写入 `environment.csv`，论文据此填写。
