# Group 4 · Password Hashing Benchmarks

**网络安全技术课程实验** · PBKDF2-HMAC-SHA256 / bcrypt / Argon2id

在统一的 Python 框架下比较三种口令哈希方案的耗时、内存占用和并行扩展。这里维护实验代码、配置和数据。论文在小组共享的 Overleaf 上协作。

**入口**　[Python 脚本](hashing_benchmark.py) · [依赖](requirements.txt) · [E5 GPU 报告](results/E5/E5_GPU_Benchmark_Report.md) · [E5 数据](results/E5/e5_hashcat_gpu.csv)

## 快速开始

使用 Python 3.10 或更新版本，在仓库根目录执行：

```bash
python -m pip install -r requirements.txt
python hashing_benchmark.py env
```

`env` 把本机实验环境写入 `results/environment.csv`。R6 在统一的 CPU 实验机器上运行正式实验：

```bash
python hashing_benchmark.py all --repeats 30
```

`all` 会执行 Python 实验，并将 E2 的 250 ms 档配置传给 E4 和 E7。单独执行 `parallel` 或 `anderson` 时，脚本使用各算法的默认配置。`--repeats` 控制 E1 和 E2 的延迟测量次数。E5 由有独显的组员单独运行。

## 实验与产物

| 实验 | 内容 | 产物 |
| --- | --- | --- |
| E1 | 参数扫描与 Argon2id 热力图 | `latency_sweep.csv`、`latency_sweep.pdf`、`argon2_heatmap.pdf` |
| E2 / E3 | 100、250、500 ms 三档校准与内存测量 | `equal_latency.csv` |
| E4 | CPU 多进程吞吐量 | `parallel_scaling.csv`、`parallel_scaling.pdf` |
| E5 | 独立 GPU 基准 | [实验报告](results/E5/E5_GPU_Benchmark_Report.md)、[CSV](results/E5/e5_hashcat_gpu.csv)、[原始日志](results/E5/) |
| E6 | 口令加盐前后的耗时比较 | `salting.csv`、`salting.pdf` |
| E7 | Anderson 公式下的口令长度估算 | `anderson.csv` |

Python 脚本把产物写入 `results/`。当前的 E1/E2 计时包含一次哈希和一次验证。E3 以独立子进程采样 RSS，bcrypt 的约 4 KiB 属于算法内部状态大小。实验使用合成账号和测试口令。

R6 把正式实验的 CSV、图和环境记录提交到 GitHub，并将论文引用的四张 PDF 复制到 Overleaf 的 `results/` 目录。图文件沿用上表的名称，方便 `main.tex` 直接编译。

## 小组分工

| 角色 | 负责内容 |
| --- | --- |
| R1 | 协调进度与 E5，整合 Overleaf 稿件、检查格式并统一提交 |
| R2 | 管理引用与参考文献、撰写 Related Work，与 R7 互审 |
| R3 | 维护 `PBKDF2Hasher`、撰写 PBKDF2 方法、核对对应结果，审阅 R4 |
| R4 | 维护 `BcryptHasher`、撰写 bcrypt 方法、核对对应结果，审阅 R5 |
| R5 | 维护 `Argon2idHasher`、撰写 Argon2id 方法、核对对应结果，审阅 R3 |
| R6 | 统一修改公共实验脚本、运行正式 CPU 实验、整理数据和图表、撰写 Results |
| R7 | 撰写摘要、引言、讨论和结论，汇总全组对结果的解读，与 R2 互审 |

## 协作方式

- R3、R4、R5 各自维护对应的类，实验前确认参数点，实验后核对自己算法的数据。
- 公共脚本的改动先在群里沟通，也可以开 GitHub Issue 记录。把涉及的实验、运行命令和预期行为写清，交给 R6 统一整合。
- 实验代码和正式数据统一维护在 `main`。论文改动直接在共享 Overleaf 中完成。
