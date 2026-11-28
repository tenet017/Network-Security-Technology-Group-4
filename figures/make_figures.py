"""Publication figures for the Group 4 password-hashing paper.

House style (from /Users/科研 figure workflow): Times New Roman, embedded
vector fonts (pdf/ps fonttype 42), restrained palette with Argon2id as the
high-saturation hero, muted baselines, hidden top/right spines, light dashed
grid, a single shared legend per figure. Every figure reads the real-value
CSVs in <results>/ and writes figures/PLOTTED_VALUES_<fig>.csv alongside the
PDF/PNG, with asserts on the headline numbers.

Usage:
    python make_figures.py --results ../results --out ../results
"""
import argparse
import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import FixedLocator, FuncFormatter, NullLocator

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
    "axes.linewidth": 0.9,
    "axes.edgecolor": "#333333",
})

SCHEMES = ["PBKDF2", "bcrypt", "Argon2id"]
COLOR = {"PBKDF2": "#9aabb3", "bcrypt": "#3a679c", "Argon2id": "#059669"}
HATCH = {"PBKDF2": "", "bcrypt": "", "Argon2id": ""}
BUDGETS = [100, 250, 500]


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def style(ax, grid_axis="both"):
    ax.set_axisbelow(True)
    ax.grid(True, axis=grid_axis, color="#c4c4c4", linestyle="--",
            linewidth=0.7, alpha=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(labelsize=9, length=3, width=0.8, color="#333333")


def log_fmt(v, _):
    if v >= 1:
        return f"{v:g}"
    return f"{v:g}"


def save(fig, out, stem, plotted, header):
    fig.savefig(out / f"{stem}.pdf", bbox_inches="tight")
    fig.savefig(out / f"{stem}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    with open(out / f"PLOTTED_{stem}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(plotted)
    print("wrote", out / f"{stem}.pdf")


# ---------------------------------------------------------------------------
# Fig 1 (headline): attacker GPU speed-up over one CPU core at equal latency
# ---------------------------------------------------------------------------
def fig_gpu_multiplier(res, out):
    cal = {(int(r["target_ms"]), r["scheme"]): float(r["verify_mean_ms"])
           for r in read_csv(res / "equal_latency.csv")}
    gpu_rows = read_csv(res / "gpu_calibrated.csv")
    gpu = {}
    for r in gpu_rows:
        tag = r["setting"].split()[0]  # "100", "250", "500", "OWASP"
        if tag.isdigit():
            gpu[(int(tag), r["scheme"])] = float(r["gpu_hps_mean"])

    mult, cpu, plotted = {}, {}, []
    for b in BUDGETS:
        for s in SCHEMES:
            cpu[(b, s)] = 1000.0 / cal[(b, s)]
            mult[(b, s)] = gpu[(b, s)] / cpu[(b, s)]
            plotted.append([b, s, round(cpu[(b, s)], 3),
                            round(gpu[(b, s)], 1), round(mult[(b, s)], 1)])
    # raw unsalted SHA-256 rate on the same GPU -- the "fast hash" reference
    sha_hps = float(read_csv(res / "gpu_sha256.csv")[0]["gpu_hps_mean"])
    # headline sanity: Argon2id must give the smallest multiplier at 250 ms
    assert mult[(250, "Argon2id")] < mult[(250, "bcrypt")] < mult[(250, "PBKDF2")]

    # One figure carries everything: absolute GPU attack rate (bars), the
    # single-CPU-core floor (shaded band), and the GPU/CPU speed-up (labels).
    cpu_lo, cpu_hi = min(cpu.values()), max(cpu.values())
    gpu_hi = max(gpu.values())
    fig, ax = plt.subplots(figsize=(3.5, 2.7))
    style(ax, grid_axis="y")
    x = np.arange(len(BUDGETS))
    bw = 0.26
    ax.axhspan(cpu_lo * 0.7, cpu_hi * 1.3, color="#d8a24a", alpha=0.20, zorder=1)
    ax.text(len(BUDGETS) - 0.42, (cpu_lo * cpu_hi) ** 0.5, "single CPU core",
            ha="center", va="center", fontsize=6, color="#9a6a1a",
            rotation=90)
    for i, s in enumerate(SCHEMES):
        xs = x + (i - 1) * bw
        vals = [gpu[(b, s)] for b in BUDGETS]
        ax.bar(xs, vals, width=bw * 0.92, color=COLOR[s], edgecolor="white",
               linewidth=0.4, label=s, zorder=3)
        for xi, b in zip(xs, BUDGETS):
            ax.text(xi, gpu[(b, s)] * 1.35, f"{mult[(b, s)]:,.0f}$\\times$",
                    ha="center", va="bottom", fontsize=5.8, color="#333333",
                    rotation=90)
    ax.set_yscale("log")
    # reference line: raw unsalted SHA-256 on the same card (~10^6x above)
    ax.axhline(sha_hps, color="#b03030", linestyle="--", linewidth=0.9, zorder=2)
    ax.text(-0.46, sha_hps * 1.5,
            f"unsalted SHA-256: {sha_hps/1e9:.1f} GH/s",
            ha="left", va="bottom", fontsize=5.8, color="#b03030")
    ax.set_ylim(1, sha_hps * 4)
    ax.set_xlim(-0.5, len(BUDGETS) - 0.3)
    ax.yaxis.set_major_formatter(FuncFormatter(log_fmt))
    ax.set_xticks(x, [f"{b} ms" for b in BUDGETS])
    ax.set_xlabel("Defender login-latency budget", fontsize=10)
    ax.set_ylabel("Attacker guesses / s (log)\n1$\\times$RTX 4090", fontsize=9.5)
    ax.legend(frameon=False, fontsize=8, ncol=3, loc="upper center",
              bbox_to_anchor=(0.5, 1.16), columnspacing=0.9, handlelength=1.1,
              handletextpad=0.4)
    save(fig, out, "fig1_gpu_multiplier", plotted,
         ["budget_ms", "scheme", "cpu_core_per_s", "gpu_per_s", "multiplier"])


# ---------------------------------------------------------------------------
# Fig 2: latency vs cost sweep (3 panels, log-log)
# ---------------------------------------------------------------------------
def fig_latency_sweep(res, out):
    rows = read_csv(res / "latency_sweep.csv")
    xlabel = {"PBKDF2": "Iterations", "bcrypt": "Cost factor $f$",
              "Argon2id": "Memory $m$ (KiB), $t{=}2$"}
    fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.25))
    plotted = []
    for ax, s in zip(axes, SCHEMES):
        d = [r for r in rows if r["scheme"] == s]
        xs = [float(r["value"]) for r in d]
        ys = [float(r["verify_mean_ms"]) for r in d]
        es = [float(r["verify_std_ms"]) for r in d]
        style(ax)
        ax.errorbar(xs, ys, yerr=es, marker="o", ms=4, lw=1.4, capsize=2.5,
                    color=COLOR[s], mfc=COLOR[s], mec="white", mew=0.5)
        ax.set_xscale("log", base=2 if s == "bcrypt" else 10)
        ax.set_yscale("log")
        ax.set_title(s, fontsize=10, color=COLOR[s])
        ax.set_xlabel(xlabel[s], fontsize=9)
        for xi, yi in zip(xs, ys):
            plotted.append([s, xi, yi])
    axes[0].set_ylabel("Login latency (ms)", fontsize=9.5)
    fig.tight_layout(w_pad=1.0)
    save(fig, out, "fig2_latency_sweep", plotted, ["scheme", "value", "ms"])


# ---------------------------------------------------------------------------
# Fig 3: Argon2id latency heat map over memory x time
# ---------------------------------------------------------------------------
def fig_heatmap(res, out):
    rows = read_csv(res / "argon2_heatmap.csv")
    mems = sorted({int(r["memory_kib"]) for r in rows})
    times = sorted({int(r["time_cost"]) for r in rows})
    grid = np.full((len(times), len(mems)), np.nan)
    for r in rows:
        i = times.index(int(r["time_cost"]))
        j = mems.index(int(r["memory_kib"]))
        grid[i, j] = float(r["verify_mean_ms"])
    fig, ax = plt.subplots(figsize=(3.5, 2.5))
    im = ax.imshow(grid, aspect="auto", cmap="viridis", origin="lower")
    ax.set_xticks(range(len(mems)), [f"{m // 1024}" for m in mems])
    ax.set_yticks(range(len(times)), times)
    for i in range(len(times)):
        for j in range(len(mems)):
            v = grid[i, j]
            ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=7,
                    color="white" if v < np.nanmax(grid) * 0.6 else "black")
    ax.set_xlabel("Memory cost $m$ (MiB)", fontsize=9.5)
    ax.set_ylabel("Time cost $t$ (passes)", fontsize=9.5)
    cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cb.set_label("Login latency (ms)", fontsize=9)
    cb.ax.tick_params(labelsize=8)
    ax.tick_params(labelsize=9)
    save(fig, out, "fig3_argon2_heatmap",
         [[times[i], mems[j], grid[i, j]] for i in range(len(times))
          for j in range(len(mems))], ["time_cost", "memory_kib", "ms"])


# ---------------------------------------------------------------------------
# Fig 4: GPU attack rate vs Argon2id memory (memory defeats the GPU)
# ---------------------------------------------------------------------------
def fig_argon2_gpu_sweep(res, out):
    rows = sorted(read_csv(res / "gpu_argon2_sweep.csv"),
                  key=lambda r: int(r["memory_mib"]))
    xs = [int(r["memory_mib"]) for r in rows]
    ys = [float(r["gpu_hps_mean"]) for r in rows]
    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    style(ax)
    ax.plot(xs, ys, marker="o", ms=5, lw=1.8, color=COLOR["Argon2id"],
            mfc=COLOR["Argon2id"], mec="white", mew=0.6, zorder=3)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.xaxis.set_major_locator(FixedLocator(xs))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    ax.xaxis.set_minor_locator(NullLocator())
    # OWASP 19 MiB floor on the swept curve
    for r in rows:
        if int(r["memory_mib"]) == 19:
            ax.annotate("OWASP\n19 MiB", (19, float(r["gpu_hps_mean"])),
                        textcoords="offset points", xytext=(6, 10),
                        fontsize=7, color="#333333",
                        arrowprops=dict(arrowstyle="-", lw=0.6, color="#888"))
    # the true 250 ms calibration point (117 MiB), which lies between swept
    # memory values, taken from gpu_calibrated.csv and equal_latency.csv
    cal_gpu = {r["scheme"]: float(r["gpu_hps_mean"])
               for r in read_csv(res / "gpu_calibrated.csv")
               if r["setting"].split()[0] == "250"}
    cal_mem = {r["scheme"]: float(r["memory_median_kib"]) / 1024.0
               for r in read_csv(res / "equal_latency.csv")
               if r["target_ms"] == "250"}
    mx, my = cal_mem["Argon2id"], cal_gpu["Argon2id"]
    ax.plot([mx], [my], marker="*", ms=13, color="#d1495b", mec="white",
            mew=0.6, zorder=4)
    ax.annotate(f"250 ms calib.\n{mx:.0f} MiB", (mx, my),
                textcoords="offset points", xytext=(-60, -26), ha="center",
                fontsize=7, color="#d1495b",
                arrowprops=dict(arrowstyle="-", lw=0.6, color="#d1495b"))
    ax.set_xlabel("Argon2id memory cost $m$ (MiB), $t{=}2$", fontsize=9.5)
    ax.set_ylabel("GPU attack rate (H/s)\n1× RTX 4090", fontsize=9.5)
    save(fig, out, "fig4_argon2_gpu_sweep", list(zip(xs, ys)),
         ["memory_mib", "gpu_hps"])


# ---------------------------------------------------------------------------
# Fig 5: CPU parallel scaling
# ---------------------------------------------------------------------------
def fig_parallel(res, out):
    rows = read_csv(res / "parallel_scaling.csv")
    workers = sorted({int(r["workers"]) for r in rows})
    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    style(ax)
    plotted = []
    for s in SCHEMES:
        means, errs = [], []
        for w in workers:
            v = [float(r["guesses_per_second"]) for r in rows
                 if r["scheme"] == s and int(r["workers"]) == w]
            means.append(np.mean(v))
            errs.append(np.std(v))
            plotted.append([s, w, np.mean(v)])
        ax.errorbar(workers, means, yerr=errs, marker="o", ms=4.5, lw=1.6,
                    capsize=2.5, color=COLOR[s], mfc=COLOR[s], mec="white",
                    mew=0.5, label=s)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.xaxis.set_major_locator(FixedLocator(workers))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    ax.xaxis.set_minor_locator(NullLocator())
    ax.set_xlabel("Parallel attacker processes", fontsize=9.5)
    ax.set_ylabel("CPU guesses per second", fontsize=9.5)
    ax.legend(frameon=False, fontsize=8, loc="upper left",
              handlelength=1.3, handletextpad=0.5)
    save(fig, out, "fig5_parallel_scaling", plotted, ["scheme", "workers", "gps"])


FIGS = {"1": fig_gpu_multiplier, "2": fig_latency_sweep, "3": fig_heatmap,
        "4": fig_argon2_gpu_sweep, "5": fig_parallel}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=Path("../results"))
    ap.add_argument("--out", type=Path, default=Path("../results"))
    ap.add_argument("--only", nargs="*", help="figure numbers, e.g. 1 3")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for num, fn in FIGS.items():
        if args.only and num not in args.only:
            continue
        try:
            fn(args.results.resolve(), args.out.resolve())
        except FileNotFoundError as e:
            print(f"skip fig {num}: missing {e.filename}")


if __name__ == "__main__":
    main()
