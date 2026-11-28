"""
Password hashing benchmark: PBKDF2 vs bcrypt vs Argon2id.

Unified interface and experiments for the group assignment:
  E1 parameter sweeps (1-D sweeps plus a separate Argon2id m x t grid)
  E2 equal-latency calibration at 100 / 250 / 500 ms
  E3 isolated child-process peak memory
  E4 CPU attacker throughput and parallel scaling (1/2/4/8 processes)
  E5 GPU attacker throughput: hashcat -b data is collected separately
     (results/E5/); the `gpu` command only re-scales it to common parameters
  E6 salting cost analysis (m vs n x m), SHA-256 as a fast-hash baseline
  E7 Anderson-formula minimum password lengths

Timing convention
  "Latency" everywhere in this script is LOGIN latency: the wall-clock time
  of one verify() call against a stored verifier, i.e. one key derivation.
  The time of hash() (registration: salt generation + one derivation) is
  recorded in separate columns and is never added to the login latency.
  Calibration targets, sweeps, the heat map, E4 throughput and E7 all use
  the same verify()-based definition.

All raw data is written to <repo>/results (next to main.tex) as CSV plus
figures. Run `python hashing_benchmark.py --help` for the commands.
"""

import argparse
import csv
import hashlib
import hmac
import importlib.metadata
import itertools
import multiprocessing as mp
import os
import platform
import re
import ssl
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import psutil
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Outputs go to the top-level results/ folder that main.tex includes from.
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
TEST_PASSWORD = "CorrectHorseBatteryStaple!2026"
SALT_BYTES = 16
MEMORY_POLL_S = 0.002


# ---------------------------------------------------------------------------
# Unified hasher interface
# ---------------------------------------------------------------------------
class BaseHasher:
    name = "base"

    def spec(self):
        raise NotImplementedError

    def hash(self, password: str) -> str:
        raise NotImplementedError

    def verify(self, password: str, stored: str) -> bool:
        raise NotImplementedError


class PBKDF2Hasher(BaseHasher):
    """PBKDF2-HMAC-SHA256. Cost parameter: iteration count."""

    name = "PBKDF2"
    SALT_LEN = 16
    DK_LEN = 32

    def __init__(self, iterations: int = 600_000, hash_name: str = "sha256",
                 dklen: int = DK_LEN):
        self.iterations = iterations
        self.hash_name = hash_name
        self.dklen = dklen

    def spec(self):
        return "PBKDF2Hasher", {
            "iterations": self.iterations,
            "hash_name": self.hash_name,
            "dklen": self.dklen,
        }

    def hash(self, password: str) -> str:
        salt = os.urandom(self.SALT_LEN)
        dk = hashlib.pbkdf2_hmac(
            self.hash_name, password.encode("utf-8"), salt,
            self.iterations, dklen=self.dklen)
        return f"pbkdf2${self.hash_name}${self.iterations}${salt.hex()}${dk.hex()}"

    def verify(self, password: str, stored: str) -> bool:
        try:
            parts = stored.split("$")
            if len(parts) != 5 or parts[0] != "pbkdf2":
                return False
            _, hash_name, iterations, salt_hex, dk_hex = parts
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(dk_hex)
            dklen = len(expected)
            if dklen == 0:
                return False
            candidate = hashlib.pbkdf2_hmac(
                hash_name,
                password.encode("utf-8"),
                salt,
                int(iterations),
                dklen=dklen)
            return hmac.compare_digest(candidate, expected)
        except (ValueError, AttributeError, TypeError):
            return False


class BcryptHasher(BaseHasher):
    """bcrypt with a work factor of 2**cost.

    Passwords are encoded as UTF-8 and limited to 72 bytes. bcrypt 5.0+
    rejects longer inputs. Earlier versions silently truncate them.
    """

    name = "bcrypt"

    def __init__(self, cost: int = 12):
        self.cost = cost

    def spec(self):
        return "BcryptHasher", {"cost": self.cost}

    def hash(self, password: str) -> str:
        salt = bcrypt.gensalt(rounds=self.cost)
        return bcrypt.hashpw(password.encode(), salt).decode()

    def verify(self, password: str, stored: str) -> bool:
        return bcrypt.checkpw(password.encode(), stored.encode())


class Argon2idHasher(BaseHasher):
    """Argon2id. Cost parameters: memory (KiB), time passes, parallelism."""

    name = "Argon2id"

    def __init__(self, memory_kib: int = 19_456, time_cost: int = 2,
                 parallelism: int = 1, hash_len: int = 32):
        self.memory_kib = memory_kib
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.hasher = PasswordHasher(
            time_cost=time_cost, memory_cost=memory_kib,
            parallelism=parallelism, hash_len=hash_len, salt_len=SALT_BYTES)

    def spec(self):
        return "Argon2idHasher", {
            "memory_kib": self.memory_kib, "time_cost": self.time_cost,
            "parallelism": self.parallelism, "hash_len": self.hasher.hash_len}

    def hash(self, password: str) -> str:
        return self.hasher.hash(password)

    def verify(self, password: str, stored: str) -> bool:
        try:
            return self.hasher.verify(stored, password)
        except VerifyMismatchError:
            return False


HASHER_CLASSES = {
    "PBKDF2Hasher": PBKDF2Hasher,
    "BcryptHasher": BcryptHasher,
    "Argon2idHasher": Argon2idHasher,
}

SCHEMES = ["PBKDF2", "bcrypt", "Argon2id"]
PRIMARY_PARAMETER = {"PBKDF2": "iterations", "bcrypt": "cost",
                     "Argon2id": "memory_kib"}
# Argon2id is calibrated and swept along memory with t=2, p=1 (OWASP shape).
ARGON2_DEFAULT_T = 2


def build_hasher(class_name: str, kwargs: dict) -> BaseHasher:
    return HASHER_CLASSES[class_name](**kwargs)


def make_hasher(scheme: str, value: int, time_cost: int = ARGON2_DEFAULT_T):
    if scheme == "PBKDF2":
        return PBKDF2Hasher(iterations=value)
    if scheme == "bcrypt":
        return BcryptHasher(cost=value)
    if scheme == "Argon2id":
        return Argon2idHasher(memory_kib=value, time_cost=time_cost)
    raise ValueError(scheme)


def describe(hasher: BaseHasher) -> str:
    _, kwargs = hasher.spec()
    keys = {"PBKDF2Hasher": ["iterations"], "BcryptHasher": ["cost"],
            "Argon2idHasher": ["memory_kib", "time_cost", "parallelism"]}
    class_name = hasher.spec()[0]
    return ";".join(f"{k}={kwargs[k]}" for k in keys[class_name])


# ---------------------------------------------------------------------------
# Measurement helpers
# ---------------------------------------------------------------------------
def _mean_std(values):
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    return statistics.mean(values), std


def time_operations(hasher: BaseHasher, repeats: int):
    """Time hash() and verify() separately, `repeats` times after a warm-up.

    verify_* is the login latency used for every comparison in the paper.
    hash_* is the registration cost and is reported separately.
    """
    stored = hasher.hash(TEST_PASSWORD)  # warm-up
    hasher.verify(TEST_PASSWORD, stored)
    hash_ms, verify_ms = [], []
    for _ in range(repeats):
        t0 = time.perf_counter()
        stored = hasher.hash(TEST_PASSWORD)
        t1 = time.perf_counter()
        ok = hasher.verify(TEST_PASSWORD, stored)
        t2 = time.perf_counter()
        if not ok:
            raise RuntimeError(f"{hasher.name}: verify() failed on own hash")
        hash_ms.append((t1 - t0) * 1000.0)
        verify_ms.append((t2 - t1) * 1000.0)
    v_mean, v_std = _mean_std(verify_ms)
    h_mean, h_std = _mean_std(hash_ms)
    return {"verify_mean_ms": v_mean, "verify_std_ms": v_std,
            "hash_mean_ms": h_mean, "hash_std_ms": h_std}


def _memory_worker(class_name, kwargs, queue):
    hasher = build_hasher(class_name, kwargs)
    queue.put("ready")
    hasher.hash(TEST_PASSWORD)
    queue.put("done")


def _idle_worker(queue):
    queue.put("ready")
    queue.put("done")


def _child_peak_rss(target, args):
    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    proc = ctx.Process(target=target, args=(*args, queue))
    proc.start()
    ps = psutil.Process(proc.pid)
    peak = 0
    while proc.is_alive():
        try:
            peak = max(peak, ps.memory_info().rss)
        except psutil.NoSuchProcess:
            break
        time.sleep(MEMORY_POLL_S)
    proc.join()
    queue.close()
    return peak


_BASELINE_RSS = None


def baseline_rss_kib(samples: int = 5):
    """Median peak RSS of an idle spawned interpreter (same imports)."""
    global _BASELINE_RSS
    if _BASELINE_RSS is None:
        peaks = [_child_peak_rss(_idle_worker, ()) for _ in range(samples)]
        _BASELINE_RSS = statistics.median(peaks)
    return _BASELINE_RSS / 1024.0


def measure_memory_kib(hasher: BaseHasher, repeats: int):
    """Peak child RSS above the idle baseline for one hash() call.

    Returns (median, max) over `repeats` fresh child processes. Values below
    the polling/page resolution (e.g. bcrypt's ~4 KiB state) read as ~0 and
    must be reported as a measurement limit, not as zero memory.
    """
    class_name, kwargs = hasher.spec()
    base = baseline_rss_kib()
    values = []
    for _ in range(repeats):
        peak = _child_peak_rss(_memory_worker, (class_name, kwargs))
        values.append(max(peak / 1024.0 - base, 0.0))
    return statistics.median(values), max(values)


# ---------------------------------------------------------------------------
# E1: parameter sweeps and Argon2 heat map
# ---------------------------------------------------------------------------
SWEEP_VALUES = {
    "PBKDF2": [10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000],
    "bcrypt": [4, 6, 8, 9, 10, 11, 12, 13, 14],
    # 8 MiB .. 256 MiB at t=2, p=1
    "Argon2id": [8_192, 16_384, 19_456, 32_768, 65_536, 131_072, 262_144],
}
HEATMAP_MEMORY_KIB = [8_192, 16_384, 32_768, 65_536, 131_072]  # 8..128 MiB
HEATMAP_TIME_COST = [1, 2, 3, 4]


def run_sweeps(repeats: int, memory_repeats: int):
    rows = []
    for scheme in SCHEMES:
        for value in SWEEP_VALUES[scheme]:
            hasher = make_hasher(scheme, value)
            t = time_operations(hasher, repeats)
            mem_med, mem_max = measure_memory_kib(hasher, memory_repeats)
            print(f"{scheme:>8} {PRIMARY_PARAMETER[scheme]}={value:>8} "
                  f"verify={t['verify_mean_ms']:9.2f} ms "
                  f"memory={mem_med:9.1f} KiB")
            rows.append({
                "scheme": scheme,
                "parameter": PRIMARY_PARAMETER[scheme],
                "value": value,
                "settings": describe(hasher),
                **t,
                "timing_repeats": repeats,
                "memory_median_kib": mem_med,
                "memory_max_kib": mem_max,
                "memory_repeats": memory_repeats,
            })
    write_dict_csv("latency_sweep.csv", rows)
    plot_sweeps(rows)
    run_heatmap(repeats)


def plot_sweeps(rows):
    fig, axes = plt.subplots(1, 3, figsize=(11, 3.2))
    for ax, scheme in zip(axes, SCHEMES):
        data = [r for r in rows if r["scheme"] == scheme]
        ax.errorbar([r["value"] for r in data],
                    [r["verify_mean_ms"] for r in data],
                    yerr=[r["verify_std_ms"] for r in data],
                    marker="o", capsize=3)
        ax.set_title(scheme)
        ax.set_xscale("log", base=2 if scheme == "Argon2id" else 10)
        ax.set_yscale("log")
        ax.set_xlabel({"PBKDF2": "Iterations", "bcrypt": "Cost factor",
                       "Argon2id": "Memory cost (KiB), t=2"}[scheme])
        ax.grid(True, alpha=0.3)
    axes[0].set_ylabel("Login (verify) latency (ms)")
    fig.tight_layout()
    save_figure(fig, "latency_sweep")


def run_heatmap(repeats: int):
    rows = []
    grid = []
    for t in HEATMAP_TIME_COST:
        line = []
        for m in HEATMAP_MEMORY_KIB:
            res = time_operations(Argon2idHasher(memory_kib=m, time_cost=t),
                                  repeats)
            line.append(res["verify_mean_ms"])
            rows.append({"memory_kib": m, "time_cost": t, "parallelism": 1,
                         **res, "timing_repeats": repeats})
        grid.append(line)
    write_dict_csv("argon2_heatmap.csv", rows)

    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    image = ax.imshow(grid, aspect="auto", cmap="viridis", origin="lower")
    ax.set_xticks(range(len(HEATMAP_MEMORY_KIB)))
    ax.set_xticklabels([f"{m // 1024}" for m in HEATMAP_MEMORY_KIB])
    ax.set_yticks(range(len(HEATMAP_TIME_COST)))
    ax.set_yticklabels(HEATMAP_TIME_COST)
    for i, line in enumerate(grid):
        for j, value in enumerate(line):
            ax.text(j, i, f"{value:.0f}", ha="center", va="center",
                    color="white", fontsize=7)
    ax.set_xlabel("Memory cost (MiB)")
    ax.set_ylabel("Time cost t")
    fig.colorbar(image, ax=ax, label="Login (verify) latency (ms)")
    fig.tight_layout()
    save_figure(fig, "argon2_heatmap")


# ---------------------------------------------------------------------------
# E2 + E3: equal-latency calibration at three budgets with memory
# ---------------------------------------------------------------------------
CALIBRATION_CANDIDATES = {
    "PBKDF2": [10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 750_000,
               1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000],
    "bcrypt": list(range(4, 17)),
    # 4 MiB .. 512 MiB at t=2, p=1
    "Argon2id": [4_096, 8_192, 12_288, 19_456, 32_768, 47_104, 65_536,
                 98_304, 131_072, 196_608, 262_144, 393_216, 524_288],
}


# PBKDF2 latency is linear in the iteration count and Argon2id latency is
# linear in the memory cost (at fixed t), so after the nearest grid point we
# refine by linear interpolation to hit the target closely. bcrypt's cost is
# an integer that doubles the work per step and cannot be refined; its
# achieved latency and relative error are always reported.
REFINABLE = {"PBKDF2": 1_000, "Argon2id": 1_024}  # round the parameter to this


def calibrate_one(scheme, target_ms, repeats):
    best = None
    tried = []
    for value in CALIBRATION_CANDIDATES[scheme]:
        res = time_operations(make_hasher(scheme, value), repeats)
        tried.append((value, res["verify_mean_ms"]))
        gap = abs(res["verify_mean_ms"] - target_ms)
        if best is None or gap < best[0]:
            best = (gap, value, res)
        if res["verify_mean_ms"] > target_ms * 1.5:
            break
    _, value, res = best

    if scheme in REFINABLE and res["verify_mean_ms"] > 0:
        step = REFINABLE[scheme]
        scaled = value * target_ms / res["verify_mean_ms"]
        refined = max(step, int(round(scaled / step)) * step)
        if refined != value:
            r2 = time_operations(make_hasher(scheme, refined), repeats)
            tried.append((refined, r2["verify_mean_ms"]))
            if abs(r2["verify_mean_ms"] - target_ms) < abs(res["verify_mean_ms"] - target_ms):
                value, res = refined, r2
    if value == CALIBRATION_CANDIDATES[scheme][-1] and \
            res["verify_mean_ms"] < target_ms:
        print(f"WARNING: {scheme} grid exhausted below {target_ms} ms")
    return make_hasher(scheme, value), value, res, tried


def run_calibrate(repeats: int, memory_repeats: int, budgets=(100, 250, 500)):
    rows = []
    calibrated = {}
    for budget in budgets:
        calibrated[budget] = {}
        for scheme in SCHEMES:
            print(f"Calibrating {scheme} towards {budget} ms...")
            hasher, value, res, tried = calibrate_one(scheme, budget, repeats)
            mem_med, mem_max = measure_memory_kib(hasher, memory_repeats)
            rows.append({
                "target_ms": budget,
                "scheme": scheme,
                "parameter": PRIMARY_PARAMETER[scheme],
                "value": value,
                "settings": describe(hasher),
                **res,
                "relative_error": (res["verify_mean_ms"] - budget) / budget,
                "timing_repeats": repeats,
                "memory_median_kib": mem_med,
                "memory_max_kib": mem_max,
                "memory_median_mib": mem_med / 1024.0,
                "memory_repeats": memory_repeats,
                "candidates_tried": " ".join(f"{v}:{ms:.1f}"
                                             for v, ms in tried),
            })
            calibrated[budget][scheme] = hasher
    write_dict_csv("equal_latency.csv", rows)
    return calibrated


def load_calibrated(budget: int = 250):
    """Rebuild calibrated hashers from equal_latency.csv (for E4/E7 runs)."""
    path = RESULTS_DIR / "equal_latency.csv"
    if not path.exists():
        sys.exit(f"{path} not found: run `calibrate` first so that E4/E7 "
                 f"use the {budget} ms calibrated parameters.")
    hashers = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if int(row["target_ms"]) == budget:
                hashers[row["scheme"]] = make_hasher(row["scheme"],
                                                     int(row["value"]))
    missing = [s for s in SCHEMES if s not in hashers]
    if missing:
        sys.exit(f"equal_latency.csv has no {budget} ms rows for {missing}")
    return {s: hashers[s] for s in SCHEMES}


# ---------------------------------------------------------------------------
# E4: CPU attacker throughput and parallel scaling
# ---------------------------------------------------------------------------
# Built-in fallback list for smoke tests only. Final runs must pass
# --wordlist with a public common-password list and cite its source.
BUILTIN_WORDLIST = [
    "123456", "password", "qwerty", "12345678", "111111", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine", "princess",
    "admin", "welcome", "shadow", "superman", "michael", "ninja",
    "abc123", "passw0rd", "master", "hello", "freedom", "whatever",
]
WORDLIST = list(BUILTIN_WORDLIST)
WORDLIST_SOURCE = "built-in 24-word sample (smoke test only)"


def load_wordlist(path: str):
    global WORDLIST, WORDLIST_SOURCE
    words = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.rstrip("\r\n")
            if word and word != TEST_PASSWORD and len(word.encode()) <= 72:
                words.append(word)
    if not words:
        sys.exit(f"word list {path} is empty")
    WORDLIST = words
    WORDLIST_SOURCE = f"{Path(path).name} ({len(words)} entries)"


def guesses_for(count: int):
    """First `count` candidates; none equals TEST_PASSWORD, so every verify
    runs the full derivation and fails (worst case for the attacker)."""
    return list(itertools.islice(itertools.cycle(WORDLIST), count))


def _attack_worker(class_name, kwargs, guesses, ready_queue, start_event,
                   result_queue):
    hasher = build_hasher(class_name, kwargs)
    stored = hasher.hash(TEST_PASSWORD)
    hasher.verify(guesses[0], stored)  # warm-up, excluded from timing
    ready_queue.put(os.getpid())
    start_event.wait()
    start = time.perf_counter()
    for guess in guesses:
        hasher.verify(guess, stored)
    result_queue.put(time.perf_counter() - start)


def parallel_throughput(hasher: BaseHasher, worker_count: int,
                        guesses_per_worker: int):
    """Aggregate guesses/s with `worker_count` processes.

    Process start-up, imports, the target hash and a warm-up verify happen
    before a shared start event, so only the guessing loop is timed.
    Throughput = total guesses / slowest worker's loop time.
    """
    class_name, kwargs = hasher.spec()
    guesses = guesses_for(guesses_per_worker)
    ctx = mp.get_context("spawn")
    ready_queue, result_queue = ctx.Queue(), ctx.Queue()
    start_event = ctx.Event()
    processes = [
        ctx.Process(target=_attack_worker,
                    args=(class_name, kwargs, guesses, ready_queue,
                          start_event, result_queue))
        for _ in range(worker_count)]
    for p in processes:
        p.start()
    for _ in processes:
        ready_queue.get()
    start_event.set()
    elapsed = [result_queue.get() for _ in processes]
    for p in processes:
        p.join()
    return worker_count * len(guesses) / max(elapsed)


def run_parallel(hashers, repeats: int, guesses_per_worker: int,
                 worker_counts=(1, 2, 4, 8)):
    logical = psutil.cpu_count(logical=True)
    physical = psutil.cpu_count(logical=False)
    rows = []
    for scheme, hasher in hashers.items():
        for workers in worker_counts:
            if workers > logical:
                print(f"WARNING: {workers} workers > {logical} logical cores")
            for rep in range(repeats):
                rate = parallel_throughput(hasher, workers,
                                           guesses_per_worker)
                rows.append({
                    "scheme": scheme, "settings": describe(hasher),
                    "workers": workers, "repeat": rep,
                    "guesses_per_worker": guesses_per_worker,
                    "guesses_per_second": rate,
                    "physical_cores": physical, "logical_cores": logical,
                    "wordlist": WORDLIST_SOURCE,
                })
            rates = [r["guesses_per_second"] for r in rows
                     if r["scheme"] == scheme and r["workers"] == workers]
            print(f"{scheme:>8} workers={workers} "
                  f"throughput={statistics.mean(rates):8.2f} guesses/s")
    write_dict_csv("parallel_scaling.csv", rows)

    fig, ax = plt.subplots(figsize=(5, 3.4))
    for scheme in hashers:
        means, stds = [], []
        for workers in worker_counts:
            rates = [r["guesses_per_second"] for r in rows
                     if r["scheme"] == scheme and r["workers"] == workers]
            mean, std = _mean_std(rates)
            means.append(mean)
            stds.append(std)
        ax.errorbar(worker_counts, means, yerr=stds, marker="o", capsize=3,
                    label=f"{scheme} ({describe(hashers[scheme])})")
    ax.axvline(physical, color="grey", linestyle=":", linewidth=1)
    ax.set_xlabel("Number of parallel processes")
    ax.set_ylabel("CPU guesses per second")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=6)
    fig.tight_layout()
    save_figure(fig, "parallel_scaling")


# ---------------------------------------------------------------------------
# E5: re-scale the separately collected hashcat GPU benchmark
# ---------------------------------------------------------------------------
def run_gpu_rescale():
    """Re-scale hashcat -b speeds to common parameter settings.

    hashcat benchmarks each mode at its own example parameters (PBKDF2 999
    iterations, bcrypt cost 5, Argon2id m=64 MiB t=3), so raw H/s are not
    comparable. PBKDF2 work is linear in iterations and bcrypt work is
    linear in 2**cost, so those two are re-scaled exactly up to kernel
    overheads. Argon2id is NOT re-scaled: GPU throughput depends non-linearly
    on m (memory capacity limits concurrent instances), so it is reported
    only at the measured setting.
    """
    src = RESULTS_DIR / "E5" / "e5_hashcat_gpu.csv"
    if not src.exists():
        sys.exit(f"{src} not found")
    with open(src, newline="", encoding="utf-8") as f:
        measured = {r["algorithm"]: r for r in csv.DictReader(f)}

    targets = {"PBKDF2": [("OWASP minimum", 600_000)],
               "bcrypt": [("OWASP minimum", 10)]}
    cal = RESULTS_DIR / "equal_latency.csv"
    if cal.exists():
        with open(cal, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["scheme"] in targets:
                    targets[r["scheme"]].append(
                        (f"CPU {r['target_ms']} ms calibration",
                         int(r["value"])))

    rows = []
    for scheme, r in measured.items():
        speed = float(r["speed_Hps"])
        params = r["benchmark_params"]
        rows.append({"scheme": scheme, "setting": params, "basis": "measured",
                     "gpu_guesses_per_second": speed, "gpu": r["gpu"]})
        if scheme == "PBKDF2":
            base_iter = int(re.search(r"iterations=(\d+)", params).group(1))
            for label, iters in targets["PBKDF2"]:
                rows.append({"scheme": scheme,
                             "setting": f"iterations={iters}",
                             "basis": f"re-scaled ({label})",
                             "gpu_guesses_per_second":
                                 speed * base_iter / iters,
                             "gpu": r["gpu"]})
        elif scheme == "bcrypt":
            base_cost = int(re.search(r"cost=(\d+)", params).group(1))
            for label, cost in targets["bcrypt"]:
                rows.append({"scheme": scheme, "setting": f"cost={cost}",
                             "basis": f"re-scaled ({label})",
                             "gpu_guesses_per_second":
                                 speed * 2 ** (base_cost - cost),
                             "gpu": r["gpu"]})
    for row in rows:
        print(f"{row['scheme']:>8} {row['setting']:<24} "
              f"{row['gpu_guesses_per_second']:14.1f} H/s  {row['basis']}")
    write_dict_csv("e5_gpu_rescaled.csv", rows)


# ---------------------------------------------------------------------------
# E6: salting cost analysis
# ---------------------------------------------------------------------------
SALTING_HASHERS = [  # deliberately light so the n x m runs finish quickly
    ("PBKDF2", lambda: PBKDF2Hasher(iterations=50_000)),
    ("bcrypt", lambda: BcryptHasher(cost=8)),
    ("Argon2id", lambda: Argon2idHasher(memory_kib=8_192, time_cost=1)),
]


def sha256_verifier(password: str, salt: bytes = b""):
    return hashlib.sha256(salt + password.encode()).hexdigest()


def run_salting(account_counts=(1, 2, 4, 8, 16), candidates=20):
    rows = []
    guesses = guesses_for(candidates)
    slow = [(name, factory()) for name, factory in SALTING_HASHERS]

    for n in account_counts:
        # Unsalted SHA-256: each candidate hashed once, checked against all n.
        unsalted = set(sha256_verifier(f"{TEST_PASSWORD}{i}")
                       for i in range(n))
        start = time.perf_counter()
        computations = 0
        for guess in guesses:
            computations += 1
            if sha256_verifier(guess) in unsalted:
                break
        rows.append({"configuration": "unsalted SHA-256", "settings": "",
                     "accounts": n, "candidates": len(guesses),
                     "hash_computations": computations,
                     "elapsed_s": time.perf_counter() - start})

        # Salted SHA-256: every (account, candidate) pair is a new hash.
        salts = [os.urandom(16) for _ in range(n)]
        targets = [sha256_verifier(f"{TEST_PASSWORD}{i}", s)
                   for i, s in enumerate(salts)]
        start = time.perf_counter()
        computations = 0
        for salt, target in zip(salts, targets):
            for guess in guesses:
                computations += 1
                if sha256_verifier(guess, salt) == target:
                    break
        rows.append({"configuration": "salted SHA-256", "settings": "",
                     "accounts": n, "candidates": len(guesses),
                     "hash_computations": computations,
                     "elapsed_s": time.perf_counter() - start})

        # Slow hashes: same n x m structure with per-guess KDF cost.
        for name, hasher in slow:
            stored = [hasher.hash(f"{TEST_PASSWORD}{i}") for i in range(n)]
            start = time.perf_counter()
            computations = 0
            for verifier in stored:
                for guess in guesses:
                    computations += 1
                    if hasher.verify(guess, verifier):
                        break
            rows.append({"configuration": name, "settings": describe(hasher),
                         "accounts": n, "candidates": len(guesses),
                         "hash_computations": computations,
                         "elapsed_s": time.perf_counter() - start})
        print(f"salting experiment n={n} done")

    write_dict_csv("salting.csv", rows)

    order = ["unsalted SHA-256", "salted SHA-256"] + [n for n, _ in slow]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    for config in order:
        data = [r for r in rows if r["configuration"] == config]
        label = config if not data[0]["settings"] else \
            f"{config} ({data[0]['settings']})"
        ax.plot([r["accounts"] for r in data], [r["elapsed_s"] for r in data],
                marker="o", label=label)
    ax.set_xlabel("Number of accounts n")
    ax.set_ylabel("Total cracking time (s)")
    ax.set_yscale("log")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=6)
    fig.tight_layout()
    save_figure(fig, "salting")


# ---------------------------------------------------------------------------
# E7: Anderson formula
# ---------------------------------------------------------------------------
def minimum_length(alphabet: int, required_n: float):
    total = 0
    for length in range(1, 64):
        total += alphabet ** length
        if total >= required_n:
            return length
    return None


def run_anderson(hashers, repeats: int, guesses_per_worker: int):
    seconds_per_year = 365 * 24 * 3600
    target_p = 0.5
    rows = []
    for scheme, hasher in hashers.items():
        # Single-process attacker rate, same timing rule as E4.
        rates = [parallel_throughput(hasher, 1, guesses_per_worker)
                 for _ in range(repeats)]
        rate = statistics.mean(rates)
        required_n = seconds_per_year * rate / target_p
        lengths = {a: minimum_length(a, required_n) for a in (62, 96)}
        print(f"{scheme:>8} G={rate:7.2f}/s  S(62)={lengths[62]}  "
              f"S(96)={lengths[96]}")
        rows.append({"scheme": scheme, "settings": describe(hasher),
                     "guesses_per_second": rate,
                     "rate_repeats": repeats,
                     "window_s": seconds_per_year, "target_p": target_p,
                     "required_N": required_n,
                     "length_A62": lengths[62], "length_A96": lengths[96]})
    write_dict_csv("anderson.csv", rows)


# ---------------------------------------------------------------------------
# Environment and utilities
# ---------------------------------------------------------------------------
def write_dict_csv(filename, rows):
    with open(RESULTS_DIR / filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def save_figure(fig, stem):
    fig.savefig(RESULTS_DIR / f"{stem}.pdf")
    fig.savefig(RESULTS_DIR / f"{stem}.png", dpi=300)
    plt.close(fig)


def _package_version(name):
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def _cpu_model():
    system = platform.system()
    try:
        if system == "Darwin":
            return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                  capture_output=True, text=True,
                                  check=True).stdout.strip()
        if system == "Linux":
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    return platform.processor() or "unknown"


def record_environment():
    freq = psutil.cpu_freq()
    info = {
        "recorded_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cpu_model": _cpu_model(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "cpu_max_mhz": round(freq.max, 0) if freq else "unknown",
        "total_ram_gib": round(psutil.virtual_memory().total / 1024 ** 3, 2),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "openssl_version": ssl.OPENSSL_VERSION,
        "bcrypt_version": _package_version("bcrypt"),
        "argon2_cffi_version": _package_version("argon2-cffi"),
        "argon2_cffi_bindings_version":
            _package_version("argon2-cffi-bindings"),
        "psutil_version": _package_version("psutil"),
        "matplotlib_version": _package_version("matplotlib"),
    }
    write_dict_csv("environment.csv",
                   [{"key": k, "value": v} for k, v in info.items()])
    for key, value in info.items():
        print(f"{key}: {value}")


def record_run_config(args):
    """Append one line per invocation so every CSV can be traced to a run."""
    path = RESULTS_DIR / "run_log.csv"
    row = {
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "command": args.command,
        "repeats": args.repeats,
        "memory_repeats": args.memory_repeats,
        "parallel_repeats": args.parallel_repeats,
        "guesses_per_worker": args.guesses_per_worker,
        "wordlist": WORDLIST_SOURCE,
        "timing": "login latency = one verify() call",
        "argv": " ".join(sys.argv),
    }
    new = not path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new:
            writer.writeheader()
        writer.writerow(row)


def main():
    global RESULTS_DIR
    parser = argparse.ArgumentParser(description="Password hashing benchmark")
    parser.add_argument("command",
                        choices=["env", "sweep", "calibrate", "parallel",
                                 "gpu", "salting", "anderson", "all"])
    parser.add_argument("--repeats", type=int, default=30,
                        help="timing repetitions per latency point (E1/E2)")
    parser.add_argument("--memory-repeats", type=int, default=5,
                        help="fresh child processes per memory point (E3)")
    parser.add_argument("--parallel-repeats", type=int, default=5,
                        help="repetitions per worker count (E4) and per "
                             "single-process rate (E7)")
    parser.add_argument("--guesses-per-worker", type=int, default=20)
    parser.add_argument("--wordlist", help="public common-password list")
    parser.add_argument("--out", help="output directory (default: ../results)")
    args = parser.parse_args()

    if args.out:
        RESULTS_DIR = Path(args.out).resolve()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.wordlist:
        load_wordlist(args.wordlist)
    elif args.command in ("parallel", "salting", "anderson", "all"):
        print("WARNING: using the built-in 24-word list; pass --wordlist "
              "for the final run")
    record_run_config(args)

    calibrated = None
    if args.command in ("env", "all"):
        record_environment()
    if args.command in ("sweep", "all"):
        run_sweeps(args.repeats, args.memory_repeats)
    if args.command in ("calibrate", "all"):
        calibrated = run_calibrate(args.repeats, args.memory_repeats)
    if args.command in ("parallel", "anderson", "all"):
        at_250 = calibrated[250] if calibrated else load_calibrated(250)
    if args.command in ("parallel", "all"):
        run_parallel(at_250, args.parallel_repeats, args.guesses_per_worker)
    if args.command in ("gpu", "all"):
        if (RESULTS_DIR / "E5" / "e5_hashcat_gpu.csv").exists():
            run_gpu_rescale()
        elif args.command == "gpu":
            run_gpu_rescale()
    if args.command in ("salting", "all"):
        run_salting()
    if args.command in ("anderson", "all"):
        run_anderson(at_250, args.parallel_repeats, args.guesses_per_worker)


if __name__ == "__main__":
    mp.freeze_support()
    main()
