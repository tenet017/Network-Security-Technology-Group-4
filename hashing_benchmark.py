"""
Password hashing benchmark: PBKDF2 vs bcrypt vs Argon2id.

Unified interface and experiments for the group assignment:
  E1 parameter sweeps (with Argon2 m/t heat map)
  E2 equal-latency calibration at 100 / 250 / 500 ms
  E3 isolated child-process peak memory
  E4 attacker throughput and parallel scaling (1/2/4/8 processes)
  E6 salting cost analysis (m vs n x m), SHA-256 as a fast-hash baseline
  E7 Anderson-formula minimum password lengths

All raw data is written to ./results as CSV plus figures.
Run `python hashing_benchmark.py --help` for the commands.
"""

import argparse
import csv
import hashlib
import hmac
import multiprocessing as mp
import os
import platform
import statistics
import time
from pathlib import Path

import bcrypt
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import psutil
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)
TEST_PASSWORD = "CorrectHorseBatteryStaple!2026"
SALT_BYTES = 16


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


def build_hasher(class_name: str, kwargs: dict) -> BaseHasher:
    return HASHER_CLASSES[class_name](**kwargs)


# ---------------------------------------------------------------------------
# Measurement helpers
# ---------------------------------------------------------------------------
def time_latency(hasher: BaseHasher, repeats: int):
    stored = hasher.hash(TEST_PASSWORD)  # warm-up
    hasher.verify(TEST_PASSWORD, stored)
    times_ms = []
    for _ in range(repeats):
        start = time.perf_counter()
        stored = hasher.hash(TEST_PASSWORD)
        hasher.verify(TEST_PASSWORD, stored)
        times_ms.append((time.perf_counter() - start) * 1000.0)
    std = statistics.stdev(times_ms) if len(times_ms) > 1 else 0.0
    return statistics.mean(times_ms), std


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
        time.sleep(0.005)
    proc.join()
    queue.close()
    return peak


_BASELINE_RSS = None


def baseline_rss_kib():
    global _BASELINE_RSS
    if _BASELINE_RSS is None:
        _BASELINE_RSS = _child_peak_rss(_idle_worker, ())
    return _BASELINE_RSS / 1024.0


def measure_memory_kib(hasher: BaseHasher):
    class_name, kwargs = hasher.spec()
    peak = _child_peak_rss(_memory_worker, (class_name, kwargs))
    return max(peak / 1024.0 - baseline_rss_kib(), 0)


# ---------------------------------------------------------------------------
# E1: parameter sweeps and Argon2 heat map
# ---------------------------------------------------------------------------
def run_sweeps(repeats: int):
    configs = [
        ("PBKDF2", lambda v: PBKDF2Hasher(iterations=v),
         [10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000],
         "iterations"),
        ("bcrypt", lambda v: BcryptHasher(cost=v),
         [4, 6, 8, 9, 10, 11, 12, 13, 14], "cost"),
        ("Argon2id", lambda v: Argon2idHasher(memory_kib=v),
         [8_192, 16_384, 19_456, 32_768, 65_536, 131_072, 262_144],
         "memory_kib"),
    ]
    rows = []
    for name, factory, values, param_name in configs:
        for value in values:
            hasher = factory(value)
            mean_ms, std_ms = time_latency(hasher, repeats)
            memory_kib = measure_memory_kib(hasher)
            print(f"{name:>8} {param_name}={value:>8} latency={mean_ms:9.2f} ms"
                  f" memory={memory_kib:9.1f} KiB")
            rows.append([name, param_name, value, mean_ms, std_ms, memory_kib])

    write_csv("latency_sweep.csv",
              ["scheme", "parameter", "value", "mean_ms", "std_ms",
               "memory_kib"], rows)
    plot_sweeps(rows)
    run_heatmap(repeats)


def plot_sweeps(rows):
    fig, axes = plt.subplots(1, 3, figsize=(11, 3.2), sharey=True)
    for ax, scheme in zip(axes, ["PBKDF2", "bcrypt", "Argon2id"]):
        data = [r for r in rows if r[0] == scheme]
        ax.errorbar([r[2] for r in data], [r[3] for r in data],
                    yerr=[r[4] for r in data], marker="o", capsize=3)
        ax.set_title(scheme)
        ax.set_xscale("log")
        ax.set_xlabel({"PBKDF2": "Iterations", "bcrypt": "Cost factor",
                       "Argon2id": "Memory cost (KiB)"}[scheme])
        ax.grid(True, alpha=0.3)
    axes[0].set_ylabel("Latency (ms)")
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "latency_sweep.pdf")
    fig.savefig(RESULTS_DIR / "latency_sweep.png", dpi=300)
    plt.close(fig)


def run_heatmap(repeats: int):
    memories = [8_192, 16_384, 32_768, 65_536, 131_072]
    times = [1, 2, 3, 4]
    grid = []
    for t in times:
        row = []
        for m in memories:
            mean_ms, _ = time_latency(Argon2idHasher(memory_kib=m, time_cost=t),
                                      repeats)
            row.append(mean_ms)
        grid.append(row)

    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    image = ax.imshow(grid, aspect="auto", cmap="viridis")
    ax.set_xticks(range(len(memories)))
    ax.set_xticklabels([f"{m // 1024}" for m in memories])
    ax.set_yticks(range(len(times)))
    ax.set_yticklabels(times)
    ax.set_xlabel("Memory cost (MiB)")
    ax.set_ylabel("Time cost t")
    fig.colorbar(image, ax=ax, label="Latency (ms)")
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "argon2_heatmap.pdf")
    fig.savefig(RESULTS_DIR / "argon2_heatmap.png", dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------------------
# E2 + E3: equal-latency calibration at three budgets with memory
# ---------------------------------------------------------------------------
CALIBRATION_CONFIGS = [
    ("PBKDF2", lambda v: PBKDF2Hasher(iterations=v),
     [10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 750_000,
      1_000_000, 1_500_000, 2_000_000]),
    ("bcrypt", lambda v: BcryptHasher(cost=v), list(range(4, 16))),
    ("Argon2id", lambda v: Argon2idHasher(memory_kib=v, time_cost=2),
     [4_096, 8_192, 12_288, 19_456, 32_768, 47_104, 65_536, 98_304,
      131_072, 196_608, 262_144]),
]


def calibrate_one(factory, candidates, target_ms, repeats):
    best = None
    for value in candidates:
        mean_ms, std_ms = time_latency(factory(value), repeats)
        record = (abs(mean_ms - target_ms), value, mean_ms, std_ms)
        if best is None or record[0] < best[0]:
            best = record
        if mean_ms > target_ms * 1.5:
            break
    _, value, mean_ms, std_ms = best
    hasher = factory(value)
    return hasher, value, mean_ms, std_ms, measure_memory_kib(hasher)


def run_calibrate(repeats: int, budgets=(100, 250, 500)):
    rows = []
    calibrated = {}
    for budget in budgets:
        calibrated[budget] = {}
        for name, factory, candidates in CALIBRATION_CONFIGS:
            print(f"Calibrating {name} towards {budget} ms...")
            hasher, value, mean_ms, std_ms, memory_kib = calibrate_one(
                factory, candidates, budget, repeats)
            rows.append([budget, name, value, mean_ms, std_ms, memory_kib])
            calibrated[budget][name] = hasher
    write_csv("equal_latency.csv",
              ["target_ms", "scheme", "parameter", "mean_ms", "std_ms",
               "memory_kib"], rows)
    return calibrated


# ---------------------------------------------------------------------------
# E4: attacker throughput and parallel scaling
# ---------------------------------------------------------------------------
WORDLIST = [
    "123456", "password", "qwerty", "12345678", "111111", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine", "princess",
    "admin", "welcome", "shadow", "superman", "michael", "ninja",
    "abc123", "passw0rd", "master", "hello", "freedom", "whatever",
]


def _attack_worker(class_name, kwargs, guesses, queue):
    hasher = build_hasher(class_name, kwargs)
    stored = hasher.hash(TEST_PASSWORD)
    start = time.perf_counter()
    for guess in guesses:
        hasher.verify(guess, stored)
    queue.put(time.perf_counter() - start)


def parallel_throughput(hasher: BaseHasher, worker_count: int,
                        guesses_per_worker: int = 12):
    spec = hasher.spec()
    guesses = WORDLIST[:guesses_per_worker]
    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    processes = [
        ctx.Process(target=_attack_worker,
                    args=(spec[0], spec[1], guesses, queue))
        for _ in range(worker_count)]
    start = time.perf_counter()
    for p in processes:
        p.start()
    for p in processes:
        p.join()
    elapsed = time.perf_counter() - start
    while not queue.empty():
        queue.get()
    queue.close()
    total_guesses = worker_count * len(guesses)
    return total_guesses / elapsed


def run_parallel(repeats_hashers):
    rows = []
    worker_counts = [1, 2, 4, 8]
    for name, hasher in repeats_hashers.items():
        for workers in worker_counts:
            rate = parallel_throughput(hasher, workers)
            print(f"{name:>8} workers={workers} throughput={rate:8.1f} guesses/s")
            rows.append([name, workers, rate])
    write_csv("parallel_scaling.csv",
              ["scheme", "workers", "guesses_per_second"], rows)

    fig, ax = plt.subplots(figsize=(5, 3.4))
    for name in repeats_hashers:
        data = [r for r in rows if r[0] == name]
        ax.plot([r[1] for r in data], [r[2] for r in data], marker="o",
                label=name)
    ax.set_xlabel("Number of parallel processes")
    ax.set_ylabel("Guesses per second")
    ax.set_xscale("log", base=2)
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "parallel_scaling.pdf")
    fig.savefig(RESULTS_DIR / "parallel_scaling.png", dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------------------
# E6: salting cost analysis
# ---------------------------------------------------------------------------
def sha256_verifier(password: str, salt: bytes = b""):
    return hashlib.sha256(salt + password.encode()).hexdigest()


def run_salting(account_counts=(1, 2, 4, 8, 16), candidates=20):
    # Lightweight slow-hash settings so the n x m runs finish in reasonable time.
    slow = [("PBKDF2", PBKDF2Hasher(iterations=50_000)),
            ("bcrypt", BcryptHasher(cost=8)),
            ("Argon2id", Argon2idHasher(memory_kib=8_192, time_cost=1))]
    rows = []
    guesses = WORDLIST[:candidates]

    for n in account_counts:
        # Unsalted SHA-256: each candidate hashed once, checked against all n.
        unsalted = [sha256_verifier(TEST_PASSWORD)] * n
        start = time.perf_counter()
        for guess in guesses:
            h = sha256_verifier(guess)
            if h in unsalted:
                break
        rows.append(["unsalted SHA-256", n, time.perf_counter() - start])

        # Salted SHA-256: every (account, candidate) pair is a new hash.
        salts = [os.urandom(16) for _ in range(n)]
        start = time.perf_counter()
        for salt in salts:
            target = sha256_verifier(TEST_PASSWORD, salt)
            for guess in guesses:
                if sha256_verifier(guess, salt) == target:
                    break
        rows.append(["salted SHA-256", n, time.perf_counter() - start])

        # Slow hashes: same n x m structure with per-guess KDF cost.
        for name, hasher in slow:
            stored = [hasher.hash(TEST_PASSWORD) for _ in range(n)]
            start = time.perf_counter()
            for verifier in stored:
                for guess in guesses:
                    if hasher.verify(guess, verifier):
                        break
            rows.append([name, n, time.perf_counter() - start])
        print(f"salting experiment n={n} done")

    write_csv("salting.csv", ["configuration", "accounts", "elapsed_s"], rows)

    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    for config in {r[0] for r in rows}:
        data = [r for r in rows if r[0] == config]
        ax.plot([r[1] for r in data], [r[2] for r in data], marker="o",
                label=config)
    ax.set_xlabel("Number of accounts n")
    ax.set_ylabel("Total cracking time (s)")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "salting.pdf")
    fig.savefig(RESULTS_DIR / "salting.png", dpi=300)
    plt.close(fig)


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


def run_anderson(calibrated_250):
    seconds_per_year = 365 * 24 * 3600
    target_p = 0.5
    rows = []
    for name, hasher in calibrated_250.items():
        # Single-threaded attacker rate measured directly.
        rate = parallel_throughput(hasher, 1, guesses_per_worker=8)
        required_n = seconds_per_year * rate / target_p
        lengths = {a: minimum_length(a, required_n) for a in (62, 96)}
        print(f"{name:>8} G={rate:7.1f}/s  S(62)={lengths[62]}  "
              f"S(96)={lengths[96]}")
        rows.append([name, rate, lengths[62], lengths[96]])
    write_csv("anderson.csv",
              ["scheme", "guesses_per_second", "length_A62", "length_A96"],
              rows)


# ---------------------------------------------------------------------------
# Environment and utilities
# ---------------------------------------------------------------------------
def write_csv(filename, header, rows):
    with open(RESULTS_DIR / filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def record_environment():
    info = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "total_ram_gib": round(psutil.virtual_memory().total / 1024 ** 3, 2),
        "bcrypt_version": bcrypt.__version__,
    }
    write_csv("environment.csv", ["key", "value"], list(info.items()))
    for key, value in info.items():
        print(f"{key}: {value}")


def main():
    parser = argparse.ArgumentParser(description="Password hashing benchmark")
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("command",
                        choices=["env", "sweep", "calibrate", "parallel",
                                 "salting", "anderson", "all"])
    args = parser.parse_args()

    if args.command in ("env", "all"):
        record_environment()
    if args.command in ("sweep", "all"):
        run_sweeps(args.repeats)
    if args.command in ("calibrate", "all"):
        calibrated = run_calibrate(args.repeats)
    else:
        calibrated = None
    if args.command in ("parallel", "all"):
        target = calibrated[250] if calibrated else {
            "PBKDF2": PBKDF2Hasher(), "bcrypt": BcryptHasher(),
            "Argon2id": Argon2idHasher()}
        run_parallel(target)
    if args.command in ("salting", "all"):
        run_salting()
    if args.command in ("anderson", "all"):
        target = calibrated[250] if calibrated else {
            "PBKDF2": PBKDF2Hasher(), "bcrypt": BcryptHasher(),
            "Argon2id": Argon2idHasher()}
        run_anderson(target)


if __name__ == "__main__":
    mp.freeze_support()
    main()
