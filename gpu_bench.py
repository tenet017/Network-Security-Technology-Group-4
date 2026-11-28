"""Measure real hashcat GPU attack speed at our CPU-calibrated parameters.

For each (scheme, setting) we build one genuine hash in hashcat's input
format, run a dictionary attack whose word list does NOT contain the
password (so the full per-guess derivation runs), and parse the machine-
readable Speed field. Apples-to-apples with the CPU verify() rate at the
same parameters.

Outputs (in <out>/):
  gpu_calibrated.csv   three schemes at 100/250/500 ms + OWASP minimums
  gpu_argon2_sweep.csv Argon2id GPU rate vs memory cost m (t=2), the
                       "memory defeats the GPU" figure source
"""
import base64, csv, hashlib, os, re, subprocess, sys, time
from pathlib import Path

HC = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
DEVICES = sys.argv[3] if len(sys.argv) > 3 else "1"
REPEATS = int(sys.argv[4]) if len(sys.argv) > 4 else 3
OUT.mkdir(parents=True, exist_ok=True)
PASSWORD = "CorrectHorseBatteryStaple!2026"

import bcrypt
from argon2 import PasswordHasher

b64 = lambda raw: base64.b64encode(raw).decode()


def pbkdf2_hash(iterations):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, iterations, 32)
    return 40024, f"sha256:{iterations}:{b64(salt)}:{b64(dk)}"


def bcrypt_hash(cost):
    return 3200, bcrypt.hashpw(PASSWORD.encode(),
                               bcrypt.gensalt(rounds=cost)).decode()


def argon2_hash(m, t, p=1):
    return 34000, PasswordHasher(time_cost=t, memory_cost=m, parallelism=p,
                                 hash_len=32, salt_len=16).hash(PASSWORD)


# Word list without the password: every guess is a full-cost miss.
WL = OUT / "wl.txt"
if not WL.exists():
    WL.write_text("\n".join(f"guess{i:06d}" for i in range(200_000)) + "\n")

ENV = dict(os.environ)
_hits = list(Path(sys.prefix).rglob("libnvrtc.so*"))
if _hits:
    ENV["LD_LIBRARY_PATH"] = str(_hits[0].parent) + ":" + \
        ENV.get("LD_LIBRARY_PATH", "")
else:
    sys.exit("libnvrtc.so not found under " + sys.prefix)


def parse_speed(text):
    """Sum per-device H/s from machine-readable STATUS lines; take the max
    stable reading over the run."""
    best = 0.0
    for line in text.splitlines():
        m = re.search(r"SPEED\t(.+?)\tEXEC_RUNTIME", line)
        if not m:
            continue
        nums = [float(x) for x in m.group(1).split("\t") if x]
        hps = sum(nums[i] / (nums[i + 1] / 1000.0)
                  for i in range(0, len(nums) - 1, 2) if nums[i + 1] > 0)
        best = max(best, hps)
    return best


def bench(mode, hash_str, tag):
    hf = OUT / f"hash_{tag}.txt"
    hf.write_text(hash_str + "\n")
    speeds = []
    for rep in range(REPEATS):
        log = OUT / f"gpu_{tag}_r{rep}.log"
        cmd = [str(HC / "hashcat.bin"), "-m", str(mode), "-a", "0",
               str(hf), str(WL), "-d", DEVICES, "--potfile-disable",
               "--runtime", "30", "--status", "--status-timer", "6",
               "--machine-readable", "--quiet", "-O"]
        proc = subprocess.run(cmd, cwd=str(HC), env=ENV,
                              capture_output=True, text=True)
        log.write_text(proc.stdout + "\n" + proc.stderr)
        speeds.append(parse_speed(proc.stdout + proc.stderr))
    speeds = [s for s in speeds if s > 0]
    return (sum(speeds) / len(speeds)) if speeds else 0.0, speeds


def hash_for(scheme, value):
    """Build a hashcat-format hash at the scheme's calibrated parameter."""
    if scheme == "PBKDF2":
        return pbkdf2_hash(int(value))
    if scheme == "bcrypt":
        return bcrypt_hash(int(value))
    if scheme == "Argon2id":
        return argon2_hash(int(value), 2)
    raise ValueError(scheme)


def load_calibrated_jobs():
    """Read the real calibrated parameters from equal_latency.csv so the GPU
    attacks exactly the CPU-calibrated settings (not hard-coded guesses)."""
    cal = OUT.parent / "equal_latency.csv"
    if not cal.exists():
        cal = OUT / "equal_latency.csv"
    jobs = []
    with open(cal, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            jobs.append((r["scheme"], f"{r['target_ms']} ms",
                         hash_for(r["scheme"], r["value"])))
    # fixed OWASP reference points for a second comparison
    jobs += [("PBKDF2", "OWASP (600000)", pbkdf2_hash(600_000)),
             ("bcrypt", "OWASP (cost 10)", bcrypt_hash(10)),
             ("Argon2id", "OWASP (19 MiB)", argon2_hash(19456, 2))]
    return jobs


def run_calibrated():
    jobs = load_calibrated_jobs()
    rows = []
    for i, (scheme, setting, (mode, h)) in enumerate(jobs):
        rate, speeds = bench(mode, h, f"cal_{scheme}_{i}")
        print(f"{scheme:>9} {setting:<16} {rate:12.1f} H/s  {speeds}")
        rows.append({"scheme": scheme, "setting": setting,
                     "hashcat_mode": mode, "gpu_hps_mean": round(rate, 2),
                     "gpu_hps_runs": " ".join(f"{s:.0f}" for s in speeds),
                     "gpu": "RTX 4090 (CUDA)"})
    _write("gpu_calibrated.csv", rows)


def run_argon2_sweep():
    """GPU rate vs memory cost m (t=2). Also records the CPU verify latency at
    each point so the absolute GPU-rate drop can be normalised to equal login
    latency (the 342x absolute drop is mostly the defender's rising latency;
    the equal-latency memory benefit is only a few-fold)."""
    import statistics
    import time
    from argon2.low_level import hash_secret_raw, Type
    pw, salt = b"correct horse battery staple", b"0123456789abcdef"
    rows = []
    for m_mib in [8, 19, 32, 64, 128, 256, 512]:
        kw = dict(time_cost=2, memory_cost=m_mib * 1024, parallelism=1,
                  hash_len=32, type=Type.ID)
        hash_secret_raw(pw, salt, **kw)  # warm-up
        ts = []
        for _ in range(5 if m_mib >= 256 else 7):
            a = time.perf_counter()
            hash_secret_raw(pw, salt, **kw)
            ts.append((time.perf_counter() - a) * 1000.0)
        verify_ms = round(statistics.median(ts), 1)
        mode, h = argon2_hash(m_mib * 1024, 2)
        rate, speeds = bench(mode, h, f"sweep_argon2_{m_mib}")
        print(f"Argon2id m={m_mib:>4} MiB t=2   {verify_ms:7.1f} ms CPU"
              f"   {rate:12.1f} H/s GPU")
        rows.append({"scheme": "Argon2id", "memory_mib": m_mib, "time_cost": 2,
                     "hashcat_mode": mode, "gpu_hps_mean": round(rate, 2),
                     "gpu_hps_runs": " ".join(f"{s:.0f}" for s in speeds),
                     "verify_ms": verify_ms, "gpu": "RTX 4090 (CUDA)"})
    _write("gpu_argon2_sweep.csv", rows)


def run_mt_sweep():
    """GPU rate vs CPU verify latency at several (m, t) points (p=1). Pairs with
    the t=2 memory sweep to show that on this card the GPU rate tracks the CPU
    verify latency almost independently of how the budget splits between memory
    and passes. Records both the measured verify latency and the GPU rate."""
    import statistics
    import time
    from argon2.low_level import hash_secret_raw, Type
    pw, salt = b"correct horse battery staple", b"0123456789abcdef"
    rows = []
    for m_mib, t in [(16, 4), (32, 4), (64, 4), (64, 3), (128, 1)]:
        # CPU-side verify latency (p=1), median of a short warmed run
        kw = dict(time_cost=t, memory_cost=m_mib * 1024, parallelism=1,
                  hash_len=32, type=Type.ID)
        hash_secret_raw(pw, salt, **kw)  # warm-up
        ts = []
        for _ in range(7):
            a = time.perf_counter()
            hash_secret_raw(pw, salt, **kw)
            ts.append((time.perf_counter() - a) * 1000.0)
        verify_ms = round(statistics.median(ts), 1)
        # GPU-side attack rate
        mode, h = argon2_hash(m_mib * 1024, t)
        rate, speeds = bench(mode, h, f"mt_argon2_{m_mib}_{t}")
        print(f"Argon2id m={m_mib:>4} MiB t={t}   {verify_ms:7.1f} ms CPU"
              f"   {rate:12.1f} H/s GPU")
        rows.append({"scheme": "Argon2id", "memory_mib": m_mib, "time_cost": t,
                     "hashcat_mode": mode, "gpu_hps_mean": round(rate, 2),
                     "gpu_hps_runs": " ".join(f"{s:.0f}" for s in speeds),
                     "verify_ms": verify_ms, "gpu": "RTX 4090 (CUDA)"})
    _write("gpu_mt_sweep.csv", rows)


_UNIT = {"": 1, "k": 1e3, "M": 1e6, "G": 1e9}


def run_sha256():
    """Raw unsalted SHA-256 benchmark on one card, a reference fast-hash rate
    for Intro's 'billions of guesses per second' and a baseline bar in Fig 3."""
    speeds = []
    for rep in range(REPEATS):
        cmd = [str(HC / "hashcat.bin"), "-b", "-m", "1400", "-d", DEVICES]
        proc = subprocess.run(cmd, cwd=str(HC), env=ENV,
                              capture_output=True, text=True)
        (OUT / f"gpu_sha256_r{rep}.log").write_text(proc.stdout + "\n" + proc.stderr)
        tot = 0.0
        for line in (proc.stdout + proc.stderr).splitlines():
            mm = re.search(r"Speed\.#\d+.*?:\s*([\d.]+)\s*([kMG]?)H/s", line)
            if mm:
                tot += float(mm.group(1)) * _UNIT[mm.group(2)]
        if tot > 0:
            speeds.append(tot)
    rate = (sum(speeds) / len(speeds)) if speeds else 0.0
    print(f"SHA-256 raw   {rate:14.0f} H/s   {speeds}")
    _write("gpu_sha256.csv", [{"scheme": "SHA-256 (unsalted)",
            "setting": "raw benchmark", "hashcat_mode": 1400,
            "gpu_hps_mean": round(rate, 1),
            "gpu_hps_runs": " ".join(f"{s:.0f}" for s in speeds),
            "gpu": "RTX 4090 (CUDA)"}])


def _write(name, rows):
    with open(OUT / name, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("wrote", OUT / name)


if __name__ == "__main__":
    which = sys.argv[5] if len(sys.argv) > 5 else "all"
    if which in ("all", "calibrated"):
        run_calibrated()
    if which in ("all", "sweep"):
        run_argon2_sweep()
    if which in ("all", "extra", "mt"):
        run_mt_sweep()
    if which in ("all", "extra", "sha"):
        run_sha256()
