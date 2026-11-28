"""Generate data-driven LaTeX tables and a numbers dump from the result CSVs.

Rigour rule (house workflow): no number is ever hand-copied into the paper.
This reads the real CSVs and emits results/tables/*.tex that main.tex \\input,
plus prints a flat list of every value the prose needs so they stay consistent.

    python build_paper_numbers.py --results ../results --out ../results/tables
"""
import argparse
import csv
import json
from pathlib import Path

SCHEMES = ["PBKDF2", "bcrypt", "Argon2id"]
BUDGETS = [100, 250, 500]
SECONDS_PER_YEAR = 365 * 24 * 3600


def read(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def min_length(alphabet, required_n):
    total = 0
    for k in range(1, 64):
        total += alphabet ** k
        if total >= required_n:
            return k
    return None


def fmt(x, nd=0):
    return f"{x:,.{nd}f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=Path("../results"))
    ap.add_argument("--out", type=Path, default=Path("../results/tables"))
    args = ap.parse_args()
    R, OUT = args.results.resolve(), args.out.resolve()
    OUT.mkdir(parents=True, exist_ok=True)
    dump = {}

    # ---- load ----
    cal = {(int(r["target_ms"]), r["scheme"]): r
           for r in read(R / "equal_latency.csv")}
    gpu = {}
    for r in read(R / "gpu_calibrated.csv"):
        tag = r["setting"].split()[0]
        if tag.isdigit():
            gpu[(int(tag), r["scheme"])] = float(r["gpu_hps_mean"])

    # ---- Table I: equal-latency calibration ----
    param_name = {"PBKDF2": "$c$", "bcrypt": "$f$", "Argon2id": "$m$ (MiB)"}
    lines = [r"\begin{tabular}{llrrr}", r"\toprule",
             r"\textbf{Budget} & \textbf{Scheme} & \textbf{Param} & "
             r"\textbf{Latency (ms)} & \textbf{Memory (MiB)} \\", r"\midrule"]
    for b in BUDGETS:
        for s in SCHEMES:
            r = cal[(b, s)]
            val = int(r["value"])
            pval = f"{val // 1024}" if s == "Argon2id" else f"{val:,}"
            mem = float(r["memory_median_kib"]) / 1024.0
            mems = f"{mem:.2f}" if mem >= 0.1 else "$<0.01$"
            lines.append(f"{b} & {s} & {pval} & {float(r['verify_mean_ms']):.1f}"
                         f" $\\pm$ {float(r['verify_std_ms']):.1f} & {mems} \\\\")
        if b != BUDGETS[-1]:
            lines.append(r"\midrule")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (OUT / "tab_equal_latency.tex").write_text("\n".join(lines))

    # ---- Table II: GPU cross-hardware attack at each budget ----
    lines = [r"\begin{tabular}{llrrr}", r"\toprule",
             r"\textbf{Budget} & \textbf{Scheme} & \textbf{CPU core (g/s)} & "
             r"\textbf{GPU (H/s)} & \textbf{Speed-up} \\", r"\midrule"]
    mult = {}
    for b in BUDGETS:
        for s in SCHEMES:
            cpu_rate = 1000.0 / float(cal[(b, s)]["verify_mean_ms"])
            g = gpu[(b, s)]
            m = g / cpu_rate
            mult[(b, s)] = m
            lines.append(f"{b} & {s} & {cpu_rate:.1f} & {fmt(g)} & "
                         f"{fmt(m)}$\\times$ \\\\")
        if b != BUDGETS[-1]:
            lines.append(r"\midrule")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (OUT / "tab_gpu_attack.tex").write_text("\n".join(lines))

    # ---- Table III: Anderson minimum length from the 1x GPU rate (250 ms) ----
    lines = [r"\begin{tabular}{lrrr}", r"\toprule",
             r"\textbf{Scheme (250\,ms)} & \textbf{GPU $G$ (H/s)} & "
             r"\textbf{$A{=}62$} & \textbf{$A{=}96$} \\", r"\midrule"]
    and_rows = []
    for s in SCHEMES:
        g = gpu[(250, s)]
        req = SECONDS_PER_YEAR * g / 0.5
        l62, l96 = min_length(62, req), min_length(96, req)
        and_rows.append((s, g, l62, l96))
        lines.append(f"{s} & {fmt(g)} & {l62} & {l96} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (OUT / "tab_anderson.tex").write_text("\n".join(lines))

    # ---- Table: GPU attack at OWASP minimum parameters ----
    # GPU rates were measured at the OWASP minimums (gpu_calibrated.csv);
    # the implied login latency is measured where a calibration point exists
    # and otherwise interpolated from the same CSVs -- never hand-copied.
    owasp = {}
    for r in read(R / "gpu_calibrated.csv"):
        if r["setting"].startswith("OWASP"):
            owasp[r["scheme"]] = float(r["gpu_hps_mean"])

    def _interp(xs, ys, x):
        for i in range(len(xs) - 1):
            if xs[i] <= x <= xs[i + 1]:
                return ys[i] + (x - xs[i]) / (xs[i + 1] - xs[i]) * (ys[i + 1] - ys[i])
        return ys[-1]

    def _cand_curve(scheme, budget):
        pairs = [p.split(":") for p in cal[(budget, scheme)]["candidates_tried"].split()]
        pts = sorted((float(a), float(b)) for a, b in pairs)
        return [a for a, _ in pts], [b for _, b in pts]

    px, py = _cand_curve("PBKDF2", 500)
    lat_pbk = _interp(px, py, 600_000)                 # PBKDF2 600k iters
    lat_bcr = float(cal[(100, "bcrypt")]["verify_mean_ms"])  # bcrypt cost 10 (measured)
    heat = read(R / "argon2_heatmap.csv")
    t2 = sorted((int(h["memory_kib"]), float(h["verify_mean_ms"]))
                for h in heat if int(h["time_cost"]) == 2)
    lat_arg = _interp([m for m, _ in t2], [v for _, v in t2], 19456)  # 19 MiB, t=2
    owasp_lat = {"PBKDF2": lat_pbk, "bcrypt": lat_bcr, "Argon2id": lat_arg}
    owasp_param = {"PBKDF2": "600{,}000 iters", "bcrypt": "cost 10",
                   "Argon2id": "19\\,MiB, $t{=}2$"}
    owasp_sp = {s2: owasp[s2] * owasp_lat[s2] / 1000.0 for s2 in SCHEMES}
    lines = [r"\begin{tabular}{llrrr}", r"\toprule",
             r"\textbf{Scheme} & \textbf{OWASP min.} & \textbf{Latency (ms)} & "
             r"\textbf{GPU (H/s)} & \textbf{Speed-up} \\", r"\midrule"]
    for s2 in SCHEMES:
        lines.append(f"{s2} & {owasp_param[s2]} & {owasp_lat[s2]:.0f} & "
                     f"{fmt(owasp[s2])} & {fmt(owasp_sp[s2])}$\\times$ \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (OUT / "tab_owasp.tex").write_text("\n".join(lines))

    # ---- Table: salting cost (hash computations vs number of accounts) ----
    byn = {}
    for r in read(R / "salting.csv"):
        byn.setdefault(int(r["accounts"]), {})[r["configuration"]] = \
            int(r["hash_computations"])
    lines = [r"\begin{tabular}{rrr}", r"\toprule",
             r"\textbf{Accounts $n$} & \textbf{Unsalted} & "
             r"\textbf{Salted ($n{\times}m$)} \\", r"\midrule"]
    for n in sorted(byn):
        lines.append(f"{n} & {byn[n]['unsalted SHA-256']} & "
                     f"{byn[n]['salted SHA-256']} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (OUT / "tab_salting.tex").write_text("\n".join(lines))
    dump["owasp"] = {s2: {"gpu": owasp[s2], "lat": owasp_lat[s2],
                          "sp": owasp_sp[s2]} for s2 in SCHEMES}
    dump["salt_m"] = 20

    # ---- Table: Argon2id (m,t) allocation -- GPU rate vs verify latency ----
    # Shows that on the RTX 4090 the GPU attack rate tracks the induced CPU
    # verify latency almost independently of how a compute budget is split
    # between memory m and passes t (p=1 throughout). Both columns measured.
    mt = read(R / "gpu_mt_sweep.csv")
    mt = sorted(mt, key=lambda r: float(r["verify_ms"]))
    # equal-latency speed-up = GPU rate / (CPU core rate) = GPU * verify_ms/1000
    def _sp(g, lat):
        return g * lat / 1000.0
    lines = [r"\begin{tabular}{rrrrr}", r"\toprule",
             r"\textbf{$m$ (MiB)} & \textbf{$t$} & \textbf{Verify (ms)} & "
             r"\textbf{GPU (H/s)} & \textbf{Speed-up} \\", r"\midrule"]
    for r in mt:
        g, lat = float(r["gpu_hps_mean"]), float(r["verify_ms"])
        lines.append(f"{int(r['memory_mib'])} & {int(r['time_cost'])} & "
                     f"{lat:.0f} & {fmt(g)} & {fmt(_sp(g, lat))}$\\times$ \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (OUT / "tab_mt.tex").write_text("\n".join(lines))
    mt_by = {(int(r["memory_mib"]), int(r["time_cost"])):
             (float(r["gpu_hps_mean"]), float(r["verify_ms"])) for r in mt}
    dump["mt"] = {f"{m}_{t}": {"gpu": g, "lat": l, "sp": _sp(g, l)}
                  for (m, t), (g, l) in mt_by.items()}
    lats = [float(r["verify_ms"]) for r in mt]
    gps = [float(r["gpu_hps_mean"]) for r in mt]
    sps = [_sp(g, l) for g, l in mt_by.values()]
    dump["mt_lat_lo"], dump["mt_lat_hi"] = min(lats), max(lats)
    dump["mt_gpu_lo"], dump["mt_gpu_hi"] = min(gps), max(gps)
    dump["mt_sp_lo"], dump["mt_sp_hi"] = min(sps), max(sps)

    # Memory sweep, normalized: the 342x absolute drop vs the equal-latency gain.
    # Uses the measured per-point verify latency (t=2) so nothing is hand-copied.
    sw = sorted(read(R / "gpu_argon2_sweep.csv"), key=lambda r: int(r["memory_mib"]))
    sw_lo, sw_hi = sw[0], sw[-1]        # 8 MiB and 512 MiB
    sp_lo_mem = _sp(float(sw_lo["gpu_hps_mean"]), float(sw_lo["verify_ms"]))
    sp_hi_mem = _sp(float(sw_hi["gpu_hps_mean"]), float(sw_hi["verify_ms"]))
    dump["argon2_sp_8"] = round(sp_lo_mem, 0)       # speed-up at 8 MiB
    dump["argon2_sp_512"] = round(sp_hi_mem, 0)     # speed-up at 512 MiB
    dump["argon2_norm_benefit"] = round(sp_lo_mem / sp_hi_mem, 1)
    dump["argon2_lat_rise"] = round(float(sw_hi["verify_ms"]) /
                                    float(sw_lo["verify_ms"]), 0)
    # the equal-latency speed-up is non-monotone in memory: it rises to a peak in
    # the low-memory (bandwidth-bound) regime before falling. Record that peak so
    # the prose does not claim a monotone "more memory -> more resistance".
    sw_sp = [(int(r["memory_mib"]),
              _sp(float(r["gpu_hps_mean"]), float(r["verify_ms"]))) for r in sw]
    pk_mem, pk_sp = max(sw_sp, key=lambda t: t[1])
    dump["argon2_sp_peak"] = round(pk_sp, 0)
    dump["argon2_sp_peak_mem"] = pk_mem

    # ---- raw unsalted SHA-256 GPU rate (reference line for Fig. 3) ----
    sha = read(R / "gpu_sha256.csv")[0]
    dump["sha256_hps"] = float(sha["gpu_hps_mean"])
    dump["sha256_ghs"] = round(float(sha["gpu_hps_mean"]) / 1e9, 1)

    # ---- numbers dump for the prose ----
    for b in BUDGETS:
        for s in SCHEMES:
            dump[f"cpu_{s}_{b}"] = round(1000.0 / float(cal[(b, s)]["verify_mean_ms"]), 2)
            dump[f"gpu_{s}_{b}"] = round(gpu[(b, s)], 1)
            dump[f"mult_{s}_{b}"] = round(mult[(b, s)], 1)
            dump[f"mem_{s}_{b}_MiB"] = round(float(cal[(b, s)]["memory_median_kib"]) / 1024.0, 2)
            dump[f"ms_{s}_{b}"] = round(float(cal[(b, s)]["verify_mean_ms"]), 1)
            dump[f"param_{s}_{b}"] = int(cal[(b, s)]["value"])
    dump["anderson_gpu"] = [{"scheme": s, "G": round(g, 1), "A62": a, "A96": c}
                            for s, g, a, c in and_rows]
    # GPU argon2 memory sweep span
    sweep = sorted(read(R / "gpu_argon2_sweep.csv"), key=lambda r: int(r["memory_mib"]))
    dump["argon2_gpu_sweep"] = [(int(r["memory_mib"]), round(float(r["gpu_hps_mean"]), 1))
                                for r in sweep]
    dump["argon2_gpu_drop"] = round(float(sweep[0]["gpu_hps_mean"]) /
                                    float(sweep[-1]["gpu_hps_mean"]), 1)
    # effective memory bandwidth of each device at the 250 ms point. An Argon2id
    # guess moves ~6m bytes (read+write each of ~m blocks per pass at t=2, plus one
    # reference read); dividing by the CPU verify time and multiplying by the GPU
    # rate gives the per-device throughput whose ratio IS the normalised speed-up.
    _bytes = 6.0 * dump["mem_Argon2id_250_MiB"] * (1024 ** 2)
    dump["argon2_bw_cpu"] = round(_bytes / (dump["ms_Argon2id_250"] / 1000.0) / 1e9, 1)  # GB/s
    dump["argon2_bw_gpu"] = round(_bytes * dump["gpu_Argon2id_250"] / 1e12, 2)            # TB/s
    # parallel scaling: speed-up at 8 workers vs 1
    par = read(R / "parallel_scaling.csv")
    for s in SCHEMES:
        r1 = [float(r["guesses_per_second"]) for r in par
              if r["scheme"] == s and int(r["workers"]) == 1]
        r8 = [float(r["guesses_per_second"]) for r in par
              if r["scheme"] == s and int(r["workers"]) == 8]
        if r1 and r8:
            dump[f"scale8_{s}"] = round((sum(r8) / len(r8)) / (sum(r1) / len(r1)), 2)
    # ---- pre-formatted tokens that main.tex «...» expects ----
    def mem_str(mib):
        return f"{mib:.2f}" if mib >= 0.1 else f"{mib:.3f}"
    tok = {
        "mult_PBKDF2_250": f"{dump['mult_PBKDF2_250']:,.0f}",
        "mult_bcrypt_250": f"{dump['mult_bcrypt_250']:,.0f}",
        "mult_Argon2id_250": f"{dump['mult_Argon2id_250']:,.0f}",
        "gpu_PBKDF2_250": f"{dump['gpu_PBKDF2_250']:,.0f}",
        "gpu_Argon2id_250": f"{dump['gpu_Argon2id_250']:,.0f}",
        "mult_Argon2id_100": f"{dump['mult_Argon2id_100']:,.0f}",
        "mult_Argon2id_500": f"{dump['mult_Argon2id_500']:,.0f}",
        "param_PBKDF2_250": f"{dump['param_PBKDF2_250']:,}",
        "param_bcrypt_250": f"{dump['param_bcrypt_250']}",
        "mem_PBKDF2_250_MiB": mem_str(dump["mem_PBKDF2_250_MiB"]),
        "mem_Argon2id_250_MiB": f"{dump['mem_Argon2id_250_MiB']:.0f}",
        "argon2_gpu_drop": f"{dump['argon2_gpu_drop']:.0f}",
        "ratio_pbk_arg": f"{dump['mult_PBKDF2_250'] / dump['mult_Argon2id_250']:.0f}",
        "scale8_PBKDF2": f"{dump['scale8_PBKDF2']:.1f}",
        "scale8_Argon2id": f"{dump['scale8_Argon2id']:.1f}",
        "owasp_gpu_PBKDF2": f"{dump['owasp']['PBKDF2']['gpu']:,.0f}",
        "owasp_gpu_bcrypt": f"{dump['owasp']['bcrypt']['gpu']:,.0f}",
        "owasp_gpu_Argon2id": f"{dump['owasp']['Argon2id']['gpu']:,.0f}",
        "owasp_lat_PBKDF2": f"{dump['owasp']['PBKDF2']['lat']:.0f}",
        "owasp_lat_bcrypt": f"{dump['owasp']['bcrypt']['lat']:.0f}",
        "owasp_lat_Argon2id": f"{dump['owasp']['Argon2id']['lat']:.0f}",
        "owasp_sp_PBKDF2": f"{dump['owasp']['PBKDF2']['sp']:,.0f}",
        "owasp_sp_bcrypt": f"{dump['owasp']['bcrypt']['sp']:,.0f}",
        "owasp_sp_Argon2id": f"{dump['owasp']['Argon2id']['sp']:,.0f}",
        "mt_gpu_32_4": f"{dump['mt']['32_4']['gpu']:,.0f}",
        "mt_gpu_128_1": f"{dump['mt']['128_1']['gpu']:,.0f}",
        "mt_lat_32_4": f"{dump['mt']['32_4']['lat']:.0f}",
        "mt_lat_128_1": f"{dump['mt']['128_1']['lat']:.0f}",
        "mt_sp_32_4": f"{dump['mt']['32_4']['sp']:,.0f}",
        "mt_sp_128_1": f"{dump['mt']['128_1']['sp']:,.0f}",
        "mt_lat_lo": f"{dump['mt_lat_lo']:.0f}",
        "mt_lat_hi": f"{dump['mt_lat_hi']:.0f}",
        "mt_gpu_lo": f"{dump['mt_gpu_lo']:,.0f}",
        "mt_gpu_hi": f"{dump['mt_gpu_hi']:,.0f}",
        "mt_sp_lo": f"{dump['mt_sp_lo']:,.0f}",
        "mt_sp_hi": f"{dump['mt_sp_hi']:,.0f}",
        "argon2_sp_8": f"{dump['argon2_sp_8']:,.0f}",
        "argon2_sp_512": f"{dump['argon2_sp_512']:,.0f}",
        "argon2_sp_peak": f"{dump['argon2_sp_peak']:,.0f}",
        "argon2_sp_peak_mem": f"{dump['argon2_sp_peak_mem']:d}",
        "argon2_norm_benefit": f"{dump['argon2_norm_benefit']:.1f}",
        "argon2_lat_rise": f"{dump['argon2_lat_rise']:.0f}",
        "argon2_bw_cpu": f"{dump['argon2_bw_cpu']:.0f}",
        "argon2_bw_gpu": f"{dump['argon2_bw_gpu']:.2f}",
        "sha256_ghs": f"{dump['sha256_ghs']:.1f}",
    }
    (OUT.parent / "paper_numbers.json").write_text(json.dumps(dump, indent=2))
    (OUT.parent / "paper_tokens.json").write_text(json.dumps(tok, indent=2))
    print(json.dumps(dump, indent=2))
    print("\nTOKENS:", json.dumps(tok, indent=2))
    print("\nwrote tables to", OUT)


if __name__ == "__main__":
    main()
