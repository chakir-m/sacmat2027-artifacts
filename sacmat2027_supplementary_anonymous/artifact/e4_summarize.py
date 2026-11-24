"""
Summarise E4 cost runs: per workload, median/p95 latency of snapshot vs fork with 95%
bootstrap CIs of the difference of medians (fork - snapshot) and of the ratio, pooling the
interleaved runs of each variant; throughput per repetition.

Usage: python e4_summarize.py <dir-with-e4_*.json> <out-json>
"""
import glob, json, os, sys
import numpy as np

D, OUTJ = sys.argv[1], sys.argv[2]
A, Bp = (sys.argv[3], sys.argv[4]) if len(sys.argv) > 4 else ("base", "fork")
runs = {"base": [], "fork": []}
for f in sorted(glob.glob(os.path.join(D, "e4_*.json"))):
    j = json.load(open(f))
    if j["label"].startswith(A + "_"):
        runs["base"].append(j)
    elif j["label"].startswith(Bp + "_"):
        runs["fork"].append(j)
rng = np.random.default_rng(11)
B = 10000
out = {"runs": {k: [r["label"] for r in v] for k, v in runs.items()}, "workloads": {}, "race": {}}
for w in runs["base"][0]["workloads"]:
    xb = np.concatenate([np.asarray(r["workloads"][w]["latencies_ms"]) for r in runs["base"]])
    xf = np.concatenate([np.asarray(r["workloads"][w]["latencies_ms"]) for r in runs["fork"]])
    mb, mf = np.median(xb), np.median(xf)
    d, q = [], []
    for _ in range(B):
        sb = np.median(rng.choice(xb, xb.size)); sf = np.median(rng.choice(xf, xf.size))
        d.append(sf - sb); q.append(sf / sb)
    thr_b = [t for r in runs["base"] for t in r["workloads"][w]["throughput_rps"]]
    thr_f = [t for r in runs["fork"] for t in r["workloads"][w]["throughput_rps"]]
    out["workloads"][w] = {
        "n_base": int(xb.size), "n_fork": int(xf.size),
        "median_base_ms": round(float(mb), 1), "median_fork_ms": round(float(mf), 1),
        "p95_base_ms": round(float(np.percentile(xb, 95)), 1), "p95_fork_ms": round(float(np.percentile(xf, 95)), 1),
        "p99_base_ms": round(float(np.percentile(xb, 99)), 1), "p99_fork_ms": round(float(np.percentile(xf, 99)), 1),
        "throughput_mean_base_rps": round(float(np.mean([t for r in runs["base"] for t in r["workloads"][w]["throughput_rps"]])), 1),
        "throughput_mean_fork_rps": round(float(np.mean([t for r in runs["fork"] for t in r["workloads"][w]["throughput_rps"]])), 1),
        "errors_base": sum(n for r in runs["base"] for c, n in r["workloads"][w]["status_counts"].items() if int(c) >= 500),
        "errors_fork": sum(n for r in runs["fork"] for c, n in r["workloads"][w]["status_counts"].items() if int(c) >= 500),
        "diff_median_ms": round(float(mf - mb), 1),
        "diff_median_ci95": [round(float(np.percentile(d, 2.5)), 1), round(float(np.percentile(d, 97.5)), 1)],
        "ratio_median": round(float(mf / mb), 3),
        "ratio_median_ci95": [round(float(np.percentile(q, 2.5)), 3), round(float(np.percentile(q, 97.5)), 3)],
        "throughput_base_rps": [round(t, 1) for t in thr_b], "throughput_fork_rps": [round(t, 1) for t in thr_f],
        "per_run_median_ms": {r["label"]: round(r["workloads"][w]["median_ms"], 1) for r in runs["base"] + runs["fork"]},
        "status_base": [r["workloads"][w]["status_counts"] for r in runs["base"]],
        "status_fork": [r["workloads"][w]["status_counts"] for r in runs["fork"]],
    }
for k, v in runs.items():
    t = sum(r["race_multiworker"]["trials"] for r in v)
    s = sum(r["race_multiworker"]["allow_after_commit"] for r in v)
    e = sum(r["race_multiworker"]["stale_entry_after_commit"] for r in v)
    out["race"][k] = {"trials": t, "allow_after_commit": s, "stale_entry_after_commit": e,
                      "rate": round(s / t, 3) if t else None}
json.dump(out, open(OUTJ, "w"), indent=1)
for w, v in out["workloads"].items():
    print(f"{w:12s} base {v['median_base_ms']:6.1f}  fork {v['median_fork_ms']:6.1f}  "
          f"diff {v['diff_median_ms']:+6.1f} {v['diff_median_ci95']}  ratio {v['ratio_median']} {v['ratio_median_ci95']}")
print(out["race"])
