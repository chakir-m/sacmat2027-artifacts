"""Recompute every number reported in the Phase-3 paper from raw results.
Usage: python summarize_phase3.py <phase3-results-dir> <phase2-results-dir> <out-json>
"""
import json, os, statistics as st, sys

P3, P2, OUT = sys.argv[1:4]
J = lambda *p: json.load(open(os.path.join(*p)))
S = {}

# RQ1 -- L1 (snapshot, E1-ext), criterion G, coverage, SMT, alternative readings
e1 = J(P3, "e1_summary_ext.json")
S["E1_ext"] = {k: e1[k] for k in ("worlds_evaluated", "api_reachable_worlds", "runtime_s", "indeterminate",
                                  "agreement_vs_M_IMPL_decision", "agreement_vs_M_IMPL_rule",
                                  "agreement_vs_R_PAPER_decision", "invariant_violations_api_reachable",
                                  "invariant_violations_all", "Pctx_inertness_pairs", "Pctx_inertness_equal")}
S["E1_ext"]["R_PAPER_disagreements"] = e1["worlds_evaluated"] - e1["agreement_vs_R_PAPER_decision"]
S["E1_ext"]["R_PAPER_disagreements_api"] = sum(e1["R_PAPER_disagreements_api_reachable"].values())
g = J(P3, "wp1_genericity.json")
S["criterion_G"] = {"holds": g["criterion_G_holds"], "occurrences": g["occurrences"], "escapes": len(g["escapes"])}
S["checker_selftest"] = J(P3, "wp1_checker_selftest.json")["seeded_violations"]
cv, cb = J(P3, "wp1_coverage.json"), J(P3, "wp1_coverage_base.json")
S["coverage"] = {sc: {"satisfiable": cv[sc]["satisfiable"], "realised_ext": cv[sc]["realised"],
                      "missing_ext": len(cv[sc]["missing"]), "realised_published": cb[sc]["realised"],
                      "missing_published": len(cb[sc]["missing"])} for sc in ("all", "api")}
e6 = J(P3, "e6_smt_ext.json")["results"]
S["E6_ext"] = {k: v["result"] for k, v in e6.items() if "|api|" in k or "inert" in k}
S["E6_ext_max_time_s"] = max(v["time_s"] for v in e6.values())
alt = J(P3, "wp7_alt_readings.json")
S["alt_readings"] = {"z3": {k: v["result"] for k, v in alt["z3"].items()}, "counts": alt["violations_api_reachable"]}

# RQ2 -- L2 (snapshot, n = 10)
r2 = os.path.join(P3, "e2_n10")
rv, ex, ra = J(r2, "e2_revoke.json"), J(r2, "e2_expiry.json"), J(r2, "e2_race.json")


def win(rows, key, akey, tau):
    by = {}
    for t in rows:
        by.setdefault(t["delta_s"], []).append(t)
    return {d: {"n": len(v), "median": round(st.median(t[key] for t in v), 2), "min": min(t[key] for t in v),
                "max": max(t[key] for t in v), "max_allows": max(t[akey] for t in v),
                "max_dev_from_bound": round(max(abs(t[key] - (tau - d)) for t in v), 2)} for d, v in sorted(by.items())}


S["E2_n10"] = {"deleg_revoke": win(rv["E2b_delegation_revocation"], "window_s", "allows_after_revoke", 60),
               "deleg_expiry": win(ex["E2c_delegation_expiry"], "window_after_expiry_s", "allows_after_expiry", 60),
               "asg_expiry": win(ex["E2d_assignment_expiry"], "window_after_expiry_s", "allows_after_expiry", 120),
               "asg_revoke_control": [t["window_s"] for t in rv["E2b_control_assignment_revocation"]],
               "race_forced": [t["window_s"] for t in ra["E2e_race_forced_interleaving"]],
               "race_forced_max_allows": max(t["allows_after_revoke"] for t in ra["E2e_race_forced_interleaving"]),
               "race_unforced": ra["E2e_race_unforced"]}
devs = []
for t in rv["E2b_delegation_revocation"]: devs.append(t["window_s"] - (60 - t["delta_s"]))
for t in ex["E2c_delegation_expiry"]: devs.append(t["window_after_expiry_s"] - (60 - t["delta_s"]))
for t in ex["E2d_assignment_expiry"]: devs.append(t["window_after_expiry_s"] - (120 - t["delta_s"]))
S["E2_n10"]["deviation_range_s"] = [round(min(devs), 2), round(max(devs), 2)]
S["E2_n10"]["trials_with_bound"] = len(devs)

# RQ3 -- L3 (snapshot, Phase 2 results) and fork
S["E2a_snapshot"] = J(P2, "e2_audit.json")["E2a_audit_persistence"]
S["E2_enforce_snapshot"] = J(P2, "e2_enforce.json")["E2_enforcement"]
S["E2_enforce_fork"] = J(P3, "fork", "e2_enforce.json")["E2_enforcement"]
S["E2a_fork"] = J(P3, "fork", "e2_audit.json")["E2a_audit_persistence"]

# RQ4 -- mutation (decision logic: Phase 2 summary; enforcement: E5)
S["E3"] = J(P2, "summary.json")["E3"]
e5p = os.path.join(P3, "e5", "e5_l3_mutation.json")
if os.path.exists(e5p):
    e5 = J(e5p)
    S["E5"] = {"baseline": e5["baseline"], "mutants": len(e5["results"]),
               "killed_repo": sum(r["killed_by_repo_tests"] for r in e5["results"]),
               "killed_probe": sum(r["killed_by_probe"] for r in e5["results"]),
               "killed_either": sum(r["killed_by_repo_tests"] or r["killed_by_probe"] for r in e5["results"]),
               "probe_only": sum(r["killed_by_probe"] and not r["killed_by_repo_tests"] for r in e5["results"]),
               "repo_only": sum(r["killed_by_repo_tests"] and not r["killed_by_probe"] for r in e5["results"]),
               "survivors": [(r["file"], r["id"], r["op"], r["line"]) for r in e5["results"]
                             if not (r["killed_by_repo_tests"] or r["killed_by_probe"])]}
    byf = {}
    for r in e5["results"]:
        b = byf.setdefault(r["file"], {"n": 0, "repo": 0, "probe": 0})
        b["n"] += 1; b["repo"] += r["killed_by_repo_tests"]; b["probe"] += r["killed_by_probe"]
    S["E5"]["by_file"] = byf

# RQ5 -- fork, cost, Cedar, external systems
f1 = J(P3, "fork", "e1_summary_ext.json")
S["fork_E1"] = {k: f1[k] for k in ("worlds_evaluated", "agreement_vs_C9_FIX_decision", "invariant_violations_all")}
S["fork_E1b"] = {k: J(P3, "fork", "e1b_state.json")[k] for k in ("worlds", "mismatches")}
frv, fex, fra = J(P3, "fork", "e2_revoke.json"), J(P3, "fork", "e2_expiry.json"), J(P3, "fork", "e2_race.json")
S["fork_E2"] = {"deleg_revoke_windows": [t["window_s"] for t in frv["E2b_delegation_revocation"]],
                "deleg_revoke_allows": max(t["allows_after_revoke"] for t in frv["E2b_delegation_revocation"]),
                "expiry_windows": [t["window_after_expiry_s"] for t in fex["E2c_delegation_expiry"] + fex["E2d_assignment_expiry"]],
                "race_forced": [t["window_s"] for t in fra["E2e_race_forced_interleaving"]],
                "race_unforced": fra["E2e_race_unforced"]}
S["E4"] = J(P3, "e4", "e4_summary.json")
for w in S["E4"]["workloads"].values():
    w.pop("per_run_median_ms", None)
S["cedar"] = {k: v for k, v in J(P3, "wp5", "wp5_cedar.json").items()}
S["cedar_idiomatic"] = J(P3, "wp5", "wp5_idiomatic.json")
tt = J(P3, "wp3", "tinytodo.json")
S["tinytodo"] = {"T1": {k: {x: tt[k][x] for x in ("rounds", "user_checks", "mismatches")} for k in tt if k.startswith("T1")},
                 "propagation_s": [min(x for x in tt["T2"]["propagation_s"] if x is not None),
                                   max(x for x in tt["T2"]["propagation_s"] if x is not None)],
                 "fail_stale": sum(x["forbid_never_enforced_5s"] for x in tt["T2"]["invalid_validation"] + tt["T2"]["invalid_syntax"]),
                 "share_revocation_next_request": sum(tt["T2"]["share_revocation"]),
                 "mediation_denied": sum(not v["allowed"] for k, v in tt["T3a_mediation"].items() if not k.startswith("_")),
                 "identity": tt["T3b_identity"]}
S["backstage"] = J(P3, "wp3", "backstage_rbac.json")
# OpenFGA (third external system)
of = J(P3, "wp3", "openfga.json")
S["openfga"] = {"version": of["version"], "O1": {k: of["O1_L1_differential"][k] for k in ("states", "checks", "agree")}, "O2": {}}
for cfg, rows in of["O2_L2_revocation"].items():
    by = {}
    for x in rows:
        by.setdefault(f'{x["revocation"]}@{x["delta_s"]}', []).append(x["window_s"])
    S["openfga"]["O2"][cfg] = {k: {"n": len(v), "median": round(st.median(v), 3), "min": min(v), "max": max(v)} for k, v in by.items()}
# Cost ablations (one worker; DR5 off)
ab = os.path.join(P3, "e4", "ablation")
for f in ("summary_base1w_vs_fork1w.json", "summary_fork2noDR5_vs_fork2.json"):
    if os.path.exists(os.path.join(ab, f)):
        S["E4_" + f[8:-5]] = {w: {k: v[k] for k in ("median_base_ms", "median_fork_ms", "ratio_median")}
                              for w, v in J(ab, f)["workloads"].items()}
# Probe on v1 and v2, and the rerun mutation study with the extended probe (v2 probe, ablation switch excluded)
for v in ("v1", "v2"):
    pp = os.path.join(P3, "e5", f"probe_{v}.json")
    if os.path.exists(pp):
        pr = J(pp); S[f"probe_{v}"] = {"probes": len(pr), "failed": sorted(k for k, x in pr.items() if not x["pass"])}
e5b = os.path.join(P3, "e5v2", "e5_l3_mutation.json")
if os.path.exists(e5b):
    rs = [r for r in J(e5b)["results"] if not (r["file"] == "app/api/pep.py" and r["line"] == 153)]
    S["E5v2"] = {"mutants": len(rs), "killed_repo": sum(r["killed_by_repo_tests"] for r in rs),
                 "killed_probe": sum(r["killed_by_probe"] for r in rs),
                 "killed_either": sum(r["killed_by_repo_tests"] or r["killed_by_probe"] for r in rs),
                 "probe_only": sum(r["killed_by_probe"] and not r["killed_by_repo_tests"] for r in rs),
                 "repo_only": sum(r["killed_by_repo_tests"] and not r["killed_by_probe"] for r in rs)}
    byf = {}
    for r in rs:
        b = byf.setdefault(r["file"], {"n": 0, "repo": 0, "probe": 0, "survive": []})
        b["n"] += 1; b["repo"] += r["killed_by_repo_tests"]; b["probe"] += r["killed_by_probe"]
        if not (r["killed_by_repo_tests"] or r["killed_by_probe"]):
            b["survive"].append((r["op"], r["line"]))
    S["E5v2"]["by_file"] = byf
json.dump(S, open(OUT, "w"), indent=1, default=str)
print(json.dumps({k: S[k] for k in ("E1_ext", "coverage", "E2_n10")}, indent=1, default=str)[:3000])
if "E5" in S:
    print(json.dumps({k: v for k, v in S["E5"].items() if k != "survivors"}, indent=1))
