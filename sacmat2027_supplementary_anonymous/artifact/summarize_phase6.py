"""Phase 6 numbers. Recomputes every number of the paper that phase 6 re-measured, from phase6/results, and
carries over (with their phase-5 source marked) the results whose code has not changed since: v1's criterion-G
certificate and self-test, the mixed-view reproduction, the F8 session test, the frozen-clock boundary oracle and
the pre-fix E1c run.
Usage: python summarize_phase6.py <phase5-results> <phase6-results> <fork-backend> <out-json>
As in phases 4-5, the mutants of the cost-ablation switch (the `if EVAL_ABLATE_DR5` statement in pep.py and its
body) are excluded: they mutate an evaluation-only switch, not v2 behaviour.
"""
import ast, json, os, sys

P5, P6, FORK, OUT = sys.argv[1:5]
J = lambda *p: json.load(open(os.path.join(*p)))
X = lambda *p: os.path.exists(os.path.join(*p))
S = {"_sources": {"phase6": P6, "phase5_carried_over": P5}}

e = J(P6, "e1_v2", "e1_summary_ext_own.json")
S["E1_v2_own"] = {k: e[k] for k in ("worlds_evaluated", "api_reachable_worlds", "indeterminate",
                                    "agreement_vs_C9_FIX_decision", "invariant_violations_all",
                                    "invariant_violations_api_reachable", "applied_rule_histogram")}
for f in ("e1_summary.json", "e1_summary_ext.json"):
    d = J(P6, "e1_v1", f)
    S.setdefault("E1_v1_rerun", {})[f] = {k: d[k] for k in ("worlds_evaluated", "agreement_vs_M_IMPL_decision",
                                                             "invariant_violations_all")}
c = J(P6, "wp1", "wp1_coverage_own.json")
S["coverage_own"] = {s: {"satisfiable": c[s]["satisfiable"], "realised": c[s]["realised"], "missing": len(c[s]["missing"])}
                     for s in ("all", "api")}
for v, base in (("v1", P5), ("v2", P6)):
    g = J(base, f"wp1_genericity_{v}.json"); t = J(base, f"wp1_checker_selftest_{v}.json")
    S[f"criterion_G_{v}"] = {"source": "phase6" if base == P6 else "phase5", "occurrences": g["occurrences"],
                             "holds": g["criterion_G_holds"],
                             "obs_act_constants": g["accepted_language"]["obs_act_constants"],
                             "selftest_original": t["original_pdp"],
                             "selftest_flagged": sum(x.startswith("flagged") for x in t["seeded_violations"].values()),
                             "selftest_cases": len(t["seeded_violations"])}
z = J(P6, "e6", "e6_smt_ext.json")["results"]
S["E6_ext_C9_FIX"] = {k.split("|", 1)[1]: v["result"] for k, v in z.items() if k.startswith("C9_FIX")}
S["E6_max_time_s"] = max(max(v["time_s"] for v in J(P6, "e6", f)["results"].values()) for f in ("e6_smt.json", "e6_smt_ext.json"))
d = J(P6, "e1c_document_v2.json")
S["E1c_final"] = {k: d[k] for k in ("worlds", "agreement_with_M_DOC", "non_403_errors", "requirement_violations", "runtime_s")}
d = J(P5, "e1c_document_v2_pre.json")
S["E1c_before_fix_phase5"] = {k: d[k] for k in ("worlds", "agreement_with_M_DOC", "requirement_violations")}
d = J(P6, "e1b_v2", "e1b_state.json"); S["E1b_v2"] = {"worlds": d["worlds"], "mismatches": d["mismatches"]}
for v in ("v1", "v2"):
    m = J(P5, f"e2_mixed_{v}.json")
    S[f"mixed_{v}_phase5"] = m.get("summary", {k: m[k] for k in m if k != "trials"})
for f, k in (("e2_collab_v1.json", "F8_v1"), ("e2_collab_v2.json", "F8_v2"), ("e2_collab_v2_before_fix.json", "F8_v2_before_fix")):
    d = J(P5, "f8", f)
    S[k + "_phase5"] = {x: d[x] for x in ("n", "closed", "window_min_s", "window_max_s")}
b = J(P5, "e3_boundary_v1.json")
S["E3_boundary_phase5"] = {i: {"line": m["line"], "killed": m["killed"], "differs_on": m["differs_on"]}
                           for i, m in b["mutants"].items()}
for v in ("v1", "v2", "v2_6a26954", "v2_e590e08", "v2_224eac8"):
    if X(P6, f"probe_{v}.json"):
        p = J(P6, f"probe_{v}.json")
        S[f"probe_{v}"] = {"checks": len(p), "safety": sum(k.startswith("S") for k in p),
                          "liveness": sum(k.startswith("L") for k in p),
                          "failed": sorted((k for k, x in p.items() if not x["pass"]),
                                           key=lambda k: (k[0], int(k.split("_")[0][1:])))}
w5 = J(P6, "wp5", "wp5_cedar.json"); w5i = J(P6, "wp5", "wp5_idiomatic.json")
S["cedar"] = {k: {"policies": w5[k]["policies"], "valid": w5[k]["validation_passed"],
                  "requests": w5[k]["differential_vs_reference"]["requests"], "agree": w5[k]["differential_vs_reference"]["agree"]}
              for k in ("M_IMPL", "M_IMPL_without_Pctx", "C9_FIX")}
S["cedar_idiomatic"] = {"policies": w5i["policies"], "valid": w5i["validation_passed"], **w5i["differential_vs_C9_FIX"]}

# L3 inventory and sweeps
for v in ("v1", "v2"):
    inv = J(P6, "l3inv", f"inventory_{v}.json")["summary"]
    S[f"inventory_{v}"] = {k: inv[k] for k in ("api_routes", "in_scope", "in_scope_probed", "in_scope_with_pdp",
                                              "in_scope_with_doc_read", "in_scope_with_no_decision_procedure")}
    sw = J(P6, "l3inv", f"sweep_{v}.json")
    S[f"get_sweep_{v}"] = {"routes": sw["routes"], "content": sw["content_flagged"], "metadata": sw["metadata_flagged"]}
    if X(P6, "l3inv", f"state_sweep_{v}.json"):
        ss = J(P6, "l3inv", f"state_sweep_{v}.json")
        S[f"state_sweep_{v}"] = {"routes": ss["routes"], "flagged": sorted(ss["flagged"]),
                                 "not_exercised_422": ss["not_exercised_422"], "skipped": ss["skipped"]}
# cache operations (epsilon_b, lost increment)
if X(P6, "e7", "e7_cache_ops.json"):
    d = J(P6, "e7", "e7_cache_ops.json")
    S["E7"] = {f"A_workers{w}": {k: d[f"A_workers{w}"][k] for k in ("cycles", "hook_calls", "server_pids", "eps_b_ms",
                                                                    "bumped_before_response", "deny_after_revocation",
                                                                    "load_5xx")} for w in (1, 2)}
    for k in ("B_control", "B_refused", "B_timeout"):
        t = d[k]
        S["E7"][k] = {"n": len(t), "bump_lost": sum(x["bump_lost"] for x in t),
                      "first_deny_s": [min(x["first_deny_after_revocation_s"] for x in t),
                                       max(x["first_deny_after_revocation_s"] for x in t)],
                      "revoke_request_s": [min(x["revoke_request_s"] for x in t), max(x["revoke_request_s"] for x in t)],
                      "unrelated_request_s": [min(x["unrelated_request"][1] for x in t),
                                              max(x["unrelated_request"][1] for x in t)]}

src = open(os.path.join(FORK, "app/api/pep.py")).read()
abl = {l for n in ast.walk(ast.parse(src)) if isinstance(n, ast.If) and "EVAL_ABLATE_DR5" in ast.unparse(n.test)
       for l in range(n.lineno, max(b.end_lineno for b in n.body) + 1)}


def mut_summary(path, key):
    e = J(path)
    rs = [r for r in e["results"] if not (r["file"] == "app/api/pep.py" and r["line"] in abl)]
    out = {"baseline": e["baseline"], "points_total": len(e["results"]), "excluded_ablation": len(e["results"]) - len(rs),
           "mutants": len(rs), "killed_repo": sum(r["killed_by_repo_tests"] for r in rs),
           "killed_probe": sum(r["killed_by_probe"] for r in rs),
           "killed_either": sum(r["killed_by_repo_tests"] or r["killed_by_probe"] for r in rs),
           "probe_only": sum(r["killed_by_probe"] and not r["killed_by_repo_tests"] for r in rs),
           "repo_only": sum(r["killed_by_repo_tests"] and not r["killed_by_probe"] for r in rs)}
    byf, byop = {}, {}
    for r in rs:
        b = byf.setdefault(r["file"], {"n": 0, "both": 0, "probe_only": 0, "repo_only": 0, "survive": []})
        o = byop.setdefault(r["op"], {"n": 0, "killed_either": 0, "killed_probe": 0})
        b["n"] += 1; o["n"] += 1
        t, p = r["killed_by_repo_tests"], r["killed_by_probe"]
        o["killed_either"] += t or p; o["killed_probe"] += p
        if t and p: b["both"] += 1
        elif p: b["probe_only"] += 1
        elif t: b["repo_only"] += 1
        else: b["survive"].append([r["op"], r["line"], r["id"]])
    out["by_file"] = byf; out["by_op"] = byop
    out["survivors"] = sum(len(b["survive"]) for b in byf.values())
    S[key] = out


if X(P6, "e5v4", "e5_l3_mutation.json"):
    mut_summary(os.path.join(P6, "e5v4", "e5_l3_mutation.json"), "E5v4")
if X(P6, "e5h", "e5_heldout.json"):
    mut_summary(os.path.join(P6, "e5h", "e5_heldout.json"), "E5_heldout")
for f, k in (("e5v4_survivor_classes.json", "E5v4_classes"), ("e5h_survivor_classes.json", "E5h_classes")):
    if X(P6, f):
        S[k] = {c: len(v["mutants"]) for c, v in J(P6, f)["classes"].items()}
if X(P6, "e1c_on_e5v4_survivors.json"):
    d = J(P6, "e1c_on_e5v4_survivors.json")
    S["E1c_on_E5v4_survivors"] = {k: {"line": v["line"], "op": v["op"], "killed": v["killed"],
                                      "disagreements": v["worlds"] - v["agreement_with_M_DOC"],
                                      "violated": sorted({x.split("|")[0] for x in v["requirement_violations"]})}
                                  for k, v in d.items()}
if X(P6, "e4", "summary_base1w_vs_final1w.json"):
    d = J(P6, "e4", "summary_base1w_vs_final1w.json")
    S["E4_final"] = {w: {k: v[k] for k in v if k not in ("throughput_base_rps", "throughput_fork_rps")}
                     for w, v in d["workloads"].items()}
    S["E4_race"] = d.get("race")
json.dump(S, open(OUT, "w"), indent=1, default=str)
print(json.dumps({k: S[k] for k in ("E1_v2_own", "probe_v2", "inventory_v2") if k in S}, default=str)[:2500])
