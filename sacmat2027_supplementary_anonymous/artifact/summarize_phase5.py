"""Phase 5 numbers: E1 with ownership (v2), coverage with the owner atoms, criterion G certificates and self-tests,
the document-procedure check (E1c), the mixed-view reproduction, the F8 session test, the frozen-clock boundary
oracle, the extended probe, the E5v4 mutation run of the final v2, the held-out mutation set, the Cedar check
and the cost re-run.
Usage: python summarize_phase5.py <phase5-results> <fork-backend> <out-json>
As in phase 4, the mutants of the cost-ablation switch (the `if EVAL_ABLATE_DR5` statement in pep.py, with its
body) are excluded: they mutate an evaluation-only switch, not v2 behaviour.
"""
import ast, json, os, sys

P5, FORK, OUT = sys.argv[1:4]
J = lambda *p: json.load(open(os.path.join(*p)))
X = lambda *p: os.path.exists(os.path.join(*p))
S = {}

e = J(P5, "e1_v2", "e1_summary_ext_own.json")
S["E1_v2_own"] = {k: e[k] for k in ("worlds_evaluated", "api_reachable_worlds", "indeterminate",
                                    "agreement_vs_C9_FIX_decision", "invariant_violations_all",
                                    "invariant_violations_api_reachable", "applied_rule_histogram")}
for v in ("v1", "v2"):
    for f in ("e1_summary.json", "e1_summary_ext.json"):
        if X(P5, f"e1_{v}", f):
            S.setdefault("E1_rerun", {})[f"{v}/{f}"] = {k: J(P5, f"e1_{v}", f)[k] for k in
                                                       ("worlds_evaluated", "agreement_vs_M_IMPL_decision",
                                                        "agreement_vs_C9_FIX_decision", "invariant_violations_all")}
c = J(P5, "wp1", "wp1_coverage_own.json")
S["coverage_own"] = {s: {"satisfiable": c[s]["satisfiable"], "realised": c[s]["realised"], "missing": len(c[s]["missing"])}
                     for s in ("all", "api")}
for v in ("v1", "v2"):
    g = J(P5, f"wp1_genericity_{v}.json"); t = J(P5, f"wp1_checker_selftest_{v}.json")
    S[f"criterion_G_{v}"] = {"occurrences": g["occurrences"], "holds": g["criterion_G_holds"],
                             "obs_act_constants": g["accepted_language"]["obs_act_constants"],
                             "selftest_original": t["original_pdp"],
                             "selftest_flagged": sum(x.startswith("flagged") for x in t["seeded_violations"].values()),
                             "selftest_cases": len(t["seeded_violations"])}
z = J(P5, "e6", "e6_smt_ext.json")["results"]
S["E6_ext_C9_FIX"] = {k.split("|", 1)[1]: v["result"] for k, v in z.items() if k.startswith("C9_FIX")}
S["E6_max_time_s"] = max(max(v["time_s"] for v in J(P5, "e6", f)["results"].values()) for f in ("e6_smt.json", "e6_smt_ext.json"))
for tag in ("pre", None):
    f = f"e1c_document_v2{'_pre' if tag else ''}.json"
    d = J(P5, f)
    S[f"E1c_{'before_fix' if tag else 'final'}"] = {k: d[k] for k in ("worlds", "agreement_with_M_DOC", "non_403_errors",
                                                                      "requirement_violations")}
for v in ("v1", "v2"):
    m = J(P5, f"e2_mixed_{v}.json")
    S[f"mixed_{v}"] = m.get("summary", {k: m[k] for k in m if k != "trials"})
for f, k in (("e2_collab_v1.json", "F8_v1"), ("e2_collab_v2.json", "F8_v2"), ("e2_collab_v2_before_fix.json", "F8_v2_before_fix")):
    d = J(P5, "f8", f)
    S[k] = {x: d[x] for x in ("n", "closed", "window_min_s", "window_max_s")}
    S[k]["doc_api_read_after_removal"] = sorted({t.get("doc_api_read_after_removal") for t in d["trials"]})
b = J(P5, "e3_boundary_v1.json")
S["E3_boundary"] = {i: {"line": m["line"], "killed": m["killed"], "differs_on": m["differs_on"]} for i, m in b["mutants"].items()}
for v in ("v1", "v2"):
    p = J(P5, f"probe_{v}.json")
    S[f"probe_{v}"] = {"checks": len(p), "safety": sum(k.startswith("S") for k in p),
                      "liveness": sum(k.startswith("L") for k in p),
                      "failed": sorted((k for k, x in p.items() if not x["pass"]), key=lambda k: (k[0], int(k.split("_")[0][1:])))}
w5 = J(P5, "wp5", "wp5_cedar.json"); w5i = J(P5, "wp5", "wp5_idiomatic.json")
S["cedar"] = {k: {"policies": w5[k]["policies"], "valid": w5[k]["validation_passed"],
                  "requests": w5[k]["differential_vs_reference"]["requests"], "agree": w5[k]["differential_vs_reference"]["agree"]}
              for k in ("M_IMPL", "M_IMPL_without_Pctx", "C9_FIX")}
S["cedar_idiomatic"] = {"policies": w5i["policies"], "valid": w5i["validation_passed"], **w5i["differential_vs_C9_FIX"]}

src = open(os.path.join(FORK, "app/api/pep.py")).read()
# the ablation `if` and its body (the held-out operators also reach the statements inside it)
abl = {l for n in ast.walk(ast.parse(src)) if isinstance(n, ast.If) and "EVAL_ABLATE_DR5" in ast.unparse(n.test)
       for l in range(n.lineno, max(b.end_lineno for b in n.body) + 1)}


def mut_summary(path, key):
    e = J(path)
    # line numbers in the mutation results refer to the fork's source file
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


if X(P5, "e5v4", "e5_l3_mutation.json"):
    mut_summary(os.path.join(P5, "e5v4", "e5_l3_mutation.json"), "E5v4")
if X(P5, "e5h", "e5_heldout.json"):
    mut_summary(os.path.join(P5, "e5h", "e5_heldout.json"), "E5_heldout")
if X(P5, "e5h_survivor_classes.json"):
    cl = J(P5, "e5h_survivor_classes.json")
    S["E5h_classes"] = {k: len(v["mutants"]) for k, v in cl["classes"].items()}
if X(P5, "e5v4_survivor_classes.json"):
    cl = J(P5, "e5v4_survivor_classes.json")
    S["E5v4_classes"] = {k: len(v["mutants"]) for k, v in cl["classes"].items()}
if X(P5, "e1b_v2", "e1b_state.json"):
    d = J(P5, "e1b_v2", "e1b_state.json"); S["E1b_v2"] = {"worlds": d["worlds"], "mismatches": d["mismatches"]}
if X(P5, "e1c_on_e5v4_survivors.json"):
    d = J(P5, "e1c_on_e5v4_survivors.json")
    S["E1c_on_E5v4_survivors"] = {k: {"line": v["line"], "op": v["op"], "killed": v["killed"],
                                      "disagreements": v["worlds"] - v["agreement_with_M_DOC"],
                                      "violated": sorted({x.split("|")[0] for x in v["requirement_violations"]})}
                                  for k, v in d.items()}
if X(P5, "e4", "summary_base1w_vs_final1w.json"):
    d = J(P5, "e4", "summary_base1w_vs_final1w.json")["workloads"]
    S["E4_final"] = {w: {k: v[k] for k in v if k not in ("throughput_base_rps", "throughput_fork_rps", "per_run_median_ms")}
                     for w, v in d.items()}
json.dump(S, open(OUT, "w"), indent=1, default=str)
print(json.dumps({k: v for k, v in S.items() if k in ("E1_v2_own", "E1c_final", "F8_v2", "probe_v2", "E5v4", "E5_heldout")},
                 default=str)[:3000])
