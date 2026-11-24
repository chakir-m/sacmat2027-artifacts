"""Phase 4 numbers: extended probe (v1, v2), mutation rerun of the final v2, running example.
Usage: python summarize_phase4.py <phase4-results> <fork-backend> <out-json>
The two mutants of the cost-ablation switch (the `if EVAL_ABLATE_DR5` statement in pep.py) are excluded:
they mutate an evaluation-only switch, not v2 behaviour.
"""
import ast, json, os, sys

P4, FORK, OUT = sys.argv[1:4]
J = lambda *p: json.load(open(os.path.join(*p)))
S = {}

src = open(os.path.join(FORK, "app/api/pep.py")).read()
abl = set()
for n in ast.walk(ast.parse(src)):
    if isinstance(n, ast.If) and "EVAL_ABLATE_DR5" in ast.unparse(n.test):
        abl.add(n.lineno)
S["ablation_switch_lines"] = sorted(abl)

for v in ("v1", "v2"):
    p = J(P4, f"probe_{v}.json")
    S[f"probe_{v}"] = {"checks": len(p), "safety": sum(k.startswith("S") for k in p),
                      "liveness": sum(k.startswith("L") for k in p),
                      "failed": sorted((k for k, x in p.items() if not x["pass"]), key=lambda k: (k[0], int(k.split("_")[0][1:])))}

e = J(P4, "e5v3", "e5_l3_mutation.json")
rs = [r for r in e["results"] if not (r["file"] == "app/api/pep.py" and r["line"] in abl)]
S["E5v3"] = {"baseline": e["baseline"], "points_total": len(e["results"]), "excluded_ablation": len(e["results"]) - len(rs),
             "mutants": len(rs),
             "killed_repo": sum(r["killed_by_repo_tests"] for r in rs),
             "killed_probe": sum(r["killed_by_probe"] for r in rs),
             "killed_either": sum(r["killed_by_repo_tests"] or r["killed_by_probe"] for r in rs),
             "probe_only": sum(r["killed_by_probe"] and not r["killed_by_repo_tests"] for r in rs),
             "repo_only": sum(r["killed_by_repo_tests"] and not r["killed_by_probe"] for r in rs)}
byf = {}
for r in rs:
    b = byf.setdefault(r["file"], {"n": 0, "both": 0, "probe_only": 0, "repo_only": 0, "survive": []})
    b["n"] += 1
    t, p = r["killed_by_repo_tests"], r["killed_by_probe"]
    if t and p: b["both"] += 1
    elif p: b["probe_only"] += 1
    elif t: b["repo_only"] += 1
    else: b["survive"].append([r["op"], r["line"], r["id"]])
S["E5v3"]["by_file"] = byf
S["E5v3"]["survivors"] = sum(len(b["survive"]) for b in byf.values())
re_ = J(P4, "running_example.json")
S["running_example"] = {k: {"v1": v["v1"]["decision"], "v2": v["v2"]["decision"], "rho": v["rho"]} for k, v in re_.items()}
json.dump(S, open(OUT, "w"), indent=1)
print(json.dumps({k: v for k, v in S["E5v3"].items() if k not in ("by_file", "baseline")}),
      json.dumps({k: (v["n"], v["both"], v["probe_only"], v["repo_only"], len(v["survive"])) for k, v in byf.items()}))
