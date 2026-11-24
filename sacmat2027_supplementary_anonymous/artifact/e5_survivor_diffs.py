"""Prints the source change of every surviving enforcement mutant, for manual classification.
Usage: python e5_survivor_diffs.py <fork-backend> <e5_l3_mutation.json> [<summary_phase4.json>]
"""
import ast, difflib, json, os, sys

FORK, RES = sys.argv[1:3]
SUMMARY = sys.argv[3] if len(sys.argv) > 3 else None
here = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(here, "e5_l3_mutation.py")).read()
ns = {}
saved = sys.argv
sys.argv = ["x"] + ["-"] * 6                       # the module reads its CLI arguments at import
exec(src.split("def run(")[0], ns)
sys.argv = saved
abl = set(json.load(open(SUMMARY))["ablation_switch_lines"]) if SUMMARY else set()
for r in json.load(open(RES))["results"]:
    if r["killed_by_repo_tests"] or r["killed_by_probe"]:
        continue
    if r["file"] == "app/api/pep.py" and r["line"] in abl:
        continue
    tree = ast.parse(open(os.path.join(FORK, r["file"])).read())
    base = ast.unparse(tree).splitlines()
    kind, ln, mut = ns["apply"](tree, ns["TARGETS"][r["file"]], r["id"])
    diff = [l for l in difflib.unified_diff(base, mut.splitlines(), n=0, lineterm="")
            if l[:1] in "+-" and l[:3] not in ("+++", "---")]
    old = [l[1:].strip() for l in diff if l.startswith("-")]
    new = [l[1:].strip() for l in diff if l.startswith("+")]
    print(f'{r["file"].split("/")[-1]}:{r["line"]} {kind} id={r["id"]}')
    for o, n in zip(old, new):
        i = next((k for k, (a, b) in enumerate(zip(o, n)) if a != b), 0)
        print("   -", o[max(0, i - 70):i + 50]); print("   +", n[max(0, i - 70):i + 50])
