"""Prints the source change of every surviving held-out mutant (E5h), for manual classification.
Usage: python e5h_survivor_diffs.py <fork-backend> <e5_heldout.json>
"""
import ast, difflib, json, os, sys
FORK, RES = sys.argv[1:3]
here = os.path.dirname(os.path.abspath(__file__))
sys.argv = [sys.argv[0], FORK, "-", "-", "-", "-", "-"]
sys.path.insert(0, here)
import e5_heldout as H                                               # noqa: E402
trees = {}
for r in json.load(open(RES))["results"]:
    if r["killed_by_repo_tests"] or r["killed_by_probe"]:
        continue
    f = r["file"]
    t = trees.setdefault(f, ast.parse(open(os.path.join(FORK, f)).read()))
    kind, line, src = H.apply(t, H.E.TARGETS[f], r["id"])
    a, b = ast.unparse(t).splitlines(), src.splitlines()
    print(f"{f.split('/')[-1]}:{line} {kind} id={r['id']}")
    for d in difflib.unified_diff(a, b, n=0, lineterm=""):
        if d.startswith(("---", "+++", "@@")):
            continue
        print("   " + d[:150])
