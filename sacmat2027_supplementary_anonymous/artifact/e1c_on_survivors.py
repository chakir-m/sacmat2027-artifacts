"""E1c as an oracle for the document-procedure survivors of E5v4 (phase 5).

E5v4 leaves some mutants of _doc_read_allowed alive under the repository tests and the L3 probe. This script
applies each listed mutant to a throw-away copy of the fork and runs the bounded-exhaustive document check
(e1c_document.py, fixed transcription M_DOC) on it. A mutant is killed by E1c if any world's decision
differs from M_DOC or a requirement is violated. The fork itself is never modified.

Usage: python e1c_on_survivors.py <fork-backend> <work> <out-json> <python> <id> [<id> ...]
(ids are E5v4 point ids in app/api/documents.py)
"""
import ast, json, os, shutil, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
FORK, WORK, OUT, PY = sys.argv[1:5]
IDS = [int(x) for x in sys.argv[5:]]
argv = sys.argv
sys.argv = [argv[0]] + ["-"] * 6
sys.path.insert(0, here)
import e5_l3_mutation as E                                          # noqa: E402
sys.argv = argv
F = "app/api/documents.py"
tree = ast.parse(open(os.path.join(FORK, F)).read())
res = {}
for i in [None] + IDS:
    w = os.path.join(WORK, f"e1c_m{i}")
    if os.path.exists(w):
        shutil.rmtree(w)
    shutil.copytree(FORK, w, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "tests"))
    if i is None:
        line, kind, src = None, "original", ast.unparse(tree)
    else:
        kind, line, src = E.apply(tree, E.TARGETS[F], i)
    open(os.path.join(w, F), "w").write(src)
    o = os.path.join(WORK, f"e1c_m{i}.json")
    subprocess.run([PY, os.path.join(here, "e1c_document.py"), w, o], check=True,
                   env=dict(os.environ, E1C_FIXED="1", PYTHONDONTWRITEBYTECODE="1"), stdout=subprocess.DEVNULL)
    d = json.load(open(o))
    killed = d["agreement_with_M_DOC"] != d["worlds"] or bool(d["requirement_violations"])
    res["original" if i is None else str(i)] = {
        "op": kind, "line": line, "worlds": d["worlds"], "agreement_with_M_DOC": d["agreement_with_M_DOC"],
        "requirement_violations": d["requirement_violations"], "theta_used": d["theta_used"],
        "mismatch_example": d["mismatch_examples"][:1], "killed": killed}
    print(i, kind, line, d["agreement_with_M_DOC"], d["worlds"], d["requirement_violations"], flush=True)
json.dump(res, open(OUT, "w"), indent=1, default=str)
