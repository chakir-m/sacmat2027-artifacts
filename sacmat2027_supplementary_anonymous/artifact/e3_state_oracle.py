"""
E3 (continued) -- re-run rule-level survivors against the state-level oracle E1b.
Usage: python e3_state_oracle.py <backend> <work-dir> <results-dir> <python> <artifact-dir> <db-url>
"""
import ast, json, os, shutil, subprocess, sys

BACKEND, WORK, RES, PY, ART, DBURL = sys.argv[1:7]
sys.argv = ["x", BACKEND, WORK, RES, PY, ART]
ns = {}
exec(open(os.path.join(ART, "e3_mutation.py")).read().split("def main")[0], ns)
rs = []
for k in (0, 1):
    rs += json.load(open(os.path.join(RES, f"e3_mutation_shard{k}.json")))["results"]
survivors = [r["id"] for r in rs if not r["killed_by_existing_tests"] and not r["killed_by_E1_full"]]
tree = ast.parse(open(os.path.join(BACKEND, "app/services/pdp.py")).read())
work = os.path.join(WORK, "state")
if os.path.exists(work):
    shutil.rmtree(work)
shutil.copytree(BACKEND, work, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
target = os.path.join(work, "app/services/pdp.py")
env = dict(os.environ, E1_ORACLE="1", PYTHONDONTWRITEBYTECODE="1")
cmd = [PY, os.path.join(ART, "e1b_state.py"), work, os.path.join(WORK, "e1btmp"), DBURL]
open(target, "w").write(ast.unparse(tree))
base = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300).returncode
out = []
for i in survivors:
    kind, line, src = ns["apply"](tree, i)
    open(target, "w").write(src)
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
    last = (p.stdout.strip().splitlines() or [""])[-1]
    out.append({"id": i, "op": kind, "line": line, "killed_by_E1b": p.returncode != 0, "out": last})
    print(i, kind, line, p.returncode, last, flush=True)
json.dump({"baseline_rc": base, "results": out}, open(os.path.join(RES, "e3_state_oracle.json"), "w"), indent=2)
