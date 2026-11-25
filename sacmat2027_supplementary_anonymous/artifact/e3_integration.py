"""
E3 (continued) -- run the repository's 76 integration tests against every mutant that the
repository's unit + conformance suites did not kill. Requires PostgreSQL/Redis and the external
test-environment plugin (rate limits, CSRF header). Application code is mutated only in a copy.
Usage: python e3_integration.py <backend> <work> <results> <python> <artifact> <plugin-dir>
"""
import ast, json, os, shutil, subprocess, sys

BACKEND, WORK, RES, PY, ART, PLUG = sys.argv[1:7]
ns = {}
sys.argv = ["x", BACKEND, WORK, RES, PY, ART]
exec(open(os.path.join(ART, "e3_mutation.py")).read().split("def main")[0], ns)
rs = []
for k in (0, 1):
    rs += json.load(open(os.path.join(RES, f"e3_mutation_shard{k}.json")))["results"]
todo = [r["id"] for r in rs if not r["killed_by_existing_tests"]]
tree = ast.parse(open(os.path.join(BACKEND, "app/services/pdp.py")).read())
work = os.path.join(WORK, "integ")
if os.path.exists(work):
    shutil.rmtree(work)
shutil.copytree(BACKEND, work, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
target = os.path.join(work, "app/services/pdp.py")
env = dict(os.environ, PYTHONPATH=PLUG, PYTHONDONTWRITEBYTECODE="1",
           SECRET_KEY="ci_test_secret_key_32_chars_minimum_xx", ENVIRONMENT="test", STORAGE_BACKEND="local",
           DATABASE_URL="postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_test",
           REDIS_URL="redis://localhost:6379/0")
cmd = [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no_ratelimit", "-o", "log_cli=false",
       "tests/test_integration.py"]
open(target, "w").write(ast.unparse(tree))
b = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=600)
base = (b.returncode, (b.stdout.strip().splitlines() or [""])[-1])
print("baseline", base, flush=True)
out = []
for i in todo:
    kind, line, src = ns["apply"](tree, i)
    open(target, "w").write(src)
    p = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=600)
    last = (p.stdout.strip().splitlines() or [""])[-1]
    out.append({"id": i, "op": kind, "line": line, "killed_by_integration": p.returncode != 0, "summary": last})
    print(i, kind, line, p.returncode, last, flush=True)
json.dump({"baseline": base, "results": out}, open(os.path.join(RES, "e3_integration.json"), "w"), indent=2)
