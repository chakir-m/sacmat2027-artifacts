"""
E5h -- Held-out mutation set for the FROZEN L3 probe (phase 5).

The probe of e5_l3_probe.py grew while we studied the survivors of E5 (operators ROR, MEM, LCR, UOI-, NEG,
CRP, CRPb, RET). To estimate how well the frozen probe (28 safety + 18 liveness checks in phase 6; 27 + 18 in phase 5) generalises, this
script applies operators that were NOT used while the probe was built, to the same target functions:
  SDL  statement deletion: one simple statement (expression call, assignment, augmented assignment, raise,
       delete) is replaced by `pass`
  RSW  raise swallowing: one `raise` becomes `return None` (the error is swallowed and the function returns)
  ARG  argument swap: the first two positional arguments of one call are swapped
Points inside logging, HTTP error payloads, f-strings and audit details are excluded, as in E5. The oracles are
the repository suite (T) and the frozen probe (P), each in a throw-away copy of the fork.

Usage: python e5_heldout.py <fork-backend> <work> <out> <python> <artifact> <plugin-dir> [--count]
"""
import ast, copy, json, os, shutil, sys, time
here = os.path.dirname(os.path.abspath(__file__))
argv = sys.argv
sys.argv = [argv[0]] + argv[1:7]
sys.path.insert(0, here)
import e5_l3_mutation as E                                          # noqa: E402  (reuses targets, oracles)
sys.argv = argv
FORK, WORK, OUT, PY, ART, PLUG = argv[1:7]
COUNT_ONLY = "--count" in argv
SIMPLE = (ast.Expr, ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Raise, ast.Delete)


def points(tree, funcs):
    pts = []

    def walk(node, stack, inside):
        st = stack + [node]
        inside = inside or (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in funcs)
        if inside and not E.metadata(st):
            if isinstance(node, SIMPLE) and not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)):
                if not (isinstance(node, ast.Expr) and E.metadata([node.value])):   # logging calls only
                    pts.append(("SDL", node))
            if isinstance(node, ast.Raise):
                pts.append(("RSW", node))
            if isinstance(node, ast.Call) and len(node.args) >= 2 \
                    and not any(isinstance(a, ast.Starred) for a in node.args[:2]) \
                    and ast.dump(node.args[0]) != ast.dump(node.args[1]):
                pts.append(("ARG", node))
        for ch in ast.iter_child_nodes(node):
            walk(ch, st, inside)
    walk(tree, [], False)
    return pts


def apply(tree, funcs, idx):
    t = copy.deepcopy(tree)
    kind, node = points(t, funcs)[idx]
    line = getattr(node, "lineno", None)

    class Rep(ast.NodeTransformer):
        def generic_visit(self, n):
            super().generic_visit(n)
            if n is node:
                if kind == "SDL":
                    return ast.copy_location(ast.Pass(), n)
                if kind == "RSW":
                    return ast.copy_location(ast.Return(value=ast.Constant(value=None)), n)
            return n
    if kind == "ARG":
        node.args[0], node.args[1] = node.args[1], node.args[0]
    else:
        t = Rep().visit(t)
    return kind, line, ast.unparse(ast.fix_missing_locations(t))


def main():
    trees = {f: ast.parse(open(os.path.join(FORK, f)).read()) for f in E.TARGETS}
    plan = [(f, i) for f in E.TARGETS for i in range(len(points(trees[f], E.TARGETS[f])))]
    by = {}
    for f in E.TARGETS:
        for k, _ in points(trees[f], E.TARGETS[f]):
            by[k] = by.get(k, 0) + 1
    print("held-out points:", {f: len(points(trees[f], E.TARGETS[f])) for f in E.TARGETS}, by, "total", len(plan), flush=True)
    if COUNT_ONLY:
        return
    work = os.path.join(WORK, "e5h")
    if os.path.exists(work):
        shutil.rmtree(work)
    shutil.copytree(FORK, work, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    for f, t in trees.items():
        open(os.path.join(work, f), "w").write(ast.unparse(t))
    env = dict(os.environ, PYTHONPATH=PLUG, PYTHONDONTWRITEBYTECODE="1", ENVIRONMENT="test",
               SECRET_KEY="ci_test_secret_key_32_chars_minimum_xx", STORAGE_BACKEND="local",
               DATABASE_URL="postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_test",
               REDIS_URL="redis://localhost:6379/0")
    T = [PY, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-p", "no_ratelimit", "-o", "log_cli=false", "tests/",
         "--deselect", "tests/test_conformance.py::TestP4NeedToKnow::test_phi_minus_assigned_analyst_write_not_in_actions"]
    P = [PY, os.path.join(ART, "e5_l3_probe.py"), work,
         "postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_e5", "redis://localhost:6379/2"]
    resf = os.path.join(OUT, "e5_heldout.json")
    prev = json.load(open(resf)) if os.path.exists(resf) else None
    base = prev["baseline"] if prev else {"T": E.run(T, work, env), "P": E.run(P, work, env)}
    print("baseline", base, flush=True)
    out = prev["results"] if prev else []
    done = {(r["file"], r["id"]) for r in out}
    for f, i in plan:
        if (f, i) in done:
            continue
        kind, line, src = apply(trees[f], E.TARGETS[f], i)
        path = os.path.join(work, f)
        open(path, "w").write(src)
        rT, tT, lT = E.run(T, work, env)
        rP, tP, lP = E.run(P, work, env)
        open(path, "w").write(ast.unparse(trees[f]))
        out.append({"file": f, "id": i, "op": kind, "line": line, "killed_by_repo_tests": rT != 0,
                    "killed_by_probe": rP != 0, "probe_out": lP, "tests_out": lT})
        print(f, i, kind, line, "T" if rT else "-", "P" if rP else "-", lP[:120], flush=True)
        os.makedirs(OUT, exist_ok=True)
        json.dump({"baseline": base, "results": out}, open(resf, "w"), indent=1)


if __name__ == "__main__":
    main()
