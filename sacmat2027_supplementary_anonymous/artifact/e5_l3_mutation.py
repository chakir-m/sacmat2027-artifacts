"""
E5 -- Mutation analysis of the ENFORCEMENT and STATE code of the evaluation fork (WP6).

Question: if a later change silently undid one of the L2/L3 fixes, would the repository's
own test suite notice, or only a layer-aware oracle?

Targets (fork): the single PEP gate, the document read decision, both revocation handlers,
the versioned grant cache, and the post-commit invalidation hooks. Operators as in E3
(ROR, MEM, LCR, UOI-, NEG, CRP, CRPb) plus RET (return value True<->False / None). Points
inside logging, HTTP error payloads, f-strings and audit 'details' are excluded (metadata).

Oracles per mutant (each in a throw-away copy of the fork):
  T  = the repository's full suite (unit + conformance + integration, with the external
       test plugin), as shipped
  P  = e5_l3_probe.py (Phase 4: 23 safety + 15 liveness checks; Phase 5: 27 safety + 18 liveness; Phase 6: 28 safety + 18 liveness)

Usage: python e5_l3_mutation.py <fork-backend> <work> <out> <python> <artifact> <plugin-dir> [--count]
"""
import ast, copy, json, os, shutil, subprocess, sys, time

FORK, WORK, OUT, PY, ART, PLUG = sys.argv[1:7]
COUNT_ONLY = "--count" in sys.argv
TARGETS = {
    "app/api/pep.py": {"_pep_gate"},
    "app/api/documents.py": {"_doc_read_allowed"},
    "app/api/delegations.py": {"revoke_delegation"},
    "app/api/resources.py": {"revoke_assignment"},
    "app/services/pip.py": {"_get_grant", "_set_grant"},
    "app/services/pip_invalidation.py": {"_track_orm", "_track_bulk", "_bump"},
    # phase 5 (DR4, request context): the middleware that hands the request address to the document read procedure
    "app/main.py": {"_client_ip_middleware"},
}
ROR = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE, ast.LtE: ast.Lt,
       ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Is: ast.IsNot, ast.IsNot: ast.Is}


def metadata(stack):
    for n in stack:
        if isinstance(n, ast.JoinedStr):
            return True
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            base = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
            if base == "logger" or name == "HTTPException":
                return True
        if isinstance(n, ast.keyword) and n.arg in ("details", "detail", "context_snapshot", "status_code"):
            return True
    return False


def points(tree, funcs):
    pts = []

    def walk(node, stack, inside):
        st = stack + [node]
        inside = inside or (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in funcs)
        if inside and not metadata(st):
            if isinstance(node, ast.Compare):
                for i, op in enumerate(node.ops):
                    if type(op) in ROR:
                        pts.append(("ROR", node, i))
                    if isinstance(op, (ast.In, ast.NotIn)):
                        pts.append(("MEM", node, i))
            if isinstance(node, ast.BoolOp):
                pts.append(("LCR", node, None))
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                pts.append(("UOI-", node, None))
            if isinstance(node, (ast.If, ast.IfExp)):
                pts.append(("NEG", node, None))
            if isinstance(node, ast.Constant) and type(node.value) is int:
                pts.append(("CRP+", node, None)); pts.append(("CRP-", node, None))
            if isinstance(node, ast.Constant) and isinstance(node.value, bool):
                pts.append(("CRPb", node, None))
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) and node.value.value in (True, False, None):
                pts.append(("RET", node, None))
        for ch in ast.iter_child_nodes(node):
            walk(ch, st, inside)
    walk(tree, [], False)
    return pts


def apply(tree, funcs, idx):
    t = copy.deepcopy(tree)
    kind, node, i = points(t, funcs)[idx]
    if kind == "ROR":
        node.ops[i] = ROR[type(node.ops[i])]()
    elif kind == "MEM":
        node.ops[i] = ast.NotIn() if isinstance(node.ops[i], ast.In) else ast.In()
    elif kind == "LCR":
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif kind == "NEG":
        node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)
    elif kind == "CRP+":
        node.value += 1
    elif kind == "CRP-":
        node.value -= 1
    elif kind == "CRPb":
        node.value = not node.value
    elif kind == "RET":
        v = node.value.value
        node.value.value = {True: False, False: True, None: True}[v]
    elif kind == "UOI-":
        node.op = ast.UAdd()

        class Drop(ast.NodeTransformer):
            def visit_UnaryOp(self, n):
                self.generic_visit(n)
                return n.operand if isinstance(n.op, ast.UAdd) else n
        t = ast.fix_missing_locations(Drop().visit(t))
    return kind, getattr(node, "lineno", None), ast.unparse(t)


def run(cmd, cwd, env, timeout=900):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, round(time.time() - t0, 1), (p.stdout.strip().splitlines() or [""])[-1]
    except subprocess.TimeoutExpired:
        return 124, timeout, "timeout"


def main():
    trees = {f: ast.parse(open(os.path.join(FORK, f)).read()) for f in TARGETS}
    plan = [(f, i) for f in TARGETS for i in range(len(points(trees[f], TARGETS[f])))]
    print("mutation points:", {f: len(points(trees[f], TARGETS[f])) for f in TARGETS}, "total", len(plan), flush=True)
    if COUNT_ONLY:
        return
    work = os.path.join(WORK, "e5")
    if os.path.exists(work):
        shutil.rmtree(work)
    shutil.copytree(FORK, work, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    for f, t in trees.items():                         # normalised (unparsed) originals
        open(os.path.join(work, f), "w").write(ast.unparse(t))
    env = dict(os.environ, PYTHONPATH=PLUG, PYTHONDONTWRITEBYTECODE="1", ENVIRONMENT="test",
               SECRET_KEY="ci_test_secret_key_32_chars_minimum_xx", STORAGE_BACKEND="local",
               DATABASE_URL="postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_test",
               REDIS_URL="redis://localhost:6379/0")
    T = [PY, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-p", "no_ratelimit", "-o", "log_cli=false", "tests/",
         # the one test whose expected deciding-rule label changes by design in the fork (WP4)
         "--deselect", "tests/test_conformance.py::TestP4NeedToKnow::test_phi_minus_assigned_analyst_write_not_in_actions"]
    P = [PY, os.path.join(ART, "e5_l3_probe.py"), work,
         "postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_e5", "redis://localhost:6379/2"]
    resf = os.path.join(OUT, "e5_l3_mutation.json")
    prev = json.load(open(resf)) if os.path.exists(resf) else None      # resume support
    base = prev["baseline"] if prev else {"T": run(T, work, env), "P": run(P, work, env)}
    print("baseline", base, flush=True)
    out = prev["results"] if prev else []
    done = {(r["file"], r["id"]) for r in out}
    for f, i in plan:
        if (f, i) in done:
            continue
        kind, line, src = apply(trees[f], TARGETS[f], i)
        path = os.path.join(work, f)
        open(path, "w").write(src)
        rT, tT, lT = run(T, work, env)
        rP, tP, lP = run(P, work, env)
        open(path, "w").write(ast.unparse(trees[f]))
        out.append({"file": f, "id": i, "op": kind, "line": line, "killed_by_repo_tests": rT != 0,
                    "killed_by_probe": rP != 0, "probe_out": lP, "tests_out": lT})
        print(f, i, kind, line, "T" if rT else "-", "P" if rP else "-", lP[:120], flush=True)
        json.dump({"baseline": base, "results": out}, open(os.path.join(OUT, "e5_l3_mutation.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
