"""
E3 -- Mutation analysis of the decision logic (test-suite adequacy).

Generates first-order mutants of the decision logic in pdp.py (functions
_evaluate, _build_context, _clearance_rank, _sensitivity_rank and the two rank
maps) with standard operators, writes each mutant into a THROW-AWAY COPY of the
backend, and runs two oracles:
  T  = the repository's own unit + conformance suites (tests/test_pdp.py,
       tests/test_conformance.py; Hypothesis installed), as shipped
  E1 = the bounded-exhaustive differential oracle (reduced domain, E1_FAST=1);
       survivors of E1-fast are re-run on the full E1 domain
The original repository is never written.

Operators: ROR (relational swap), LCR (and<->or), UOI (drop/insert `not`),
           MEM (in <-> not in), CRP (int constant +/-1, True<->False),
           EFF (allow(...) <-> deny(...) at a rule return), NEG (if C -> if not C)

Usage: python e3_mutation.py <backend> <work-dir> <out-dir> <python> <artifact-dir> [shard k/n]
"""
import ast, copy, json, os, shutil, subprocess, sys, time

BACKEND, WORK, OUT, PY, ART = sys.argv[1:6]
SHARD = sys.argv[6] if len(sys.argv) > 6 else "0/1"
K, NSH = map(int, SHARD.split("/"))
TARGET_FUNCS = {"_evaluate", "_build_context", "_clearance_rank", "_sensitivity_rank"}
TARGET_ASSIGN = {"_CLEARANCE_RANK", "_SENSITIVITY_RANK"}
SRC_REL = "app/services/pdp.py"

ROR = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE, ast.LtE: ast.Lt,
       ast.Gt: ast.GtE, ast.GtE: ast.Gt}


def _metadata_only(stack):
    """Trace labels, reason strings and the cache-hit counter cannot affect a decision."""
    for n in stack:
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "tr":
            return True
        if isinstance(n, ast.JoinedStr):
            return True
        if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Attribute) and n.target.attr == "_cache_hits":
            return True
        # audit context-snapshot construction (metadata recorded with the decision)
        if isinstance(n, ast.Assign) and any(
                (isinstance(t, ast.Name) and t.id == "snap") or
                (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == "snap")
                for t in n.targets):
            return True
        if isinstance(n, ast.If) and any(isinstance(c, ast.Constant) and c.value in ("tester", "surface")
                                          for c in ast.walk(n.test)):
            return True
    return False


def in_scope(stack):
    if _metadata_only(stack):
        return False
    for n in stack:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in TARGET_FUNCS:
            return True
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in TARGET_ASSIGN for t in n.targets):
            return True
    return False


def enumerate_points(tree):
    pts = []

    def walk(node, stack):
        st = stack + [node]
        if in_scope(st):
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
            if isinstance(node, ast.If):
                pts.append(("NEG", node, None))
            if isinstance(node, ast.Constant) and type(node.value) is int and not isinstance(node.value, bool):
                pts.append(("CRP+", node, None)); pts.append(("CRP-", node, None))
            if isinstance(node, ast.Constant) and isinstance(node.value, bool):
                pts.append(("CRPb", node, None))
            if (isinstance(node, ast.Return) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name) and node.value.func.id in ("allow", "deny")):
                pts.append(("EFF", node, None))
        for ch in ast.iter_child_nodes(node):
            walk(ch, st)
    walk(tree, [])
    return pts


def apply(tree, idx):
    t = copy.deepcopy(tree)
    kind, node, i = enumerate_points(t)[idx]
    if kind == "ROR":
        node.ops[i] = ROR[type(node.ops[i])]()
    elif kind == "MEM":
        node.ops[i] = ast.NotIn() if isinstance(node.ops[i], ast.In) else ast.In()
    elif kind == "LCR":
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif kind == "UOI-":
        node.op = ast.UAdd()  # replaced below by operand
    elif kind == "NEG":
        node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)
    elif kind == "CRP+":
        node.value += 1
    elif kind == "CRP-":
        node.value -= 1
    elif kind == "CRPb":
        node.value = not node.value
    elif kind == "EFF":
        node.value.func.id = "deny" if node.value.func.id == "allow" else "allow"
    src = ast.unparse(t)
    if kind == "UOI-":   # drop the `not`: replace '+(' pattern produced by UAdd with operand
        class Drop(ast.NodeTransformer):
            def visit_UnaryOp(self, n):
                self.generic_visit(n)
                return n.operand if isinstance(n.op, ast.UAdd) else n
        src = ast.unparse(ast.fix_missing_locations(Drop().visit(t)))
    return kind, getattr(node, "lineno", None), src


def run(cmd, cwd, env, timeout=600):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, round(time.time() - t0, 1), p.stdout[-400:]
    except subprocess.TimeoutExpired:
        return 124, timeout, "timeout"


def main():
    orig_src = open(os.path.join(BACKEND, SRC_REL)).read()
    tree = ast.parse(orig_src)
    pts = enumerate_points(tree)
    work = os.path.join(WORK, f"shard{K}")
    if os.path.exists(work):
        shutil.rmtree(work)
    shutil.copytree(BACKEND, work, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    env = dict(os.environ, SECRET_KEY="e3_harness_secret_key_32_chars_minimum", ENVIRONMENT="test",
               DATABASE_URL="postgresql+asyncpg://x:y@localhost:1/none", REDIS_URL="redis://localhost:1/0",
               PYTHONDONTWRITEBYTECODE="1")
    T_CMD = [PY, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-o", "log_cli=false",
             "tests/test_pdp.py", "tests/test_conformance.py"]
    E1_CMD = [PY, os.path.join(ART, "e1_differential.py"), work, os.path.join(WORK, "e1tmp")]
    target = os.path.join(work, SRC_REL)
    # baseline: unparsed original must pass both oracles
    open(target, "w").write(ast.unparse(tree))
    base_T = run(T_CMD, work, env)[0]
    base_E = run(E1_CMD, work, dict(env, E1_FAST="1", E1_ORACLE="1"))[0]
    results = []
    for idx in range(len(pts)):
        if idx % NSH != K:
            continue
        kind, line, src = apply(tree, idx)
        open(target, "w").write(src)
        rT, tT, _ = run(T_CMD, work, env)
        rE, tE, oE = run(E1_CMD, work, dict(env, E1_FAST="1", E1_ORACLE="1"))
        rEf = None
        if rE == 0:
            rEf, _, oE = run(E1_CMD, work, dict(env, E1_ORACLE="1"))
        results.append({"id": idx, "op": kind, "line": line,
                        "killed_by_existing_tests": rT != 0,
                        "killed_by_E1_fast": rE != 0,
                        "killed_by_E1_full": (rE != 0) or (rEf not in (0, None)),
                        "E1_out": oE.strip().splitlines()[-1] if oE.strip() else ""})
        print(idx, kind, line, "T" if rT else "-", "E" if (rE or rEf) else "-", flush=True)
    open(target, "w").write(orig_src)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, f"e3_mutation_shard{K}.json"), "w") as f:
        json.dump({"baseline_existing_tests_rc": base_T, "baseline_E1_rc": base_E,
                   "mutation_points_total": len(pts), "results": results}, f, indent=2)


if __name__ == "__main__":
    main()
