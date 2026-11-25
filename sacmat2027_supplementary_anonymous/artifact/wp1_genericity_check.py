"""
WP1 -- Syntactic genericity check of the decision code (data-independence criterion).

Criterion G (checked on the AST of pdp.py, functions _evaluate and _build_context, plus the
rank helpers):
  every occurrence of a value of an *open* sort is used only through an allowed observation
    Dept, Div, Id : (in)equality / `is None` with another term of the same sort or None
                    (Id includes resource.owner_id since phase 5: the atom own = [owner(o) = u])
    Act           : membership `a in S` in a grant set, (in)equality with a string constant that is an
                    atom of obs (OBS_ACT_CONSTANTS = {"read"}); any other action constant is a violation
    ActSet        : membership right operand, truthiness / bool(), `is None` (cache miss),
                    copied (list()/alias/ctx entry), or stored/loaded through the PIP cache
    Risk (risk.score, risk.flags) : only `score >= RISK_DENY_THRESHOLD`, otherwise sinks
    Rank (clearance, sensitivity: finite enums, exhaustively enumerated in E1)
                  : passed to the rank tables _clearance_rank/_sensitivity_rank
  or flows only into a SINK that never reaches a branch condition:
    f-strings, the trace (tr), decision reason strings, the context snapshot `snap`,
    logging/metrics.
  and the sink variables (`snap`, `trace`) never occur in a branch condition.
Closed values (phase 5): an attribute of a closed sort may be read in the decision functions only if it is
represented in obs (CLOSED_OBS: role, clearance, sensitivity, platform-admin flag); the request context may only
be passed to the risk helper (whose result is compared with the threshold) or flow into sinks, including
branches whose body only writes sinks. Anything else is reported as a closed-value violation.
The result JSON is the certificate: every occurrence with its observation class, the accepted language, the
obs atoms and the action constants it admits.

If G holds, the decision is a function of the observation vector (Lemma 1 in the paper).
The script prints every occurrence with its classification and exits 1 on any violation.

Escape check: whenever a whole entity (`subject`, `resource`, `request`) is passed to a
callee, the callee must be one of the checked functions or a SINK (logging), or a helper whose
body never reads an open-sort attribute (checked: compute_risk_score in risk.py,
_obligations_for in pdp.py; their outputs affect only P_ctx's threshold test and obligations).

Usage: python wp1_genericity_check.py <path-to-pdp.py> <path-to-risk.py> <out-json>
"""
import ast, json, sys

SRC_PATH, RISK_PATH, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(SRC_PATH).read()
tree = ast.parse(src)
for n in ast.walk(tree):
    for c in ast.iter_child_nodes(n):
        c._parent = n

TARGET_FUNCS = {"_evaluate", "_build_context", "_clearance_rank", "_sensitivity_rank",
                "_load_subject", "_load_resource"}
ID_PARAMS = {"sid", "rid"}           # parameters of the two loaders
ENTITY = {"subject", "resource"}
ACTSET_ALIASES = {"assignment_actions", "delegation_actions", "cached_assign", "cached_deleg"}
SINK_CALLS = {"tr", "deny", "allow", "AccessDecisionResult", "PolicyTrace", "str"}
RANK_FUNCS = {"_clearance_rank", "_sensitivity_rank"}
CACHE_OBJ = "pip_cache"
SINK_VARS = {"snap", "trace"}
import os
# the action constants that obs represents (atom a = read); phase 5: v2's P_own adds a = download,
# passed as OBS_ACT=read,download (the obs of v2 also has the atom own = [owner(o) = u])
OBS_ACT_CONSTANTS = set(os.environ.get("OBS_ACT", "read").split(","))
CLOSED_OBS = {"clearance", "sensitivity", "is_platform_admin", "role", "builtin_type"}
RISK_HELPER = "compute_risk_score"


def sort_of(n):
    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
        v, a = n.value.id, n.attr
        if v in ENTITY and a == "department_id": return "Dept"
        if v in ENTITY and a == "division_id": return "Div"
        if v in ENTITY and a == "id": return "Id"
        if v == "resource" and a == "owner_id": return "Id"          # phase 5: owner(o), for P_own
        if v == "request" and a == "action": return "Act"
        if v == "request" and a in ("subject_id", "resource_id"): return "Id"
        if v in ("row", "deleg_row") and a in ("actions", "approved_actions"): return "ActSet"
        if v == "subject" and a == "clearance": return "Rank"
        if v == "resource" and a == "sensitivity": return "Rank"
        if v == "risk" and a in ("score", "flags"): return "Risk"
    if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id == "ctx":
        k = n.slice
        if isinstance(k, ast.Constant) and k.value in ("assignment_actions", "delegation_actions"):
            return "ActSet"
    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in ACTSET_ALIASES:
        return "ActSet"
    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in ID_PARAMS:
        return "Id"
    return None


def is_none(n): return isinstance(n, ast.Constant) and n.value is None
def is_str(n): return isinstance(n, ast.Constant) and isinstance(n.value, str)


def call_name(c):
    f = c.func
    if isinstance(f, ast.Name): return f.id
    if isinstance(f, ast.Attribute):
        base = f.value.id if isinstance(f.value, ast.Name) else "?"
        return f"{base}.{f.attr}"
    return "?"


def classify(n, s):
    """Return (class, detail) for one occurrence n of sort s."""
    child, p = n, n._parent
    # climb through value-preserving wrappers
    while True:
        if isinstance(p, ast.IfExp) and child is not p.test:
            child, p = p, p._parent; continue
        if isinstance(p, ast.BoolOp) and not isinstance(p._parent, (ast.If, ast.IfExp, ast.While, ast.UnaryOp)) \
                and s == "ActSet":
            # `row and row.actions` used as a value (truthiness guarded copy)
            child, p = p, p._parent; continue
        break
    # inside an f-string / formatted value -> sink
    q = p
    while q is not None and not isinstance(q, ast.FunctionDef | ast.AsyncFunctionDef):
        if isinstance(q, (ast.JoinedStr, ast.FormattedValue)):
            return "SINK", "f-string"
        q = getattr(q, "_parent", None)
    if isinstance(p, ast.Compare):
        ops = p.ops; others = [x for x in [p.left] + p.comparators if x is not child]
        if all(isinstance(o, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)) for o in ops):
            if all(sort_of(x) == s or is_none(x) or (s == "Act" and is_str(x) and x.value in OBS_ACT_CONSTANTS) for x in others):
                return "OBS", f"{s} {'/'.join(type(o).__name__ for o in ops)}"
            # SQLAlchemy column equality inside select(): Column == entity id
            if s == "Id" and all(isinstance(x, ast.Attribute) and isinstance(x.value, ast.Name)
                                 and x.value.id in ("ResourceAssignment", "Delegation", "Subject", "Resource")
                                 and x.attr in ("id", "subject_id", "resource_id", "requester_id")
                                 for x in others):
                return "OBS", "Id == column (SQL key lookup)"
        if s == "Risk" and len(ops) == 1 and isinstance(ops[0], (ast.GtE, ast.Gt, ast.Lt, ast.LtE)) \
                and all(isinstance(x, ast.Attribute) and x.attr == "RISK_DENY_THRESHOLD" for x in others):
            return "OBS", "risk score vs threshold"
        if all(isinstance(o, (ast.In, ast.NotIn)) for o in ops):
            if s == "Act" and p.left is child and all(sort_of(x) == "ActSet" for x in p.comparators):
                return "OBS", "Act in ActSet"
            if s == "ActSet" and child in p.comparators and sort_of(p.left) == "Act":
                return "OBS", "Act in ActSet"
        return "VIOLATION", f"comparison {ast.unparse(p)}"
    if isinstance(p, ast.Call):
        cn = call_name(p)
        if s == "ActSet" and cn == "bool": return "OBS", "ActSet non-empty"
        if s == "ActSet" and cn == "list":
            return classify_flow(p, s)
        if s == "Rank" and cn in RANK_FUNCS: return "OBS", f"rank table {cn}"
        if cn.startswith(CACHE_OBJ + "."): return "OBS", f"PIP cache key/value ({cn})"
        if s == "Id" and cn in ("self._load_subject", "self._load_resource"):
            return "OBS", f"Id key lookup ({cn}, checked below)"
        if cn in SINK_CALLS: return "SINK", f"call {cn}"
        if cn.startswith("logger."): return "SINK", "log"
        return "VIOLATION", f"call {cn}({ast.unparse(p)[:60]})"
    if isinstance(p, (ast.If, ast.While)) and child is p.test and s == "ActSet":
        return "OBS", "ActSet non-empty (branch)"
    if isinstance(p, ast.BoolOp) and s == "ActSet":
        return "OBS", "ActSet non-empty (bool-op)"
    if isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not) and s == "ActSet":
        return "OBS", "ActSet non-empty (not)"
    if isinstance(p, ast.Dict) or isinstance(p, ast.Assign):
        return classify_flow(child, s)
    return "VIOLATION", f"{type(p).__name__}: {ast.unparse(p)[:60]}"


def classify_flow(node, s):
    """Value flows into a container/variable: allowed if into a sink or a known alias."""
    p = node._parent
    while isinstance(p, ast.IfExp) and node is not p.test:
        node, p = p, p._parent
    if isinstance(p, ast.Assign):
        tg = p.targets[0]
        if isinstance(tg, ast.Name) and tg.id in ACTSET_ALIASES: return "FLOW", f"alias {tg.id}"
        if isinstance(tg, ast.Subscript) and isinstance(tg.value, ast.Name) and tg.value.id in SINK_VARS:
            return "SINK", f"{tg.value.id}[...]"
        return "VIOLATION", f"assignment to {ast.unparse(tg)}"
    if isinstance(p, ast.AnnAssign) and isinstance(p.target, ast.Name) and p.target.id in ACTSET_ALIASES:
        return "FLOW", f"alias {p.target.id}"
    if isinstance(p, ast.Dict):
        key = p.keys[p.values.index(node)] if node in p.values else None
        k = key.value if isinstance(key, ast.Constant) else None
        holder = p._parent
        if isinstance(holder, ast.Assign) and isinstance(holder.targets[0], ast.Name) \
                and holder.targets[0].id in SINK_VARS:
            return "SINK", f"{holder.targets[0].id}['{k}']"
        if isinstance(holder, ast.Return) and k in ("assignment_actions", "delegation_actions"):
            return "FLOW", f"ctx['{k}']"
        return "VIOLATION", f"dict entry {k}"
    if isinstance(p, ast.Call):
        return classify(p, s) if call_name(p) == "list" else ("VIOLATION", ast.unparse(p)[:60])
    return "VIOLATION", f"flow into {type(p).__name__}"


def sink_vars_in_conditions(fn):
    bad = []
    for n in ast.walk(fn):
        tests = []
        if isinstance(n, (ast.If, ast.While, ast.IfExp, ast.Assert)): tests = [n.test]
        if isinstance(n, ast.comprehension): tests = n.ifs
        for t in tests:
            for m in ast.walk(t):
                if isinstance(m, ast.Name) and m.id in SINK_VARS:
                    bad.append((n.lineno, ast.unparse(t)))
    return bad


occ, viol, sinkcond = [], [], []
funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name in TARGET_FUNCS]
assert {f.name for f in funcs} == TARGET_FUNCS, {f.name for f in funcs}
for fn in funcs:
    sinkcond += [(fn.name, *b) for b in sink_vars_in_conditions(fn)]
    for n in ast.walk(fn):
        s = sort_of(n)
        if s is None:
            continue
        # skip the inner node of an Attribute chain already counted (e.g. `row.actions` once)
        cls, det = classify(n, s)
        rec = {"func": fn.name, "line": n.lineno, "sort": s, "expr": ast.unparse(n), "class": cls, "detail": det}
        occ.append(rec)
        if cls == "VIOLATION":
            viol.append(rec)

# ---- escape check: whole entities passed to callees ----
OPEN_ATTRS = {"department_id", "division_id", "id", "action", "subject_id", "resource_id", "owner_id"}
HELPERS = {"compute_risk_score": ast.parse(open(RISK_PATH).read()), "_obligations_for": tree}
escapes, helper_reads = [], []
for fn in funcs:
    for c in ast.walk(fn):
        if not isinstance(c, ast.Call):
            continue
        whole = [a.id for a in c.args if isinstance(a, ast.Name) and a.id in ENTITY | {"request"}]
        if not whole:
            continue
        cn = call_name(c).replace("self.", "")
        ok = cn in TARGET_FUNCS or cn in HELPERS or cn.startswith("logger.")
        escapes.append({"func": fn.name, "line": c.lineno, "callee": cn, "entities": whole, "allowed": ok})
for hname, htree in HELPERS.items():
    hdef = next(n for n in ast.walk(htree) if isinstance(n, ast.FunctionDef) and n.name == hname)
    for n in ast.walk(hdef):
        if isinstance(n, ast.Attribute) and n.attr in OPEN_ATTRS:
            helper_reads.append({"helper": hname, "line": n.lineno, "expr": ast.unparse(n)})
        if isinstance(n, ast.Call) and call_name(n) in ("getattr",) and len(n.args) > 1 \
                and isinstance(n.args[1], ast.Constant) and n.args[1].value in OPEN_ATTRS:
            helper_reads.append({"helper": hname, "line": n.lineno, "expr": ast.unparse(n)})
bad_escapes = [e for e in escapes if not e["allowed"]]


def _sink_only(stmts):
    ok = True
    for st in stmts:
        if isinstance(st, ast.Assign) and all(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                                              and t.value.id in SINK_VARS for t in st.targets):
            continue
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and call_name(st.value) in SINK_CALLS:
            continue
        ok = False
    return ok


def _context_use_ok(n):
    """request.context may reach the risk helper, a sink, or the test of a sink-only branch."""
    q = n
    while q is not None:
        p = getattr(q, "_parent", None)
        if p is None: return False
        if isinstance(p, ast.Call) and call_name(p) == RISK_HELPER: return True
        if isinstance(p, ast.If) and q is p.test: return _sink_only(p.body) and _sink_only(p.orelse)
        if isinstance(p, ast.Assign) and all(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                                             and t.value.id in SINK_VARS for t in p.targets): return True
        if isinstance(p, (ast.stmt,)): return False
        q = p
    return False


closed_viol = []
for fn in funcs:
    for n in ast.walk(fn):
        if not isinstance(n, ast.Attribute) or not isinstance(n.value, ast.Name): continue
        v, a = n.value.id, n.attr
        if v in ENTITY and a not in OPEN_ATTRS and a not in CLOSED_OBS:
            closed_viol.append({"func": fn.name, "line": n.lineno, "expr": ast.unparse(n), "why": "closed attribute not in obs"})
        if v == "request" and a == "context" and not _context_use_ok(n):
            closed_viol.append({"func": fn.name, "line": n.lineno, "expr": ast.unparse(n._parent)[:70],
                                "why": "context outside risk helper and sinks"})

summary = {}
for r in occ:
    summary.setdefault(r["sort"], {}).setdefault(r["class"], 0)
    summary[r["sort"]][r["class"]] += 1
res = {"file": SRC_PATH, "functions": sorted(TARGET_FUNCS), "occurrences": len(occ),
       "by_sort_and_class": summary, "violations": viol, "sink_vars_in_conditions": sinkcond,
       "escapes": escapes, "helper_open_sort_reads": helper_reads,
       "closed_value_violations": closed_viol,
       "accepted_language": {"open_sorts": ["Dept", "Div", "Id", "Act", "ActSet"], "obs_act_constants": sorted(OBS_ACT_CONSTANTS),
                             "closed_obs": sorted(CLOSED_OBS), "risk_helper": RISK_HELPER, "sinks": sorted(SINK_VARS | SINK_CALLS)},
       "criterion_G_holds": not viol and not sinkcond and not bad_escapes and not helper_reads and not closed_viol,
       "detail": occ}
json.dump(res, open(OUT, "w"), indent=2)
print(json.dumps({k: res[k] for k in ("occurrences", "by_sort_and_class", "escapes",
                                      "helper_open_sort_reads", "closed_value_violations", "criterion_G_holds")}, indent=1))
for v in viol:
    print("VIOLATION", v)
for s in sinkcond:
    print("SINK-IN-CONDITION", s)
sys.exit(0 if res["criterion_G_holds"] else 1)
