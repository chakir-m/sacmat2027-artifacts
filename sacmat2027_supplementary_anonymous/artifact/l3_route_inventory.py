"""
L3 route inventory generated from the framework's routing table (phase 6).

The L3 check (Algorithm 2) starts from a list of the routes that return protected content, change a grant or
open a session. In phases 3-5 that list was built by reading the code. This script builds it mechanically:

 1. It imports the application and enumerates FastAPI's routing table (every APIRoute, plain Route and Mount).
 2. For every route endpoint it computes, over the AST of app/api/*.py, the set of functions the endpoint can
    reach by name (an over-approximation: calls are resolved by name, not by type), and records
      - which decision procedures are reachable: the PDP (`decide`, `_pep_gate`), the document read procedure
        (`_assert_can_read`, `_doc_read_allowed`, `_can_read_document`, `_check_delegation_read`), the document
        write/manage procedures, role guards and the internal-call guard, and the FastAPI dependencies;
      - whether it can touch protected objects (Resource, Document and the document's sub-objects), return
        content (file or document body), or change a grant (ResourceAssignment, Delegation,
        DocumentCollaborator in a non-GET route).
 3. It extracts the URL templates that the L3 harnesses send (e5_l3_probe.py, e2_collab.py, e2_mixed.py,
    e2_runtime.py) and marks each route as probed or not.

The output lists every in-scope route (protected object or grant change) with its decision procedures and
whether a probe exercises it. It does not decide whether an unprobed route is correct: that is the manual
step, now done route by route on a complete list.

Usage: python l3_route_inventory.py <backend> <artifact-dir> <out-json>
"""
import ast, json, os, re, sys
from collections import defaultdict

BACKEND, ART, OUT = sys.argv[1:4]
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "inventory_harness_secret_key_32_chars_min")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:y@localhost:1/none")
os.environ.setdefault("REDIS_URL", "redis://localhost:1/0")
sys.path.insert(0, BACKEND)
import logging, structlog                                                    # noqa: E402
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
logging.disable(logging.CRITICAL)
from app.main import app                                                     # noqa: E402
from fastapi.routing import APIRoute                                         # noqa: E402

PDP = {"decide", "_pep_gate"}
DOC_READ = {"_assert_can_read", "_doc_read_allowed", "_can_read_document", "_check_delegation_read"}
DOC_WRITE = {"_can_write_document", "_can_write_or_collaborate", "_can_delete_document", "_can_manage_collaborators",
             "_can_reopen_directly"}
ROLE = {"_require_admin_or_director", "_require_admin", "_require_policy_manager", "_require_admin_or_dept_director",
        "is_platform_admin", "_require_oidc"}
INTERNAL = {"_require_internal"}
ADMIN_DEPS = {"get_admin_subject"}
OBJECTS = {"Resource", "Document", "DocumentVersion", "DocumentComment", "DocumentTask", "DocumentLink",
           "DocumentSignature", "DocumentFolder", "DocumentSpace", "DocumentReopenRequest", "WorkflowStep"}
CONTENT = {"content_json", "FileResponse", "StreamingResponse", "file_path", "read_file", "get_file", "open_file",
           "download_file", "content_html", "content_text"}
GRANTS = {"ResourceAssignment", "Delegation", "DocumentCollaborator"}

# --- functions of app/api and the names each one references / calls -------------------------------------
defs = {}          # name -> list of (module, node)
api_dir = os.path.join(BACKEND, "app", "api")
for fn in sorted(os.listdir(api_dir)):
    if fn.endswith(".py"):
        mod = "app.api." + fn[:-3]
        tree = ast.parse(open(os.path.join(api_dir, fn)).read())
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(n.name, []).append((mod, n))


def refs(node):
    calls, names = set(), set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            calls.add(f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else "")
        if isinstance(n, ast.Name):
            names.add(n.id)
        elif isinstance(n, ast.Attribute):
            names.add(n.attr)
    return calls, names


REFS = {}
for name, lst in defs.items():
    c, nm = set(), set()
    for _, node in lst:
        a, b = refs(node); c |= a; nm |= b
    REFS[name] = (c, nm)


def closure(start):
    seen, todo = set(), [start]
    calls, names = set(), set()
    while todo:
        f = todo.pop()
        if f in seen or f not in REFS:
            continue
        seen.add(f)
        c, nm = REFS[f]
        calls |= c; names |= nm
        todo += [x for x in c if x in REFS]
    return seen, calls, names


def deps(dependant, acc=None):
    acc = set() if acc is None else acc
    for d in dependant.dependencies:
        if d.call is not None:
            acc.add(getattr(d.call, "__name__", type(d.call).__name__))
        deps(d, acc)
    return acc


# --- URL templates sent by the L3 harnesses ---------------------------------------------------------------
probe_urls = set()
for fn in ("e5_l3_probe.py", "e2_collab.py", "e2_mixed.py", "e2_runtime.py", "e7_cache_ops.py"):
    p = os.path.join(ART, fn)
    if os.path.exists(p):
        txt = open(p).read()
        for q in ('"', "'"):          # f-strings: the URL runs to the closing quote of the literal
            for m in re.finditer(r'f' + q + r'\{API\}(/[^' + q + r'?]*)', txt):
                probe_urls.add(re.sub(r"\{[^{}]*(\[[^]]*\])?[^{}]*\}", "{x}", m.group(1)))
probe_res = [re.compile("^" + re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(u)) + "$") for u in probe_urls]
PREFIX = "/api/v1"


def probed(path):
    if not path.startswith(PREFIX):
        return False
    tmpl = path[len(PREFIX):]
    # a route template matches a probed URL if both have the same literal segments
    concrete = re.sub(r"\{[^}]*\}", "X", tmpl)
    return any(r.match(concrete) for r in probe_res) or tmpl in probe_urls


rows = []
other = []
for r in app.routes:
    if not isinstance(r, APIRoute):
        other.append({"type": type(r).__name__, "path": getattr(r, "path", None), "name": getattr(r, "name", None)})
        continue
    ep = r.endpoint.__name__
    seen, calls, names = closure(ep)
    allnames = calls | names
    methods = sorted(r.methods - {"HEAD", "OPTIONS"})
    row = {"path": r.path, "methods": methods, "endpoint": f"{r.endpoint.__module__}.{ep}",
           "dependencies": sorted(deps(r.dependant)),
           "pdp": bool(allnames & PDP), "doc_read": sorted(allnames & DOC_READ), "doc_write": sorted(allnames & DOC_WRITE),
           "role_guard": sorted((allnames & ROLE) | {d for d in deps(r.dependant) if d in ADMIN_DEPS}),
           "internal_guard": bool(allnames & INTERNAL),
           "objects": sorted(allnames & OBJECTS), "content": sorted(allnames & CONTENT),
           "grant_change": sorted(allnames & GRANTS) if methods != ["GET"] else [],
           "probed": probed(r.path)}
    row["in_scope"] = bool(row["objects"] or row["content"] or row["grant_change"])
    rows.append(row)

scope = [x for x in rows if x["in_scope"]]
summary = {
    "api_routes": len(rows), "other_routes": other,
    "in_scope": len(scope),
    "in_scope_probed": sum(x["probed"] for x in scope),
    "in_scope_by_module": {m: sum(1 for x in scope if x["endpoint"].startswith(m + "."))
                           for m in sorted({x["endpoint"].rsplit(".", 1)[0] for x in scope})},
    "in_scope_with_pdp": sum(x["pdp"] for x in scope),
    "in_scope_with_doc_read": sum(bool(x["doc_read"]) for x in scope),
    "in_scope_with_no_decision_procedure": [x["methods"][0] + " " + x["path"] for x in scope
                                            if not (x["pdp"] or x["doc_read"] or x["doc_write"] or x["role_guard"]
                                                    or x["internal_guard"])],
    "in_scope_unprobed": [x["methods"][0] + " " + x["path"] for x in scope if not x["probed"]],
    "probe_url_templates": sorted(probe_urls),
}
json.dump({"summary": summary, "routes": rows}, open(OUT, "w"), indent=1)
print(json.dumps({k: v for k, v in summary.items() if k not in ("probe_url_templates", "other_routes",
                                                               "in_scope_unprobed")}, indent=1))
