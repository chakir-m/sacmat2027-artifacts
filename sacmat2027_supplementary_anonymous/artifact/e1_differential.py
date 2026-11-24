"""
E1 -- Bounded-exhaustive differential conformance (rule/decision level).

Drives the REAL PolicyDecisionPoint (_evaluate and _build_context run unmodified)
over every world in a bounded attribute domain. Only data sources are stubbed:
  * PIP cache getters return the world's assignment/delegation action sets
    (a cache hit), so no DB query is issued;
  * policy-ID lookup returns {} (labels only);
  * audit persistence is skipped (_no_audit=True).
Each decision is compared with M_IMPL, R_PAPER and the intended invariants.

Usage:  python e1_differential.py <path-to-backend> <out-dir>
Application code is imported read-only and never modified.
"""
import asyncio, itertools, json, os, sys, time, uuid
from collections import Counter, defaultdict
from unittest.mock import MagicMock, AsyncMock

BACKEND, OUT = sys.argv[1], sys.argv[2]
os.environ.setdefault("SECRET_KEY", "e1_harness_secret_key_32_chars_minimum")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:y@localhost:1/none")
os.environ.setdefault("REDIS_URL", "redis://localhost:1/0")
sys.path.insert(0, BACKEND)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import structlog, logging
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from app.services import pdp as pdp_mod                       # noqa: E402
from app.services.pdp import PolicyDecisionPoint, AccessRequest  # noqa: E402
from app.models.models import Subject, Resource, Role, DecisionResult  # noqa: E402
from app.core.config import settings                          # noqa: E402
from semantics import (M_IMPL, R_PAPER, C9_FIX, decide_concrete,  # noqa: E402
                       invariants, ConcreteLogic, ALLOW)

ROLES = ["admin", "director", "division_manager", "analyst"]
SUBJ_DIV = ["D1", None]
DEPT_DIV = [(True, "D1"), (True, "D2"), (True, None), (False, "D3"), (False, None)]
CLEARANCE = ["normal", "elevated", "delegated"]
SENSITIVITY = ["public", "internal", "sensitive", "top_secret"]
GRANTABLE = ["read", "write", "download"]
REQUEST_ACTIONS = ["read", "write", "download", "delete"]
RISK = [0, 70]
CLR_RK = {"normal": 1, "elevated": 2, "delegated": 3}
SENS_RK = {"public": 0, "internal": 1, "sensitive": 2, "top_secret": 3}
if os.environ.get("E1_FAST") == "1":      # reduced domain, used only as a mutation oracle (E3)
    SUBJ_DIV = ["D1"]
    GRANTABLE = ["read", "write"]
    REQUEST_ACTIONS = ["read", "write", "delete"]
if os.environ.get("E1_EXT") == "1":       # WP1: role domain completed with custom roles
    ROLES = ROLES + ["custom"]            # builtin_type = None (admin-created role, audit_org.py)
    DEPT_DIV = DEPT_DIV + [(False, "D1")]  # cross-dept resource carrying the subject's division id
                                           # (only observation vectors wp1_coverage.py found missing)
OWNS = [False]
if os.environ.get("E1_OWN") == "1":       # phase 5: owner dimension (owner(o) == u), for v2's P_own
    OWNS = [False, True]
SUBSETS = [frozenset(c) for r in range(len(GRANTABLE) + 1)
           for c in itertools.combinations(GRANTABLE, r)]
THETA = settings.RISK_DENY_THRESHOLD
assert THETA == 70


class Env:
    def __init__(self, w, own=False):
        role, sdiv, same_dept, rdiv, clr, sens, A, D, risk = w
        self.own = own
        self.admin = role == "admin"
        self.dir = role == "director"
        self.dm = role == "division_manager"
        self.an = role == "analyst"
        self.same_dept = same_dept
        self.same_div_raw = (sdiv == rdiv)
        self.same_div = sdiv is not None and sdiv == rdiv
        self.sens_pos = SENS_RK[sens] > 0
        self.clr_lt_sens = CLR_RK[clr] < SENS_RK[sens]
        self.has_asg, self.has_del = bool(A), bool(D)
        self._A, self._D = A, D
        self.risk_high = risk >= THETA

    def asg(self, a): return a in self._A
    def dele(self, a): return a in self._D
    def is_read(self, a): return a == "read"
    def own_act(self, a): return a in ("read", "download")


def rule_of(name):
    if not name:
        return "NONE"
    if name.startswith("Platform Admin"):
        return "ADMIN"
    return name.split(" ")[0]


def build_subject(role, sdiv, clr, risk, ids):
    s = Subject()
    s.id = str(uuid.uuid4()); s.email = f"{s.id}@e1.test"; s.username = s.id
    s.full_name = role; s.hashed_password = "x"
    r = Role(); r.id = str(uuid.uuid4()); r.builtin_type = None if role == "custom" else role; r.name = role
    s.role = r; s.role_id = r.id
    s.department_id = ids["DA"]
    s.division_id = ids[sdiv] if sdiv else None
    s.status = "active"; s.is_platform_admin = role == "admin"
    s.clearance = clr
    s.failed_login_attempts = 5 if risk >= THETA else 0   # +40
    s.attributes = {}
    return s


def build_resource(same_dept, rdiv, sens, ids):
    o = Resource()
    o.id = str(uuid.uuid4()); o.name = "e1"
    o.department_id = ids["DA"] if same_dept else ids["DB"]
    o.division_id = ids[rdiv] if rdiv else None
    o.owner_id = str(uuid.uuid4()); o.sensitivity = sens
    o.is_active = True; o.tags = []; o.attributes = {}
    return o


CURRENT = {}

async def _get_asg(sid, rid): return sorted(CURRENT["A"])
async def _get_del(sid, rid): return sorted(CURRENT["D"])
async def _noop(*a, **k): return None


async def main():
    pdp_mod.pip_cache.get_assignment = _get_asg
    pdp_mod.pip_cache.get_delegation = _get_del
    pdp_mod.pip_cache.set_assignment = _noop
    pdp_mod.pip_cache.set_delegation = _noop
    db = MagicMock(); db.add = MagicMock(); db.flush = AsyncMock()
    pdp = PolicyDecisionPoint(db)
    pdp._load_policy_ids = AsyncMock(return_value={})

    ids = {"DA": "dept-A", "DB": "dept-B", "D1": "div-1", "D2": "div-2", "D3": "div-3"}
    ctx = {0: {"timestamp": "2026-01-05T10:00:00+00:00"},      # business hours
           70: {"timestamp": "2026-01-05T02:00:00+00:00"}}     # off hours (+30)

    subj_cache, res_cache = {}, {}
    L = ConcreteLogic
    n = 0
    agree_impl = agree_impl_rule = agree_paper = agree_fix = 0
    indeterminate = 0
    paper_diff = Counter(); paper_diff_reach = Counter()
    fix_diff = Counter()
    inv_viol = Counter(); inv_viol_reach = Counter(); inv_witness = {}
    rule_hist = Counter()
    by_risk = {}
    reach_total = 0
    t0 = time.time()

    for role, sdiv, (same_dept, rdiv), clr, sens, A, D, act, risk, own in itertools.product(
            ROLES, SUBJ_DIV, DEPT_DIV, CLEARANCE, SENSITIVITY, SUBSETS, SUBSETS,
            REQUEST_ACTIONS, RISK, OWNS):
        w = (role, sdiv, same_dept, rdiv, clr, sens, A, D, risk)
        reach = (D in (frozenset(), frozenset({"read"}))) and not (role == "division_manager" and sdiv is None)
        reach_total += reach
        sk = (role, sdiv, clr, risk)
        if sk not in subj_cache:
            subj_cache[sk] = build_subject(role, sdiv, clr, risk, ids)
        rk = (same_dept, rdiv, sens)
        if rk not in res_cache:
            res_cache[rk] = build_resource(same_dept, rdiv, sens, ids)
        s, o = subj_cache[sk], res_cache[rk]
        o.owner_id = s.id if own else "owner-elsewhere"
        CURRENT["A"], CURRENT["D"] = A, D
        res = await pdp.decide(AccessRequest(s.id, o.id, act, context=dict(ctx[risk]),
                                             _subject=s, _resource=o, _no_audit=True))
        n += 1
        if res.result == DecisionResult.INDETERMINATE:
            indeterminate += 1
        allow = res.result == DecisionResult.ALLOW
        rule = rule_of(res.applied_policy_name)
        rule_hist[rule] += 1
        e = Env(w, own)
        mi_eff, mi_rule = decide_concrete(M_IMPL, e, act)
        rp_eff, rp_rule = decide_concrete(R_PAPER, e, act)
        cf_eff, cf_rule = decide_concrete(C9_FIX, e, act)
        agree_impl += (mi_eff == ALLOW) == allow
        agree_impl_rule += (mi_rule == rule)
        agree_paper += (rp_eff == ALLOW) == allow
        agree_fix += (cf_eff == ALLOW) == allow
        if (rp_eff == ALLOW) != allow:
            key = f"paper:{rp_rule}/{rp_eff} vs impl:{rule}/{'allow' if allow else 'deny'}"
            paper_diff[key] += 1
            if reach:
                paper_diff_reach[key] += 1
        if (cf_eff == ALLOW) != allow:
            fix_diff[f"fix:{cf_rule}/{cf_eff} vs impl:{rule}"] += 1
        for name, ok in invariants(e, L, act, allow).items():
            if not ok:
                inv_viol[name] += 1
                if reach:
                    inv_viol_reach[name] += 1
                    size = len(A) + len(D)
                    if name not in inv_witness or size < inv_witness[name][0]:
                        inv_witness[name] = (size, {
                            "role": role, "subj_div": sdiv, "same_dept": same_dept,
                            "res_div": rdiv, "clearance": clr, "sensitivity": sens,
                            "A_asg": sorted(A), "A_del": sorted(D), "action": act,
                            "risk": risk, "owner": own, "decision": "allow" if allow else "deny",
                            "rule": rule})
        by_risk[(role, sdiv, same_dept, rdiv, clr, sens, A, D, act, own, risk)] = allow

    # P_ctx inertness: identical decision for risk 0 vs 70, all else equal
    inert_pairs = inert_equal = 0
    for k, v in by_risk.items():
        if k[-1] == 0:
            inert_pairs += 1
            inert_equal += v == by_risk[k[:-1] + (70,)]

    dt = time.time() - t0
    summary = {
        "worlds_evaluated": n,
        "api_reachable_worlds": reach_total,
        "runtime_s": round(dt, 1),
        "indeterminate": indeterminate,
        "agreement_vs_M_IMPL_decision": agree_impl,
        "agreement_vs_M_IMPL_rule": agree_impl_rule,
        "agreement_vs_R_PAPER_decision": agree_paper,
        "agreement_vs_C9_FIX_decision": agree_fix,
        "R_PAPER_disagreements_by_class": dict(paper_diff.most_common()),
        "R_PAPER_disagreements_api_reachable": dict(paper_diff_reach.most_common()),
        "C9_FIX_vs_impl_differences": dict(fix_diff.most_common()),
        "invariant_violations_all": dict(inv_viol),
        "invariant_violations_api_reachable": dict(inv_viol_reach),
        "invariant_witness_minimal": {k: v[1] for k, v in inv_witness.items()},
        "applied_rule_histogram": dict(rule_hist),
        "Pctx_inertness_pairs": inert_pairs,
        "Pctx_inertness_equal": inert_equal,
        "domain": {"roles": ROLES, "subj_div": [str(x) for x in SUBJ_DIV],
                   "dept_div": [list(map(str, x)) for x in DEPT_DIV],
                   "clearance": CLEARANCE, "sensitivity": SENSITIVITY,
                   "grantable_actions": GRANTABLE, "request_actions": REQUEST_ACTIONS,
                   "risk": RISK, "theta": THETA, "owner": OWNS},
    }
    if os.environ.get("E1_ORACLE") == "1":   # E3 mode: exit 1 iff the PDP deviates from M_IMPL
        ok = (agree_impl == n and agree_impl_rule == n and indeterminate == 0)
        print(f"E1_ORACLE agree={agree_impl}/{n} rule={agree_impl_rule}/{n} indet={indeterminate}")
        sys.exit(0 if ok else 1)
    os.makedirs(OUT, exist_ok=True)
    fname = "e1_summary_ext.json" if os.environ.get("E1_EXT") == "1" else "e1_summary.json"
    if os.environ.get("E1_OWN") == "1":
        fname = fname.replace(".json", "_own.json")
    with open(os.path.join(OUT, fname), "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(json.dumps({k: summary[k] for k in list(summary)[:8]}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
