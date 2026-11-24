"""
WP7 -- Sensitivity of the verdicts to the two documented conflicts.

The snapshot's own documents disagree on two points:
  (C1) whether a delegation suffices for an analyst
       CLAUDE.md / README "hard invariant": "analyst access <-> assigned or delegated"
       vs. P5 description (seed.py, CLAUDE.md, README): "role=Analyst AND Assigned(u,o)=0 => deny"
  (C2) where the risk rule sits and what it means
       seed.py P_ctx description: "Denies access when the computed risk score ... meets or exceeds
       the configured threshold" (priority 60);  README table: priority 55;
       original manuscript Def. P_ctx: "evaluated after all structural allow/deny rules".

For each conflict we evaluate BOTH readings, for the implementation transcription M_IMPL,
for the README placement of P_ctx (M_README, priority 55), and for the
repaired chain C9_FIX, with z3 (unbounded) and on the E1 bounded world space (counts).

Usage: python wp7_alt_readings.py <out-dir>
Imports no application code.
"""
import itertools, json, os, sys
import z3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from semantics import M_IMPL, C9_FIX, ConcreteLogic, decide_concrete, ALLOW, _pclass
from e6_smt import Z3Env, Z3L, decision, check

OUT = sys.argv[1]

# README lists P6=50 and P_ctx=55, so its priority order P5(45) < P6(50) < P_ctx(55) < P7(99)
# should coincide with seed.py's (P_ctx=60). Encoded from the priorities, not assumed.
PRIO_SEED = {"ADMIN": 0, "P1": 10, "P_class": 15, "P2": 20, "P3": 30, "P4": 40, "P5": 45,
             "P6": 50, "P_ctx": 60, "P7": 99}
PRIO_README = dict(PRIO_SEED, P_ctx=55)


def ordered(chain, prio):
    return sorted(chain, key=lambda r: prio[r[0]])


M_SEED = ordered(M_IMPL, PRIO_SEED)
M_README = ordered(M_IMPL, PRIO_README)
assert [r[0] for r in M_SEED] == [r[0] for r in M_IMPL]
CHAINS = {"M_IMPL(seed prio)": M_SEED, "M_IMPL(README prio)": M_README, "C9_FIX": C9_FIX}
ALLOW_RULES_IMPL = [r for r in M_IMPL if r[1] == ALLOW]


def reqs(e, L, a, allow):
    imp = lambda p, q: L.Or(L.Not(p), q)
    na = L.Not(e.admin)
    pcl = _pclass(e, L, lambda e: e.same_div)
    some_structural_allow = L.Or(*[g(e, L, a) for rid, eff, g in ALLOW_RULES_IMPL if rid != "ADMIN"])
    return {
        # C1, reading A (hard invariant, adopted in the paper)
        "R4_delegation_suffices":
            imp(L.And(na, e.an, e.dele(a), L.Not(e.risk_high), L.Not(pcl)), allow),
        # C1, reading B (P5 description taken literally)
        "R4alt_P5_literal_no_assignment_deny":
            imp(L.And(na, e.an, L.Not(e.has_asg)), L.Not(allow)),
        # C2, reading A (P_ctx description: risk denies)
        "R6_risk_denies":
            imp(L.And(na, e.risk_high), L.Not(allow)),
        # C2, reading B (manuscript ordering: risk denies only requests no structural rule allows)
        "R6alt_risk_denies_only_undecided":
            imp(L.And(na, e.risk_high, L.Not(some_structural_allow)), L.Not(allow)),
    }


# ---------------- z3 (unbounded) ----------------
def run_z3():
    from e6_smt import Act
    a = z3.Const("a", Act)
    out = {}
    for cname, chain in CHAINS.items():
        e = Z3Env("")
        allow, _ = decision(chain, e, a)
        for name, f in reqs(e, Z3L, a, allow).items():
            out[f"{cname}|api|{name}"] = check(f, [e.domain, e.wf, e.api], e, a)
        e_hi, e_lo = Z3Env("", z3.BoolVal(True)), Z3Env("", z3.BoolVal(False))
        hi, _ = decision(chain, e_hi, a); lo, _ = decision(chain, e_lo, a)
        out[f"{cname}|api|Pctx_inert"] = check(hi == lo, [e_hi.domain, e_hi.wf, e_hi.api], e_hi, a)
    return out


# ---------------- bounded counts (E1 world space, API-reachable) ----------------
ROLES = ["admin", "director", "division_manager", "analyst"]
SUBJ_DIV = ["D1", None]
DEPT_DIV = [(True, "D1"), (True, "D2"), (True, None), (False, "D3"), (False, None)]
CLR_RK = {"normal": 1, "elevated": 2, "delegated": 3}
SENS_RK = {"public": 0, "internal": 1, "sensitive": 2, "top_secret": 3}
GRANTABLE = ["read", "write", "download"]
REQ = ["read", "write", "download", "delete"]
SUBSETS = [frozenset(c) for r in range(4) for c in itertools.combinations(GRANTABLE, r)]


class Env:
    def __init__(self, role, sdiv, same_dept, rdiv, clr, sens, A, D, risk):
        self.admin, self.dir = role == "admin", role == "director"
        self.dm, self.an = role == "division_manager", role == "analyst"
        self.same_dept = same_dept
        self.same_div_raw = sdiv == rdiv
        self.same_div = sdiv is not None and sdiv == rdiv
        self.sens_pos = SENS_RK[sens] > 0
        self.clr_lt_sens = CLR_RK[clr] < SENS_RK[sens]
        self.has_asg, self.has_del = bool(A), bool(D)
        self._A, self._D = A, D
        self.risk_high = risk
        self.own = False                      # no owner dimension here (bounded counts as before)

    def own_act(self, a): return a in ("read", "download")
    def asg(self, a): return a in self._A
    def dele(self, a): return a in self._D
    def is_read(self, a): return a == "read"


def run_bounded():
    counts = {c: {} for c in CHAINS}
    n = 0
    for role, sdiv, (sd, rdiv), clr, sens, A, D, risk, act in itertools.product(
            ROLES, SUBJ_DIV, DEPT_DIV, CLR_RK, SENS_RK, SUBSETS, SUBSETS, (False, True), REQ):
        if D not in (frozenset(), frozenset({"read"})) or (role == "division_manager" and sdiv is None):
            continue                                   # API-reachable worlds only
        n += 1
        e = Env(role, sdiv, sd, rdiv, clr, sens, A, D, risk)
        for cname, chain in CHAINS.items():
            allow = decide_concrete(chain, e, act)[0] == ALLOW
            for name, ok in reqs(e, ConcreteLogic, act, allow).items():
                if not ok:
                    counts[cname][name] = counts[cname].get(name, 0) + 1
    return n, counts


if __name__ == "__main__":
    z = run_z3()
    n, c = run_bounded()
    os.makedirs(OUT, exist_ok=True)
    json.dump({"api_reachable_worlds": n, "violations_api_reachable": c, "z3": z},
              open(os.path.join(OUT, "wp7_alt_readings.json"), "w"), indent=2)
    print("API-reachable worlds:", n)
    for k, v in z.items():
        print(f"{k:58s} {v['result']}")
    print(json.dumps(c, indent=1))
