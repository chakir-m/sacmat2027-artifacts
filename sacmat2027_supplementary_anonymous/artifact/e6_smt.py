"""
E6 -- SMT verification of CHAIN-9 properties (z3).

Encodes M_IMPL, R_PAPER and C9_FIX from semantics.py symbolically. Departments,
divisions and actions are UNINTERPRETED sorts and grant sets are arbitrary
predicates, so a PROVED result holds for any number of departments, divisions
and actions (not only the bounded E1 domain). E1 separately shows that M_IMPL
coincides with the real PDP on all 245,760 bounded worlds.

Usage: python e6_smt.py <out-dir>
"""
import json, os, sys, time
import z3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from semantics import M_IMPL, R_PAPER, C9_FIX, invariants, ALLOW

OUT = sys.argv[1]
Dept = z3.DeclareSort("Dept"); Div = z3.DeclareSort("Div"); Act = z3.DeclareSort("Act")
OptDiv = z3.Datatype("OptDiv"); OptDiv.declare("none"); OptDiv.declare("some", ("val", Div))
OptDiv = OptDiv.create()
Role = z3.Datatype("Role")
EXT = os.environ.get("E6_EXT") == "1"          # WP1: add custom roles (builtin_type = None)
for r in ("admin", "director", "dm", "analyst") + (("custom",) if EXT else ()):
    Role.declare(r)
Role = Role.create()
READ = z3.Const("READ", Act)
DOWNLOAD = z3.Const("DOWNLOAD", Act)     # phase 5: action constant of P_own (read, download)


class Z3L:
    And = staticmethod(lambda *xs: z3.And(*xs))
    Or = staticmethod(lambda *xs: z3.Or(*xs))
    Not = staticmethod(z3.Not)
    TRUE = z3.BoolVal(True)


class Z3Env:
    def __init__(self, tag, risk_high=None):
        self.role = z3.Const(f"role{tag}", Role)
        self.du, self.do = z3.Const("du", Dept), z3.Const("do", Dept)
        self.divu, self.divo = z3.Const("divu", OptDiv), z3.Const("divo", OptDiv)
        self.clr, self.sens = z3.Int("clr"), z3.Int("sens")
        self.A = z3.Function("Asg", Act, z3.BoolSort())
        self.D = z3.Function("Del", Act, z3.BoolSort())
        x = z3.Const("x", Act)
        self.admin = self.role == Role.admin
        self.dir = self.role == Role.director
        self.dm = self.role == Role.dm
        self.an = self.role == Role.analyst
        self.same_dept = self.du == self.do
        self.same_div_raw = self.divu == self.divo
        self.same_div = z3.And(OptDiv.is_some(self.divu), self.divu == self.divo)
        self.sens_pos = self.sens > 0
        self.clr_lt_sens = self.clr < self.sens
        self.has_asg = z3.Exists([x], self.A(x))
        self.has_del = z3.Exists([x], self.D(x))
        self.risk_high = z3.Bool(f"risk_high{tag}") if risk_high is None else risk_high
        self.own = z3.Bool("own")                                   # owner(o) == u
        self.domain = z3.And(self.clr >= 1, self.clr <= 3, self.sens >= 0, self.sens <= 3,
                             READ != DOWNLOAD)
        self.wf = z3.ForAll([x], z3.Implies(self.D(x), x == READ))   # delegation workflow invariant
        self.api = z3.Implies(self.dm, OptDiv.is_some(self.divu))    # PAP: managers have a division

    def asg(self, a): return self.A(a)
    def dele(self, a): return self.D(a)
    def is_read(self, a): return a == READ
    def own_act(self, a): return z3.Or(a == READ, a == DOWNLOAD)


def decision(chain, e, a):
    """Nested If over the first-match chain; returns (allow:Bool, rule:String)."""
    allow = z3.BoolVal(False); rule = z3.StringVal("NONE")
    for rid, eff, guard in reversed(chain):
        g = guard(e, Z3L, a)
        allow = z3.If(g, z3.BoolVal(eff == ALLOW), allow)
        rule = z3.If(g, z3.StringVal(rid), rule)
    return allow, rule


def check(goal, assumptions, e, a, timeout_ms=60000):
    s = z3.Solver(); s.set("timeout", timeout_ms)
    s.add(*assumptions); s.add(z3.Not(goal))
    t0 = time.time(); r = s.check(); dt = round(time.time() - t0, 3)
    if r == z3.unsat:
        return {"result": "PROVED", "time_s": dt}
    if r == z3.sat:
        m = s.model()
        ev = lambda t: str(m.eval(t, model_completion=True))
        return {"result": "COUNTEREXAMPLE", "time_s": dt, "witness": {
            "role": ev(e.role), "same_dept": ev(e.same_dept), "same_div": ev(e.same_div),
            "same_div_raw": ev(e.same_div_raw), "clr": ev(e.clr), "sens": ev(e.sens),
            "asg(a)": ev(e.A(a)), "del(a)": ev(e.D(a)), "has_asg": ev(e.has_asg),
            "has_del": ev(e.has_del), "a==READ": ev(a == READ), "a==DOWNLOAD": ev(a == DOWNLOAD),
            "own": ev(e.own), "risk_high": ev(e.risk_high)}}
    return {"result": "UNKNOWN", "time_s": dt, "reason": s.reason_unknown()}


def main():
    a = z3.Const("a", Act)
    results = {}
    for cname, chain in (("M_IMPL", M_IMPL), ("R_PAPER", R_PAPER), ("C9_FIX", C9_FIX)):
        e = Z3Env("")
        allow, rule = decision(chain, e, a)
        for scope, assm in (("all", [e.domain]), ("api", [e.domain, e.wf, e.api])):
            for name, inv in invariants(e, Z3L, a, allow).items():
                results[f"{cname}|{scope}|{name}"] = check(inv, assm, e, a)
        # P_ctx inertness: allow decision independent of the risk signal
        e_hi, e_lo = Z3Env("", z3.BoolVal(True)), Z3Env("", z3.BoolVal(False))
        al_hi, _ = decision(chain, e_hi, a); al_lo, _ = decision(chain, e_lo, a)
        results[f"{cname}|all|Pctx_decision_inert"] = check(al_hi == al_lo, [e_hi.domain], e_hi, a)
    # Equivalence of the manuscript chain and the implementation (API scope)
    e = Z3Env("")
    al_i, _ = decision(M_IMPL, e, a); al_p, _ = decision(R_PAPER, e, a)
    results["EQUIV|api|R_PAPER==M_IMPL"] = check(al_i == al_p, [e.domain, e.wf, e.api], e, a)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "e6_smt_ext.json" if EXT else "e6_smt.json"), "w") as f:
        json.dump({"z3_version": z3.get_version_string(), "results": results}, f, indent=2)
    for k, v in results.items():
        print(f"{k:62s} {v['result']:15s} {v['time_s']}s")


if __name__ == "__main__":
    main()
