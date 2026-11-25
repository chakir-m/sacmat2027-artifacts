"""
WP5 -- CHAIN-9 in Cedar.

The SAME guard definitions used for differential testing (Python booleans) and proofs (z3)
are interpreted a third time, as Cedar expression strings, and compiled into a Cedar policy
set. Cedar has no first-applicable combinator (forbid overrides permit, default deny), so a
first-applicable chain r_1..r_n is compiled as
    permit r_i  when g_i && !(g_j for every earlier DENY rule j)
    forbid r_k  when g_k && !(g_j for every earlier ALLOW rule j)
which is exact: the first matching rule decides. Cedar actions are finite by schema, so
grant membership a in G is expanded per action.

Checks:
  1. strict schema validation of the generated policies (Cedar validator),
  2. exhaustive differential check of the Cedar authorizer against the reference chain
     on the E1-ext world space (368,640 requests per chain, all states),
  3. Cedar view of F1: in the compiled M_IMPL every P_ctx forbid is guarded by the negation
     of all allow scopes, and deleting it leaves all 368,640 decisions unchanged; in C9_FIX
     the forbid is unguarded (only the admin bypass precedes it).

Usage: python wp5_cedar.py <out-dir>
"""
import itertools, json, os, sys, time
import cedarpy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from semantics import M_IMPL, C9_FIX, decide_concrete, ALLOW, ConcreteLogic  # noqa: E402

OUT = sys.argv[1]
ACTIONS = ["read", "write", "download", "delete"]
THETA = 70

SCHEMA = """
entity User = { "role": String, "dept": String, "div"?: String, "clr": Long };
entity Res  = { "dept": String, "div"?: String, "sens": Long };
type Ctx = { "asg": Set<String>, "del": Set<String>, "risk": Long, "own": Bool };
action "read", "write", "download", "delete" appliesTo { principal: User, resource: Res, context: Ctx };
"""


class CL:  # logic over Cedar expression strings
    TRUE = "true"
    @staticmethod
    def And(*xs): return "(" + " && ".join(xs) + ")"
    @staticmethod
    def Or(*xs): return "(" + " || ".join(xs) + ")"
    @staticmethod
    def Not(x): return f"(!{x})"


class CedarEnv:
    admin = '(principal.role == "admin")'
    dir = '(principal.role == "director")'
    dm = '(principal.role == "division_manager")'
    an = '(principal.role == "analyst")'
    same_dept = "(principal.dept == resource.dept)"
    same_div = "(principal has div && resource has div && principal.div == resource.div)"
    same_div_raw = ("((principal has div && resource has div && principal.div == resource.div) || "
                    "(!(principal has div) && !(resource has div)))")
    sens_pos = "(resource.sens > 0)"
    clr_lt_sens = "(principal.clr < resource.sens)"
    has_asg = "(!context.asg.isEmpty())"
    has_del = "(!context.del.isEmpty())"
    risk_high = f"(context.risk >= {THETA})"
    own = "(context.own)"                       # phase 5: owner(o) == u, for P_own
    def own_act(self, a): return "true" if a in ("read", "download") else "false"
    def asg(self, a): return f'(context.asg.contains("{a}"))'
    def dele(self, a): return f'(context.del.contains("{a}"))'
    def is_read(self, a): return "true" if a == "read" else "false"


def compile_chain(chain, drop=()):
    e, out = CedarEnv(), []
    for a in ACTIONS:
        for i, (rid, eff, g) in enumerate(chain):
            if rid == "P7" or rid in drop:          # default deny is Cedar's own default
                continue
            guard = g(e, CL, a)
            blockers = [g2(e, CL, a) for (r2, e2, g2) in chain[:i] if e2 != eff and r2 not in drop]
            cond = CL.And(guard, *[CL.Not(b) for b in blockers]) if blockers else guard
            kw = "permit" if eff == ALLOW else "forbid"
            out.append(f'@id("{rid}:{a}")\n{kw}(principal, action == Action::"{a}", resource)\n  when {{ {cond} }};')
    return "\n\n".join(out)


# ---- E1-ext world space (identical constants to e1_differential.py with E1_EXT=1) ----
ROLES = ["admin", "director", "division_manager", "analyst", "custom"]
SUBJ_DIV = ["D1", None]
DEPT_DIV = [(True, "D1"), (True, "D2"), (True, None), (False, "D3"), (False, None), (False, "D1")]
CLR = {"normal": 1, "elevated": 2, "delegated": 3}
SENS = {"public": 0, "internal": 1, "sensitive": 2, "top_secret": 3}
GRANTABLE = ["read", "write", "download"]
SUBSETS = [frozenset(c) for r in range(4) for c in itertools.combinations(GRANTABLE, r)]


class Env:
    def __init__(self, role, sdiv, sd, rdiv, clr, sens, A, D, risk, own=False):
        self.own = own
        self.admin, self.dir = role == "admin", role == "director"
        self.dm, self.an = role == "division_manager", role == "analyst"
        self.same_dept = sd
        self.same_div_raw = sdiv == rdiv
        self.same_div = sdiv is not None and sdiv == rdiv
        self.sens_pos = SENS[sens] > 0
        self.clr_lt_sens = CLR[clr] < SENS[sens]
        self.has_asg, self.has_del = bool(A), bool(D)
        self._A, self._D = A, D
        self.risk_high = risk >= THETA
    def asg(self, a): return a in self._A
    def dele(self, a): return a in self._D
    def is_read(self, a): return a == "read"
    def own_act(self, a): return a in ("read", "download")


def entities():
    ents, P, R = [], {}, {}
    for role, sdiv, clr in itertools.product(ROLES, SUBJ_DIV, CLR):
        uid = f"{role}|{sdiv}|{clr}"; P[(role, sdiv, clr)] = uid
        attrs = {"role": role, "dept": "DA", "clr": CLR[clr]}
        if sdiv: attrs["div"] = sdiv
        ents.append({"uid": {"type": "User", "id": uid}, "attrs": attrs, "parents": []})
    for (sd, rdiv), sens in itertools.product(DEPT_DIV, SENS):
        uid = f"{sd}|{rdiv}|{sens}"; R[(sd, rdiv, sens)] = uid
        attrs = {"dept": "DA" if sd else "DB", "sens": SENS[sens]}
        if rdiv: attrs["div"] = rdiv
        ents.append({"uid": {"type": "Res", "id": uid}, "attrs": attrs, "parents": []})
    return ents, P, R


def differential(policies, chain, ents, P, R, batch=4096, owns=(False,)):
    ps = cedarpy.PolicySet.from_str(policies)
    schema = cedarpy.Schema.from_str(SCHEMA)
    E = cedarpy.Entities.from_json_str(json.dumps(ents), schema)
    n = agree = 0; mism = []; reqs = []; exp = []; decisions = []

    def flush():
        nonlocal n, agree
        res = cedarpy.is_authorized_batch(reqs, ps, E, schema)
        for (w, ex), r in zip(exp, res):
            got = r.decision == cedarpy.Decision.Allow
            n += 1; agree += got == ex; decisions.append(got)
            if got != ex and len(mism) < 5:
                mism.append({"world": w, "expected_allow": ex, "cedar": str(r.decision),
                             "errors": [str(x) for x in r.diagnostics.errors][:2]})
        reqs.clear(); exp.clear()

    for role, sdiv, (sd, rdiv), clr, sens, A, D, act, risk, own in itertools.product(
            ROLES, SUBJ_DIV, DEPT_DIV, CLR, SENS, SUBSETS, SUBSETS, ACTIONS, (0, THETA), owns):
        e = Env(role, sdiv, sd, rdiv, clr, sens, A, D, risk, own)
        ex = decide_concrete(chain, e, act)[0] == ALLOW
        reqs.append({"principal": f'User::"{P[(role, sdiv, clr)]}"', "action": f'Action::"{act}"',
                     "resource": f'Res::"{R[(sd, rdiv, sens)]}"',
                     "context": {"asg": sorted(A), "del": sorted(D), "risk": risk, "own": own}})
        exp.append(((role, sdiv, sd, rdiv, clr, sens, sorted(A), sorted(D), act, risk, own), ex))
        if len(reqs) >= batch:
            flush()
    if reqs:
        flush()
    return {"requests": n, "agree": agree, "mismatch_examples": mism}, decisions


def main():
    os.makedirs(OUT, exist_ok=True)
    ents, P, R = entities()
    res = {"cedarpy": __import__("importlib.metadata").metadata.version("cedarpy")}
    dec = {}
    for name, chain, drop in (("M_IMPL", M_IMPL, ()), ("M_IMPL_without_Pctx", M_IMPL, ("P_ctx",)),
                              ("C9_FIX", C9_FIX, ())):
        pol = compile_chain(chain, drop)
        open(os.path.join(OUT, f"chain9_{name}.cedar"), "w").write(pol)
        v = cedarpy.validate_policies(pol, SCHEMA)
        t0 = time.time()
        # phase 5: the owner dimension is enumerated for C9_FIX (P_own); M_IMPL does not read it
        d, decisions = differential(pol, M_IMPL if name.startswith("M_IMPL") else chain, ents, P, R,
                                    owns=(False,) if name.startswith("M_IMPL") else (False, True))
        dec[name] = decisions
        res[name] = {"policies": pol.count("@id("), "chars": len(pol),
                     "validation_passed": bool(v.validation_passed),
                     "validation_errors": [str(x) for x in getattr(v, "errors", [])][:3],
                     "differential_vs_reference": d, "time_s": round(time.time() - t0, 1)}
        print(name, json.dumps({k: res[name][k] for k in ("policies", "validation_passed")}), d["requests"], d["agree"], flush=True)
    res["Pctx_removal_changes_decisions_in_M_IMPL"] = sum(a != b for a, b in zip(dec["M_IMPL"], dec["M_IMPL_without_Pctx"]))
    sch = open(os.path.join(OUT, "chain9.cedarschema"), "w"); sch.write(SCHEMA); sch.close()
    json.dump(res, open(os.path.join(OUT, "wp5_cedar.json"), "w"), indent=2)
    print(json.dumps({k: v for k, v in res.items() if not isinstance(v, dict)}, indent=1))


if __name__ == "__main__":
    main()
