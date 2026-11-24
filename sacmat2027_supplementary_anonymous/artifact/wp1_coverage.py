"""
WP1 -- Coverage of the bounded world space (second half of the data-independence argument).

Observation atoms (everything the PDP, the reference chains and the requirements can see,
for a fixed request action a):
  role in {admin, director, dm, analyst, custom}, clearance rank, sensitivity rank,
  same_dept, u_div_none, same_div_raw, risk_high, a_is_read, asg_a, del_a, has_asg, has_del
(the PDP-observations certified by wp1_genericity_check.py are a subset of these).

For each scope (all states / API-reachable states) the script
  1. enumerates the observation vectors that are SATISFIABLE over unbounded domains (z3,
     uninterpreted sorts Dept, Div, Act; grant sets arbitrary predicates), and
  2. the vectors REALISED by the bounded E1 world space (with custom roles, E1_EXT),
and reports SAT \\ REALISED. Empty difference => every satisfiable observation vector is
exercised by E1, so (with criterion G) the bounded verdicts are complete.

Usage: python wp1_coverage.py <out-dir>      (imports no application code)
"""
import itertools, json, os, sys
import z3
os.environ["E6_EXT"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e6_smt
from e6_smt import Z3Env, Role, OptDiv, Act, READ, DOWNLOAD

OWN = os.environ.get("COVER_OWN") == "1"   # phase 5: obs of v2 adds own and a = download (P_own)

OUT = sys.argv[1]
ROLES = ["admin", "director", "dm", "analyst", "custom"]
BOOL_ATOMS = ["same_dept", "u_div_none", "same_div_raw", "risk_high",
              "a_is_read", "asg_a", "del_a", "has_asg", "has_del"]
if OWN:
    BOOL_ATOMS = BOOL_ATOMS + ["own", "a_is_download"]


def z3_atoms(e, a):
    return {"same_dept": e.same_dept, "u_div_none": OptDiv.is_none(e.divu),
            "same_div_raw": e.same_div_raw, "risk_high": e.risk_high,
            "a_is_read": a == READ, "asg_a": e.A(a), "del_a": e.D(a),
            "has_asg": e.has_asg, "has_del": e.has_del,
            "own": e.own, "a_is_download": a == DOWNLOAD}


def satisfiable_vectors(scope):
    e = Z3Env(""); a = z3.Const("a", Act)
    at = z3_atoms(e, a)
    base = [e.domain] + ([e.wf, e.api] if scope == "api" else [])
    out = set()
    s = z3.Solver(); s.add(*base)
    for role in ROLES:
        for bits in itertools.product((False, True), repeat=len(BOOL_ATOMS)):
            s.push()
            s.add(e.role == getattr(Role, role))
            for name, b in zip(BOOL_ATOMS, bits):
                s.add(at[name] if b else z3.Not(at[name]))
            r = s.check()
            s.pop()
            if r == z3.sat:
                out.add((role,) + bits)
            elif r != z3.unsat:
                raise RuntimeError("unknown")
    return out


# --- E1 bounded world space (E1_EXT), same constants as e1_differential.py ---
SUBJ_DIV = ["D1", None]
DEPT_DIV = [(True, "D1"), (True, "D2"), (True, None), (False, "D3"), (False, None)]
if os.environ.get("COVER_BASE") != "1":
    DEPT_DIV = DEPT_DIV + [(False, "D1")]      # as in e1_differential.py with E1_EXT=1
GRANTABLE = ["read", "write", "download"]
REQ = ["read", "write", "download", "delete"]
SUBSETS = [frozenset(c) for r in range(4) for c in itertools.combinations(GRANTABLE, r)]
E1_ROLE = {"admin": "admin", "director": "director", "division_manager": "dm",
           "analyst": "analyst", "custom": "custom"}


def realised_vectors(scope):
    out = set()
    for role, sdiv, (sd, rdiv), A, D, risk, act, own in itertools.product(
            E1_ROLE, SUBJ_DIV, DEPT_DIV, SUBSETS, SUBSETS, (False, True), REQ,
            (False, True) if OWN else (False,)):
        if scope == "api" and (D not in (frozenset(), frozenset({"read"}))
                               or (role == "division_manager" and sdiv is None)):
            continue
        v = (E1_ROLE[role], sd, sdiv is None, sdiv == rdiv, risk, act == "read",
             act in A, act in D, bool(A), bool(D))
        out.add(v + ((own, act == "download") if OWN else ()))
    return out


if __name__ == "__main__":
    res = {}
    for scope in ("all", "api"):
        sat, rea = satisfiable_vectors(scope), realised_vectors(scope)
        missing = sorted(sat - rea); spurious = sorted(rea - sat)
        res[scope] = {"satisfiable": len(sat), "realised": len(rea),
                      "missing": [dict(zip(["role"] + BOOL_ATOMS, v)) for v in missing],
                      "realised_but_unsat (encoding error if non-empty)": len(spurious)}
        print(scope, "SAT", len(sat), "REALISED", len(rea), "MISSING", len(missing), "SPURIOUS", len(spurious))
    res["note"] = ("clearance (3 values) and sensitivity (4 values) are finite enums enumerated "
                   "completely by E1 and unconstrained by the other atoms, so they factor out.")
    os.makedirs(OUT, exist_ok=True)
    fn = "wp1_coverage_base.json" if os.environ.get("COVER_BASE") == "1" else "wp1_coverage.json"
    if OWN:
        fn = fn.replace(".json", "_own.json")
    json.dump(res, open(os.path.join(OUT, fn), "w"), indent=2)
    for scope in ("all", "api"):
        from collections import Counter
        c = Counter((m["same_dept"], m["u_div_none"], m["same_div_raw"]) for m in res[scope]["missing"])
        print(scope, "missing by (same_dept,u_div_none,same_div_raw):", dict(c))
