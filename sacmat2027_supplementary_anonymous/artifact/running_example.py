"""Running example of the paper, evaluated rule by rule with the reference chains
(M_IMPL = v1, C9_FIX = F = v2). Prints each guard's value and the first applicable rule.
Usage: python running_example.py <out-json>"""
import json, sys
from types import SimpleNamespace as NS
from semantics import M_IMPL, C9_FIX, ConcreteLogic as L

def env(role, same_dept, same_div, sens_pos, clr_lt_sens, asg=(), dele=(), risk=0):
    return NS(admin=role == "adm", dir=role == "dir", dm=role == "dm", an=role == "emp",
              same_dept=same_dept, same_div_raw=same_div, same_div=same_div,
              sens_pos=sens_pos, clr_lt_sens=clr_lt_sens, has_asg=bool(asg), has_del=bool(dele),
              asg=lambda a: a in asg, dele=lambda a: a in dele, risk_high=risk >= 70,
              is_read=lambda a: a == "read", rho=risk,
              own=False, own_act=lambda a: a in ("read", "download"))   # nobody owns r or o

# Org: Finance {Accounting, Audit}, Legal {Compliance}. Ana: employee, Accounting, normal.
# Dan: division manager, Audit. Lea: director, Legal. o: internal Legal contract.
# Report r: an internal Accounting report. Internal = rank 1; normal clearance = rank 1.
CASES = {
 "a_ana_reads_assigned_report": (env("emp", True, True, True, False, asg={"read"}), "read"),
 "b1_dan_writes_o_before": (env("dm", False, False, True, False), "write"),
 "b2_dan_writes_o_after_asg_and_read_delegation": (env("dm", False, False, True, False,
                                                     asg={"read", "write"}, dele={"read"}), "write"),
 "c1_ana_unassigned_0200_five_failed_logins": (env("emp", True, True, True, False, risk=70), "read"),
 "c2_same_but_assigned": (env("emp", True, True, True, False, asg={"read"}, risk=70), "read"),
}

def trace(chain, e, a):
    rows, first = [], None
    for rid, eff, g in chain:
        v = bool(g(e, L, a)); rows.append((rid, eff, v))
        if v and first is None:
            first = (rid, eff)
    return {"trace": rows, "decision": first}

out = {k: {"v1": trace(M_IMPL, e, a), "v2": trace(C9_FIX, e, a), "rho": e.rho, "action": a} for k, (e, a) in CASES.items()}
for k, v in out.items():
    print(f"{k:50s} v1={v['v1']['decision']}  v2={v['v2']['decision']}")
json.dump(out, open(sys.argv[1], "w"), indent=1)
