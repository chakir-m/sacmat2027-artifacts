"""Self-test of the criterion G checker: the unmodified PDP must pass; every seeded violation must be flagged.
Usage: python wp1_checker_selftest.py <dir-with-pdp.py-and-risk.py> <work-dir> <out-json>
Cases 1-6 are those of the earlier self-test (wp1_checker_selftest_gen.py); cases 7-10 were added after review:
an action constant that obs does not represent, a closed attribute outside obs in a condition, the request
context deciding outside the risk helper, and a department constant."""
import json, os, subprocess, sys
B, W, OUT = sys.argv[1:4]
here = os.path.dirname(os.path.abspath(__file__))
os.makedirs(W, exist_ok=True)
src = open(f"{B}/pdp.py").read(); risk = open(f"{B}/risk.py").read()
V = {
 "ordering_on_dept": ('if subject.department_id != resource.department_id:', 'if subject.department_id < resource.department_id:'),
 "string_op_on_action": ('if ctx["has_delegation"] and request.action in ctx["delegation_actions"]:', 'if ctx["has_delegation"] and request.action.startswith("r"):'),
 "cardinality_of_grants": ('"has_assignment": bool(assignment_actions),', '"has_assignment": len(assignment_actions) > 1,'),
 "sink_in_condition": ('if ctx["is_admin"]:', 'if ctx["is_admin"] or snap["same_div"]:'),
 "hash_of_division": ('and subject.division_id == resource.division_id)', 'and hash(subject.division_id) % 2 == 0)'),
 "action_constant_outside_obs": ('if ctx["is_admin"]:', 'if ctx["is_admin"] or request.action == "delete":'),
 "closed_attribute_outside_obs": ('if ctx["is_admin"]:', 'if ctx["is_admin"] or subject.mfa_enabled:'),
 "context_decides": ('if ctx["is_admin"]:', 'if ctx["is_admin"] or request.context.get("vip"):'),
 "department_constant": ('if ctx["is_admin"]:', 'if ctx["is_admin"] or subject.department_id == "D0":'),
}
def run(pdp, rk):
    r = subprocess.run([sys.executable, f"{here}/wp1_genericity_check.py", pdp, rk, f"{W}/_out.json"], capture_output=True, text=True)
    return r.returncode
res = {"original_pdp": "criterion G holds (exit 0)" if run(f"{B}/pdp.py", f"{B}/risk.py") == 0 else "FLAGGED (unexpected)",
       "seeded_violations": {}}
for name, (old, new) in V.items():
    if src.count(old) < 1:
        res["seeded_violations"][name] = "not applicable to this version (anchor missing)"; continue
    p = f"{W}/{name}.py"; open(p, "w").write(src.replace(old, new, 1))
    res["seeded_violations"][name] = "flagged (exit 1)" if run(p, f"{B}/risk.py") == 1 else "NOT FLAGGED"
rp = f"{W}/risk_reads_dept.py"; open(rp, "w").write(risk.replace('    score = 0\n', '    score = 0 if subject.department_id else 1\n', 1))
res["seeded_violations"]["risk_reads_dept (helper reads an open-sort attribute)"] = \
    "flagged (exit 1)" if run(f"{B}/pdp.py", rp) == 1 else "NOT FLAGGED"
json.dump(res, open(OUT, "w"), indent=1); print(json.dumps(res, indent=1))
