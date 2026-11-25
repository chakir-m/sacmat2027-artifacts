import sys, shutil
B, W = sys.argv[1], sys.argv[2]
src = open(f"{B}/pdp.py").read(); risk = open(f"{B}/risk.py").read()
V = {
 "ordering_on_dept": ('if subject.department_id != resource.department_id:', 'if subject.department_id < resource.department_id:'),
 "string_op_on_action": ('if ctx["has_delegation"] and request.action in ctx["delegation_actions"]:', 'if ctx["has_delegation"] and request.action.startswith("r"):'),
 "cardinality_of_grants": ('"has_assignment": bool(assignment_actions),', '"has_assignment": len(assignment_actions) > 1,'),
 "sink_in_condition": ('if ctx["is_admin"]:', 'if ctx["is_admin"] or snap["same_div"]:'),
 "hash_of_division": ('and subject.division_id == resource.division_id)\n        if sens_rank', 'and hash(subject.division_id) % 2 == 0)\n        if sens_rank'),
}
for name, (old, new) in V.items():
    assert src.count(old) >= 1, name
    open(f"{W}/{name}.py", "w").write(src.replace(old, new, 1))
open(f"{W}/risk_reads_dept.py", "w").write(risk.replace('    score = 0\n', '    score = 0 if subject.department_id else 1\n', 1))
