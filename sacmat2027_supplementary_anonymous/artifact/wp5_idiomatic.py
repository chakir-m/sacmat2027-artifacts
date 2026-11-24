"""
WP5b -- the hand-written, idiomatic Cedar version of the repaired chain F
(wp5_chain9_fix_idiomatic.cedar: forbid-overrides, `unless` exemptions, no compiled blockers).
Validates it against the schema of wp5_cedar.py and checks it differentially against C9_FIX on the
E1-ext world space, with the owner dimension (phase 5: P_own).

Usage: python wp5_idiomatic.py <out-dir>
"""
import json, os, sys
import cedarpy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("w5", os.path.join(os.path.dirname(os.path.abspath(__file__)), "wp5_cedar.py"))
argv = sys.argv; sys.argv = [argv[0], os.devnull]
w5 = importlib.util.module_from_spec(spec); spec.loader.exec_module(w5); sys.argv = argv
from semantics import C9_FIX                                       # noqa: E402

OUT = sys.argv[1]
pol = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "wp5_chain9_fix_idiomatic.cedar")).read()
v = cedarpy.validate_policies(pol, w5.SCHEMA)
ents, P, R = w5.entities()
d, _ = w5.differential(pol, C9_FIX, ents, P, R, owns=(False, True))
res = {"validation_passed": bool(v.validation_passed), "policies": pol.count("@id("),
       "lines": sum(1 for l in pol.splitlines() if l.strip() and not l.strip().startswith("//")),
       "differential_vs_C9_FIX": d}
os.makedirs(OUT, exist_ok=True)
json.dump(res, open(os.path.join(OUT, "wp5_idiomatic.json"), "w"), indent=1)
print(json.dumps(res, indent=1))
