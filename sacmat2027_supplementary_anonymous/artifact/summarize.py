"""Consolidate E1/E1b/E2/E3/E6 raw results into results/summary.json (numbers used in the paper)."""
import json, os, statistics, sys

RES = sys.argv[1]
J = lambda f: json.load(open(os.path.join(RES, f)))
e1, e1b, e6 = J("e1_summary.json"), J("e1b_state.json"), J("e6_smt.json")
au, en, rv, ex, ra = J("e2_audit.json"), J("e2_enforce.json"), J("e2_revoke.json"), J("e2_expiry.json"), J("e2_race.json")
m = []
for k in (0, 1):
    m += J(f"e3_mutation_shard{k}.json")["results"]
st = {r["id"]: r for r in J("e3_state_oracle.json")["results"]}

integ = {r["id"]: r["killed_by_integration"] for r in J("e3_integration.json")["results"]}
EQUIV = {4, 6, 7, 9, 14, 15, 16, 17, 38, 39, 40, 46, 47}      # equivalent on valid inputs (see paper Sec. 6.4)
BOUNDARY = {80, 82, 88}                                        # strict vs non-strict at the validity bound
DOMAIN = {94}                                                  # requires inconsistent admin flags
nonEq = [r for r in m if r["id"] not in EQUIV | BOUNDARY | DOMAIN]
T = sum(r["killed_by_existing_tests"] for r in nonEq)
E1k = sum(r["killed_by_E1_full"] for r in nonEq)
E1bk = sum(1 for r in nonEq if not r["killed_by_E1_full"] and st.get(r["id"], {}).get("killed_by_E1b"))


def windows(rows, key):
    by = {}
    for r in rows:
        by.setdefault(r["delta_s"], []).append(r[key])
    return {d: {"n": len(v), "min": min(v), "max": max(v), "median": statistics.median(v)} for d, v in sorted(by.items())}


summary = {
    "E1": {k: e1[k] for k in ("worlds_evaluated", "api_reachable_worlds", "runtime_s", "indeterminate",
                              "agreement_vs_M_IMPL_decision", "agreement_vs_M_IMPL_rule",
                              "agreement_vs_R_PAPER_decision", "invariant_violations_api_reachable",
                              "invariant_violations_all", "Pctx_inertness_pairs", "Pctx_inertness_equal")},
    "E1_spec_disagreements": e1["R_PAPER_disagreements_by_class"],
    "E1b": {"worlds": e1b["worlds"], "mismatches": e1b["mismatches"]},
    "E6": {k: v["result"] for k, v in e6["results"].items()},
    "E6_max_time_s": max(v["time_s"] for v in e6["results"].values()),
    "E2a": au["E2a_audit_persistence"],
    "E2_enforcement": en["E2_enforcement"],
    "E2b_delegation_revocation": windows(rv["E2b_delegation_revocation"], "window_s"),
    "E2b_control_assignment_revocation": [r["window_s"] for r in rv["E2b_control_assignment_revocation"]],
    "E2c_delegation_expiry": windows(ex["E2c_delegation_expiry"], "window_after_expiry_s"),
    "E2d_assignment_expiry": windows(ex["E2d_assignment_expiry"], "window_after_expiry_s"),
    "E2_max_allows_after_end": max([r["allows_after_revoke"] for r in rv["E2b_delegation_revocation"]] +
                                   [r["allows_after_expiry"] for r in ex["E2d_assignment_expiry"]]),
    "E2e_race_forced": ra["E2e_race_forced_interleaving"],
    "E2e_race_unforced": ra["E2e_race_unforced"],
    "E3": {"decision_relevant_mutants": len(m), "equivalent": len(EQUIV), "boundary_equivalent": len(BOUNDARY),
           "domain_assumption": len(DOMAIN), "non_equivalent": len(nonEq),
           "killed_existing_tests": T,
           "killed_full_repository_suite": sum(r["killed_by_existing_tests"] or integ.get(r["id"], False) for r in nonEq),
           "survivors_full_repository_suite": sorted(r["id"] for r in nonEq
                                                     if not (r["killed_by_existing_tests"] or integ.get(r["id"], False))),
           "killed_E1": E1k, "killed_E1b_additional": E1bk,
           "killed_E1_or_E1b": E1k + E1bk,
           "equivalent_killed_by_existing_tests_structural_asserts":
               sum(r["killed_by_existing_tests"] for r in m if r["id"] in EQUIV)},
}
json.dump(summary, open(os.path.join(RES, "summary.json"), "w"), indent=2, default=str)
print(json.dumps(summary["E3"], indent=1)); print(json.dumps({k: summary[k] for k in ("E2b_delegation_revocation", "E2c_delegation_expiry", "E2d_assignment_expiry")}, indent=1))
