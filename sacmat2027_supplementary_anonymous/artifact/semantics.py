"""
CHAIN-9 research artifact -- reference semantics.

Three first-match rule chains over a common predicate vocabulary:

  M_IMPL   transcription of the analysed implementation (pdp.py, snapshot df4f95ae)
  R_PAPER  the chain exactly as defined in the original manuscript (Sec. 4)
  C9_FIX   the repaired chain F, implemented by v2 (evaluation fork)

Each guard is written against an abstract environment `e` and logic module `L`,
so the SAME definitions are evaluated concretely (E1, differential testing
against the real PolicyDecisionPoint) and symbolically (E6, z3 proofs).

This module does not import application code.
"""

ALLOW, DENY = "allow", "deny"


class ConcreteLogic:
    @staticmethod
    def And(*xs):
        return all(xs)

    @staticmethod
    def Or(*xs):
        return any(xs)

    @staticmethod
    def Not(x):
        return not x

    TRUE = True


# ---------------------------------------------------------------------------
# Rule chains: list of (rule_id, effect, guard(e, L, a)).
# Predicates provided by an environment e:
#   admin, dir, dm, an                      role flags (admin = platform admin)
#   same_dept                               dept(u) == dept(o)
#   same_div_raw                            div(u) == div(o)   (None == None counts)
#   same_div                                div(u) != bottom and div(u) == div(o)
#   sens_pos                                sensitivity rank > 0
#   clr_lt_sens                             clearance rank < sensitivity rank
#   has_asg, has_del                        some active assignment / delegation exists
#   asg(a), dele(a)                         a in assignment / delegation action set
#   risk_high                               riskScore >= theta (70)
#   is_read(a)                              a == read
#   own                                     owner(o) == u           (phase 5, used by C9_FIX only)
#   own_act(a)                              a in {read, download}   (phase 5, used by C9_FIX only)
# ---------------------------------------------------------------------------

def _pclass(e, L, same_div_pred):
    return L.And(e.sens_pos,
                 L.Not(L.And(e.dir, e.same_dept)),
                 L.Not(L.And(e.dm, e.same_dept, same_div_pred(e))),
                 e.clr_lt_sens)


M_IMPL = [
    ("ADMIN",   ALLOW, lambda e, L, a: e.admin),
    ("P1",      DENY,  lambda e, L, a: L.And(L.Not(e.same_dept), L.Not(e.has_del))),
    ("P_class", DENY,  lambda e, L, a: _pclass(e, L, lambda e: e.same_div_raw)),
    ("P2",      ALLOW, lambda e, L, a: L.And(e.dir, e.same_dept)),
    ("P3",      ALLOW, lambda e, L, a: L.And(e.dm, e.same_dept, e.same_div_raw)),
    ("P4",      ALLOW, lambda e, L, a: L.And(e.has_asg, e.asg(a), L.Or(e.an, e.dm))),
    ("P5",      DENY,  lambda e, L, a: L.And(e.an, L.Not(e.has_asg))),
    ("P6",      ALLOW, lambda e, L, a: L.And(e.has_del, e.dele(a))),
    ("P_ctx",   DENY,  lambda e, L, a: e.risk_high),
    ("P7",      DENY,  lambda e, L, a: L.TRUE),
]

# Manuscript Sec. 4 (Defs. P1..P7, P_cl, P_ctx; Alg. 1 admin bypass).
# Clearance ranks are not defined by the manuscript (it types clr: U -> S);
# the implementation's rank map is used so that the definition is evaluable.
R_PAPER = [
    ("ADMIN",   ALLOW, lambda e, L, a: e.admin),
    ("P1",      DENY,  lambda e, L, a: L.And(L.Not(e.same_dept), L.Not(e.has_del))),
    ("P_class", DENY,  lambda e, L, a: _pclass(e, L, lambda e: e.same_div)),
    ("P2",      ALLOW, lambda e, L, a: L.And(e.dir, e.same_dept)),
    ("P3",      ALLOW, lambda e, L, a: L.And(e.dm, e.same_dept, e.same_div)),
    ("P4",      ALLOW, lambda e, L, a: L.And(L.Or(e.an, e.dm), e.has_asg, e.is_read(a))),
    ("P5",      DENY,  lambda e, L, a: L.And(e.an, L.Not(e.has_asg))),
    ("P6",      ALLOW, lambda e, L, a: L.And(e.has_del, e.dele(a))),
    ("P_ctx",   DENY,  lambda e, L, a: e.risk_high),
    ("P7",      DENY,  lambda e, L, a: L.TRUE),
]

# Repaired chain F (implemented in v2). Changes w.r.t. M_IMPL:
#  (1) P_ctx moved before every allow rule, so a risk deny is effective;
#  (2) P4 requires same department, so a delegation cannot unlock
#      cross-department assignment actions;
#  (3) P6 is evaluated before P5, and P5 denies only analysts holding
#      neither an assignment nor a delegation for the requested action;
#  (4) sameDiv uses the formal definition (div(u) != bottom);
#  (5) [phase 5, DR4: owner rule] the owner rule P_own is part of the chain (after P3), confined to the
#      owner's department and to the file actions read and download, and exempt from P_class
#      like the director and division-manager rules. It follows P_ctx and P1.
#      (Up to fork commit 49d99a9 the owner rule was applied by the PEP gate, outside the PDP.)
#  (6) [phase 6, D1: read-only assignments] P4 grants read only, as documented (CLAUDE.md P4:
#      "action = read"; design document: "assignments grant read access only, never write"),
#      whatever other actions the assignment lists. (Up to fork commit 6a26954, P4 granted any listed action.)
def _own(e, L, a):
    return L.And(e.own, e.same_dept, e.own_act(a))


C9_FIX = [
    ("ADMIN",   ALLOW, lambda e, L, a: e.admin),
    ("P_ctx",   DENY,  lambda e, L, a: e.risk_high),
    ("P1",      DENY,  lambda e, L, a: L.And(L.Not(e.same_dept), L.Not(e.has_del))),
    ("P_class", DENY,  lambda e, L, a: L.And(_pclass(e, L, lambda e: e.same_div),
                                             L.Not(_own(e, L, a)))),
    ("P2",      ALLOW, lambda e, L, a: L.And(e.dir, e.same_dept)),
    ("P3",      ALLOW, lambda e, L, a: L.And(e.dm, e.same_dept, e.same_div)),
    ("P_own",   ALLOW, _own),
    ("P4",      ALLOW, lambda e, L, a: L.And(L.Or(e.an, e.dm), e.same_dept, e.asg(a), e.is_read(a))),
    ("P6",      ALLOW, lambda e, L, a: e.dele(a)),
    ("P5",      DENY,  lambda e, L, a: e.an),
    ("P7",      DENY,  lambda e, L, a: L.TRUE),
]

CHAINS = {"M_IMPL": M_IMPL, "R_PAPER": R_PAPER, "C9_FIX": C9_FIX}


def decide_concrete(chain, e, a):
    """First-match evaluation; returns (effect, rule_id)."""
    L = ConcreteLogic
    for rid, eff, guard in chain:
        if guard(e, L, a):
            return eff, rid
    raise AssertionError("chain without terminal rule")


# ---------------------------------------------------------------------------
# Intended invariants (from CLAUDE.md hard invariants + author decision Q1 +
# documented intent of P_ctx in seed.py). Each returns True iff satisfied for
# request (e, a) with decision d (True = allow).
# ---------------------------------------------------------------------------

def invariants(e, L, a, allow):
    """Return dict name -> boolean formula (True = invariant holds).

    Phase 5: R2, R3 and R7 carry the owner exception of the developer guide (conflict C3):
    an owner inside her department may read and download her own object. Environments
    without an owner dimension have own = False, for which the formulas are the earlier ones."""
    imp = lambda p, q: L.Or(L.Not(p), q)
    na = L.Not(e.admin)
    pclass_cond = _pclass(e, L, lambda e: e.same_div)
    own_ok = _own(e, L, a)
    return {
        "I1_isolation":
            imp(L.And(na, L.Not(e.same_dept), L.Not(e.has_del)), L.Not(allow)),
        "I2_classification":
            imp(L.And(na, pclass_cond, allow), own_ok),
        "I3_analyst_need_to_know":
            imp(L.And(na, e.an, allow), L.Or(e.asg(a), e.dele(a), own_ok)),
        "I4_analyst_delegation_liveness":
            imp(L.And(na, e.an, e.dele(a), L.Not(e.risk_high), L.Not(pclass_cond)), allow),
        "I5_cross_dept_only_delegated_actions":
            imp(L.And(na, L.Not(e.same_dept), allow), e.dele(a)),
        "I6_risk_deny":
            imp(L.And(na, e.risk_high), L.Not(allow)),
        "I7_justified_allow":
            imp(L.And(na, allow),
                L.Or(L.And(e.dir, e.same_dept),
                     L.And(e.dm, e.same_dept, e.same_div),
                     L.And(L.Or(e.an, e.dm), e.asg(a)),
                     e.dele(a),
                     own_ok)),
        # Manuscript Theorem (Analyst Least-Privilege), as stated:
        "PAPER_analyst_least_privilege":
            imp(L.And(na, e.an, e.same_dept, L.Not(e.has_del), allow),
                L.And(e.is_read(a), e.has_asg)),
        # Phase 6: the same theorem with the owner exception of conflict C3 (as R2, R3, R7 carry it)
        "LP_least_privilege_with_owner_exception":
            imp(L.And(na, e.an, e.same_dept, L.Not(e.has_del), allow),
                L.Or(L.And(e.is_read(a), e.has_asg), own_ok)),
    }
