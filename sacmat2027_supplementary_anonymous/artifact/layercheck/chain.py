"""Rule chains: one definition, three interpretations (see semantics.py for CHAIN-9)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from semantics import ALLOW, DENY, ConcreteLogic, decide_concrete        # noqa: F401,E402


def compile_cedar(chain, env, logic, actions, terminal=("P7",)):
    """Exact compilation of a first-applicable chain to Cedar (forbid-overrides, default deny):
    permit r_i when g_i && no earlier DENY guard; forbid r_k when g_k && no earlier ALLOW guard."""
    out = []
    for a in actions:
        for i, (rid, eff, g) in enumerate(chain):
            if rid in terminal:
                continue
            blockers = [g2(env, logic, a) for (_, e2, g2) in chain[:i] if e2 != eff]
            cond = logic.And(g(env, logic, a), *[logic.Not(b) for b in blockers]) if blockers else g(env, logic, a)
            kw = "permit" if eff == ALLOW else "forbid"
            out.append(f'@id("{rid}:{a}")\n{kw}(principal, action == Action::"{a}", resource)\n  when {{ {cond} }};')
    return "\n\n".join(out)


def redundant_denies(chain, worlds, actions, decide=decide_concrete):
    """Deny rules whose removal changes no decision on the given worlds (e.g. a deny placed
    after every allow rule in a first-applicable chain)."""
    res = {}
    for rid, eff, _ in chain:
        if eff != DENY or rid in ("P7",):
            continue
        reduced = [r for r in chain if r[0] != rid]
        res[rid] = all(decide(chain, e, a)[0] == decide(reduced, e, a)[0] for e in worlds for a in actions)
    return res
