"""layercheck -- layered (rule / state / enforcement) conformance checking for ABAC deployments.

Reusable core, independent of any one system:
  chain      first-applicable rule chains written once over a predicate vocabulary and
             interpreted three ways: Python booleans (differential testing), z3 terms (proofs),
             Cedar expressions (compilation to a forbid-overrides language)
  genericity syntactic data-independence criterion G over a Python decision function,
             configured by a sort map (which attributes are open sorts)
  coverage   z3 enumeration of satisfiable observation vectors vs. those a bounded world space
             realises (completeness of the bounded check, Theorem 2)
  l2         revocation / expiry window measurement with the bounded-staleness prediction
  l3         probe registry: (name, level, kind=safety|liveness, callable) -> pass/fail report
Adapters bind a concrete system: adapters/chain9.py (in-process FastAPI PDP/PEP),
adapters/tinytodo.py (HTTP). The Backstage harness is JavaScript (wp3_backstage_rbac.test.js)
and follows the same probe structure.
"""
