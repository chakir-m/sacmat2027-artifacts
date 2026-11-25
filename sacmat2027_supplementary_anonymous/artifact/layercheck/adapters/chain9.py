"""CHAIN-9 adapter: reference chains and the bounded world space of E1-ext (no app import)."""
import itertools, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from semantics import M_IMPL, R_PAPER, C9_FIX            # noqa: F401,E402

ACTIONS = ["read", "write", "download", "delete"]


def worlds():
    """Abstract environments of the E1-ext world space (actions handled by the caller)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("w5", os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "wp5_cedar.py"))
    argv = sys.argv; sys.argv = [argv[0], os.devnull]
    w5 = importlib.util.module_from_spec(spec); spec.loader.exec_module(w5); sys.argv = argv
    for role, sdiv, (sd, rdiv), clr, sens, A, D, risk in itertools.product(
            w5.ROLES, w5.SUBJ_DIV, w5.DEPT_DIV, w5.CLR, w5.SENS, w5.SUBSETS, w5.SUBSETS, (0, w5.THETA)):
        yield w5.Env(role, sdiv, sd, rdiv, clr, sens, A, D, risk)
