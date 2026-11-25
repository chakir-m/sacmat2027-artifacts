"""L3: probe registry. A probe is (name, level, kind, fn) with fn() -> (passed: bool, detail)."""
PROBES = []


def probe(name, level="L3", kind="safety"):
    def deco(fn):
        PROBES.append((name, level, kind, fn)); return fn
    return deco


def run_all(probes=None):
    rep = {}
    for name, level, kind, fn in (probes or PROBES):
        try:
            ok, detail = fn()
        except Exception as e:                    # a crash fails the probe
            ok, detail = False, repr(e)[:200]
        rep[name] = {"level": level, "kind": kind, "pass": bool(ok), "detail": detail}
    return rep
