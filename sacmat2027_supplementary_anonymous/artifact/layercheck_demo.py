"""WP2 demonstration: the reusable layercheck core applied to two systems.
  (1) CHAIN-9: deny-after-permit redundancy lint over the E1-ext world space
      (finds P_ctx in M_IMPL; none in C9_FIX) -- design rule 1 as a reusable check;
  (2) TinyTodo: L2 window measurement (share revocation, policy propagation) and an
      L3 probe set, through the same l2/l3 modules.
Usage: python layercheck_demo.py <tinytodo-src> <tinytodo-binary> <work> <out-json>
"""
import json, os, sys, time
SRC, BIN, WORK, OUT = sys.argv[1:5]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from layercheck import chain, l2, l3                       # noqa: E402
from layercheck.adapters import chain9, tinytodo          # noqa: E402

res = {}
W = list(chain9.worlds())
res["chain9_redundant_denies"] = {name: chain.redundant_denies(c, W, chain9.ACTIONS)
                                  for name, c in (("M_IMPL", chain9.M_IMPL), ("C9_FIX", chain9.C9_FIX))}
print(res["chain9_redundant_denies"], flush=True)

T = tinytodo.load(SRC, BIN, WORK)
s = T.Server(T.BASE)
try:
    l = T.create_list("emina", "demo"); T.share("emina", l, T.U("aaron"), "Reader")
    allow = lambda: T.ok(T.get_list("aaron", l))
    res["tinytodo_share_revocation_window_s"] = l2.measure_window(
        allow, lambda: T.share("emina", l, T.U("aaron"), "Reader", add=False), poll=0.02, limit=10)
    T.share("emina", l, T.U("aaron"), "Reader"); time.sleep(1.3)
    res["tinytodo_policy_propagation_window_s"] = l2.measure_window(
        allow, lambda: open(s.policies_path(), "a").write('\nforbid (principal == User::"aaron", action, resource);\n'),
        poll=0.02, limit=10)
    res["tinytodo_predicted_upper_bound_s"] = 1.0 + 0.1        # watcher period + slack (mtime granularity)

    @l3.probe("reader_cannot_rename", kind="safety")
    def _():
        r = T.httpx.post(f"{T.URL}/list/update", json={"uid": T.U("kesha"), "list": l, "name": "x"}); return not T.ok(r), r.status_code

    @l3.probe("owner_can_read", kind="liveness")
    def _():
        return T.ok(T.get_list("emina", l)), None
    res["tinytodo_l3"] = l3.run_all()
finally:
    s.stop()
json.dump(res, open(OUT, "w"), indent=1, default=str)
print(json.dumps({k: v for k, v in res.items() if k != "chain9_redundant_denies"}, indent=1, default=str))
