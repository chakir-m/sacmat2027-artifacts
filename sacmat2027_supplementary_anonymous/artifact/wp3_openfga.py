"""
WP3 (third external system) -- OpenFGA, a Zanzibar-style authorization server (CNCF), run
unmodified from its release binary with the in-memory datastore.

L1  O1 bounded differential: Check vs. a reference evaluation of the authorization model
       (owner -> editor -> viewer, group membership via usersets, can_read = viewer but not
       blocked) over all 2^9 states of nine candidate tuples, five relations, two users.
L2  O2 revocation windows (Theorem 3): delete a tuple and poll Check every 50 ms until it
       denies, under four configurations:
         A  default (no check cache)
         B  --check-query-cache-enabled (TTL 10 s), requests MINIMIZE_LATENCY
         C  B + --cache-controller-enabled (changelog-based invalidation, controller TTL 10 s)
         D  B, requests with consistency HIGHER_CONSISTENCY
       for direct revocation (viewer tuple) and indirect revocation (group membership),
       with the cached result warmed delta seconds before the revocation.

Usage: python wp3_openfga.py <openfga-binary> <out-json>
"""
import itertools, json, subprocess, sys, time
import httpx

BIN, OUTJ = sys.argv[1:3]
R = {}

MODEL = {"schema_version": "1.1", "type_definitions": [
    {"type": "user"},
    {"type": "group", "relations": {"member": {"this": {}}},
     "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
    {"type": "document", "relations": {
        "owner": {"this": {}},
        "editor": {"union": {"child": [{"this": {}}, {"computedUserset": {"relation": "owner"}}]}},
        "viewer": {"union": {"child": [{"this": {}}, {"computedUserset": {"relation": "editor"}}]}},
        "blocked": {"this": {}},
        "can_read": {"difference": {"base": {"computedUserset": {"relation": "viewer"}},
                                    "subtract": {"computedUserset": {"relation": "blocked"}}}}},
     "metadata": {"relations": {
        "owner": {"directly_related_user_types": [{"type": "user"}]},
        "editor": {"directly_related_user_types": [{"type": "user"}, {"type": "group", "relation": "member"}]},
        "viewer": {"directly_related_user_types": [{"type": "user"}, {"type": "group", "relation": "member"}]},
        "blocked": {"directly_related_user_types": [{"type": "user"}]},
        "can_read": {"directly_related_user_types": []}}}}]}

CANDIDATES = [("user:u1", "member", "group:g1"), ("user:u2", "member", "group:g1"),
              ("user:u1", "owner", "document:d1"), ("user:u1", "editor", "document:d1"),
              ("group:g1#member", "editor", "document:d1"), ("user:u1", "viewer", "document:d1"),
              ("group:g1#member", "viewer", "document:d1"), ("user:u1", "blocked", "document:d1"),
              ("user:u2", "blocked", "document:d1")]
RELS = ["owner", "editor", "viewer", "blocked", "can_read"]


def reference(T, user, rel):
    member = (user, "member", "group:g1") in T
    direct = lambda r: (user, r, "document:d1") in T or (member and ("group:g1#member", r, "document:d1") in T)
    owner = (user, "owner", "document:d1") in T
    editor = direct("editor") or owner
    viewer = direct("viewer") or editor
    blocked = (user, "blocked", "document:d1") in T
    return {"owner": owner, "editor": editor, "viewer": viewer, "blocked": blocked,
            "can_read": viewer and not blocked}[rel]


class FGA:
    def __init__(self, port, flags=()):
        self.url = f"http://127.0.0.1:{port}"
        self.log = open(f"/tmp/openfga_{port}.log", "w")
        self.p = subprocess.Popen([BIN, "run", "--http-addr", f"127.0.0.1:{port}", "--grpc-addr",
                                   f"127.0.0.1:{port + 1000}", "--playground-enabled=false",
                                   "--metrics-enabled=false", "--log-level", "warn", *flags], stdout=self.log, stderr=self.log)
        for _ in range(100):
            try:
                if httpx.get(self.url + "/healthz", timeout=1).status_code == 200:
                    break
            except Exception:
                time.sleep(0.1)
        self.c = httpx.Client(base_url=self.url, timeout=10)

    def store(self):
        sid = self.c.post("/stores", json={"name": "conformance"}).json()["id"]
        mid = self.c.post(f"/stores/{sid}/authorization-models", json=MODEL).json()["authorization_model_id"]
        return sid, mid

    def write(self, sid, mid, writes=(), deletes=()):
        body = {"authorization_model_id": mid}
        if writes:
            body["writes"] = {"tuple_keys": [{"user": u, "relation": r, "object": o} for u, r, o in writes]}
        if deletes:
            body["deletes"] = {"tuple_keys": [{"user": u, "relation": r, "object": o} for u, r, o in deletes]}
        r = self.c.post(f"/stores/{sid}/write", json=body)
        assert r.status_code == 200, r.text

    def check(self, sid, mid, user, rel, obj="document:d1", consistency=None):
        body = {"authorization_model_id": mid, "tuple_key": {"user": user, "relation": rel, "object": obj}}
        if consistency:
            body["consistency"] = consistency
        r = self.c.post(f"/stores/{sid}/check", json=body)
        assert r.status_code == 200, r.text
        return r.json()["allowed"]

    def stop(self):
        self.p.terminate(); self.p.wait(5); self.log.close()


def o1():
    f = FGA(18080)
    try:
        n = agree = 0; ex = []
        for bits in itertools.product((False, True), repeat=len(CANDIDATES)):
            T = {t for t, b in zip(CANDIDATES, bits) if b}
            sid, mid = f.store()
            if T:
                f.write(sid, mid, writes=sorted(T))
            for user in ("user:u1", "user:u2"):
                for rel in RELS:
                    got = f.check(sid, mid, user, rel)
                    exp = reference(T, user, rel)
                    n += 1; agree += got == exp
                    if got != exp and len(ex) < 5:
                        ex.append({"tuples": sorted(T), "user": user, "rel": rel, "got": got, "expected": exp})
        R["O1_L1_differential"] = {"states": 2 ** len(CANDIDATES), "checks": n, "agree": agree, "mismatches": ex}
    finally:
        f.stop()


def window(f, revoke_tuple, setup, delta, consistency, limit=30.0, step=0.05):
    sid, mid = f.store()
    f.write(sid, mid, writes=setup)
    warm = f.check(sid, mid, "user:u1", "viewer", consistency=consistency)
    time.sleep(delta)
    f.write(sid, mid, deletes=[revoke_tuple])
    t0 = time.monotonic(); allows = 0
    while time.monotonic() - t0 < limit:
        if not f.check(sid, mid, "user:u1", "viewer", consistency=consistency):
            return {"delta_s": delta, "warm": warm, "window_s": round(time.monotonic() - t0, 3), "allows": allows}
        allows += 1
        time.sleep(step)
    return {"delta_s": delta, "warm": warm, "window_s": None, "allows": allows}


def o2(n=10):
    cache = ["--check-query-cache-enabled", "--check-query-cache-ttl", "10s"]
    configs = {"A_default": ([], None),
               "B_query_cache_10s": (cache, None),
               "C_cache_plus_controller": (cache + ["--cache-controller-enabled"], None),
               "D_cache_higher_consistency": (cache, "HIGHER_CONSISTENCY")}
    direct = [("user:u1", "viewer", "document:d1")]
    indirect = [("user:u1", "member", "group:g1"), ("group:g1#member", "viewer", "document:d1")]
    out = {}
    port = 18100
    for name, (flags, cons) in configs.items():
        f = FGA(port, flags); port += 10
        try:
            res = []
            for kind, setup, rev in (("direct", direct, direct[0]), ("indirect", indirect, indirect[0])):
                deltas = (0, 5) if name in ("B_query_cache_10s", "C_cache_plus_controller") else (0,)
                for d in deltas:
                    for _ in range(n):
                        r = window(f, rev, setup, d, cons); r["revocation"] = kind; res.append(r)
            out[name] = res
            print(name, [(r["revocation"], r["delta_s"], r["window_s"]) for r in res][:6], flush=True)
        finally:
            f.stop()
    R["O2_L2_revocation"] = out


if __name__ == "__main__":
    ver = subprocess.run([BIN, "version"], capture_output=True, text=True)
    R["version"] = (ver.stdout + ver.stderr).strip()
    o1()
    print("O1", {k: v for k, v in R["O1_L1_differential"].items() if k != "mismatches"}, flush=True)
    o2()
    json.dump(R, open(OUTJ, "w"), indent=1)
