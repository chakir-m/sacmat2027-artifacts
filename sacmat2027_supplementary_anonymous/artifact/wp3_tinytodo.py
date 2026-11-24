"""
WP3 -- Layered conformance of an external system: Cedar's TinyTodo reference application
(cedar-policy/cedar-examples, analysed unmodified; it runs from a copy of its directory so
that policy-file edits never touch the clone).

L1  T1  differential: the list set returned by GetLists (computed with Cedar partial
        evaluation + re-authorisation) vs. the lists for which GetList (a concrete
        is_authorized call) succeeds, for every user, over random states, under the shipped
        policy set and a variant with the three commented-out policies (admin omnipotence,
        interns forbid, location forbid) enabled.
L2  T2a policy-change propagation: time from writing a new forbid into the policy file until
        decisions change (the PAP is the file; the PDP reloads it).
    T2b fail-stale reload: the same forbid written together with one policy that fails
        validation (and, separately, a syntax error); is the forbid ever enforced, and does
        any API response signal the divergence?
    T2c share revocation (DeleteShare) takes effect on the next request.
L3  T3a mediation: every mutating or reading endpoint, invoked by a principal without
        permission, is denied (no effect observed afterwards).
    T3b identity binding: the principal is the `uid` field of the request.

Usage: python wp3_tinytodo.py <tinytodo-src-dir> <binary> <work-dir> <out-json>
"""
import json, os, random, shutil, subprocess, sys, time
import httpx

SRC, BIN, WORK, OUTJ = sys.argv[1:5]
USERS = ["kesha", "aaron", "emina", "andrew"]
TEAMS = ["temp", "admin", "interns"]
PORT = 8199
URL = f"http://127.0.0.1:{PORT}/api"
R = {}


def U(u): return f'User::"{u}"'


class Server:
    def __init__(self, policies_text=None):
        if os.path.exists(WORK):
            shutil.rmtree(WORK)
        os.makedirs(WORK)
        for f in ("entities.json", "policies.cedar", "tinytodo.cedarschema",
                  "policies-templates.cedar", "tinytodo-templates.cedarschema"):
            shutil.copy(os.path.join(SRC, f), WORK)
        if policies_text is not None:
            open(os.path.join(WORK, "policies.cedar"), "w").write(policies_text)
        self.log = open(os.path.join(WORK, "server.log"), "w")
        self.p = subprocess.Popen([BIN, str(PORT)], cwd=WORK, stdout=self.log, stderr=self.log,
                                  env=dict(os.environ, RUST_LOG="info"))
        for _ in range(100):
            try:
                httpx.get(f"{URL}/lists/get", params={"uid": U("emina")}, timeout=1)
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("tinytodo did not start")

    def policies_path(self): return os.path.join(WORK, "policies.cedar")

    def stop(self):
        self.p.terminate(); self.p.wait(5); self.log.close()


def ok(r):
    if r.status_code != 200:
        return False
    try:
        b = r.json()
    except ValueError:
        return False
    return not (isinstance(b, dict) and "error" in b)


def create_list(u, name):
    r = httpx.post(f"{URL}/list/create", json={"uid": U(u), "name": name}); return r.json()
def get_list(u, l): return httpx.get(f"{URL}/list/get", params={"uid": U(u), "list": l})
def get_lists(u): return httpx.get(f"{URL}/lists/get", params={"uid": U(u)})
def share(u, l, target, role, add=True):
    body = {"uid": U(u), "list": l, ("share_with" if add else "unshare_with"): target, "role": role}
    if add:
        return httpx.post(f"{URL}/share", json=body)
    return httpx.request("DELETE", f"{URL}/share", json=body)


BASE = open(os.path.join(SRC, "policies.cedar")).read()
ENABLED = BASE + """
// Policies 4-6 of the shipped file, uncommented verbatim
@id("admin-omnipotence")
permit (
   principal in Team::"admin",
   action,
   resource in Application::"TinyTodo"
);
forbid (
    principal in Team::"interns",
    action == Action::"CreateList",
    resource == Application::"TinyTodo"
);
forbid(
    principal,
    action,
    resource is List
) unless {
    principal.joblevel > 6 && principal.location like "DEF*" ||
    principal.location == resource.owner.location
};
"""


def t1_differential(policies, label, rounds=25, seed=1):
    rng = random.Random(seed)
    checks = mism = 0; ex = []
    for rd in range(rounds):
        s = Server(policies)
        try:
            lists = []
            for u in USERS:
                for k in range(rng.randint(1, 3)):
                    r = create_list(u, f"{u}-{rd}-{k}")
                    if isinstance(r, str):
                        lists.append((u, r))
            for owner, l in lists:
                for _ in range(rng.randint(0, 3)):
                    tgt = rng.choice([U(x) for x in USERS] + [f'Team::"{t}"' for t in TEAMS])
                    share(owner, l, tgt, rng.choice(["Reader", "Editor"]))
            for u in USERS:
                r = get_lists(u)
                got = {x["uid"] for x in r.json()} if ok(r) else None
                truth = {l for _, l in lists if ok(get_list(u, l))}
                checks += 1
                if got != truth:
                    mism += 1
                    if len(ex) < 5:
                        ex.append({"round": rd, "user": u, "get_lists": sorted(got or []), "get_list_allowed": sorted(truth)})
        finally:
            s.stop()
    R[f"T1_{label}"] = {"rounds": rounds, "user_checks": checks, "mismatches": mism, "examples": ex}


def poll(fn, want, limit, step=0.02):
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        if fn() == want:
            return round(time.monotonic() - t0, 3)
        time.sleep(step)
    return None


def t2_reload(n=10):
    out = {"propagation_s": [], "invalid_validation": [], "invalid_syntax": [], "share_revocation": []}
    forbid = '\n@id("deny-aaron")\nforbid (principal == User::"aaron", action, resource);\n'
    bad_val = '\npermit (principal, action, resource is List) when { resource.no_such_attr == 1 };\n'
    bad_syn = '\npermit (principal, action, resource) when { ;\n'
    for kind in ("propagation_s", "invalid_validation", "invalid_syntax"):
        for i in range(n):
            s = Server(BASE)
            try:
                l = create_list("emina", "x"); share("emina", l, U("aaron"), "Reader")
                assert ok(get_list("aaron", l))
                time.sleep(1.1 + random.random())        # desynchronise from the 1 s watcher tick
                extra = forbid + ({"invalid_validation": bad_val, "invalid_syntax": bad_syn}.get(kind, ""))
                with open(s.policies_path(), "a") as f:
                    f.write(extra)
                if kind == "propagation_s":
                    out[kind].append(poll(lambda: ok(get_list("aaron", l)), False, 10))
                else:
                    still = poll(lambda: ok(get_list("aaron", l)), False, 5) is None
                    r = get_list("aaron", l)
                    out[kind].append({"forbid_never_enforced_5s": still, "status": r.status_code,
                                      "response_signals_policy_error": "policy" in r.text.lower()})
            finally:
                s.stop()
    for i in range(n):
        s = Server(BASE)
        try:
            l = create_list("emina", "y"); share("emina", l, U("aaron"), "Reader")
            assert ok(get_list("aaron", l))
            share("emina", l, U("aaron"), "Reader", add=False)
            out["share_revocation"].append(not ok(get_list("aaron", l)))
        finally:
            s.stop()
    R["T2"] = out


def t3_enforcement():
    s = Server(BASE)
    try:
        l = create_list("emina", "secret")
        t = httpx.post(f"{URL}/task/create", json={"uid": U("emina"), "list": l, "name": "t"}).json()
        before = get_list("emina", l).json()
        probes = {
            "GET /list/get": lambda: get_list("aaron", l),
            "POST /list/update": lambda: httpx.post(f"{URL}/list/update", json={"uid": U("aaron"), "list": l, "name": "pwn"}),
            "DELETE /list/delete": lambda: httpx.request("DELETE", f"{URL}/list/delete", json={"uid": U("aaron"), "list": l}),
            "POST /task/create": lambda: httpx.post(f"{URL}/task/create", json={"uid": U("aaron"), "list": l, "name": "pwn"}),
            "POST /task/update": lambda: httpx.post(f"{URL}/task/update", json={"uid": U("aaron"), "list": l, "task": t, "name": "pwn"}),
            "DELETE /task/delete": lambda: httpx.request("DELETE", f"{URL}/task/delete", json={"uid": U("aaron"), "list": l, "task": t}),
            "POST /share": lambda: share("aaron", l, U("aaron"), "Editor"),
            "DELETE /share": lambda: share("aaron", l, U("emina"), "Editor", add=False),
        }
        res = {k: {"status": (r := f()).status_code, "allowed": ok(r)} for k, f in probes.items()}
        after = get_list("emina", l).json()
        res["_state_unchanged"] = before == after
        res["_lists_visible_to_aaron"] = [x["uid"] for x in get_lists("aaron").json()] if ok(get_lists("aaron")) else None
        R["T3a_mediation"] = res
        # identity: the caller states the principal; aaron's client simply sends emina's uid
        r = get_list("emina", l)
        R["T3b_identity"] = {"principal_source": "request field `uid` (query string or JSON body)",
                             "request_as_emina_without_credentials_allowed": ok(r)}
    finally:
        s.stop()


if __name__ == "__main__":
    t1_differential(BASE, "shipped_policies")
    t1_differential(ENABLED, "all_example_policies_enabled", seed=2)
    t2_reload()
    t3_enforcement()
    json.dump(R, open(OUTJ, "w"), indent=1)
    print(json.dumps({k: (v if k != "T2" else {kk: vv for kk, vv in v.items()}) for k, v in R.items()}, indent=1)[:4000])
