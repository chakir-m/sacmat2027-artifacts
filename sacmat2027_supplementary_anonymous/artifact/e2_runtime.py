"""
E2 -- State- and enforcement-level conformance on the running application.

Runs the real FastAPI app in-process (httpx ASGITransport) against real
PostgreSQL 16 and Redis 7, using the application's own get_db dependency
(no override), so transaction/rollback behaviour is the production one.
Application code is imported read-only; the harness only:
  * creates fixtures (subjects, resources, grants) through the ORM or the API,
  * mints access tokens with the app's own create_access_token,
  * for E2-race-forced, wraps pip_cache.invalidate_subject to inject one
    concurrent decision (instrumentation of timing, not of semantics).

Usage: python e2_runtime.py <backend> <out-dir> <database-url> <part>
       part in {audit, enforce, revoke, expiry, race, all}
"""
import asyncio, json, os, sys, time, uuid, random, statistics
from datetime import datetime, timezone, timedelta

BACKEND, OUT, DBURL, PART = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
os.environ.update({"DATABASE_URL": DBURL, "REDIS_URL": "redis://localhost:6379/0",
                   "SECRET_KEY": "e2_harness_secret_key_32_chars_minimum",
                   "ENVIRONMENT": "test", "STORAGE_BACKEND": "local"})
sys.path.insert(0, BACKEND)
import logging, structlog
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
logging.disable(logging.CRITICAL)

import httpx                                                   # noqa: E402
from sqlalchemy import select, func                            # noqa: E402
import redis.asyncio as aioredis                               # noqa: E402
from app.main import app                                       # noqa: E402
from app.db.database import AsyncSessionLocal, engine          # noqa: E402
from app.db.seed import seed_initial_data                      # noqa: E402
from app.models.models import (Base, Subject, Resource, Role, Department, Division,  # noqa: E402
    AccessDecision, AuditLog, ResourceAssignment, Document, DocumentSpace,
    DocumentStatus, UserStatus, ClearanceLevel, ResourceSensitivity)
from app.core.security import create_access_token, get_password_hash  # noqa: E402
from app.services import pip as pip_mod                         # noqa: E402
from app.services.pdp import PolicyDecisionPoint, AccessRequest  # noqa: E402

API = "/api/v1"
R = {}  # results
REPS = int(os.environ.get("E2_REPS", "3"))   # trials per delta (published runs: 3; WP6: 10)


def now():
    return datetime.now(timezone.utc)


async def setup_db():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as s:
        await seed_initial_data(s)
        await s.commit()
    r = aioredis.from_url("redis://localhost:6379/0")
    await r.flushall(); await r.aclose()


async def ctx():
    async with AsyncSessionLocal() as s:
        depts = {d.code: d for d in (await s.execute(select(Department))).scalars()}
        divs = {d.code: d for d in (await s.execute(select(Division))).scalars()}
        roles = {r.builtin_type: r for r in (await s.execute(select(Role))).scalars()}
        admin = (await s.execute(select(Subject).where(Subject.is_platform_admin == True))).scalars().first()  # noqa
    return depts, divs, roles, admin


async def mk_subject(roles, role, dept, div=None, clearance="normal", mfa=False):
    async with AsyncSessionLocal() as s:
        sid = str(uuid.uuid4())
        s.add(Subject(id=sid, email=f"{role}-{sid[:8]}@e2.test", username=f"{role}-{sid[:8]}",
                      full_name=f"{role} {sid[:4]}", hashed_password="x", role_id=roles[role].id,
                      department_id=dept.id, division_id=div.id if div else None,
                      clearance=ClearanceLevel(clearance), status=UserStatus.ACTIVE,
                      is_platform_admin=False, mfa_enabled=mfa, session_version=0, attributes={}))
        await s.commit()
    return sid


async def mk_resource(owner, dept, div=None, sens="internal", with_file=False):
    rid = str(uuid.uuid4()); fp = None
    if with_file:
        os.makedirs("/app/storage/e2", exist_ok=True)
        fp = f"e2/{rid}.txt"
        with open(f"/app/storage/{fp}", "w") as f:
            f.write("E2 payload " + rid)
    async with AsyncSessionLocal() as s:
        s.add(Resource(id=rid, name=f"res-{rid[:6]}", department_id=dept.id,
                       division_id=div.id if div else None, owner_id=owner,
                       sensitivity=ResourceSensitivity(sens), is_active=True, attributes={}, tags=[],
                       file_path=fp, file_size=(len("E2 payload ") + 36) if fp else None,
                       mime_type="text/plain" if fp else None))
        await s.commit()
    return rid


def H(sid):
    return {"Authorization": "Bearer " + create_access_token(sid, f"{sid}@e2", extra_claims={"sv": 0})}


async def count_rows(sid, rid):
    async with AsyncSessionLocal() as s:
        ad = (await s.execute(select(func.count()).select_from(AccessDecision).where(
            AccessDecision.subject_id == sid, AccessDecision.resource_id == rid))).scalar()
        al = (await s.execute(select(func.count()).select_from(AuditLog).where(
            AuditLog.subject_id == sid, AuditLog.entity_id == rid))).scalar()
    return ad, al


async def decide(c, sid, rid, action="read"):
    r = await c.post(f"{API}/access/decide", json={"resource_id": rid, "action": action}, headers=H(sid))
    j = r.json()
    return j.get("result"), j.get("applied_policy")


# ─── E2a: audit persistence per enforcement endpoint ─────────────────────────
async def part_audit(c, depts, divs, roles, admin):
    FIN, ACCT = depts["FIN"], divs["ACCT"]
    director = await mk_subject(roles, "director", FIN, clearance="elevated")
    analyst = await mk_subject(roles, "analyst", FIN, ACCT)
    owner = await mk_subject(roles, "division_manager", FIN, divs["AUD"])
    rid = await mk_resource(owner, FIN, ACCT, "internal", with_file=True)
    endpoints = {
        "POST /access/decide": lambda h: c.post(f"{API}/access/decide", json={"resource_id": rid, "action": "read"}, headers=h),
        "GET /pep/access/{id}": lambda h: c.get(f"{API}/pep/access/{rid}", headers=h),
        "GET /pep/preview/{id}": lambda h: c.get(f"{API}/pep/preview/{rid}", headers=h),
        "GET /pep/download/{id}": lambda h: c.get(f"{API}/pep/download/{rid}", headers=h),
        "GET /pep/access/{id}/check": lambda h: c.get(f"{API}/pep/access/{rid}/check", headers=h),
    }
    N = 20
    out = {}
    for name, call in endpoints.items():
        for label, sid in (("allow(director,P2)", director), ("deny(analyst,P5)", analyst)):
            ad0, al0 = await count_rows(sid, rid)
            codes = []
            for _ in range(N):
                resp = await call(H(sid)); codes.append(resp.status_code)
            ad1, al1 = await count_rows(sid, rid)
            out[f"{name} | {label}"] = {"requests": N, "http_status": sorted(set(codes)),
                                        "access_decisions_rows_added": ad1 - ad0,
                                        "audit_logs_rows_added": al1 - al0}
    R["E2a_audit_persistence"] = out


# ─── E2-enforce: path-level divergences ──────────────────────────────────────
async def part_enforce(c, depts, divs, roles, admin):
    FIN, LEG, ACCT = depts["FIN"], depts["LEG"], divs["ACCT"]
    res = {}
    # (i) document API vs PEP for a published TOP_SECRET document
    owner = await mk_subject(roles, "director", FIN, clearance="delegated")
    an = await mk_subject(roles, "analyst", FIN, ACCT, clearance="normal")
    async with AsyncSessionLocal() as s:
        sp = DocumentSpace(id=str(uuid.uuid4()), name="E2 space", department_id=FIN.id, created_by_id=owner)
        s.add(sp); await s.flush()
        did = str(uuid.uuid4())
        s.add(Document(id=did, title="E2 top-secret memo", space_id=sp.id, department_id=FIN.id,
                       division_id=ACCT.id, owner_id=owner, sensitivity=ResourceSensitivity.TOP_SECRET,
                       status=DocumentStatus.PUBLISHED, content_json={"type": "doc", "secret": "TS-PAYLOAD"}))
        lr = str(uuid.uuid4())
        s.add(Resource(id=lr, name="E2 top-secret memo", department_id=FIN.id, division_id=ACCT.id,
                       owner_id=owner, sensitivity=ResourceSensitivity.TOP_SECRET, is_active=True,
                       attributes={"document_id": did, "source": "edm"}, tags=[],
                       content_json={"type": "doc", "secret": "TS-PAYLOAD"}))
        await s.commit()
    r1 = await c.get(f"{API}/documents/{did}", headers=H(an))
    r2 = await c.get(f"{API}/pep/access/{lr}", headers=H(an))
    d3 = await decide(c, an, lr)
    res["doc_api_vs_pep_top_secret"] = {
        "subject": "analyst, clearance=normal, no assignment, same dept/div",
        "GET /documents/{id}": r1.status_code,
        "content_returned": "TS-PAYLOAD" in r1.text,
        "GET /pep/access/{linked_resource}": r2.status_code,
        "PDP decision": d3}
    # (ii) obligations: TOP_SECRET, director without MFA
    d = await mk_subject(roles, "director", FIN, clearance="delegated", mfa=False)
    rts = await mk_resource(an, FIN, ACCT, "top_secret", with_file=True)  # owner != d (no owner bypass)
    res["mfa_obligation_by_endpoint"] = {
        "PDP decision": await decide(c, d, rts),
        "GET /pep/access/{id}": (await c.get(f"{API}/pep/access/{rts}", headers=H(d))).status_code,
        "GET /pep/preview/{id}": (await c.get(f"{API}/pep/preview/{rts}", headers=H(d))).status_code,
        "GET /pep/download/{id}": (await c.get(f"{API}/pep/download/{rts}", headers=H(d))).status_code}
    # (iii) owner bypass across departments
    an_fin = await mk_subject(roles, "analyst", FIN, ACCT)
    r_leg = await mk_resource(an_fin, LEG, divs["COMP"], "sensitive", with_file=True)
    res["owner_bypass_cross_dept"] = {
        "setup": "Legal SENSITIVE resource owned by a Finance analyst (normal clearance)",
        "PDP decision": await decide(c, an_fin, r_leg),
        "GET /pep/access/{id}?action=delete": (await c.get(f"{API}/pep/access/{r_leg}?action=delete", headers=H(an_fin))).status_code,
        "GET /pep/download/{id}": (await c.get(f"{API}/pep/download/{r_leg}", headers=H(an_fin))).status_code}
    # (iv) client-chosen action on download
    dirf = await mk_subject(roles, "director", FIN, clearance="elevated")
    an2 = await mk_subject(roles, "analyst", FIN, ACCT)
    r4 = await mk_resource(dirf, FIN, ACCT, "internal", with_file=True)
    ra = await c.post(f"{API}/resources/{r4}/assignments", json={"subject_id": an2, "actions": ["read"]}, headers=H(dirf))
    res["download_action_chosen_by_client"] = {
        "assignment": {"status": ra.status_code, "actions": ["read"]},
        "PDP(download)": await decide(c, an2, r4, "download"),
        "GET /pep/download/{id}": (await c.get(f"{API}/pep/download/{r4}", headers=H(an2))).status_code,
        "GET /pep/download/{id}?action=download": (await c.get(f"{API}/pep/download/{r4}?action=download", headers=H(an2))).status_code}
    # (v) revocation authority: unrelated analyst revokes a delegation and an assignment
    LEGdir = await mk_subject(roles, "director", LEG, clearance="elevated")
    stranger = await mk_subject(roles, "analyst", LEG, divs["CONT"])
    rL = await mk_resource(LEGdir, LEG, divs["COMP"], "internal")
    dr = await c.post(f"{API}/delegations", json={"resource_id": rL, "justification": "e2"}, headers=H(dirf))
    dl = dr.json()["id"]
    await c.post(f"{API}/delegations/{dl}/approve", json={"expires_at": (now() + timedelta(hours=1)).isoformat()}, headers=H(LEGdir))
    rv = await c.post(f"{API}/delegations/{dl}/revoke", json={"reason": "e2"}, headers=H(stranger))
    asg_id = ra.json().get("id")
    rva = await c.delete(f"{API}/resources/{r4}/assignments/{asg_id}", headers=H(stranger))
    res["revocation_authority"] = {
        "unrelated Legal analyst revokes Finance director's delegation": rv.status_code,
        "unrelated Legal analyst revokes Finance assignment": rva.status_code}
    # (vi) cross-department write via delegation + assignment
    dm_fin = await mk_subject(roles, "division_manager", FIN, divs["AUD"])
    rL2 = await mk_resource(LEGdir, LEG, divs["COMP"], "internal")
    a1 = await c.post(f"{API}/resources/{rL2}/assignments", json={"subject_id": dm_fin, "actions": ["read", "write"]}, headers=H(LEGdir))
    pre = await decide(c, dm_fin, rL2, "write")
    dr2 = await c.post(f"{API}/delegations", json={"resource_id": rL2, "justification": "e2"}, headers=H(dm_fin))
    ap2 = await c.post(f"{API}/delegations/{dr2.json()['id']}/approve", json={"expires_at": (now() + timedelta(hours=1)).isoformat()}, headers=H(LEGdir))
    await asyncio.sleep(61)  # let the negative delegation cache entry (60 s) expire
    post = await decide(c, dm_fin, rL2, "write")
    res["cross_dept_write"] = {"assignment_create": a1.status_code, "approve": ap2.status_code,
                               "approved_actions": ap2.json().get("approved_actions"),
                               "PDP(write) before delegation": pre, "PDP(write) after read-only delegation": post}
    R["E2_enforcement"] = res


# ─── E2b/E2c/E2d: revocation and expiry staleness windows ───────────────────
async def poll_until_deny(c, sid, rid, t_ref, limit=200.0, step=0.25):
    allows = 0
    while True:
        res, pol = await decide(c, sid, rid)
        t = time.monotonic()
        if res != "allow":
            return round(t - t_ref, 2), allows, pol
        allows += 1
        if t - t_ref > limit:
            return None, allows, pol
        await asyncio.sleep(step)


async def trial_deleg_revoke(c, depts, divs, roles, delta, req, LEGdir):
    rid = await mk_resource(LEGdir, depts["LEG"], divs["COMP"], "internal")
    d = (await c.post(f"{API}/delegations", json={"resource_id": rid, "justification": "e2"}, headers=H(req))).json()["id"]
    await c.post(f"{API}/delegations/{d}/approve", json={"expires_at": (now() + timedelta(hours=1)).isoformat()}, headers=H(LEGdir))
    warm = await decide(c, req, rid)
    await asyncio.sleep(delta)
    rv = await c.post(f"{API}/delegations/{d}/revoke", json={"reason": "e2"}, headers=H(LEGdir))
    t_r = time.monotonic()
    w, n, pol = await poll_until_deny(c, req, rid, t_r)
    return {"delta_s": delta, "warm": warm, "revoke_http": rv.status_code, "window_s": w,
            "allows_after_revoke": n, "final_policy": pol}


async def trial_deleg_expiry(c, depts, divs, roles, delta, req, LEGdir, E=70.0):
    rid = await mk_resource(LEGdir, depts["LEG"], divs["COMP"], "internal")
    d = (await c.post(f"{API}/delegations", json={"resource_id": rid, "justification": "e2"}, headers=H(req))).json()["id"]
    t0 = time.monotonic(); exp = now() + timedelta(seconds=E)
    await c.post(f"{API}/delegations/{d}/approve", json={"expires_at": exp.isoformat()}, headers=H(LEGdir))
    await asyncio.sleep(max(0.0, E - delta - (time.monotonic() - t0)))
    warm = await decide(c, req, rid)
    await asyncio.sleep(max(0.0, E - (time.monotonic() - t0)))
    t_e = time.monotonic()
    w, n, pol = await poll_until_deny(c, req, rid, t_e)
    return {"delta_s": delta, "warm": warm, "window_after_expiry_s": w, "allows_after_expiry": n, "final_policy": pol}


async def trial_asg_expiry(c, depts, divs, roles, delta, E=110.0):
    FIN, ACCT = depts["FIN"], divs["ACCT"]
    dirf = await mk_subject(roles, "director", FIN, clearance="elevated")
    an = await mk_subject(roles, "analyst", FIN, ACCT)
    rid = await mk_resource(dirf, FIN, ACCT, "internal")
    t0 = time.monotonic(); exp = now() + timedelta(seconds=E)
    await c.post(f"{API}/resources/{rid}/assignments", json={"subject_id": an, "actions": ["read"], "valid_until": exp.isoformat()}, headers=H(dirf))
    await asyncio.sleep(max(0.0, E - delta - (time.monotonic() - t0)))
    warm = await decide(c, an, rid)
    await asyncio.sleep(max(0.0, E - (time.monotonic() - t0)))
    t_e = time.monotonic()
    w, n, pol = await poll_until_deny(c, an, rid, t_e)
    return {"delta_s": delta, "warm": warm, "window_after_expiry_s": w, "allows_after_expiry": n, "final_policy": pol}


async def trial_asg_revoke_control(c, depts, divs, roles):
    FIN, ACCT = depts["FIN"], divs["ACCT"]
    dirf = await mk_subject(roles, "director", FIN, clearance="elevated")
    an = await mk_subject(roles, "analyst", FIN, ACCT)
    rid = await mk_resource(dirf, FIN, ACCT, "internal")
    a = (await c.post(f"{API}/resources/{rid}/assignments", json={"subject_id": an, "actions": ["read"]}, headers=H(dirf))).json()["id"]
    warm = await decide(c, an, rid)
    await c.delete(f"{API}/resources/{rid}/assignments/{a}", headers=H(dirf))
    t_r = time.monotonic()
    w, n, pol = await poll_until_deny(c, an, rid, t_r)
    return {"warm": warm, "window_s": w, "allows_after_revoke": n, "final_policy": pol}


async def part_revoke(c, depts, divs, roles, admin):
    LEGdir = await mk_subject(roles, "director", depts["LEG"], clearance="elevated")
    trials = []
    for delta in (0, 15, 30, 45):
        for _ in range(REPS):
            req = await mk_subject(roles, "director", depts["FIN"], clearance="elevated")
            trials.append(trial_deleg_revoke(c, depts, divs, roles, delta, req, LEGdir))
    R["E2b_delegation_revocation"] = await asyncio.gather(*trials)
    R["E2b_control_assignment_revocation"] = await asyncio.gather(
        *[trial_asg_revoke_control(c, depts, divs, roles) for _ in range(5)])


async def part_expiry(c, depts, divs, roles, admin):
    LEGdir = await mk_subject(roles, "director", depts["LEG"], clearance="elevated")
    jobs = []
    for delta in (10, 30, 50):
        for _ in range(REPS):
            req = await mk_subject(roles, "director", depts["FIN"], clearance="elevated")
            jobs.append(("deleg", trial_deleg_expiry(c, depts, divs, roles, delta, req, LEGdir)))
    for delta in (20, 60, 100):
        for _ in range(REPS):
            jobs.append(("asg", trial_asg_expiry(c, depts, divs, roles, delta)))
    out = await asyncio.gather(*[j for _, j in jobs])
    R["E2c_delegation_expiry"] = [o for (k, _), o in zip(jobs, out) if k == "deleg"]
    R["E2d_assignment_expiry"] = [o for (k, _), o in zip(jobs, out) if k == "asg"]


# ─── E2e: invalidate-before-commit race ──────────────────────────────────────
async def served_entry(rds, base, sid, rid):
    """The entry a decision would be served now: plain key (snapshot layout) or the key
    under the current generation counters (evaluation-fork layout, DR3)."""
    v = await rds.get(base)
    if v is None:
        g0, gs, gr = [x or "0" for x in await rds.mget("pip:gen:all", f"pip:gen:s:{sid}", f"pip:gen:r:{rid}")]
        v = await rds.get(f"{base}:{g0}:{gs}:{gr}")
    return v


async def part_race(c, depts, divs, roles, admin):
    FIN, ACCT = depts["FIN"], divs["ACCT"]
    orig = pip_mod.PIPCache.invalidate_subject

    async def forced(self, subject_id):
        await orig(self, subject_id)
        # one concurrent decision in a separate session, after invalidation, before commit
        async with AsyncSessionLocal() as s2:
            await PolicyDecisionPoint(s2).decide(AccessRequest(subject_id, FORCED["rid"], "read", _no_audit=True))
    FORCED = {}
    forced_out = []
    for _ in range(REPS):
        dirf = await mk_subject(roles, "director", FIN, clearance="elevated")
        an = await mk_subject(roles, "analyst", FIN, ACCT)
        rid = await mk_resource(dirf, FIN, ACCT, "internal")
        a = (await c.post(f"{API}/resources/{rid}/assignments", json={"subject_id": an, "actions": ["read"]}, headers=H(dirf))).json()["id"]
        await decide(c, an, rid)
        FORCED["rid"] = rid
        pip_mod.PIPCache.invalidate_subject = forced
        await c.delete(f"{API}/resources/{rid}/assignments/{a}", headers=H(dirf))
        pip_mod.PIPCache.invalidate_subject = orig
        t_r = time.monotonic()
        w, n, pol = await poll_until_deny(c, an, rid, t_r, limit=200)
        forced_out.append({"window_s": w, "allows_after_revoke": n, "final_policy": pol})
    R["E2e_race_forced_interleaving"] = forced_out

    # unforced: concurrent decisions racing a revoke, in-process (single event loop)
    rds = aioredis.from_url("redis://localhost:6379/0", decode_responses=True)
    stale = 0; T = 60
    for _ in range(T):
        dirf = await mk_subject(roles, "director", FIN, clearance="elevated")
        an = await mk_subject(roles, "analyst", FIN, ACCT)
        rid = await mk_resource(dirf, FIN, ACCT, "internal")
        a = (await c.post(f"{API}/resources/{rid}/assignments", json={"subject_id": an, "actions": ["read"]}, headers=H(dirf))).json()["id"]
        async for k in rds.scan_iter(match=f"pip:assign:{an}:{rid}*"):   # cold cache (both layouts)
            await rds.delete(k)
        tasks = [c.delete(f"{API}/resources/{rid}/assignments/{a}", headers=H(dirf))]
        tasks += [decide(c, an, rid) for _ in range(8)]
        random.shuffle(tasks)
        await asyncio.gather(*tasks)
        v = await served_entry(rds, f"pip:assign:{an}:{rid}", an, rid)
        if v and json.loads(v).get("actions"):
            stale += 1
    await rds.aclose()
    R["E2e_race_unforced"] = {"trials": T, "concurrent_decisions_per_trial": 8,
                              "trials_with_stale_grant_cached_after_commit": stale}


async def main():
    await setup_db()
    depts, divs, roles, admin = await ctx()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://e2",
                                 headers={"X-Requested-With": "XMLHttpRequest"}, timeout=60) as c:
        parts = {"audit": part_audit, "enforce": part_enforce, "revoke": part_revoke,
                 "expiry": part_expiry, "race": part_race}
        for name, fn in parts.items():
            if PART in (name, "all"):
                t0 = time.time()
                await fn(c, depts, divs, roles, admin)
                R.setdefault("_runtime_s", {})[name] = round(time.time() - t0, 1)
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, f"e2_{PART}.json")
    with open(path, "w") as f:
        json.dump(R, f, indent=2, default=str)
    print(json.dumps(R, indent=1, default=str)[:6000])


if __name__ == "__main__":
    asyncio.run(main())
