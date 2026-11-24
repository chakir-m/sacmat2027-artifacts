"""
E2-mixed -- L2 coherence oracle: can a decision combine grant components read from DIFFERENT committed
states, and allow a request that no committed state allows?

Scenario per trial (subject u: employee of department LEG; object o: FIN, division ACCT, internal):
  t=0      the FIN director assigns u {write} on o, valid for 10 s           (assignment invalidates u's cache)
  t~0.5    decision (u,o,write): deny (P1); warms both cache entries (assignment {write}, delegation [])
  t=10     the assignment expires                                            (expiry is never checked on hits)
  t>=62    u requests a read delegation; the FIN director approves it        (approval does not invalidate)
  t>=63    decision (u,o,write) and PEP /pep/access?action=write
At every committed state in [0, t] the reference chain denies (u,o,write): first P1 (no delegation), then
P1/P5 (no grant), then P5/P7 (delegation {read} only). An allow is therefore justified by no committed state.
The reference decision of each committed state is recomputed with the shared semantics (semantics.py).

Usage: python e2_mixed.py <backend> <db-url> <redis-url> <out-json> [n_trials]
"""
import asyncio, json, os, sys, time, uuid
from datetime import datetime, timezone, timedelta

BACKEND, DBURL, REDIS, OUTJ = sys.argv[1:5]
N = int(sys.argv[5]) if len(sys.argv) > 5 else 5
os.environ.update({"DATABASE_URL": DBURL, "REDIS_URL": REDIS, "ENVIRONMENT": "test",
                   "SECRET_KEY": "e2_harness_secret_key_32_chars_minimum", "STORAGE_BACKEND": "local"})
sys.path.insert(0, BACKEND)
import logging, structlog                                        # noqa: E402
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
logging.disable(logging.CRITICAL)
import httpx                                                     # noqa: E402
import redis.asyncio as aioredis                                 # noqa: E402
from sqlalchemy import select                                    # noqa: E402
from app.main import app                                         # noqa: E402
from app.db.database import AsyncSessionLocal, engine            # noqa: E402
from app.db.seed import seed_initial_data                        # noqa: E402
from app.models.models import (Base, Subject, Resource, Role, Department, Division,  # noqa: E402
    UserStatus, ClearanceLevel, ResourceSensitivity)
from app.core.security import create_access_token                # noqa: E402

API = "/api/v1"
def now(): return datetime.now(timezone.utc)
def H(sid): return {"Authorization": "Bearer " + create_access_token(sid, f"{sid}@e2", extra_claims={"sv": 0})}


async def setup():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all); await c.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as s:
        await seed_initial_data(s); await s.commit()
    r = aioredis.from_url(REDIS); await r.flushdb(); await r.aclose()
    async with AsyncSessionLocal() as s:
        depts = {d.code: d for d in (await s.execute(select(Department))).scalars()}
        divs = {d.code: d for d in (await s.execute(select(Division))).scalars()}
        roles = {r.builtin_type: r for r in (await s.execute(select(Role))).scalars()}
    return depts, divs, roles


async def mk_subject(roles, role, dept, div=None, clearance="normal", mfa=False):
    async with AsyncSessionLocal() as s:
        sid = str(uuid.uuid4())
        s.add(Subject(id=sid, email=f"{role}-{sid[:8]}@e2.test", username=f"{role}-{sid[:8]}", full_name=role,
                      hashed_password="x", role_id=roles[role].id, department_id=dept.id,
                      division_id=div.id if div else None, clearance=ClearanceLevel(clearance),
                      status=UserStatus.ACTIVE, is_platform_admin=False, mfa_enabled=mfa,
                      session_version=0, attributes={}))
        await s.commit()
    return sid


async def mk_resource(owner, dept, div):
    rid = str(uuid.uuid4())
    os.makedirs("/app/storage/e2m", exist_ok=True); fp = f"e2m/{rid}.txt"
    open(f"/app/storage/{fp}", "w").write("E2-mixed payload " + rid)
    async with AsyncSessionLocal() as s:
        s.add(Resource(id=rid, name=f"m-{rid[:6]}", department_id=dept.id, division_id=div.id, owner_id=owner,
                       sensitivity=ResourceSensitivity("internal"), is_active=True, attributes={}, tags=[],
                       file_path=fp, file_size=50, mime_type="text/plain"))
        await s.commit()
    return rid


def reference(asg, deleg):
    """Reference chain v1 (\\chain) for an employee of another department, normal clearance, internal object,
    low risk, action write: P1 denies iff no delegation; P4 allows iff write in asg; P5 denies an employee
    without assignment; P6 allows iff write in deleg; else P7."""
    if not deleg: return ("deny", "P1")
    if "write" in asg: return ("allow", "P4")
    if not asg: return ("deny", "P5")
    if "write" in deleg: return ("allow", "P6")
    return ("deny", "P7")


async def trial(c, k, depts, divs, roles, dirF):
    FIN, LEG, ACCT = depts["FIN"], depts["LEG"], divs["ACCT"]
    u = await mk_subject(roles, "analyst", LEG)
    o = await mk_resource(dirF, FIN, ACCT)
    dec = lambda: c.post(f"{API}/access/decide", json={"resource_id": o, "action": "write"}, headers=H(u))
    log = []
    t0 = time.monotonic(); T = lambda: round(time.monotonic() - t0, 2)
    r = await c.post(f"{API}/resources/{o}/assignments", json={"subject_id": u, "actions": ["write"],
                     "valid_until": (now() + timedelta(seconds=10)).isoformat()}, headers=H(dirF))
    log.append({"t": T(), "event": "assign {write}, valid 10 s", "status": r.status_code,
                "committed": {"asg": ["write"], "del": []}})
    d0 = (await dec()).json()
    log.append({"t": T(), "event": "decide write (warm)", "decision": d0.get("result"), "rule": d0.get("applied_policy"),
                "reference_committed": reference(["write"], [])})
    await asyncio.sleep(max(0, 62 - (time.monotonic() - t0)))
    log.append({"t": T(), "event": "assignment expired at t=10 (no commit)", "committed": {"asg": [], "del": []},
                "reference_committed": reference([], [])})
    rq = await c.post(f"{API}/delegations", json={"resource_id": o, "justification": "e2-mixed"}, headers=H(u))
    did = rq.json().get("id")
    ap = await c.post(f"{API}/delegations/{did}/approve", json={"expires_at": (now() + timedelta(hours=1)).isoformat()},
                      headers=H(dirF))
    log.append({"t": T(), "event": "read delegation requested and approved", "status": [rq.status_code, ap.status_code],
                "committed": {"asg": [], "del": ["read"]}, "reference_committed": reference([], ["read"])})
    await asyncio.sleep(max(0, 63 - (time.monotonic() - t0)))
    d1 = (await dec()).json()
    pep = await c.get(f"{API}/pep/access/{o}?action=write", headers=H(u))
    log.append({"t": T(), "event": "decide write", "decision": d1.get("result"), "rule": d1.get("applied_policy"),
                "pep_access_write_status": pep.status_code, "reference_committed": reference([], ["read"])})
    refs = {tuple(reference(a, d)) for a, d in ((["write"], []), ([], []), ([], ["read"]))}
    return {"trial": k, "log": log, "final_decision": d1.get("result"), "final_rule": d1.get("applied_policy"),
            "pep_status": pep.status_code, "any_committed_state_allows": any(x[0] == "allow" for x in refs),
            "unjustified_allow": d1.get("result") == "allow" and not any(x[0] == "allow" for x in refs)}


async def main():
    depts, divs, roles = await setup()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://e2",
                                 headers={"X-Requested-With": "XMLHttpRequest"}, timeout=120) as c:
        dirF = await mk_subject(roles, "director", depts["FIN"], clearance="delegated", mfa=True)
        res = await asyncio.gather(*[trial(c, k, depts, divs, roles, dirF) for k in range(N)])
    out = {"backend": BACKEND, "n": N, "trials": res,
           "unjustified_allows": sum(r["unjustified_allow"] for r in res),
           "pep_200": sum(r["pep_status"] == 200 for r in res)}
    json.dump(out, open(OUTJ, "w"), indent=1, default=str)
    print("E2_MIXED", BACKEND, "unjustified allows:", out["unjustified_allows"], "/", N, "pep 200:", out["pep_200"])
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
