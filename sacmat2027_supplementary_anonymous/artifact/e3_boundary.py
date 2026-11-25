"""
E3b -- Frozen-clock boundary oracle for the three v1 PDP mutants that E1/E1b do not kill (phase 5).

E3 left three mutants of the v1 PDP that differ from the original only at the instant a grant's validity
bound is reached (ids 80, 82, 88: `valid_from <= now`, `valid_until > now`, `expires_at > now` made strict or
non-strict). With a frozen clock T this oracle decides, on a cold cache, three requests whose grant bound equals
T exactly:
  B1  assignment {read} with valid_from = T     (original: allow, P4)
  B2  assignment {read} with valid_until = T    (original: deny; the grant has just ended)
  B3  delegation {read} with expires_at = T, held by a director of another department (original: deny, P1)
A mutant is killed if any decision or deciding rule differs from the original's (as in E1). Each mutant runs in a child process on a
throw-away copy of v1's pdp.py; the frozen snapshot is never modified.

Usage: python e3_boundary.py <v1-backend> <work-dir> <out-json>
Needs PostgreSQL (database abac_f8) and Redis (db 5).
"""
import ast, asyncio, json, os, shutil, subprocess, sys, uuid
from datetime import datetime, timezone, timedelta

if len(sys.argv) > 1 and sys.argv[1] == "--child":
    BACKEND = sys.argv[2]; OUT = sys.argv[3]
    os.environ.update({"DATABASE_URL": "postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_f8",
                       "REDIS_URL": "redis://localhost:6379/5", "ENVIRONMENT": "test",
                       "SECRET_KEY": "e3b_harness_secret_key_32_chars_minimum_x", "STORAGE_BACKEND": "local"})
    sys.path.insert(0, BACKEND)
    import logging, structlog
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
    logging.disable(logging.CRITICAL)
    import redis.asyncio as aioredis
    from sqlalchemy import select
    from app.db.database import AsyncSessionLocal, engine
    from app.db.seed import seed_initial_data
    from app.models.models import (Base, Subject, Resource, Role, Department, Division, ResourceAssignment,
                                   Delegation, DelegationStatus, UserStatus, ClearanceLevel, ResourceSensitivity,
                                   DecisionResult)
    from app.services import pdp as pdp_mod
    T = datetime(2026, 1, 5, 10, 0, 0, 123456, tzinfo=timezone.utc)

    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return T if tz else T.replace(tzinfo=None)
    pdp_mod.datetime = Frozen

    async def child():
        async with engine.begin() as c:
            await c.run_sync(Base.metadata.drop_all); await c.run_sync(Base.metadata.create_all)
        async with AsyncSessionLocal() as s:
            await seed_initial_data(s); await s.commit()
        async with AsyncSessionLocal() as s:
            depts = {d.code: d for d in (await s.execute(select(Department))).scalars()}
            divs = {d.code: d for d in (await s.execute(select(Division))).scalars()}
            roles = {r.builtin_type: r for r in (await s.execute(select(Role))).scalars()}
        FIN, LEG, ACCT, COMP = depts["FIN"], depts["LEG"], divs["ACCT"], divs["COMP"]
        H = timedelta(hours=1)
        out = {}
        async with AsyncSessionLocal() as s:
            dirF = str(uuid.uuid4()); an = str(uuid.uuid4())
            for sid, role, dept, div in ((dirF, "director", FIN, None), (an, "analyst", FIN, ACCT)):
                s.add(Subject(id=sid, email=f"{sid[:8]}@e3b", username=sid[:8], full_name=role, hashed_password="x",
                              role_id=roles[role].id, department_id=dept.id, division_id=div.id if div else None,
                              clearance=ClearanceLevel.NORMAL, status=UserStatus.ACTIVE, is_platform_admin=False,
                              session_version=0, attributes={}))
            rid = {}
            for k, dept, div in (("B1", FIN, ACCT), ("B2", FIN, ACCT), ("B3", LEG, COMP)):
                rid[k] = str(uuid.uuid4())
                s.add(Resource(id=rid[k], name=k, department_id=dept.id, division_id=div.id, owner_id=dirF,
                               sensitivity=ResourceSensitivity.INTERNAL, is_active=True, attributes={}, tags=[]))
            await s.flush()
            s.add(ResourceAssignment(id=str(uuid.uuid4()), subject_id=an, resource_id=rid["B1"], assigned_by_id=dirF,
                                     actions=["read"], is_active=True, valid_from=T, valid_until=T + H))
            s.add(ResourceAssignment(id=str(uuid.uuid4()), subject_id=an, resource_id=rid["B2"], assigned_by_id=dirF,
                                     actions=["read"], is_active=True, valid_from=T - H, valid_until=T))
            s.add(Delegation(id=str(uuid.uuid4()), requester_id=dirF, resource_id=rid["B3"], justification="e3b",
                             requested_actions=["read"], approved_actions=["read"], status=DelegationStatus.APPROVED,
                             expires_at=T))
            await s.commit()
        rds = aioredis.from_url("redis://localhost:6379/5")
        for k in ("B1", "B2", "B3"):
            await rds.flushdb()
            async with AsyncSessionLocal() as s:
                who = dirF if k == "B3" else an      # B3: a director of another department (P6 would allow)
                d = await pdp_mod.PolicyDecisionPoint(s).decide(pdp_mod.AccessRequest(who, rid[k], "read", _no_audit=True))
            out[k] = [d.result.value, d.applied_policy_name]
        await rds.aclose(); await engine.dispose()
        json.dump(out, open(OUT, "w"))
    asyncio.run(child())
    sys.exit(0)

V1, WORK, OUTJ = sys.argv[1:4]
here = os.path.dirname(os.path.abspath(__file__))
argv = sys.argv; sys.argv = [argv[0], V1, WORK, "/dev/null", sys.executable, here]
sys.path.insert(0, here)
import e3_mutation as E3                                    # noqa: E402
sys.argv = argv
IDS = (80, 82, 88)


def decide_with(pdp_src, tag):
    w = os.path.join(WORK, tag)
    if os.path.exists(w):
        shutil.rmtree(w)
    shutil.copytree(V1, w, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "tests"))
    open(os.path.join(w, E3.SRC_REL), "w").write(pdp_src)
    out = os.path.join(WORK, tag + ".json")
    subprocess.run([sys.executable, os.path.abspath(__file__), "--child", w, out], check=True,
                   env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return json.load(open(out))


tree = ast.parse(open(os.path.join(V1, E3.SRC_REL)).read())
res = {"original": decide_with(ast.unparse(tree), "original"), "mutants": {}}
for i in IDS:
    kind, line, src = E3.apply(tree, i)
    d = decide_with(src, f"m{i}")
    diff = {k: (res["original"][k], d[k]) for k in d if d[k] != res["original"][k]}
    res["mutants"][str(i)] = {"op": kind, "line": line, "decisions": d, "killed": bool(diff), "differs_on": diff}
json.dump(res, open(OUTJ, "w"), indent=1)
print(json.dumps(res, indent=1))
