"""
E1b -- State-level differential conformance (real PostgreSQL, cold cache).

For every combination of role x department relation x assignment lifecycle
state x delegation lifecycle state, inserts the grant rows into PostgreSQL and
asks the REAL PolicyDecisionPoint (real _load_subject/_load_resource/
_build_context queries) for a decision with a cold Redis cache. The expected
decision is M_IMPL applied to grants derived from the manuscript's temporal
definitions (Def. assigned/delegated): an assignment counts iff active and
valid_from <= t < valid_until; a delegation iff approved and t < expires_at.

Usage: python e1b_state.py <backend> <out-dir> <database-url>
       E1_ORACLE=1 -> exit 1 on any mismatch (used by E3)
"""
import asyncio, itertools, json, os, sys, uuid
from datetime import datetime, timezone, timedelta

BACKEND, OUT, DBURL = sys.argv[1], sys.argv[2], sys.argv[3]
os.environ.update({"DATABASE_URL": DBURL, "REDIS_URL": "redis://localhost:6379/0",
                   "SECRET_KEY": "e1b_harness_secret_key_32_chars_minimum", "ENVIRONMENT": "test",
                   "STORAGE_BACKEND": "local"})
sys.path.insert(0, BACKEND); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging, structlog
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL)); logging.disable(logging.CRITICAL)
from sqlalchemy import select                                       # noqa: E402
import redis.asyncio as aioredis                                    # noqa: E402
from app.db.database import AsyncSessionLocal, engine               # noqa: E402
from app.db.seed import seed_initial_data                           # noqa: E402
from app.models.models import (Base, Subject, Resource, Role, Department, Division,  # noqa: E402
    ResourceAssignment, Delegation, DelegationStatus, DecisionResult, UserStatus,
    ClearanceLevel, ResourceSensitivity)
from app.services.pdp import PolicyDecisionPoint, AccessRequest      # noqa: E402
from semantics import M_IMPL, C9_FIX, decide_concrete, ALLOW         # noqa: E402
CHAIN = C9_FIX if os.environ.get("E1B_CHAIN") == "C9_FIX" else M_IMPL   # fork: compare with C9_FIX

ASG = ["none", "active", "inactive", "expired", "not_yet_valid"]
DEL = ["none", "approved_valid", "approved_expired", "pending", "revoked", "rejected", "expired_status"]
ROLES = ["director", "division_manager", "analyst"]
DEPT = ["same", "cross"]
ACTIONS = ["read", "write"]


class Env:
    def __init__(self, role, same_dept, asg_on, del_on):
        self.admin = False
        self.dir, self.dm, self.an = role == "director", role == "division_manager", role == "analyst"
        self.same_dept = same_dept
        self.same_div_raw = self.same_div = same_dept and role != "director"
        self.sens_pos, self.clr_lt_sens = True, False          # internal resource, normal clearance
        self.has_asg, self.has_del = asg_on, del_on
        self.risk_high = False
        self.own = False                                       # the owner is a separate subject
    def own_act(self, a): return a in ("read", "download")
    def asg(self, a): return self.has_asg and a == "read"
    def dele(self, a): return self.has_del and a == "read"
    def is_read(self, a): return a == "read"


async def main():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all); await c.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as s:
        await seed_initial_data(s); await s.commit()
    rds = aioredis.from_url("redis://localhost:6379/0"); await rds.flushall()
    async with AsyncSessionLocal() as s:
        depts = {d.code: d for d in (await s.execute(select(Department))).scalars()}
        divs = {d.code: d for d in (await s.execute(select(Division))).scalars()}
        roles = {r.builtin_type: r for r in (await s.execute(select(Role))).scalars()}
    FIN, LEG, ACCT, COMP = depts["FIN"], depts["LEG"], divs["ACCT"], divs["COMP"]
    now = datetime.now(timezone.utc); H = timedelta(hours=1)
    subj = {}
    async with AsyncSessionLocal() as s:
        for r in ROLES + ["owner"]:
            sid = str(uuid.uuid4()); subj[r] = sid
            s.add(Subject(id=sid, email=f"{r}-{sid[:6]}@e1b", username=f"{r}-{sid[:6]}", full_name=r,
                          hashed_password="x", role_id=roles["director" if r == "owner" else r].id,
                          department_id=(LEG if r == "owner" else FIN).id,
                          division_id=None if r in ("director", "owner") else ACCT.id,
                          clearance=ClearanceLevel.NORMAL, status=UserStatus.ACTIVE,
                          is_platform_admin=False, session_version=0, attributes={}))
        await s.commit()
    n = mism = 0; mismatches = []
    for role, dept, a_st, d_st, act in itertools.product(ROLES, DEPT, ASG, DEL, ACTIONS):
        rid = str(uuid.uuid4())
        async with AsyncSessionLocal() as s:
            s.add(Resource(id=rid, name="e1b", department_id=(FIN if dept == "same" else LEG).id,
                           division_id=(ACCT if dept == "same" else COMP).id, owner_id=subj["owner"],
                           sensitivity=ResourceSensitivity.INTERNAL, is_active=True, attributes={}, tags=[]))
            await s.flush()
            if a_st != "none":
                s.add(ResourceAssignment(id=str(uuid.uuid4()), subject_id=subj[role], resource_id=rid,
                      assigned_by_id=subj["owner"], actions=["read"], is_active=(a_st != "inactive"),
                      valid_from=(now + H) if a_st == "not_yet_valid" else (now - H),
                      valid_until=(now - timedelta(minutes=1)) if a_st == "expired" else None))
            if d_st != "none":
                st = {"approved_valid": DelegationStatus.APPROVED, "approved_expired": DelegationStatus.APPROVED,
                      "pending": DelegationStatus.PENDING, "revoked": DelegationStatus.REVOKED,
                      "rejected": DelegationStatus.REJECTED, "expired_status": DelegationStatus.EXPIRED}[d_st]
                s.add(Delegation(id=str(uuid.uuid4()), requester_id=subj[role], resource_id=rid,
                      justification="e1b", requested_actions=["read"], approved_actions=["read"], status=st,
                      expires_at=(now - timedelta(minutes=1)) if d_st in ("approved_expired", "expired_status") else (now + H)))
            await s.commit()
        async with AsyncSessionLocal() as s:
            res = await PolicyDecisionPoint(s).decide(AccessRequest(subj[role], rid, act, _no_audit=True))
        got = res.result == DecisionResult.ALLOW
        e = Env(role, dept == "same", a_st == "active", d_st == "approved_valid")
        exp_eff, exp_rule = decide_concrete(CHAIN, e, act)
        n += 1
        if (exp_eff == ALLOW) != got or res.result == DecisionResult.INDETERMINATE:
            mism += 1
            mismatches.append({"role": role, "dept": dept, "assignment": a_st, "delegation": d_st, "action": act,
                               "expected": exp_eff, "expected_rule": exp_rule, "got": res.result.value,
                               "got_rule": res.applied_policy_name})
    await rds.aclose()
    out = {"worlds": n, "mismatches": mism, "examples": mismatches[:10],
           "domain": {"roles": ROLES, "dept": DEPT, "assignment_states": ASG, "delegation_states": DEL, "actions": ACTIONS}}
    if os.environ.get("E1_ORACLE") == "1":
        print(f"E1B_ORACLE worlds={n} mismatches={mism}"); sys.exit(1 if mism else 0)
    os.makedirs(OUT, exist_ok=True)
    json.dump(out, open(os.path.join(OUT, "e1b_state.json"), "w"), indent=2, default=str)
    print(json.dumps(out, indent=1, default=str)[:2500])


if __name__ == "__main__":
    asyncio.run(main())
