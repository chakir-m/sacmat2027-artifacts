"""
L3 stranger sweep over every in-scope GET route of the generated inventory (phase 6).

The L3 probe exercises 27 of the 100 in-scope routes of the inventory (l3_route_inventory.py) with fixtures
chosen per route. This sweep adds a uniform safety check for every in-scope GET route: it builds one world in
which a department (FIN) owns objects whose every text field carries a secret marker, fills each route's path
parameters with the identifiers of those objects, and sends the request three times:
  dir   the FIN director (baseline: the route works on this fixture and returns the object),
  strL  an employee of another department with no grant (R1 forbids every access),
  strF  an employee of the same division with no grant (R3 forbids every access).
Each text field carries a marker of its kind. A 2xx response to strL or strF is flagged CONTENT if it reveals a
content field (document body, file, comment, old version, task, delegation justification, notification) and
META if it reveals only names or titles (document title, object name, space, folder). Names of people are
recorded but not flagged. A 2xx that reveals nothing (an empty list, for example) is recorded but not flagged. Routes that need the internal secret are sent
without it. The application runs in-process; the fork and the snapshot are not modified.

Usage: python l3_stranger_sweep.py <backend> <inventory-json> <out-json>
Needs PostgreSQL (database abac_f8) and Redis (db 5).
"""
import asyncio, json, os, re, sys, uuid
BACKEND, INV, OUT = sys.argv[1:4]
os.environ.update({"DATABASE_URL": "postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_f8",
                   "REDIS_URL": "redis://localhost:6379/5", "ENVIRONMENT": "test",
                   "SECRET_KEY": "sweep_harness_secret_key_32_chars_minimum", "STORAGE_BACKEND": "local"})
sys.path.insert(0, BACKEND)
import logging, structlog                                                   # noqa: E402
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
logging.disable(logging.CRITICAL)
import httpx, redis.asyncio as aioredis                                     # noqa: E402
from sqlalchemy import select                                               # noqa: E402
from app.main import app                                                    # noqa: E402
from app.db.database import AsyncSessionLocal, engine                       # noqa: E402
from app.db.seed import seed_initial_data                                   # noqa: E402
from app.models.models import (Base, Subject, Role, Department, Division, Resource, Document, DocumentSpace,  # noqa: E402
    DocumentStatus, DocumentComment, DocumentVersion, DocumentTask, DocumentLink, DocumentFolder, Notification,
    Delegation, DelegationStatus, ResourceAssignment, Policy, UserStatus, ClearanceLevel, ResourceSensitivity)
from app.core.security import create_access_token                           # noqa: E402

MARK = "SWEEP"
# one marker per kind of field, so that a response can be classified by what it reveals
MK = {"body": "SWEEPBODYX", "file": "SWEEPFILEX", "comment": "SWEEPCOMMENTX", "version": "SWEEPVERSIONX",
      "task": "SWEEPTASKX", "justification": "SWEEPJUSTX", "note": "SWEEPNOTEX",
      "doc_title": "SWEEPDOCTITLEX", "res_name": "SWEEPRESNAMEX", "space": "SWEEPSPACEX", "folder": "SWEEPFOLDERX",
      "person": "SWEEPPERSONX"}
CONTENT_KINDS = {"body", "file", "comment", "version", "task", "justification", "note"}
API = "/api/v1"


def H(sid):
    return {"Authorization": "Bearer " + create_access_token(sid, f"{sid}@sweep", extra_claims={"sv": 0}),
            "X-Requested-With": "XMLHttpRequest"}


async def setup():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all); await c.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as s:
        await seed_initial_data(s); await s.commit()
    r = aioredis.from_url("redis://localhost:6379/5"); await r.flushdb(); await r.aclose()
    async with AsyncSessionLocal() as s:
        depts = {d.code: d for d in (await s.execute(select(Department))).scalars()}
        divs = {d.code: d for d in (await s.execute(select(Division))).scalars()}
        roles = {x.builtin_type: x for x in (await s.execute(select(Role))).scalars()}
        p1 = (await s.execute(select(Policy).where(Policy.builtin_id == "P1"))).scalar_one()
        FIN, LEG, ACCT, COMP = depts["FIN"], depts["LEG"], divs["ACCT"], divs["COMP"]
        ids = {"policy_id": p1.id}

        def subj(role, dept, div):
            sid = str(uuid.uuid4())
            s.add(Subject(id=sid, email=f"{sid[:8]}@sweep.test", username=f"sw{sid[:8]}", full_name=f"{MK['person']} {role}",
                          hashed_password="x", role_id=roles[role].id, department_id=dept.id,
                          division_id=div.id if div else None, clearance=ClearanceLevel.NORMAL,
                          status=UserStatus.ACTIVE, is_platform_admin=False, mfa_enabled=False, session_version=0,
                          attributes={}))
            return sid
        dirF = subj("director", FIN, None); dirL = subj("director", LEG, None)
        strL = subj("analyst", LEG, COMP); strF = subj("analyst", FIN, ACCT)
        await s.flush()
        os.makedirs("/app/storage/sweep", exist_ok=True)
        rid = str(uuid.uuid4()); fp = f"sweep/{rid}.txt"
        open(f"/app/storage/{fp}", "w").write(f"{MK['file']} file payload")
        s.add(Resource(id=rid, name=f"{MK['res_name']} resource", department_id=FIN.id, division_id=ACCT.id, owner_id=dirF,
                       sensitivity=ResourceSensitivity.INTERNAL, is_active=True, attributes={}, tags=[],
                       file_path=fp, file_size=24, mime_type="text/plain"))
        sp = DocumentSpace(id=str(uuid.uuid4()), name=f"{MK['space']} space", department_id=FIN.id, created_by_id=dirF)
        s.add(sp); await s.flush()
        fo = DocumentFolder(id=str(uuid.uuid4()), name=f"{MK['folder']} folder", space_id=sp.id, created_by_id=dirF)
        s.add(fo)
        docs = []
        for st in (DocumentStatus.PUBLISHED, DocumentStatus.DRAFT):
            did = str(uuid.uuid4()); lr = str(uuid.uuid4())
            s.add(Document(id=did, title=f"{MK['doc_title']} {st.value}", space_id=sp.id, department_id=FIN.id,
                           division_id=ACCT.id, owner_id=dirF, sensitivity=ResourceSensitivity.INTERNAL, status=st,
                           requires_signature=True, content_json={"type": "doc", "text": f"{MK['body']} body"}))
            if st == DocumentStatus.PUBLISHED:
                s.add(Resource(id=lr, name=f"{MK['res_name']} doc object", department_id=FIN.id, division_id=ACCT.id,
                               owner_id=dirF, sensitivity=ResourceSensitivity.INTERNAL, is_active=True,
                               attributes={"document_id": did, "source": "edm"}, tags=[]))
            docs.append(did)
        await s.flush()
        did = docs[0]
        cm = DocumentComment(id=str(uuid.uuid4()), document_id=did, author_id=dirF, content=f"{MK['comment']} comment")
        ve = DocumentVersion(id=str(uuid.uuid4()), document_id=did, version_number=1, title=f"{MK['doc_title']} v1",
                             created_by_id=dirF, content_json={"type": "doc", "text": f"{MK['version']} old body"})
        ta = DocumentTask(id=str(uuid.uuid4()), document_id=did, title=f"{MK['task']} task", created_by_id=dirF)
        li = DocumentLink(id=str(uuid.uuid4()), source_id=did, target_id=docs[1], created_by_id=dirF)
        no = Notification(id=str(uuid.uuid4()), recipient_id=dirF, type="x", title=f"{MK['note']} note", body=MK["note"])
        rL = str(uuid.uuid4())
        s.add(Resource(id=rL, name="legal object", department_id=LEG.id, division_id=COMP.id, owner_id=dirL,
                       sensitivity=ResourceSensitivity.INTERNAL, is_active=True, attributes={}, tags=[]))
        await s.flush()
        de = Delegation(id=str(uuid.uuid4()), requester_id=dirF, resource_id=rL, justification=f"{MK['justification']} reason",
                        requested_actions=["read"], approved_actions=["read"], status=DelegationStatus.PENDING)
        asg = ResourceAssignment(id=str(uuid.uuid4()), subject_id=dirF, resource_id=rid, assigned_by_id=dirF,
                                 actions=["read"], is_active=True)
        for x in (cm, ve, ta, li, no, de, asg):
            s.add(x)
        await s.commit()
        ids.update({"doc_id": did, "resource_id": rid, "space_id": sp.id, "subject_id": dirF, "delegation_id": de.id,
                    "task_id": ta.id, "assignment_id": asg.id, "folder_id": fo.id, "link_id": li.id,
                    "version_id": ve.id, "comment_id": cm.id, "notification_id": no.id})
    return ids, {"dir": dirF, "strL": strL, "strF": strF}


async def main():
    inv = json.load(open(INV))
    routes = [r for r in inv["routes"] if r["in_scope"] and r["methods"] == ["GET"]]
    ids, who = await setup()
    out = []
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                 base_url="http://sweep", timeout=60) as c:
        for r in routes:
            path = re.sub(r"\{(\w+)\}", lambda m: ids.get(m.group(1), "missing"), r["path"])
            row = {"path": r["path"], "url_params_filled": "missing" not in path}
            for k, sid in who.items():
                resp = await c.get(path, headers=H(sid))
                body = resp.text
                row[k] = {"status": resp.status_code, "reveals": sorted(x for x, m in MK.items() if m in body)}
            row["content_flag"] = any(row[k]["status"] < 300 and set(row[k]["reveals"]) & CONTENT_KINDS
                                      for k in ("strL", "strF"))
            row["metadata_flag"] = any(row[k]["status"] < 300 and set(row[k]["reveals"]) - CONTENT_KINDS - {"person"}
                                       for k in ("strL", "strF"))
            row["flag"] = row["content_flag"]
            out.append(row)
            print(("CONT " if row["content_flag"] else "META " if row["metadata_flag"] else "     ") + r["path"],
                  row["dir"]["status"], row["strL"]["status"], row["strL"]["reveals"], row["strF"]["status"],
                  row["strF"]["reveals"], flush=True)
    await engine.dispose()
    res = {"routes": len(out), "content_flagged": [x["path"] for x in out if x["content_flag"]],
           "metadata_flagged": [x["path"] for x in out if x["metadata_flag"] and not x["content_flag"]],
           "dir_2xx_revealing": sum(x["dir"]["status"] < 300 and bool(x["dir"]["reveals"]) for x in out),
           "stranger_2xx_revealing_nothing": [x["path"] for x in out if not (x["content_flag"] or x["metadata_flag"])
                                              and any(x[k]["status"] < 300 for k in ("strL", "strF"))],
           "rows": out}
    json.dump(res, open(OUT, "w"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "rows"}, indent=1))


asyncio.run(main())
