"""
L3 state sweep over every in-scope state-changing route of the generated inventory (phase 6).

Companion of l3_stranger_sweep.py (GET routes). For every in-scope route whose method is not GET, this script
rebuilds one world in which a department (FIN) owns documents in every workflow state, with tasks, links,
versions, comments, a pending reopen request, a folder, a delegation request and an assignment. It fills the
route's path parameters with those objects (every document state is tried for {doc_id}), sends a minimal valid
body, and checks whether the database changed. Four subjects send each request:
  dirL  the director of another department       dmL   a division manager of another department
  strL  an employee of another department        strF  an employee of FIN's division with no grant
None of them may change FIN's objects: R1 forbids every action across departments without a delegation, and an
employee without a grant may only read (R3). A request is flagged if the database changed, whatever the response
status (a route may commit and then fail); decision rows, audit rows and new notifications are ignored. Routes that need the internal secret are sent
without it. A route answered only with 422 (body not accepted) is reported as not exercised.

Usage: python l3_state_sweep.py <backend> <inventory-json> <out-json>
Needs PostgreSQL (database abac_f8) and Redis (db 5).
"""
import asyncio, hashlib, json, os, re, sys, uuid
from datetime import datetime, timezone, timedelta
BACKEND, INV, OUT = sys.argv[1:4]
os.environ.update({"DATABASE_URL": "postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_f8",
                   "REDIS_URL": "redis://localhost:6379/5", "ENVIRONMENT": "test",
                   "SECRET_KEY": "sweep_harness_secret_key_32_chars_minimum", "STORAGE_BACKEND": "local"})
sys.path.insert(0, BACKEND)
import logging, structlog                                                   # noqa: E402
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
logging.disable(logging.CRITICAL)
import httpx, redis.asyncio as aioredis                                     # noqa: E402
from sqlalchemy import select, text                                         # noqa: E402
from app.main import app                                                    # noqa: E402
from app.db.database import AsyncSessionLocal, engine                       # noqa: E402
from app.db.seed import seed_initial_data                                   # noqa: E402
from app.models.models import (Base, Subject, Role, Department, Division, Resource, Document, DocumentSpace,  # noqa: E402
    DocumentStatus, DocumentComment, DocumentVersion, DocumentTask, DocumentLink, DocumentFolder, Notification,
    Delegation, DelegationStatus, ResourceAssignment, Policy, UserStatus, ClearanceLevel, ResourceSensitivity,
    DocumentReopenRequest)
from app.core.security import create_access_token                           # noqa: E402

API = "/api/v1"
# tables whose content is compared before and after each request (decision and audit rows are excluded)
TABLES = ["documents", "document_versions", "document_comments", "document_tasks", "document_links",
          "document_folders", "document_spaces", "document_collaborators", "document_reopen_requests",
          "document_signatures", "document_workflow_steps", "delegations", "resource_assignments", "resources", "subjects",
          "policies", "retention_policies"]
BODIES = {
    ("POST", "/documents/{doc_id}/tasks"): {"title": "sweep task"},
    ("PATCH", "/documents/{doc_id}/tasks/{task_id}"): {"is_done": True},
    ("POST", "/documents/{doc_id}/links"): {"target_id": "@doc_other"},
    ("POST", "/documents/{doc_id}/collaborators"): {"subject_id": "@self"},
    ("POST", "/documents/{doc_id}/request-reopen"): {"reason": "sweep"},
    ("POST", "/documents/{doc_id}/comments"): {"content": "sweep comment"},
    ("POST", "/documents/{doc_id}/sign"): {"signer_name": "sweep"},
    ("PATCH", "/documents/spaces/{space_id}"): {"name": "sweep renamed"},
    ("POST", "/documents/spaces/{space_id}/folders"): {"name": "sweep folder"},
    ("POST", "/delegations/{delegation_id}/reject"): {"reason": "sweep"},
    ("POST", "/delegations/{delegation_id}/approve"): {"expires_at": "@future"},
    ("POST", "/delegations/{delegation_id}/revoke"): {"reason": "sweep"},
    ("PUT", "/subjects/{subject_id}"): {"full_name": "sweep renamed"},
    ("PUT", "/policies/{policy_id}"): {"description": "sweep"},
    ("PUT", "/documents/{doc_id}"): {"title": "sweep renamed"},
    ("PATCH", "/documents/{doc_id}"): {"title": "sweep renamed"},
    ("POST", "/resources/{resource_id}/assignments"): {"subject_id": "@self", "actions": ["read"]},
}
QUERY = {("PATCH", "/policies/{policy_id}/status"): {"active": "false"}}
STATES = ["draft", "review", "pending_approval", "approved", "published", "archived", "rejected"]


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

        def subj(role, dept, div, name):
            sid = str(uuid.uuid4())
            s.add(Subject(id=sid, email=f"{sid[:8]}@sweep.test", username=f"sw{sid[:8]}", full_name=name,
                          hashed_password="x", role_id=roles[role].id, department_id=dept.id,
                          division_id=div.id if div else None, clearance=ClearanceLevel.NORMAL,
                          status=UserStatus.ACTIVE, is_platform_admin=False, mfa_enabled=False, session_version=0,
                          attributes={}))
            return sid
        dirF = subj("director", FIN, None, "dirF"); dmF = subj("division_manager", FIN, ACCT, "dmF")
        who = {"dirL": subj("director", LEG, None, "dirL"), "dmL": subj("division_manager", LEG, COMP, "dmL"),
               "strL": subj("analyst", LEG, COMP, "strL"), "strF": subj("analyst", FIN, ACCT, "strF")}
        await s.flush()
        rid = str(uuid.uuid4())
        s.add(Resource(id=rid, name="fin object", department_id=FIN.id, division_id=ACCT.id, owner_id=dirF,
                       sensitivity=ResourceSensitivity.INTERNAL, is_active=True, attributes={}, tags=[]))
        sp = DocumentSpace(id=str(uuid.uuid4()), name="fin space", department_id=FIN.id, created_by_id=dirF)
        s.add(sp); await s.flush()
        fo = DocumentFolder(id=str(uuid.uuid4()), name="fin folder", space_id=sp.id, created_by_id=dirF)
        s.add(fo)
        docs = {}
        for st in STATES:
            did = str(uuid.uuid4())
            s.add(Document(id=did, title=f"fin {st}", space_id=sp.id, department_id=FIN.id, division_id=ACCT.id,
                           owner_id=dmF, sensitivity=ResourceSensitivity.INTERNAL, status=DocumentStatus(st),
                           requires_signature=True, content_json={"type": "doc"}))
            docs[st] = did
        await s.flush()
        for st in ("published",):
            s.add(Resource(id=str(uuid.uuid4()), name="fin doc object", department_id=FIN.id, division_id=ACCT.id,
                           owner_id=dmF, sensitivity=ResourceSensitivity.INTERNAL, is_active=True,
                           attributes={"document_id": docs[st], "source": "edm"}, tags=[]))
        per_doc = {}
        for st, did in docs.items():
            cm = DocumentComment(id=str(uuid.uuid4()), document_id=did, author_id=dirF, content="c")
            ve = DocumentVersion(id=str(uuid.uuid4()), document_id=did, version_number=1, title="v1",
                                 created_by_id=dirF, content_json={"type": "doc"})
            ta = DocumentTask(id=str(uuid.uuid4()), document_id=did, title="t", created_by_id=dirF)
            other = docs["draft"] if st != "draft" else docs["review"]
            li = DocumentLink(id=str(uuid.uuid4()), source_id=did, target_id=other, created_by_id=dirF)
            rr = DocumentReopenRequest(id=str(uuid.uuid4()), document_id=did, requester_id=dmF,
                                       requester_name="dmF", reason="r", status="pending")
            for x in (cm, ve, ta, li, rr):
                s.add(x)
            per_doc[st] = {"comment_id": cm.id, "version_id": ve.id, "task_id": ta.id, "link_id": li.id,
                           "doc_other": other}
        rL = str(uuid.uuid4())
        s.add(Resource(id=rL, name="legal object", department_id=LEG.id, division_id=COMP.id, owner_id=who["dirL"],
                       sensitivity=ResourceSensitivity.INTERNAL, is_active=True, attributes={}, tags=[]))
        rF2 = str(uuid.uuid4())
        s.add(Resource(id=rF2, name="fin object 2", department_id=FIN.id, division_id=ACCT.id, owner_id=dirF,
                       sensitivity=ResourceSensitivity.INTERNAL, is_active=True, attributes={}, tags=[]))
        await s.flush()
        # a pending delegation on a FIN object, requested by a LEG subject (approvers: FIN's director)
        de = Delegation(id=str(uuid.uuid4()), requester_id=who["strL"], resource_id=rF2, justification="j",
                        requested_actions=["read"], approved_actions=[], status=DelegationStatus.PENDING)
        asg = ResourceAssignment(id=str(uuid.uuid4()), subject_id=dmF, resource_id=rid, assigned_by_id=dirF,
                                 actions=["read"], is_active=True)
        no = Notification(id=str(uuid.uuid4()), recipient_id=dirF, type="x", title="n", body="n")
        for x in (de, asg, no):
            s.add(x)
        await s.commit()
        ids = {"resource_id": rid, "space_id": sp.id, "folder_id": fo.id, "subject_id": dmF, "policy_id": p1.id,
               "delegation_id": de.id, "assignment_id": asg.id, "notification_id": no.id}
    return ids, docs, per_doc, who


async def snapshot(nid):
    h = hashlib.sha256()
    async with engine.connect() as c:
        for t in TABLES:
            rows = (await c.execute(text(f"SELECT to_jsonb(x) - 'updated_at' FROM {t} x ORDER BY id"))).scalars().all()
            h.update(json.dumps([t, rows], sort_keys=True, default=str).encode())
        n = (await c.execute(text("SELECT is_read FROM notifications WHERE id = :i"), {"i": nid})).scalar()
        h.update(str(n).encode())
    return h.hexdigest()


def fill(path, ids, extra):
    return re.sub(r"\{(\w+)\}", lambda m: extra.get(m.group(1), ids.get(m.group(1), "missing")), path)


async def main():
    inv = json.load(open(INV))
    routes = [r for r in inv["routes"] if r["in_scope"] and r["methods"] != ["GET"]]
    out = []
    for r in routes:
        method = r["methods"][0]
        tmpl = r["path"][len(API):]
        if method == "POST" and tmpl == "/documents/{doc_id}/file":
            out.append({"route": f"{method} {r['path']}", "skipped": "multipart upload"}); continue
        states = STATES if "{doc_id}" in tmpl else [None]
        row = {"route": f"{method} {r['path']}", "trials": []}
        for st in states:
            ids, docs, per_doc, who = await setup()
            extra = dict(per_doc[st], doc_id=docs[st]) if st else {}
            path = API + fill(tmpl, ids, extra)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                         base_url="http://sweep", timeout=60) as c:
                for k, sid in who.items():
                    body = dict(BODIES.get((method, tmpl), {}))
                    for bk, bv in list(body.items()):
                        if bv == "@self":
                            body[bk] = sid
                        elif bv == "@doc_other":
                            body[bk] = extra.get("doc_other")
                        elif bv == "@future":
                            body[bk] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
                    before = await snapshot(ids["notification_id"])
                    resp = await c.request(method, path, headers=H(sid), json=body if method != "DELETE" else None,
                                           params=QUERY.get((method, tmpl)))
                    after = await snapshot(ids["notification_id"])
                    t = {"state": st, "who": k, "status": resp.status_code, "changed": before != after}
                    t["flag"] = t["changed"]          # any change by a subject R forbids, whatever the status
                    row["trials"].append(t)
        row["flag"] = sorted({(t["who"], t["state"]) for t in row["trials"] if t["flag"]})
        row["only_422"] = all(t["status"] == 422 for t in row["trials"])
        row["statuses"] = sorted({t["status"] for t in row["trials"]})
        out.append(row)
        print(("FLAG " if row["flag"] else "     ") + row["route"], row["statuses"], row["flag"][:6], flush=True)
    await engine.dispose()
    res = {"routes": len(out), "flagged": {x["route"]: x["flag"] for x in out if x.get("flag")},
           "not_exercised_422": [x["route"] for x in out if x.get("only_422")],
           "skipped": [x["route"] for x in out if x.get("skipped")], "rows": out}
    json.dump(res, open(OUT, "w"), indent=1, default=str)
    print(json.dumps({k: v for k, v in res.items() if k != "rows"}, indent=1, default=str))


asyncio.run(main())
