"""
E2f -- F8: does removing a collaborator end an open collaboration session? (phase 5)

Runs the real backend (uvicorn) and the real Hocuspocus collaboration server (server.mjs of the version under
test) against an isolated database, opens a collaboration session for a collaborator on a draft document, removes
the collaborator through the document API, and measures how long the session stays open. v1 re-checks sessions
only at connect time; v2 re-checks every HOCUSPOCUS_REAUTH_MS (default 5 s).

Usage: python e2_collab.py <backend> <server.mjs> <node-dir with node_modules and f8/client.mjs> <out-json> [n] [wait-s]
Needs PostgreSQL (database abac_f8) and Redis (db 5); uses ports 8010 and 1240.
"""
import asyncio, json, os, shutil, subprocess, sys, time, uuid
BACKEND, SERVER_MJS, NODE_DIR, OUTJ = sys.argv[1:5]
N = int(sys.argv[5]) if len(sys.argv) > 5 else 10
WAIT = float(sys.argv[6]) if len(sys.argv) > 6 else 30.0
DB = "postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_f8"
ENV = dict(os.environ, DATABASE_URL=DB, REDIS_URL="redis://localhost:6379/5", ENVIRONMENT="test",
           SECRET_KEY="f8_harness_secret_key_32_chars_minimum_x", STORAGE_BACKEND="local",
           HOCUSPOCUS_SECRET="f8_harness_internal_secret", PYTHONDONTWRITEBYTECODE="1")
os.environ.update({k: ENV[k] for k in ("DATABASE_URL", "REDIS_URL", "ENVIRONMENT", "SECRET_KEY", "STORAGE_BACKEND",
                                       "HOCUSPOCUS_SECRET")})
sys.path.insert(0, BACKEND)
import httpx                                                              # noqa: E402
from sqlalchemy import select                                             # noqa: E402
from app.db.database import AsyncSessionLocal, engine                     # noqa: E402
from app.db.seed import seed_initial_data                                 # noqa: E402
from app.models.models import (Base, Subject, Role, Department, Division, Document, DocumentSpace,  # noqa: E402
    DocumentStatus, DocumentCollaborator, UserStatus, ClearanceLevel, ResourceSensitivity)
from app.core.security import create_access_token                         # noqa: E402

API = "http://127.0.0.1:8010/api/v1"
WS = "ws://127.0.0.1:1240"
PY = sys.executable
NODE = shutil.which("node") or "/opt/node22/bin/node"


def tok(sid): return create_access_token(sid, f"{sid}@f8", extra_claims={"sv": 0})


async def setup():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all); await c.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as s:
        await seed_initial_data(s); await s.commit()
    async with AsyncSessionLocal() as s:
        depts = {d.code: d for d in (await s.execute(select(Department))).scalars()}
        divs = {d.code: d for d in (await s.execute(select(Division))).scalars()}
        roles = {r.builtin_type: r for r in (await s.execute(select(Role))).scalars()}
    return depts["FIN"], divs["ACCT"], roles


async def mk_subject(roles, role, dept, div):
    async with AsyncSessionLocal() as s:
        sid = str(uuid.uuid4())
        s.add(Subject(id=sid, email=f"{role}-{sid[:8]}@f8.test", username=f"{role}-{sid[:8]}", full_name=role,
                      hashed_password="x", role_id=roles[role].id, department_id=dept.id, division_id=div.id,
                      clearance=ClearanceLevel("normal"), status=UserStatus.ACTIVE, is_platform_admin=False,
                      mfa_enabled=False, session_version=0, attributes={}))
        await s.commit()
    return sid


async def mk_draft_with_collaborator(owner, collab, dept, div):
    async with AsyncSessionLocal() as s:
        sp = DocumentSpace(id=str(uuid.uuid4()), name="F8", department_id=dept.id, created_by_id=owner)
        s.add(sp); await s.flush()
        did = str(uuid.uuid4())
        s.add(Document(id=did, title="F8", space_id=sp.id, department_id=dept.id, division_id=div.id, owner_id=owner,
                       sensitivity=ResourceSensitivity.INTERNAL, status=DocumentStatus.DRAFT,
                       content_json={"type": "doc"}))
        await s.flush()
        s.add(DocumentCollaborator(id=str(uuid.uuid4()), document_id=did, subject_id=collab, invited_by_id=owner))
        await s.commit()
    return did


def wait_http(url, limit=40):
    for _ in range(int(limit * 4)):
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


async def trial(owner, collab, dept, div):
    did = await mk_draft_with_collaborator(owner, collab, dept, div)
    cl = await asyncio.create_subprocess_exec(NODE, os.path.join(NODE_DIR, "client.mjs"), WS, did, tok(collab),
                                              cwd=NODE_DIR, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    events = []

    async def read_until(pred, limit):
        end = time.time() + limit
        while time.time() < end:
            try:
                line = await asyncio.wait_for(cl.stdout.readline(), timeout=max(0.05, end - time.time()))
            except asyncio.TimeoutError:
                break
            if not line:
                break
            e = json.loads(line); events.append(e)
            if pred(e):
                return e
        return None
    synced = await read_until(lambda e: e["ev"] in ("synced", "auth_failed", "closed"), 15)
    if not synced or synced["ev"] != "synced":
        cl.kill(); return {"doc": did, "synced": False, "events": events}
    async with httpx.AsyncClient(headers={"X-Requested-With": "XMLHttpRequest"}) as c:
        r = await c.delete(f"{API}/documents/{did}/collaborators/{collab}", headers={"Authorization": f"Bearer {tok(owner)}"})
        t0 = time.time()
        # the collaborator's own read through the document API, right after removal
        rd = await c.get(f"{API}/documents/{did}", headers={"Authorization": f"Bearer {tok(collab)}"})
    closed = await read_until(lambda e: e["ev"] == "closed", WAIT)
    try:
        cl.kill()
    except ProcessLookupError:
        pass
    return {"doc": did, "synced": True, "remove_http": r.status_code, "doc_api_read_after_removal": rd.status_code,
            "session_closed": closed is not None,
            "window_s": round(closed["t"] - t0, 2) if closed else None,
            "close_code": closed.get("code") if closed else None, "observed_for_s": WAIT}


async def main():
    dept, div, roles = await setup()
    owner = await mk_subject(roles, "analyst", dept, div)
    collab = await mk_subject(roles, "analyst", dept, div)
    await engine.dispose()
    srv_copy = os.path.join(NODE_DIR, "server_under_test.mjs"); shutil.copy(SERVER_MJS, srv_copy)
    be = subprocess.Popen([PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8010",
                           "--log-level", "warning"], cwd=BACKEND, env=ENV,
                          stdout=subprocess.DEVNULL, stderr=open(OUTJ + ".backend.log", "w"))
    hp = subprocess.Popen([NODE, srv_copy], cwd=NODE_DIR,
                          env=dict(ENV, BACKEND_URL="http://127.0.0.1:8010", PORT="1240"),
                          stdout=open(OUTJ + ".hocuspocus.log", "w"), stderr=subprocess.STDOUT)
    try:
        assert wait_http("http://127.0.0.1:8010/health"), "backend did not start"
        time.sleep(1.0)
        res = []
        for i in range(N):
            res.append(await trial(owner, collab, dept, div))
            print(i, res[-1].get("window_s"), res[-1].get("close_code"), res[-1].get("doc_api_read_after_removal"), flush=True)
    finally:
        for p in (hp, be):
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
    w = [r["window_s"] for r in res if r.get("window_s") is not None]
    out = {"server": SERVER_MJS, "backend": BACKEND, "trials": res, "n": len(res),
           "closed": sum(r.get("session_closed", False) for r in res),
           "window_min_s": min(w) if w else None, "window_max_s": max(w) if w else None,
           "reauth_ms": os.environ.get("HOCUSPOCUS_REAUTH_MS", "5000 (server default)")}
    json.dump(out, open(OUTJ, "w"), indent=1)
    print(json.dumps({k: out[k] for k in ("n", "closed", "window_min_s", "window_max_s")}))


if __name__ == "__main__":
    asyncio.run(main())
