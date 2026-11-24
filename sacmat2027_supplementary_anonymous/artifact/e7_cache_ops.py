"""
E7 -- Operational premises of the v2 cache proposition (phase 6).

The freshness proposition for the v2 cache assumes (i) that every committed grant change increments its
generation counters within epsilon_b of the commit, and says that if Redis fails the TTL bound still holds.
This harness measures both on the real backend (uvicorn), against an isolated database:

  A  epsilon_b under load. N assignment create/revoke cycles (each a committed grant change) run while 16
     closed-loop clients send file requests. The post-commit hook is wrapped (in the server process, by
     the launcher below; the fork is not modified) to log, per commit, the time from the end of the
     database commit to the end of the Redis increments. After each revocation response the driver also
     reads the counters from Redis to check that the increment had already happened. Run with 1 and 2
     server workers.
  B  Lost increment. A cached allow entry is warmed, then the assignment is revoked while the hook's
     connection to Redis fails (fault injected in the launcher; the cache itself stays up), as a network
     partition or a Redis restart between the commit and the increment would. Two faults: 'refused'
     (the connection is refused at once) and 'timeout' (the increment blocks for 2 s, the hook's socket
     timeout, then fails). The driver then polls the employee's file request every 0.25 s and records when
     it is first denied, and how long the revocation and an unrelated request sent meanwhile took.
     Control trials run the same steps without a fault.

Usage: python e7_cache_ops.py <backend> <work-dir> <out-json> [cycles=200] [stall-trials=5]
Needs PostgreSQL (database abac_f8) and Redis (db 5); uses port 8020. Run when nothing else uses Redis
(experiment B uses the same Redis database).
"""
import asyncio, json, os, shutil, statistics, subprocess, sys, time, uuid
BACKEND, WORK, OUTJ = sys.argv[1:4]
CYCLES = int(sys.argv[4]) if len(sys.argv) > 4 else 200
STALLS = int(sys.argv[5]) if len(sys.argv) > 5 else 5
DB = "postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_f8"
RURL = "redis://localhost:6379/5"
ENV = dict(os.environ, DATABASE_URL=DB, REDIS_URL=RURL, ENVIRONMENT="test",
           SECRET_KEY="e7_harness_secret_key_32_chars_minimum_xx", STORAGE_BACKEND="local",
           PYTHONDONTWRITEBYTECODE="1")
os.environ.update({k: ENV[k] for k in ("DATABASE_URL", "REDIS_URL", "ENVIRONMENT", "SECRET_KEY", "STORAGE_BACKEND")})
sys.path.insert(0, BACKEND)
import httpx, redis                                                        # noqa: E402
from sqlalchemy import select                                              # noqa: E402
from app.db.database import AsyncSessionLocal, engine                      # noqa: E402
from app.db.seed import seed_initial_data                                  # noqa: E402
from app.models.models import (Base, Subject, Role, Department, Division, Resource, UserStatus,  # noqa: E402
                               ClearanceLevel, ResourceSensitivity)
from app.core.security import create_access_token                          # noqa: E402

PORT = 8020
API = f"http://127.0.0.1:{PORT}/api/v1"
HOOKLOG = os.path.join(WORK, "hook_times.log")
FAULT = os.path.join(WORK, "fault")
LAUNCHER = '''
import os, time
from sqlalchemy import event
from sqlalchemy.orm import Session
import app.services.pip_invalidation as inv
from app.main import app                      # noqa: F401
_LOG = os.environ["E7_HOOKLOG"]
_orig = inv._bump
_FLAG = os.environ["E7_FAULT"]
class _Broken:
    def __init__(self, mode): self.mode = mode
    def pipeline(self): return self
    def incr(self, *a): return self
    def execute(self):
        import redis
        if self.mode == "timeout":
            time.sleep(2.0)
            raise redis.exceptions.TimeoutError("Timeout reading from socket (injected)")
        raise redis.exceptions.ConnectionError("Connection refused (injected)")
def _timed(session):
    had = bool(session.info.get(inv._KEY))
    t0 = time.time()
    mode = open(_FLAG).read().strip() if os.path.exists(_FLAG) else ""
    saved = inv._sync
    if had and mode:
        inv._sync = _Broken(mode)
    try:
        _orig(session)
    finally:
        inv._sync = saved
        if had:
            with open(_LOG, "a") as f:
                f.write(f"{os.getpid()} {t0:.6f} {time.time():.6f}\\n")
event.remove(Session, "after_commit", inv._bump)
event.listen(Session, "after_commit", _timed)
'''


def tok(sid): return create_access_token(sid, f"{sid}@e7", extra_claims={"sv": 0})
def H(sid): return {"Authorization": f"Bearer {tok(sid)}", "X-Requested-With": "XMLHttpRequest"}


async def setup(n_res=16):
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all); await c.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as s:
        await seed_initial_data(s); await s.commit()
    async with AsyncSessionLocal() as s:
        FIN = (await s.execute(select(Department).where(Department.code == "FIN"))).scalar_one()
        ACCT = (await s.execute(select(Division).where(Division.code == "ACCT"))).scalar_one()
        roles = {r.builtin_type: r for r in (await s.execute(select(Role))).scalars()}
        ids = {}
        for k, role in (("dir", "director"), ("an", "analyst")):
            ids[k] = str(uuid.uuid4())
            s.add(Subject(id=ids[k], email=f"{k}@e7.test", username=f"e7{k}", full_name=k, hashed_password="x",
                          role_id=roles[role].id, department_id=FIN.id, division_id=ACCT.id,
                          clearance=ClearanceLevel.NORMAL, status=UserStatus.ACTIVE, is_platform_admin=False,
                          mfa_enabled=False, session_version=0, attributes={}))
        loaders = [str(uuid.uuid4()) for _ in range(8)]
        for i, sid in enumerate(loaders):
            s.add(Subject(id=sid, email=f"l{i}@e7.test", username=f"e7l{i}", full_name="l", hashed_password="x",
                          role_id=roles["director"].id, department_id=FIN.id, division_id=ACCT.id,
                          clearance=ClearanceLevel.NORMAL, status=UserStatus.ACTIVE, is_platform_admin=False,
                          mfa_enabled=False, session_version=0, attributes={}))
        res = []
        os.makedirs("/app/storage/e7", exist_ok=True)
        for i in range(n_res + 1):
            rid = str(uuid.uuid4()); fp = f"e7/{rid}.txt"
            open(f"/app/storage/{fp}", "w").write("E7 payload " + rid)
            s.add(Resource(id=rid, name=f"e7-{i}", department_id=FIN.id, division_id=ACCT.id, owner_id=ids["dir"],
                           sensitivity=ResourceSensitivity.INTERNAL, is_active=True, attributes={}, tags=[],
                           file_path=fp, file_size=47, mime_type="text/plain"))
            res.append(rid)
        await s.commit()
    await engine.dispose()
    return ids, loaders, res


def start_server(workers):
    os.makedirs(WORK, exist_ok=True)
    open(os.path.join(WORK, "e7_app.py"), "w").write(LAUNCHER)
    env = dict(ENV, E7_HOOKLOG=HOOKLOG, E7_FAULT=FAULT, PYTHONPATH=WORK + os.pathsep + BACKEND)
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "e7_app:app", "--host", "127.0.0.1", "--port", str(PORT),
                          "--workers", str(workers), "--log-level", "warning"], cwd=BACKEND, env=env,
                         stdout=subprocess.DEVNULL, stderr=open(OUTJ + f".server{workers}.log", "w"))
    for _ in range(160):
        try:
            if httpx.get(f"http://127.0.0.1:{PORT}/health", timeout=1).status_code < 500:
                return p
        except Exception:
            pass
        time.sleep(0.25)
    raise SystemExit("server did not start")


def stop(p):
    p.terminate()
    try:
        p.wait(15)
    except subprocess.TimeoutExpired:
        p.kill()


def gens(r, sid, rid):
    v = r.mget("pip:gen:all", f"pip:gen:s:{sid}", f"pip:gen:r:{rid}")
    return [int(x or 0) for x in v]


def pct(xs, q):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(q * len(xs)))]


async def experiment_a(ids, loaders, res, workers):
    open(HOOKLOG, "w").close()
    if os.path.exists(FAULT):
        os.remove(FAULT)
    srv = start_server(workers)
    r = redis.Redis.from_url(RURL)
    stop_flag = False
    load_n = [0, 0]

    async def loader(i):
        async with httpx.AsyncClient(timeout=30) as c:
            while not stop_flag:
                rr = await c.get(f"{API}/pep/access/{res[1 + i % (len(res) - 1)]}", headers=H(loaders[i % len(loaders)]))
                load_n[0] += 1; load_n[1] += rr.status_code >= 500
    tasks = [asyncio.create_task(loader(i)) for i in range(16)]
    seen_before_response, cyc = 0, []
    target = res[0]
    async with httpx.AsyncClient(timeout=30, limits=httpx.Limits(max_keepalive_connections=0)) as c:
        await asyncio.sleep(2.0)
        for k in range(CYCLES):
            g0 = gens(r, ids["an"], target)
            a = await c.post(f"{API}/resources/{target}/assignments", json={"subject_id": ids["an"], "actions": ["read"]},
                             headers=H(ids["dir"]))
            await c.get(f"{API}/pep/access/{target}", headers=H(ids["an"]))           # warm the entry
            g1 = gens(r, ids["an"], target)
            t = time.time()
            d = await c.delete(f"{API}/resources/{target}/assignments/{a.json()['id']}", headers=H(ids["dir"]))
            rt = time.time() - t
            g2 = gens(r, ids["an"], target)                                            # read right after the response
            deny = (await c.get(f"{API}/pep/access/{target}", headers=H(ids["an"]))).status_code == 403
            ok = g2[1] > g1[1] and g2[2] > g1[2]
            seen_before_response += ok
            cyc.append({"create": a.status_code, "revoke": d.status_code, "gens": [g0, g1, g2],
                        "bumped_before_response": ok, "deny_after": deny, "revoke_s": round(rt, 4)})
    stop_flag = True
    await asyncio.gather(*tasks, return_exceptions=True)
    stop(srv)
    hooks = [tuple(map(float, l.split())) for l in open(HOOKLOG) if l.strip()]
    eps = [(b - a) * 1000 for _, a, b in hooks]
    return {"workers": workers, "cycles": CYCLES, "load_requests": load_n[0], "load_5xx": load_n[1],
            "hook_calls": len(eps), "server_pids": len({p for p, _, _ in hooks}),
            "eps_b_ms": {"median": round(statistics.median(eps), 3), "p99": round(pct(eps, 0.99), 3),
                         "max": round(max(eps), 3), "mean": round(statistics.mean(eps), 3)},
            "bumped_before_response": seen_before_response,
            "deny_after_revocation": sum(x["deny_after"] for x in cyc),
            "revocation_status_ok": sum(x["revoke"] == 204 and x["create"] in (200, 201) for x in cyc),
            "trials": cyc[:5]}


async def experiment_b(ids, res, fault):
    srv = start_server(1)
    r = redis.Redis.from_url(RURL)
    target, other = res[0], res[1]
    out = []
    async with httpx.AsyncClient(timeout=60) as c:
        for k in range(STALLS):
            a = await c.post(f"{API}/resources/{target}/assignments", json={"subject_id": ids["an"], "actions": ["read"]},
                             headers=H(ids["dir"]))
            warm = (await c.get(f"{API}/pep/access/{target}", headers=H(ids["an"]))).status_code
            g1 = gens(r, ids["an"], target)
            if fault:
                open(FAULT, "w").write(fault)
            t0 = time.time()

            async def unrelated():
                await asyncio.sleep(0.2)
                t = time.time()
                s = (await c.get(f"{API}/pep/access/{other}", headers=H(ids["dir"]))).status_code
                return s, time.time() - t
            un = asyncio.create_task(unrelated())
            d = await c.delete(f"{API}/resources/{target}/assignments/{a.json()['id']}", headers=H(ids["dir"]))
            t_rev = time.time()
            us, ut = await un
            if os.path.exists(FAULT):
                os.remove(FAULT)
            g2 = gens(r, ids["an"], target)
            first_deny = None; polls = 0
            while time.time() - t_rev < 200:
                polls += 1
                if (await c.get(f"{API}/pep/access/{target}", headers=H(ids["an"]))).status_code == 403:
                    first_deny = time.time() - t_rev; break
                await asyncio.sleep(0.25)
            out.append({"warm": warm, "revoke_status": d.status_code, "revoke_request_s": round(t_rev - t0, 3),
                        "unrelated_request": [us, round(ut, 3)], "gens_before": g1, "gens_after": g2,
                        "bump_lost": g2[1] == g1[1], "first_deny_after_revocation_s":
                            round(first_deny, 2) if first_deny is not None else None, "polls": polls})
            print("B", fault or "control", out[-1], flush=True)
    stop(srv)
    return out


async def main():
    ids, loaders, res = await setup()
    res_out = {"backend": BACKEND, "assignment_ttl_s": 120}
    for w in (1, 2):
        res_out[f"A_workers{w}"] = await experiment_a(ids, loaders, res, w)
        print("A", w, {k: v for k, v in res_out[f"A_workers{w}"].items() if k != "trials"}, flush=True)
    for f in ("", "refused", "timeout"):
        res_out[f"B_{f or 'control'}"] = await experiment_b(ids, res, f)
    json.dump(res_out, open(OUTJ, "w"), indent=1)


if __name__ == "__main__":
    asyncio.run(main())
