"""
E4 -- Cost of the fixes (WP4) and multi-worker revocation race (WP6).

Runs the application under a real multi-worker uvicorn server (separate processes, true
parallelism) against PostgreSQL 16 and Redis 7, for one backend (snapshot or evaluation
fork). Fixtures are created through the ORM before the server starts; all measured traffic
goes over HTTP.

Workloads (closed loop, C concurrent clients, `reps` repetitions of n requests each):
  decide_hit   POST /access/decide, analyst with assignment (warm grant cache)
  decide_miss  POST /access/decide on n distinct resources, cache flushed per repetition
  pep_allow    GET /pep/access/{id} streaming a small file (allow)
  pep_deny     GET /pep/access/{id} (deny: analyst without grant)
  doc_read     GET /documents/{id}, published document, analyst assigned to its resource
  asg_create   POST /resources/{id}/assignments (write path incl. commit hooks)
Race (multi-worker): T trials; cold cache; one DELETE of an assignment raced against K
concurrent decisions; after the DELETE has returned, one more decision and a check of the
entry the cache would serve. A trial is stale if that decision allows or the served entry
still holds the grant.

Usage: python e4_cost.py <backend> <label> <db-url> <redis-url> <port> <workers> <out-dir>
Statistics: medians/p95 with 95% bootstrap CIs (10,000 resamples); throughput per rep.
"""
import asyncio, json, os, random, subprocess, sys, time, uuid
from datetime import datetime, timezone

BACKEND, LABEL, DBURL, REDIS, PORT, WORKERS, OUT = sys.argv[1:8]
PORT, WORKERS = int(PORT), int(WORKERS)
N = int(os.environ.get("E4_N", "1000")); REPS = int(os.environ.get("E4_REPS", "5"))
C = int(os.environ.get("E4_C", "16")); WARM = 100
T_RACE = int(os.environ.get("E4_RACE_T", "200")); K_RACE = 8
SECRET = "e4_harness_secret_key_32_chars_minimum"
ENV = {"DATABASE_URL": DBURL, "REDIS_URL": REDIS, "SECRET_KEY": SECRET, "ENVIRONMENT": "test",
       "STORAGE_BACKEND": "local", "DEBUG": "false"}
os.environ.update(ENV)
sys.path.insert(0, BACKEND)
import logging, structlog                                         # noqa: E402
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
logging.disable(logging.CRITICAL)
import httpx, numpy as np                                         # noqa: E402
import redis.asyncio as aioredis                                  # noqa: E402
from sqlalchemy import select                                     # noqa: E402
from app.db.database import AsyncSessionLocal, engine             # noqa: E402
from app.db.seed import seed_initial_data                         # noqa: E402
from app.models.models import (Base, Subject, Resource, Role, Department, Division,  # noqa: E402
    ResourceAssignment, Document, DocumentSpace, DocumentStatus, UserStatus,
    ClearanceLevel, ResourceSensitivity)
from app.core.security import create_access_token                 # noqa: E402

API = f"http://127.0.0.1:{PORT}/api/v1"
FX = {}


def tok(sid):
    return {"Authorization": "Bearer " + create_access_token(sid, f"{sid}@e4", extra_claims={"sv": 0}),
            "X-Requested-With": "XMLHttpRequest"}


async def setup():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as s:
        await seed_initial_data(s); await s.commit()
    r = aioredis.from_url(REDIS); await r.flushdb(); await r.aclose()
    async with AsyncSessionLocal() as s:
        depts = {d.code: d for d in (await s.execute(select(Department))).scalars()}
        divs = {d.code: d for d in (await s.execute(select(Division))).scalars()}
        roles = {r.builtin_type: r for r in (await s.execute(select(Role))).scalars()}
        FIN, ACCT = depts["FIN"], divs["ACCT"]

        def subj(role, clr="elevated"):
            sid = str(uuid.uuid4())
            s.add(Subject(id=sid, email=f"{role}-{sid[:8]}@e4.test", username=f"{role}-{sid[:8]}",
                          full_name=role, hashed_password="x", role_id=roles[role].id,
                          department_id=FIN.id, division_id=None if role == "director" else ACCT.id,
                          clearance=ClearanceLevel(clr), status=UserStatus.ACTIVE, is_platform_admin=False,
                          mfa_enabled=True, session_version=0, attributes={}, failed_login_attempts=0))
            return sid

        def res(owner, fp=None):
            rid = str(uuid.uuid4())
            s.add(Resource(id=rid, name=f"r-{rid[:6]}", department_id=FIN.id, division_id=ACCT.id,
                           owner_id=owner, sensitivity=ResourceSensitivity.INTERNAL, is_active=True,
                           attributes={}, tags=[], file_path=fp, file_size=60 if fp else None,
                           mime_type="text/plain" if fp else None))
            return rid

        def asg(sid, rid, acts=("read",)):
            s.add(ResourceAssignment(id=str(uuid.uuid4()), subject_id=sid, resource_id=rid,
                                     actions=list(acts), is_active=True, assigned_by_id=FX["dir"]))

        FX["dir"] = subj("director")
        FX["an"] = [subj("analyst") for _ in range(C)]
        FX["stranger"] = subj("analyst")
        await s.flush()
        os.makedirs("/app/storage/e4", exist_ok=True)
        fp = "e4/payload.txt"
        open(f"/app/storage/{fp}", "w").write("E4 payload " + "x" * 49)
        FX["rfile"] = res(FX["dir"], fp)
        FX["rmiss"] = [res(FX["dir"]) for _ in range(N)]
        FX["rasg"] = [res(FX["dir"]) for _ in range(N * REPS + WARM)]
        FX["rrace"] = [res(FX["dir"]) for _ in range(T_RACE)]
        await s.flush()
        for a in FX["an"]:
            asg(a, FX["rfile"])
        for rid in FX["rmiss"]:
            asg(FX["an"][0], rid)
        sp = DocumentSpace(id=str(uuid.uuid4()), name="E4", department_id=FIN.id, created_by_id=FX["dir"])
        s.add(sp); await s.flush()
        did = str(uuid.uuid4()); lr = str(uuid.uuid4())
        s.add(Document(id=did, title="E4 doc", space_id=sp.id, department_id=FIN.id, division_id=ACCT.id,
                       owner_id=FX["dir"], sensitivity=ResourceSensitivity.INTERNAL,
                       status=DocumentStatus.PUBLISHED, content_json={"type": "doc"}))
        s.add(Resource(id=lr, name="E4 doc", department_id=FIN.id, division_id=ACCT.id, owner_id=FX["dir"],
                       sensitivity=ResourceSensitivity.INTERNAL, is_active=True,
                       attributes={"document_id": did, "source": "edm"}, tags=[]))
        await s.flush()
        for a in FX["an"]:
            asg(a, lr)
        FX["doc"] = did
        await s.commit()
    await engine.dispose()


def start_server():
    env = dict(os.environ, **ENV, PYTHONPATH=BACKEND)
    log = open(os.path.join(OUT, f"e4_{LABEL}_uvicorn.log"), "w")
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                          "--port", str(PORT), "--workers", str(WORKERS), "--log-level", "warning",
                          "--no-access-log"], cwd=BACKEND, env=env, stdout=log, stderr=log)
    for _ in range(120):
        try:
            if httpx.get(f"http://127.0.0.1:{PORT}/health", timeout=1).status_code == 200:
                time.sleep(2)
                return p
        except Exception:
            pass
        time.sleep(0.5)
    p.kill(); raise RuntimeError("server did not start")


async def closed_loop(c, make, n):
    """n requests from C concurrent workers; returns latencies (s), statuses, wall time."""
    lat, st, idx = [], [], iter(range(n))
    lock = asyncio.Lock()

    async def worker(w):
        while True:
            async with lock:
                i = next(idx, None)
            if i is None:
                return
            m, url, kw = make(i, w)
            t0 = time.perf_counter()
            r = await c.request(m, url, **kw)
            lat.append(time.perf_counter() - t0); st.append(r.status_code)

    t0 = time.perf_counter()
    await asyncio.gather(*[worker(w) for w in range(C)])
    return lat, st, time.perf_counter() - t0


def boot(x, f, B=10000, seed=7):
    rng = np.random.default_rng(seed); x = np.asarray(x)
    v = np.array([f(rng.choice(x, x.size)) for _ in range(B)])
    return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]


async def workloads(c):
    an, rfile, doc = FX["an"], FX["rfile"], FX["doc"]
    H = {a: tok(a) for a in an + [FX["dir"], FX["stranger"]]}
    asg_iter = iter(FX["rasg"])
    W = {
        "decide_hit": lambda i, w: ("POST", f"{API}/access/decide",
                                    {"json": {"resource_id": rfile, "action": "read"}, "headers": H[an[w]]}),
        "decide_miss": lambda i, w: ("POST", f"{API}/access/decide",
                                     {"json": {"resource_id": FX["rmiss"][i % N], "action": "read"}, "headers": H[an[0]]}),
        "pep_allow": lambda i, w: ("GET", f"{API}/pep/access/{rfile}", {"headers": H[an[w]]}),
        "pep_deny": lambda i, w: ("GET", f"{API}/pep/access/{rfile}", {"headers": H[FX["stranger"]]}),
        "doc_read": lambda i, w: ("GET", f"{API}/documents/{doc}", {"headers": H[an[w]]}),
        "asg_create": lambda i, w: ("POST", f"{API}/resources/{next(asg_iter)}/assignments",
                                    {"json": {"subject_id": an[1], "actions": ["read"]}, "headers": H[FX["dir"]]}),
    }
    rds = aioredis.from_url(REDIS)
    out = {}
    for name, make in W.items():
        lat_all, thr, statuses = [], [], {}
        if name != "decide_miss":
            await closed_loop(c, make, WARM)
        for rep in range(REPS):
            if name == "decide_miss":
                await rds.flushdb()
            lat, st, wall = await closed_loop(c, make, N)
            lat_all += lat; thr.append(N / wall)
            for x in st:
                statuses[x] = statuses.get(x, 0) + 1
        ms = np.asarray(lat_all) * 1000
        out[name] = {"n": int(ms.size), "reps": REPS, "concurrency": C, "status_counts": statuses,
                     "median_ms": float(np.median(ms)), "median_ci95": boot(ms, np.median),
                     "p95_ms": float(np.percentile(ms, 95)), "p95_ci95": boot(ms, lambda v: np.percentile(v, 95)),
                     "p99_ms": float(np.percentile(ms, 99)),
                     "throughput_rps": thr, "throughput_mean": float(np.mean(thr)),
                     "latencies_ms": [round(float(v), 3) for v in ms]}
        print(f"[{LABEL}] {name:12s} n={ms.size} median={out[name]['median_ms']:.2f}ms "
              f"p95={out[name]['p95_ms']:.2f}ms thr={np.mean(thr):.1f}/s status={statuses}", flush=True)
    await rds.aclose()
    return out


async def served_entry(rds, sid, rid):
    base = f"pip:assign:{sid}:{rid}"
    v = await rds.get(base)
    if v is None:
        g0, gs, gr = [x.decode() if x else "0" for x in await rds.mget("pip:gen:all", f"pip:gen:s:{sid}", f"pip:gen:r:{rid}")]
        v = await rds.get(f"{base}:{g0}:{gs}:{gr}")
    return v


async def race(c):
    rds = aioredis.from_url(REDIS)
    Hd = tok(FX["dir"])
    stale_entry = stale_allow = 0; trials = []
    for t in range(T_RACE):
        an = FX["an"][t % len(FX["an"])]; Ha = tok(an); rid = FX["rrace"][t]
        r = await c.post(f"{API}/resources/{rid}/assignments", json={"subject_id": an, "actions": ["read"]}, headers=Hd)
        aid = r.json()["id"]
        async for k in rds.scan_iter(match=f"pip:assign:{an}:{rid}*"):
            await rds.delete(k)
        dec = lambda: c.post(f"{API}/access/decide", json={"resource_id": rid, "action": "read"}, headers=Ha)
        tasks = [c.delete(f"{API}/resources/{rid}/assignments/{aid}", headers=Hd)] + [dec() for _ in range(K_RACE)]
        random.shuffle(tasks)
        await asyncio.gather(*tasks)
        after = (await dec()).json().get("result")
        v = await served_entry(rds, an, rid)
        se = bool(v and json.loads(v).get("actions"))
        stale_entry += se; stale_allow += after == "allow"
        trials.append({"stale_entry": se, "decision_after_commit": after})
    await rds.aclose()
    return {"trials": T_RACE, "concurrent_decisions": K_RACE, "workers": WORKERS,
            "stale_entry_after_commit": stale_entry, "allow_after_commit": stale_allow}


async def main():
    os.makedirs(OUT, exist_ok=True)
    await setup()
    srv = start_server()
    try:
        limits = httpx.Limits(max_connections=C * 2, max_keepalive_connections=C * 2)
        async with httpx.AsyncClient(timeout=60, limits=limits) as c:
            res = {"label": LABEL, "backend": BACKEND, "workers": WORKERS, "cpus": os.cpu_count(),
                   "started": datetime.now(timezone.utc).isoformat()}
            res["workloads"] = await workloads(c)
            res["race_multiworker"] = await race(c)
            print(f"[{LABEL}] race {res['race_multiworker']}", flush=True)
    finally:
        srv.terminate()
        try:
            srv.wait(15)
        except Exception:
            srv.kill()
    json.dump(res, open(os.path.join(OUT, f"e4_{LABEL}.json"), "w"))


if __name__ == "__main__":
    asyncio.run(main())
