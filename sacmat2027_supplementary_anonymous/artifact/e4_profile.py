"""
E4 profile -- explains latency differences between snapshot and fork: sequential in-process
requests (no concurrency) with cProfile; reports per-request time and the application
functions with the largest cumulative time.

Usage: python e4_profile.py <backend> <label> <db-url> <redis-url> <out-dir>
"""
import asyncio, cProfile, io, os, pstats, sys, time
BACKEND, LABEL, DBURL, REDIS, OUT = sys.argv[1:6]
sys.argv = [sys.argv[0], BACKEND, LABEL, DBURL, REDIS, "0", "1", OUT]
os.environ.update({"E4_N": "50", "E4_REPS": "1", "E4_RACE_T": "1", "E4_C": "4"})
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e4_cost as E                                                # noqa: E402
import httpx                                                       # noqa: E402
from app.main import app                                           # noqa: E402

N = 300


async def main():
    await E.setup()
    an, rfile = E.FX["an"][0], E.FX["rfile"]
    h = E.tok(an)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://p") as c:
        calls = {"decide_hit": lambda: c.post("/api/v1/access/decide", json={"resource_id": rfile, "action": "read"}, headers=h),
                 "pep_allow": lambda: c.get(f"/api/v1/pep/access/{rfile}", headers=h)}
        res = {}
        for name, call in calls.items():
            for _ in range(30):
                await call()
            pr = cProfile.Profile(); t0 = time.perf_counter(); pr.enable()
            for _ in range(N):
                r = await call()
            pr.disable(); dt = (time.perf_counter() - t0) / N * 1000
            s = io.StringIO(); ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
            ps.print_stats(r"(app/|asyncpg|redis|sqlalchemy/engine)", 25)
            res[name] = (round(dt, 2), r.status_code, s.getvalue())
    with open(os.path.join(OUT, f"e4_profile_{LABEL}.txt"), "w") as f:
        for k, (dt, st, txt) in res.items():
            f.write(f"=== {k}: {dt} ms/request sequential (status {st})\n{txt}\n")
    print({k: v[:2] for k, v in res.items()})


asyncio.run(main())
