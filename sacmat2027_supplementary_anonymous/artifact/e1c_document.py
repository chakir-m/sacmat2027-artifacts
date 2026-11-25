"""
E1c -- Bounded-exhaustive check of the DOCUMENT read procedure of v2 (phase 5).

v2 decides a document read with _assert_can_read (documents.py): P_ctx first, then the PDP on the
linked object for published documents, and workflow rules for the others (classification barrier,
owner, director, division manager, published-for-employees, collaborators, grants on the linked
object). This harness drives that REAL procedure over every world of a bounded domain. As in E1, only
data sources are stubbed: an in-memory session answers the procedure's queries (linked object,
collaborator row, assignment, delegation, subject) from the world, the PIP cache getters return the
world's grant sets, policy-id lookup returns {}, and the PDP's decision log is skipped.

Each decision is compared with
  * M_DOC, a transcription of the procedure (fidelity: the reference is right), and
  * the requirements on the document route, for role != admin, with grants on the linked object o_d:
      R1  not sameDept and no delegation          => deny
      R2  cls(u,d) and not ow                     => deny
      R3  employee and allow => read in Gasg(o_d) or read in Gdel(o_d) or ow
                                or (d unpublished and u is a collaborator)
      R6  risk >= theta                           => deny
      DR4 d published and o_d exists              => same decision as F on (u, o_d, read)
    where ow = owner(d) = u and sameDept.

Usage: python e1c_document.py <backend> <out-json>
"""
import asyncio, itertools, json, os, sys, time, uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

BACKEND, OUT = sys.argv[1], sys.argv[2]
os.environ.setdefault("SECRET_KEY", "e1c_harness_secret_key_32_chars_minimum")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:y@localhost:1/none")
os.environ.setdefault("REDIS_URL", "redis://localhost:1/0")
sys.path.insert(0, BACKEND)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import structlog, logging                                                     # noqa: E402
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
logging.disable(logging.CRITICAL)
from fastapi import HTTPException                                             # noqa: E402
from app.api import documents as docs_mod                                     # noqa: E402
from app.services import pdp as pdp_mod                                       # noqa: E402
from app.models.models import Subject, Resource, Role, Document, DocumentStatus  # noqa: E402
from app.core.config import settings                                          # noqa: E402
from semantics import C9_FIX, decide_concrete, ALLOW                         # noqa: E402

ROLES = ["admin", "director", "division_manager", "analyst", "custom"]
SUBJ_DIV = ["D1", None]
DEPT_DIV = [(True, "D1"), (True, "D2"), (True, None), (False, "D3"), (False, None)]
STATUS = ["draft", "review", "pending_approval", "approved", "published", "archived", "rejected"]
CLR = {"normal": 1, "elevated": 2, "delegated": 3}
SENS = {"public": 0, "internal": 1, "sensitive": 2, "top_secret": 3}
LINKED = ["none", "active", "inactive"]
ASG = [frozenset(), frozenset({"read"}), frozenset({"write"})]
DEL = [frozenset(), frozenset({"read"})]
OFF = 0 if 7 <= datetime.now(timezone.utc).hour < 19 else 30
THETA = 40 + OFF                  # risk-high worlds: five failed logins (+40); time signal neutralised


class Res:
    def __init__(self, v): self.v = v
    def scalar_one_or_none(self): return self.v
    def first(self): return self.v
    def scalars(self): return self


class FakeDB:
    """Answers the procedure's queries from the current world W."""
    W = None
    def add(self, *a, **k): pass
    async def flush(self): pass
    async def execute(self, stmt):
        s = str(stmt); W = FakeDB.W
        if "FROM resources" in s:
            o = W["linked"]
            where = s.split("WHERE", 1)[1] if "WHERE" in s else ""
            if o is None or ("resources.is_active" in where and not o.is_active):
                return Res(None)
            return Res(o)
        if "FROM document_collaborators" in s:
            return Res(("c",) if W["collab"] else None)
        if "FROM resource_assignments" in s:   # _check_delegation_read: active, not past valid_until
            return Res("a" if W["linked"] is not None and W["A"] else None)
        if "FROM delegations" in s:
            return Res("d" if W["linked"] is not None and W["D"] else None)
        if "FROM subjects" in s:
            return Res(W["subject"])
        raise AssertionError("unexpected query: " + s[:120])


class Env:                                  # abstract environment for C9_FIX (semantics.py)
    def __init__(self, role, sdiv, sd, rdiv, clr, sens, A, D, risk, own):
        self.admin, self.dir = role == "admin", role == "director"
        self.dm, self.an = role == "division_manager", role == "analyst"
        self.same_dept = sd
        self.same_div_raw = sdiv == rdiv
        self.same_div = sdiv is not None and sdiv == rdiv
        self.sens_pos = SENS[sens] > 0
        self.clr_lt_sens = CLR[clr] < SENS[sens]
        self.has_asg, self.has_del = bool(A), bool(D)
        self._A, self._D = A, D
        self.risk_high = risk
        self.own = own
    def asg(self, a): return a in self._A
    def dele(self, a): return a in self._D
    def is_read(self, a): return a == "read"
    def own_act(self, a): return a in ("read", "download")


FIXED = os.environ.get("E1C_FIXED") == "1"     # transcription of the v2 commit that closes the E1c finding


def m_doc(w):
    """Transcription of v2's _assert_can_read (reference for fidelity)."""
    role, sdiv, sd, ddiv, st, clr, sens, own, collab, linked, A, D, risk = w
    if role == "admin":
        return True
    if risk:
        return False
    if st == "published" and (linked == "active" or (FIXED and linked == "inactive")):
        e = Env(role, sdiv, sd, ddiv, clr, sens, A, D, risk, own)
        return decide_concrete(C9_FIX, e, "read")[0] == ALLOW
    if FIXED and st == "published":
        return False
    exempt = (own and (sd or not FIXED)) or (role == "director" and sd) or (role == "division_manager" and sd and sdiv is not None
                                                    and ddiv == sdiv)
    if not exempt and SENS[sens] > 0 and CLR[clr] < SENS[sens]:
        return False
    # _can_read_document
    if sd:
        if own or role == "director":
            return True
        if role == "division_manager":
            if ddiv is not None:
                if ddiv == sdiv:
                    return True
            elif st in ("review", "pending_approval"):
                return True
        if role == "analyst" and st == "published":
            return True
        if collab:
            return True
    # _check_delegation_read: any linked object, active assignment (any action) or approved delegation
    return st == "published" and linked != "none" and (bool(A) or bool(D))


async def main():
    pdp_mod.pip_cache.get_assignment = AsyncMock(side_effect=lambda s, r: sorted(FakeDB.W["A"]))
    pdp_mod.pip_cache.get_delegation = AsyncMock(side_effect=lambda s, r: sorted(FakeDB.W["D"]))
    pdp_mod.pip_cache.set_assignment = AsyncMock(return_value=None)
    pdp_mod.pip_cache.set_delegation = AsyncMock(return_value=None)
    pdp_mod.PolicyDecisionPoint._load_policy_ids = AsyncMock(return_value={})
    pdp_mod.PolicyDecisionPoint._log_decision = AsyncMock(return_value=None)
    old_theta = settings.RISK_DENY_THRESHOLD
    settings.RISK_DENY_THRESHOLD = THETA
    db = FakeDB()
    ids = {"DA": "dept-A", "DB": "dept-B", "D1": "div-1", "D2": "div-2", "D3": "div-3"}
    n = agree = 0; indet = 0
    viol, viol_ex, mism = {}, {}, []
    t0 = time.time(); h0 = datetime.now(timezone.utc).hour
    for w in itertools.product(ROLES, SUBJ_DIV, DEPT_DIV, STATUS, CLR, SENS, (False, True), (False, True),
                               LINKED, ASG, DEL, (False, True)):
        role, sdiv, (sd, ddiv), st, clr, sens, own, collab, linked, A, D, risk = w
        wf = (role, sdiv, sd, ddiv, st, clr, sens, own, collab, linked, A, D, risk)
        u = Subject(); u.id = str(uuid.uuid4()); u.email = "e1c"; u.status = "active"
        r = Role(); r.id = "role"; r.builtin_type = None if role in ("custom", "admin") else role; r.name = role
        u.role = r; u.role_id = r.id; u.is_platform_admin = role == "admin"
        u.department_id = ids["DA"]; u.division_id = ids[sdiv] if sdiv else None
        u.clearance = clr; u.failed_login_attempts = 5 if risk else 0; u.attributes = {}
        d = Document(); d.id = str(uuid.uuid4()); d.department_id = ids["DA"] if sd else ids["DB"]
        d.division_id = ids[ddiv] if ddiv else None; d.owner_id = u.id if own else "someone-else"
        d.status = DocumentStatus(st); d.sensitivity = sens
        o = None
        if linked != "none":
            o = Resource(); o.id = str(uuid.uuid4()); o.department_id = d.department_id
            o.division_id = d.division_id; o.owner_id = d.owner_id; o.sensitivity = sens
            o.is_active = linked == "active"; o.attributes = {"document_id": d.id, "source": "edm"}
        FakeDB.W = {"linked": o, "collab": collab, "A": A, "D": D, "subject": u}
        builtin = "admin" if role == "admin" else (None if role == "custom" else role)
        try:
            await docs_mod._assert_can_read(db, d, u, builtin); got = True
        except HTTPException as ex:
            got = False
            if ex.status_code != 403:
                indet += 1
        n += 1
        ref = m_doc(wf)
        agree += ref == got
        if ref != got and len(mism) < 10:
            mism.append({"world": [str(x) if isinstance(x, frozenset) else x for x in wf], "impl": got, "ref": ref})
        if role != "admin":
            owx = own and sd
            cls = SENS[sens] > 0 and CLR[clr] < SENS[sens] and not (role == "director" and sd) \
                and not (role == "division_manager" and sd and sdiv is not None and sdiv == ddiv)
            req = {
                "R1": not (not sd and not D and got),
                "R2": not (cls and not owx and got),
                "R3": not (role == "analyst" and got) or ("read" in A or "read" in D or owx
                                                           or (st != "published" and collab)),
                "R6": not (risk and got),
            }
            if st == "published" and linked != "none":
                e = Env(role, sdiv, sd, ddiv, clr, sens, A, D, risk, own)
                req["DR4"] = got == (decide_concrete(C9_FIX, e, "read")[0] == ALLOW)
            for k, ok in req.items():
                if not ok:
                    key = f"{k}|linked={linked}|status={st}"
                    viol[key] = viol.get(key, 0) + 1
                    viol_ex.setdefault(k, {"role": role, "subj_div": sdiv, "same_dept": sd, "doc_div": ddiv,
                                           "status": st, "clearance": clr, "sensitivity": sens, "owner": own,
                                           "collaborator": collab, "linked": linked, "A_asg": sorted(A),
                                           "A_del": sorted(D), "risk_high": risk, "decision": got})
    settings.RISK_DENY_THRESHOLD = old_theta
    assert datetime.now(timezone.utc).hour == h0 or (7 <= h0 < 19) == (7 <= datetime.now(timezone.utc).hour < 19)
    res = {"worlds": n, "agreement_with_M_DOC": agree, "non_403_errors": indet, "mismatch_examples": mism,
           "requirement_violations": viol, "violation_witness": viol_ex, "runtime_s": round(time.time() - t0, 1),
           "theta_used": THETA,
           "domain": {"roles": ROLES, "subj_div": [str(x) for x in SUBJ_DIV], "dept_div": [list(map(str, x)) for x in DEPT_DIV],
                      "status": STATUS, "clearance": list(CLR), "sensitivity": list(SENS), "linked": LINKED,
                      "asg": [sorted(x) for x in ASG], "del": [sorted(x) for x in DEL]}}
    json.dump(res, open(OUT, "w"), indent=1, default=str)
    print(json.dumps({k: res[k] for k in ("worlds", "agreement_with_M_DOC", "non_403_errors", "requirement_violations",
                                          "runtime_s")}, indent=1, default=str))


if __name__ == "__main__":
    asyncio.run(main())
