"""
E5 probe -- fast L2/L3 oracle (pass/fail) used as the kill criterion in the enforcement-code
mutation study (WP6). It condenses the E2 probes into one run (~20 s) without long waits:
safety probes S1-S34 (the defect must not reappear) and liveness probes (legitimate access must
still work, L1-L23, so that mutants that deny everything are also killed). S24-S27, L16-L18
were added in phase 5 (owner rule in the PDP, request address on document reads, deleted objects);
S28-S34 and L19-L23 in phase 6 (assignments grant read only; comment resolution and signing, found by the
generated route inventory l3_route_inventory.py; document list and delegation visibility, found by the stranger
sweep l3_stranger_sweep.py; workflow transitions and folder removal, found by the state sweep l3_state_sweep.py).

Usage: python e5_l3_probe.py <backend> <db-url> <redis-url> [<out-json>]
Exit 0 iff every probe passes.
"""
import asyncio, json, os, sys, time, uuid
from datetime import datetime, timezone, timedelta

BACKEND, DBURL, REDIS = sys.argv[1:4]
OUTJ = sys.argv[4] if len(sys.argv) > 4 else None
os.environ.update({"DATABASE_URL": DBURL, "REDIS_URL": REDIS, "ENVIRONMENT": "test",
                   "SECRET_KEY": "e5_harness_secret_key_32_chars_minimum", "STORAGE_BACKEND": "local"})
sys.path.insert(0, BACKEND)
import logging, structlog                                        # noqa: E402
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
logging.disable(logging.CRITICAL)
import httpx                                                     # noqa: E402
import redis.asyncio as aioredis                                 # noqa: E402
from sqlalchemy import select, func, update                      # noqa: E402
from app.main import app                                         # noqa: E402
from app.db.database import AsyncSessionLocal, engine            # noqa: E402
from app.db.seed import seed_initial_data                        # noqa: E402
from app.models.models import (Base, Subject, Resource, Role, Department, Division, ResourceAssignment,  # noqa: E402
    AccessDecision, AuditLog, Document, DocumentSpace, DocumentStatus, UserStatus, DocumentCollaborator,
    ClearanceLevel, ResourceSensitivity, DocumentComment, DocumentSignature, DocumentFolder)
from app.core.security import create_access_token                # noqa: E402
from app.core.config import settings                              # noqa: E402
from app.services import pip as pip_mod                          # noqa: E402
from app.services.pdp import PolicyDecisionPoint, AccessRequest  # noqa: E402

API = "/api/v1"
RES = {}


def now(): return datetime.now(timezone.utc)
def H(sid): return {"Authorization": "Bearer " + create_access_token(sid, f"{sid}@e5", extra_claims={"sv": 0})}


def check(name, cond, detail=None):
    RES[name] = {"pass": bool(cond), "detail": detail}


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
        s.add(Subject(id=sid, email=f"{role}-{sid[:8]}@e5.test", username=f"{role}-{sid[:8]}", full_name=role,
                      hashed_password="x", role_id=roles[role].id, department_id=dept.id,
                      division_id=div.id if div else None, clearance=ClearanceLevel(clearance),
                      status=UserStatus.ACTIVE, is_platform_admin=False, mfa_enabled=mfa,
                      session_version=0, attributes={}))
        await s.commit()
    return sid


async def mk_resource(owner, dept, div=None, sens="internal", with_file=True, attrs=None):
    rid = str(uuid.uuid4()); fp = None
    if with_file:
        os.makedirs("/app/storage/e5", exist_ok=True); fp = f"e5/{rid}.txt"
        open(f"/app/storage/{fp}", "w").write("E5 payload " + rid)
    async with AsyncSessionLocal() as s:
        s.add(Resource(id=rid, name=f"r-{rid[:6]}", department_id=dept.id, division_id=div.id if div else None,
                       owner_id=owner, sensitivity=ResourceSensitivity(sens), is_active=True,
                       attributes=attrs or {}, tags=[], file_path=fp, file_size=47 if fp else None,
                       mime_type="text/plain" if fp else None))
        await s.commit()
    return rid


async def rows(sid, rid):
    async with AsyncSessionLocal() as s:
        ad = (await s.execute(select(func.count()).select_from(AccessDecision).where(
            AccessDecision.subject_id == sid, AccessDecision.resource_id == rid))).scalar()
        al = (await s.execute(select(func.count()).select_from(AuditLog).where(
            AuditLog.subject_id == sid, AuditLog.entity_id == rid))).scalar()
    return ad, al


async def run(c, depts, divs, roles):
    FIN, LEG, ACCT, COMP = depts["FIN"], depts["LEG"], divs["ACCT"], divs["COMP"]
    dec = lambda sid, rid, a="read": c.post(f"{API}/access/decide", json={"resource_id": rid, "action": a}, headers=H(sid))
    res_of = lambda r: r.json().get("result")
    dirF = await mk_subject(roles, "director", FIN, clearance="delegated", mfa=True)
    dirL = await mk_subject(roles, "director", LEG, clearance="elevated", mfa=True)
    an = await mk_subject(roles, "analyst", FIN, ACCT)
    an2 = await mk_subject(roles, "analyst", FIN, ACCT)
    strangerL = await mk_subject(roles, "analyst", LEG, divs["CONT"])

    # Documents: top-secret published doc (deny) and internal doc with assignment (allow)
    async with AsyncSessionLocal() as s:
        sp = DocumentSpace(id=str(uuid.uuid4()), name="E5", department_id=FIN.id, created_by_id=dirF)
        s.add(sp); await s.flush()
        docs = {}
        for key, sens in (("ts", ResourceSensitivity.TOP_SECRET), ("int", ResourceSensitivity.INTERNAL)):
            did = str(uuid.uuid4()); lr = str(uuid.uuid4())
            s.add(Document(id=did, title=f"E5 {key}", space_id=sp.id, department_id=FIN.id, division_id=ACCT.id,
                           owner_id=dirF, sensitivity=sens, status=DocumentStatus.PUBLISHED,
                           content_json={"type": "doc", "secret": f"PAYLOAD-{key}"}))
            s.add(Resource(id=lr, name=f"E5 {key}", department_id=FIN.id, division_id=ACCT.id, owner_id=dirF,
                           sensitivity=sens, is_active=True, attributes={"document_id": did, "source": "edm"}, tags=[]))
            docs[key] = (did, lr)
        await s.commit()
    r = await c.get(f"{API}/documents/{docs['ts'][0]}", headers=H(an))
    check("S1_doc_api_top_secret_denied", r.status_code == 403 and "PAYLOAD-ts" not in r.text, r.status_code)
    await c.post(f"{API}/resources/{docs['int'][1]}/assignments", json={"subject_id": an, "actions": ["read"]}, headers=H(dirF))
    r = await c.get(f"{API}/documents/{docs['int'][0]}", headers=H(an))
    check("L1_doc_api_assigned_read_allowed", r.status_code == 200, r.status_code)

    # Phase 6, found by the generated route inventory: resolving a comment and signing a document must be
    # decided like reading the document (both routes of v1 and of v2 up to commit eb9675e decide nothing).
    # These four checks use a client that turns server exceptions into HTTP 500 (as a real server does), and
    # check the database: in v1 the unauthorised resolution is committed before the route fails.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=c._transport.app, raise_app_exceptions=False),
                                 base_url="http://e5", headers={"X-Requested-With": "XMLHttpRequest"}, timeout=30) as c6:
        cm = await c.post(f"{API}/documents/{docs['int'][0]}/comments", json={"content": "E5 COMMENT-SECRET"},
                          headers=H(dirF))
        cid = cm.json().get("id")

        async def resolved():
            async with AsyncSessionLocal() as s:
                return (await s.execute(select(DocumentComment.is_resolved).where(DocumentComment.id == cid))).scalar_one()
        rz = await c6.patch(f"{API}/documents/{docs['int'][0]}/comments/{cid}/resolve", headers=H(strangerL))
        st = await resolved()
        check("S29_comment_resolve_needs_read", rz.status_code == 403 and not st and "COMMENT-SECRET" not in rz.text,
              [rz.status_code, st])
        rz2 = await c6.patch(f"{API}/documents/{docs['int'][0]}/comments/{cid}/resolve", headers=H(an))
        check("L19_reader_resolves_comment", rz2.status_code == 200 and await resolved(), rz2.status_code)
        async with AsyncSessionLocal() as s:
            dsig = str(uuid.uuid4()); lsig = str(uuid.uuid4())
            s.add(Document(id=dsig, title="E5 sig", space_id=sp.id, department_id=FIN.id, division_id=ACCT.id,
                           owner_id=dirF, sensitivity=ResourceSensitivity.INTERNAL, status=DocumentStatus.PUBLISHED,
                           requires_signature=True, content_json={"type": "doc"}))
            s.add(Resource(id=lsig, name="E5 sig", department_id=FIN.id, division_id=ACCT.id, owner_id=dirF,
                           sensitivity=ResourceSensitivity.INTERNAL, is_active=True,
                           attributes={"document_id": dsig, "source": "edm"}, tags=[]))
            await s.commit()

        async def signed(sid):
            async with AsyncSessionLocal() as s:
                return (await s.execute(select(func.count()).select_from(DocumentSignature).where(
                    DocumentSignature.document_id == dsig, DocumentSignature.signer_id == sid))).scalar_one()
        sg = await c6.post(f"{API}/documents/{dsig}/sign", json={"signer_name": "E5 stranger"}, headers=H(strangerL))
        n_s = await signed(strangerL)
        check("S30_signing_needs_read", sg.status_code == 403 and n_s == 0, [sg.status_code, n_s])
        await c.post(f"{API}/resources/{lsig}/assignments", json={"subject_id": an, "actions": ["read"]}, headers=H(dirF))
        sg2 = await c6.post(f"{API}/documents/{dsig}/sign", json={"signer_name": "E5 reader"}, headers=H(an))
        check("L20_reader_signs", sg2.status_code == 201 and await signed(an) == 1, sg2.status_code)

    # MFA obligation on every file endpoint (director without MFA on a TOP_SECRET file)
    dnm = await mk_subject(roles, "director", FIN, clearance="delegated", mfa=False)
    rts = await mk_resource(an, FIN, ACCT, "top_secret")
    codes = [(await c.get(f"{API}/pep/{e}/{rts}", headers=H(dnm))).status_code for e in ("access", "preview", "download")]
    check("S2_mfa_obligation_all_endpoints", codes == [403, 403, 403], codes)
    codes = [(await c.get(f"{API}/pep/{e}/{rts}", headers=H(dirF))).status_code for e in ("access", "preview", "download")]
    check("L2_mfa_director_allowed", codes == [200, 200, 200], codes)

    # Owner access scoped to the department; action derived from the endpoint
    anF = await mk_subject(roles, "analyst", FIN, ACCT)
    rleg = await mk_resource(anF, LEG, COMP, "sensitive")
    c1 = (await c.get(f"{API}/pep/access/{rleg}?action=delete", headers=H(anF))).status_code
    c2 = (await c.get(f"{API}/pep/download/{rleg}", headers=H(anF))).status_code
    check("S3_owner_cross_dept_denied", c1 in (400, 403) and c2 == 403, [c1, c2])
    rown = await mk_resource(anF, FIN, ACCT, "internal")
    check("L3_owner_same_dept_allowed", (await c.get(f"{API}/pep/access/{rown}", headers=H(anF))).status_code == 200)

    # Download requires the download action
    r4 = await mk_resource(dirF, FIN, ACCT, "internal")
    ra = await c.post(f"{API}/resources/{r4}/assignments", json={"subject_id": an2, "actions": ["read"]}, headers=H(dirF))
    c1 = (await c.get(f"{API}/pep/download/{r4}", headers=H(an2))).status_code
    c2 = (await c.get(f"{API}/pep/access/{r4}", headers=H(an2))).status_code
    check("S4_download_needs_download_action", c1 == 403, c1)
    check("L4_assigned_read_allowed", c2 == 200, c2)

    # Audit persistence of a denial (independent transaction)
    ad0, al0 = await rows(strangerL, r4)
    for _ in range(3):
        await c.get(f"{API}/pep/access/{r4}", headers=H(strangerL))
    ad1, al1 = await rows(strangerL, r4)
    check("S5_denials_persisted", ad1 - ad0 == 3 and al1 - al0 == 3, [ad1 - ad0, al1 - al0])

    # Revocation authority (and the legitimate revocation still works)
    rL = await mk_resource(dirL, LEG, COMP, "internal", with_file=False)
    dl = (await c.post(f"{API}/delegations", json={"resource_id": rL, "justification": "e5"}, headers=H(dirF))).json()["id"]
    ap = await c.post(f"{API}/delegations/{dl}/approve", json={"expires_at": (now() + timedelta(hours=1)).isoformat()}, headers=H(dirL))
    check("L5_delegation_approved_and_usable", ap.status_code == 200 and res_of(await dec(dirF, rL)) == "allow")
    c1 = (await c.post(f"{API}/delegations/{dl}/revoke", json={"reason": "e5"}, headers=H(strangerL))).status_code
    c2 = (await c.delete(f"{API}/resources/{r4}/assignments/{ra.json()['id']}", headers=H(strangerL))).status_code
    check("S6_revocation_needs_authority", c1 == 403 and c2 == 403, [c1, c2])
    # Delegation revocation takes effect immediately (cache warm)
    c3 = (await c.post(f"{API}/delegations/{dl}/revoke", json={"reason": "e5"}, headers=H(dirL))).status_code
    check("S7_delegation_revocation_immediate", c3 == 200 and res_of(await dec(dirF, rL)) == "deny", c3)
    # Phase 6, found by the stranger sweep (l3_stranger_sweep.py): the delegation detail and the delegation
    # list filtered by object, and the document list, must apply the same decision as the single-object routes
    g1 = await c.get(f"{API}/delegations/{dl}", headers=H(strangerL))
    g2 = await c.get(f"{API}/delegations", params={"resource_id": rL}, headers=H(strangerL))
    check("S32_delegation_visible_only_in_scope", g1.status_code in (403, 404) and dl not in g2.text,
          [g1.status_code, dl in g2.text])
    g3 = await c.get(f"{API}/delegations/{dl}", headers=H(dirF))
    check("L22_requester_sees_delegation", g3.status_code == 200, g3.status_code)
    l_un = await c.get(f"{API}/documents", headers=H(an2))
    l_as = await c.get(f"{API}/documents", headers=H(an))
    check("S31_document_list_decided_per_document",
          l_un.status_code == 200 and "PAYLOAD-int" not in l_un.text and "PAYLOAD-ts" not in l_un.text
          and "PAYLOAD-ts" not in l_as.text, [l_un.status_code, "PAYLOAD-int" in l_un.text, "PAYLOAD-ts" in l_as.text])
    check("L21_document_list_shows_readable", l_as.status_code == 200 and "PAYLOAD-int" in l_as.text, l_as.status_code)
    # Phase 6, found by the state sweep (l3_state_sweep.py): workflow transitions and folder removal stay inside
    # the actor's department
    dmL = await mk_subject(roles, "division_manager", LEG, COMP)
    async with AsyncSessionLocal() as s:
        dpub = str(uuid.uuid4()); drev = str(uuid.uuid4()); fid = str(uuid.uuid4())
        s.add(Document(id=dpub, title="E5 approved", space_id=sp.id, department_id=FIN.id, division_id=ACCT.id,
                       owner_id=dirF, sensitivity=ResourceSensitivity.INTERNAL, status=DocumentStatus.APPROVED,
                       content_json={"type": "doc"}))
        s.add(Document(id=drev, title="E5 review", space_id=sp.id, department_id=FIN.id, division_id=ACCT.id,
                       owner_id=dirF, sensitivity=ResourceSensitivity.INTERNAL, status=DocumentStatus.REVIEW,
                       content_json={"type": "doc"}))
        s.add(DocumentFolder(id=fid, name="E5 folder", space_id=sp.id, created_by_id=dirF))
        await s.commit()

    async def doc_status(did):
        async with AsyncSessionLocal() as s:
            return (await s.execute(select(Document.status).where(Document.id == did))).scalar_one()

    async def folder_active():
        async with AsyncSessionLocal() as s:
            return (await s.execute(select(DocumentFolder.is_active).where(DocumentFolder.id == fid))).scalar_one()
    p1 = await c.post(f"{API}/documents/{dpub}/publish", json={}, headers=H(dirL))
    p2 = await c.post(f"{API}/documents/{drev}/request-approval", json={}, headers=H(dirL))
    p3 = await c.delete(f"{API}/documents/spaces/{sp.id}/folders/{fid}", headers=H(dmL))
    st1, st2, fa = await doc_status(dpub), await doc_status(drev), await folder_active()
    check("S33_workflow_stays_in_department", p1.status_code == 403 and p2.status_code == 403
          and st1 == DocumentStatus.APPROVED and st2 == DocumentStatus.REVIEW,
          [p1.status_code, p2.status_code, str(st1), str(st2)])
    check("S34_folder_removal_stays_in_department", p3.status_code == 403 and fa, [p3.status_code, fa])
    p4 = await c.post(f"{API}/documents/{dpub}/publish", json={}, headers=H(dirF))
    check("L23_director_publishes_own_department", p4.status_code == 200
          and await doc_status(dpub) == DocumentStatus.PUBLISHED, p4.status_code)
    await dec(an2, r4)                                  # warm assignment entry
    c4 = (await c.delete(f"{API}/resources/{r4}/assignments/{ra.json()['id']}", headers=H(dirF))).status_code
    check("S8_assignment_revocation_immediate", c4 == 204 and res_of(await dec(an2, r4)) == "deny", c4)

    # Cross-department write after a read-only delegation
    dmF = await mk_subject(roles, "division_manager", FIN, divs["AUD"])
    rL2 = await mk_resource(dirL, LEG, COMP, "internal", with_file=False)
    await c.post(f"{API}/resources/{rL2}/assignments", json={"subject_id": dmF, "actions": ["read", "write"]}, headers=H(dirL))
    d2 = (await c.post(f"{API}/delegations", json={"resource_id": rL2, "justification": "e5"}, headers=H(dmF))).json()["id"]
    await c.post(f"{API}/delegations/{d2}/approve", json={"expires_at": (now() + timedelta(hours=1)).isoformat()}, headers=H(dirL))
    check("S9_no_cross_dept_write_via_delegation", res_of(await dec(dmF, rL2, "write")) == "deny")
    check("L6_cross_dept_read_via_delegation", res_of(await dec(dmF, rL2, "read")) == "allow")

    # Assignments grant read only (phase 6, D1): write and download listed in an assignment have no effect
    an3 = await mk_subject(roles, "analyst", FIN, ACCT)
    r28 = await mk_resource(dirF, FIN, ACCT, "internal")
    await c.post(f"{API}/resources/{r28}/assignments", json={"subject_id": an3, "actions": ["read", "write", "download"]},
                 headers=H(dirF))
    w28 = res_of(await dec(an3, r28, "write"))
    d28 = (await c.get(f"{API}/pep/download/{r28}", headers=H(an3))).status_code
    a28 = (await c.get(f"{API}/pep/access/{r28}", headers=H(an3))).status_code
    check("S28_assignment_grants_read_only", w28 == "deny" and d28 == 403 and a28 == 200, [w28, d28, a28])

    # Expiry honoured for cached grants (4 s validity, entry warmed at ~1 s)
    an3 = await mk_subject(roles, "analyst", FIN, ACCT)
    r5 = await mk_resource(dirF, FIN, ACCT, "internal", with_file=False)
    t0 = time.monotonic()
    await c.post(f"{API}/resources/{r5}/assignments", json={"subject_id": an3, "actions": ["read"],
                 "valid_until": (now() + timedelta(seconds=4)).isoformat()}, headers=H(dirF))
    warm = res_of(await dec(an3, r5))
    await asyncio.sleep(max(0, 4.6 - (time.monotonic() - t0)))
    check("S10_assignment_expiry_honoured", warm == "allow" and res_of(await dec(an3, r5)) == "deny", warm)

    # ---- v2 fixtures (WP6): separate the branches the first probe did not ----
    async with AsyncSessionLocal() as s:
        admin = (await s.execute(select(Subject).where(Subject.is_platform_admin == True))).scalars().first()  # noqa: E712
    dm_norm = await mk_subject(roles, "division_manager", FIN, ACCT, clearance="normal")
    dm_hi = await mk_subject(roles, "division_manager", FIN, divs["AUD"], clearance="delegated")
    an_lo = await mk_subject(roles, "analyst", FIN, ACCT, clearance="normal")
    an_hi = await mk_subject(roles, "analyst", FIN, ACCT, clearance="delegated")
    an_un = await mk_subject(roles, "analyst", FIN, ACCT)
    async with AsyncSessionLocal() as s:
        sp2 = DocumentSpace(id=str(uuid.uuid4()), name="E5b", department_id=FIN.id, created_by_id=dirF)
        s.add(sp2); await s.flush()
        draft = str(uuid.uuid4()); review = str(uuid.uuid4())
        s.add(Document(id=draft, title="E5 TS draft", space_id=sp2.id, department_id=FIN.id, division_id=ACCT.id,
                       owner_id=dirF, sensitivity=ResourceSensitivity.TOP_SECRET, status=DocumentStatus.DRAFT,
                       content_json={"type": "doc", "secret": "PAYLOAD-draft"}))
        s.add(Document(id=review, title="E5 TS dept review", space_id=sp2.id, department_id=FIN.id, division_id=None,
                       owner_id=dirF, sensitivity=ResourceSensitivity.TOP_SECRET, status=DocumentStatus.REVIEW,
                       content_json={"type": "doc", "secret": "PAYLOAD-review"}))
        await s.flush()
        for sub in (an_lo, an_hi):
            s.add(DocumentCollaborator(id=str(uuid.uuid4()), document_id=draft, subject_id=sub, invited_by_id=dirF))
        await s.commit()
    g = lambda sid, did: c.get(f"{API}/documents/{did}", headers=H(sid))
    r = await g(an_un, docs["int"][0])
    check("S12_published_unassigned_denied_via_pdp", r.status_code == 403, r.status_code)
    r = await g(admin.id, docs["ts"][0])
    check("L7_admin_reads_top_secret_doc", r.status_code == 200, r.status_code)
    r = await g(dirF, docs["ts"][0])
    check("L8_owner_reads_own_published_doc", r.status_code == 200, r.status_code)
    r1, r2 = await g(an_lo, draft), await g(an_hi, draft)
    check("S13_collaborator_needs_clearance_on_draft", r1.status_code == 403 and "PAYLOAD-draft" not in r1.text, r1.status_code)
    check("L9_cleared_collaborator_reads_draft", r2.status_code == 200, r2.status_code)
    r1 = await g(dm_norm, review)
    async with AsyncSessionLocal() as s:            # same check for a cleared manager of another division
        pass
    r2 = await g(dm_hi, review)
    check("S14_manager_needs_clearance_on_dept_doc_in_review", r1.status_code == 403, r1.status_code)
    check("L10_cleared_manager_reads_dept_doc_in_review", r2.status_code == 200, r2.status_code)
    # revocation authorities beyond the approving director
    anL_owner = await mk_subject(roles, "analyst", LEG, COMP, clearance="elevated")
    rO = await mk_resource(anL_owner, LEG, COMP, "internal", with_file=False)
    d3 = (await c.post(f"{API}/delegations", json={"resource_id": rO, "justification": "e5"}, headers=H(dirF))).json()["id"]
    await c.post(f"{API}/delegations/{d3}/approve", json={"expires_at": (now() + timedelta(hours=1)).isoformat()}, headers=H(dirL))
    otherDir = await mk_subject(roles, "director", depts["HR"] if "HR" in depts else FIN, clearance="elevated")
    c1 = (await c.post(f"{API}/delegations/{d3}/revoke", json={"reason": "e5"}, headers=H(otherDir))).status_code
    c2 = (await c.post(f"{API}/delegations/{d3}/revoke", json={"reason": "e5"}, headers=H(anL_owner))).status_code
    check("S15_foreign_director_cannot_revoke_delegation", c1 == 403, c1)
    check("L11_resource_owner_revokes_delegation", c2 == 200, c2)
    dmA = await mk_subject(roles, "division_manager", FIN, ACCT, clearance="elevated")
    dmB = await mk_subject(roles, "division_manager", FIN, divs["AUD"], clearance="elevated")
    an5 = await mk_subject(roles, "analyst", FIN, ACCT)
    r7 = await mk_resource(dirF, FIN, ACCT, "internal", with_file=False)
    a7 = (await c.post(f"{API}/resources/{r7}/assignments", json={"subject_id": an5, "actions": ["read"]}, headers=H(dirF))).json()["id"]
    c1 = (await c.delete(f"{API}/resources/{r7}/assignments/{a7}", headers=H(dmB))).status_code
    c2 = (await c.delete(f"{API}/resources/{r7}/assignments/{a7}", headers=H(dmA))).status_code
    check("S16_other_division_manager_cannot_revoke", c1 == 403, c1)
    check("L12_own_division_manager_revokes", c2 == 204, c2)
    # audit outcome field matches the decision
    async with AsyncSessionLocal() as s:
        outs = [r_.outcome for r_ in (await s.execute(select(AuditLog).where(
            AuditLog.subject_id == strangerL, AuditLog.entity_id == r4))).scalars()]
        outs2 = [r_.outcome for r_ in (await s.execute(select(AuditLog).where(
            AuditLog.subject_id == an2, AuditLog.entity_id == r4))).scalars()]
    check("S17_audit_outcome_matches_decision", outs and all(o == "deny" for o in outs)
          and "allow" in outs2, [outs[:3], outs2[:3]])

    # ---- Phase-4 fixtures: branches left unseparated by the 29-check probe (e5v2_survivors.md) ----
    async def mk_doc(owner, dept, div, sens, status, linked=False, rdept=None):
        async with AsyncSessionLocal() as s:
            sp_ = DocumentSpace(id=str(uuid.uuid4()), name="E5c", department_id=dept.id, created_by_id=owner)
            s.add(sp_); await s.flush()
            did = str(uuid.uuid4())
            s.add(Document(id=did, title="E5c", space_id=sp_.id, department_id=dept.id,
                           division_id=div.id if div else None, owner_id=owner, sensitivity=sens, status=status,
                           content_json={"type": "doc", "secret": f"PAYLOAD-{did[:6]}"}))
            if linked:
                s.add(Resource(id=str(uuid.uuid4()), name="E5c", department_id=(rdept or dept).id,
                               division_id=div.id if div else None, owner_id=owner, sensitivity=sens,
                               is_active=True, attributes={"document_id": did, "source": "edm"}, tags=[]))
            await s.commit()
        return did
    # S18: an owner who moved to another department loses the owner shortcut on a published document
    mover = await mk_subject(roles, "analyst", FIN, ACCT)
    dmv = await mk_doc(mover, FIN, ACCT, ResourceSensitivity.INTERNAL, DocumentStatus.PUBLISHED, linked=True)
    async with AsyncSessionLocal() as s:
        await s.execute(update(Subject).where(Subject.id == mover).values(department_id=LEG.id, division_id=COMP.id))
        await s.commit()
    r = await g(mover, dmv)
    check("S18_moved_owner_published_doc_denied", r.status_code == 403, r.status_code)
    # L13: the department's director is exempt from the clearance barrier on drafts
    dirF_el = await mk_subject(roles, "director", FIN, clearance="elevated", mfa=True)
    r = await g(dirF_el, draft)
    check("L13_dept_director_reads_ts_draft", r.status_code == 200, r.status_code)
    # L14: a division manager is exempt only in their own division
    r = await g(dm_norm, draft)
    check("L14_own_division_manager_reads_ts_draft", r.status_code == 200, r.status_code)
    # S19: a division manager without a division gets no exemption (sameDiv needs div(u) != bottom)
    dm_nodiv = await mk_subject(roles, "division_manager", FIN, None, clearance="normal")
    r = await g(dm_nodiv, review)
    check("S19_manager_without_division_not_exempt", r.status_code == 403 and "PAYLOAD-review" not in r.text, r.status_code)
    # S20: a cleared employee who is not a collaborator cannot read someone else's draft
    ownr = await mk_subject(roles, "analyst", FIN, ACCT)
    dd = await mk_doc(ownr, FIN, ACCT, ResourceSensitivity.INTERNAL, DocumentStatus.DRAFT)
    r = await g(an_hi, dd)
    check("S20_non_collaborator_cannot_read_draft", r.status_code == 403, r.status_code)
    # L15: the director of the resource's department may revoke a delegation approved by someone else
    rD = await mk_resource(anL_owner, LEG, COMP, "internal", with_file=False)
    d4 = (await c.post(f"{API}/delegations", json={"resource_id": rD, "justification": "e5"}, headers=H(dirF))).json()["id"]
    apx = await c.post(f"{API}/delegations/{d4}/approve", json={"expires_at": (now() + timedelta(hours=1)).isoformat()},
                       headers=H(admin.id))
    c1 = (await c.post(f"{API}/delegations/{d4}/revoke", json={"reason": "e5"}, headers=H(dirL))).status_code
    check("L15_resource_dept_director_revokes", apx.status_code == 200 and c1 == 200, [apx.status_code, c1])
    # S21: a statement-level (bulk) change to grants takes effect at the next decision
    an6 = await mk_subject(roles, "analyst", FIN, ACCT)
    r8 = await mk_resource(dirF, FIN, ACCT, "internal", with_file=False)
    await c.post(f"{API}/resources/{r8}/assignments", json={"subject_id": an6, "actions": ["read"]}, headers=H(dirF))
    warm = res_of(await dec(an6, r8))
    async with AsyncSessionLocal() as s:
        await s.execute(update(ResourceAssignment).where(ResourceAssignment.subject_id == an6).values(is_active=False))
        await s.commit()
    check("S21_bulk_grant_update_takes_effect", warm == "allow" and res_of(await dec(an6, r8)) == "deny", warm)
    # S22/S23: a high-risk owner is denied (P_ctx precedes the owner rule), at the gate and on documents.
    # Risk = 40 (five failed logins); the threshold is lowered to 40 for these two checks only.
    risky = await mk_subject(roles, "analyst", FIN, ACCT)
    async with AsyncSessionLocal() as s:
        await s.execute(update(Subject).where(Subject.id == risky).values(failed_login_attempts=5))
        await s.commit()
    rr = await mk_resource(risky, FIN, ACCT, "internal")
    drr = await mk_doc(risky, FIN, ACCT, ResourceSensitivity.INTERNAL, DocumentStatus.PUBLISHED, linked=True)
    old_thr = settings.RISK_DENY_THRESHOLD
    try:
        settings.RISK_DENY_THRESHOLD = 40
        c1 = (await c.get(f"{API}/pep/access/{rr}", headers=H(risky))).status_code
        c2 = (await g(risky, drr)).status_code
    finally:
        settings.RISK_DENY_THRESHOLD = old_thr
    check("S22_high_risk_owner_denied_at_gate", c1 == 403, c1)
    check("S23_high_risk_owner_denied_on_document", c2 == 403, c2)

    # ---- Phase-5 fixtures: owner rule inside the PDP (DR4) and the request address on documents (DR4) ----
    # S24/S25: an IP change (+25) on top of two failed logins (+15) reaches the threshold, at the gate and
    # on a published document. L16 is the control: the same subject profile from its known address is
    # allowed on both paths. The threshold is lowered to 40 (+30 if the probe runs off-hours, so that the
    # time signal cannot decide the check on its own) for these checks only. The test client's address
    # is 127.0.0.1.
    off = 0 if 7 <= now().hour < 19 else 30
    ipc = await mk_subject(roles, "analyst", FIN, ACCT)
    ipk = await mk_subject(roles, "analyst", FIN, ACCT)
    async with AsyncSessionLocal() as s:
        await s.execute(update(Subject).where(Subject.id == ipc).values(
            failed_login_attempts=2, attributes={"last_known_ip": "203.0.113.7"}))
        await s.execute(update(Subject).where(Subject.id == ipk).values(
            failed_login_attempts=2, attributes={"last_known_ip": "127.0.0.1"}))
        await s.commit()
    r_ipc, r_ipk = await mk_resource(ipc, FIN, ACCT, "internal"), await mk_resource(ipk, FIN, ACCT, "internal")
    d_ipc = await mk_doc(ipc, FIN, ACCT, ResourceSensitivity.INTERNAL, DocumentStatus.PUBLISHED, linked=True)
    d_ipk = await mk_doc(ipk, FIN, ACCT, ResourceSensitivity.INTERNAL, DocumentStatus.PUBLISHED, linked=True)
    old_thr = settings.RISK_DENY_THRESHOLD
    try:
        settings.RISK_DENY_THRESHOLD = 40 + off
        c1 = (await c.get(f"{API}/pep/access/{r_ipc}", headers=H(ipc))).status_code
        c2 = (await g(ipc, d_ipc)).status_code
        k1 = (await c.get(f"{API}/pep/access/{r_ipk}", headers=H(ipk))).status_code
        k2 = (await g(ipk, d_ipk)).status_code
    finally:
        settings.RISK_DENY_THRESHOLD = old_thr
    check("S24_ip_change_counts_at_gate", c1 == 403, c1)
    check("S25_ip_change_counts_on_document", c2 == 403, c2)
    check("L16_known_address_allowed", k1 == 200 and k2 == 200, [k1, k2])
    # S26: at the gate, an owner is decided by the decision procedure (the recorded rule is P_own),
    # not by a constant allow outside it. L17: the owner rule is exempt from the clearance barrier
    # (documented priority of the owner rule), so an employee reads her own object above her clearance.
    own_e = await mk_subject(roles, "analyst", FIN, ACCT, clearance="normal")
    r_own = await mk_resource(own_e, FIN, ACCT, "sensitive")
    c1 = (await c.get(f"{API}/pep/access/{r_own}", headers=H(own_e))).status_code
    async with AsyncSessionLocal() as s:
        names = [n for (n,) in (await s.execute(select(AccessDecision.applied_policy_name).where(
            AccessDecision.subject_id == own_e, AccessDecision.resource_id == r_own))).all()]
    check("S26_owner_decided_by_pdp_at_gate", names and all((n or "").startswith("P_own") for n in names), names)
    check("L17_owner_reads_own_object_above_clearance", c1 == 200, c1)

    # S27: deleting a published document's object (soft delete through the API) must not open the document
    # to the department; L18: its owner still reads it (P_own on the deleted object).
    own_d = await mk_subject(roles, "analyst", FIN, ACCT)
    reader = await mk_subject(roles, "analyst", FIN, ACCT)
    d_del = await mk_doc(own_d, FIN, ACCT, ResourceSensitivity.INTERNAL, DocumentStatus.PUBLISHED, linked=True)
    async with AsyncSessionLocal() as s:
        lid = (await s.execute(select(Resource.id).where(Resource.attributes["document_id"].astext == d_del))).scalar()
    cdel = (await c.delete(f"{API}/resources/{lid}", headers=H(dirF))).status_code
    c1 = (await g(reader, d_del)).status_code
    c2 = (await g(own_d, d_del)).status_code
    check("S27_deleted_object_keeps_document_closed", cdel == 204 and c1 == 403, [cdel, c1])
    check("L18_owner_reads_document_of_deleted_object", c2 == 200, c2)

    # Forced invalidate-before-commit interleaving
    an4 = await mk_subject(roles, "analyst", FIN, ACCT)
    r6 = await mk_resource(dirF, FIN, ACCT, "internal", with_file=False)
    a6 = (await c.post(f"{API}/resources/{r6}/assignments", json={"subject_id": an4, "actions": ["read"]}, headers=H(dirF))).json()["id"]
    await dec(an4, r6)
    orig = pip_mod.PIPCache.invalidate_subject

    async def forced(self, subject_id):
        await orig(self, subject_id)
        async with AsyncSessionLocal() as s2:
            await PolicyDecisionPoint(s2).decide(AccessRequest(subject_id, r6, "read", _no_audit=True))
    pip_mod.PIPCache.invalidate_subject = forced
    try:
        await c.delete(f"{API}/resources/{r6}/assignments/{a6}", headers=H(dirF))
    finally:
        pip_mod.PIPCache.invalidate_subject = orig
    check("S11_forced_race_no_stale_allow", res_of(await dec(an4, r6)) == "deny")


async def main():
    depts, divs, roles = await setup()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://e5",
                                 headers={"X-Requested-With": "XMLHttpRequest"}, timeout=60) as c:
        try:
            await run(c, depts, divs, roles)
        except Exception as e:                       # a crash is a kill
            RES["_crash"] = {"pass": False, "detail": repr(e)[:300]}
    ok = all(v["pass"] for v in RES.values())
    if OUTJ:
        json.dump(RES, open(OUTJ, "w"), indent=1, default=str)
    print("E5_PROBE", "PASS" if ok else "FAIL", [k for k, v in RES.items() if not v["pass"]])
    await engine.dispose()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
