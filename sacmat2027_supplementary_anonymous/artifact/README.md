# CHAIN-9 layered-conformance artifact

**To re-run the experiments, follow `REPRODUCE.md`.** This file describes what each script does.

This file grew phase by phase, as a changelog of the scripts. The section, table and figure numbers in its "Paper" columns refer to earlier drafts and the counts in the early tables to earlier runs; the final numbers are in `REPRODUCE.md`, which is organised by RQ1–RQ5 like the paper, and in `results/phase6/summary_phase6.json`.

Research evaluation artifact for *"Beyond the Decision Point: Layered Conformance Checking of a Zero-Trust ABAC System"*.

The artifact **never modifies the application**. It imports the application read-only from a frozen snapshot; mutants are written only into throw-away copies (E3).

| File | Purpose | Paper |
|---|---|---|
| `semantics.py` | Reference semantics: `M_IMPL` (implementation transcription), `R_PAPER` (documented spec, S_doc), `C9_FIX` (repaired chain F, implemented by v2); requirements `I1`–`I7` (= paper R1–R7) | §4, §5 |
| `e1_differential.py` | L1 bounded-exhaustive differential check of the real PDP over 245,760 worlds | §6, Tab. 3–4 |
| `e6_smt.py` | z3 proofs over uninterpreted sorts, for the same chains | Tab. 3 |
| `e1b_state.py` | L2 cold-cache conformance against real PostgreSQL (420 lifecycle worlds) | §7 |
| `e2_runtime.py` | L2/L3 experiments on the running app (ASGI + PostgreSQL + Redis): `audit`, `enforce`, `revoke`, `expiry`, `race` | §7–8, Tab. 6–7, Fig. 3 |
| `e3_mutation.py`, `e3_state_oracle.py`, `e3_integration.py` | Mutation analysis vs. repository suites, E1 and E1b | §9, Tab. 8 |
| `summarize.py` | Recomputes every number reported in the paper into `results/summary.json` | all |
| `run_with_services.sh` | Starts PostgreSQL 16 and Redis 7, then runs a command | — |
| `results/` | Raw JSON outputs of every run reported in the paper | — |

## Environment used
Python 3.12.3 (venv with the snapshot's `requirements.txt` plus `hypothesis 6.170.14` and `z3-solver 5.3.3`), PostgreSQL 16.15, Redis 7.0.15, 2 vCPU / 8 GB. Snapshot: `zta-abac-platform-main.zip` (SHA-256 prefix `fb7f20d137add710`; `pdp.py` prefix `df4f95aec245ff4d`).

## Reproduce
```
B=<snapshot>/backend   D=postgresql+asyncpg://user:pw@localhost:5432/db
python e1_differential.py $B results                 # ~15 s
python e6_smt.py results                             # <1 s
python e1b_state.py $B results $D
python e2_runtime.py $B results $D audit|enforce|revoke|expiry|race   # ~12 min total
python e3_mutation.py $B work results $(which python) . 0/2 & python e3_mutation.py $B work results $(which python) . 1/2
python e3_state_oracle.py $B work results $(which python) . $D
python e3_integration.py $B work results $(which python) . <dir-with-no_ratelimit.py>
python summarize.py results
```
The repository's integration tests need an external pytest plugin (`no_ratelimit.py`, included in `plugins/`) that lifts the hard-coded login rate limit and adds the `X-Requested-With` header the SPA sends. Application code is unchanged.

## Disclosed interventions
1. E1 stubs only the grant cache (returns the world's grant sets) and disables audit persistence.
2. E2e "forced" wraps `PIPCache.invalidate_subject` to inject one concurrent decision between invalidation and commit (timing instrumentation, not a change of semantics).
3. Integration tests run with the plugin above.

## Phase 3 additions (method paper)

| File | Purpose | Paper |
|---|---|---|
| `wp1_genericity_check.py`, `wp1_checker_selftest_gen.py` | Criterion G (data independence) on the PDP AST; six seeded violations | §4, §6 |
| `wp1_coverage.py` | z3 enumeration of satisfiable observation vectors vs. those the world space realises (Thm 2) | §4, §6 |
| `e1_differential.py` with `E1_EXT=1`, `e6_smt.py` with `E6_EXT=1` | completed world space (custom roles, cross-dept. same division id) | §6 |
| `wp7_alt_readings.py` | both readings of the two documented conflicts (C1, C2) | §6 |
| `e2_runtime.py` with `E2_REPS=10` | staleness, n = 10 per setting | §7 |
| `e4_cost.py`, `e4_summarize.py`, `e4_profile.py` | two-worker uvicorn cost study and multi-worker revocation race | §7, §10 |
| `e5_l3_probe.py`, `e5_l3_mutation.py` | fast L2/L3 oracle; mutation of enforcement and cache code of the fork | §9 |
| `wp5_cedar.py`, `wp5_chain9_fix_idiomatic.cedar` | exact compilation of chains to Cedar; differential check with cedarpy | §10 |
| `wp3_tinytodo.py`, `wp3_backstage_rbac.test.js` | external systems (Cedar TinyTodo; Backstage RBAC 8.1.6) | §10 |
| `layercheck/`, `layercheck_demo.py` | reusable core: chain interpreters, Cedar compiler, redundancy lint, criterion G, coverage, L2 window measurement, L3 probe registry, adapters | App. B |
| `summarize_phase3.py` | recomputes every Phase-3 number into `summary_phase3.json` | all |

The evaluation fork (`eval-fork-fb7f20d1`) is a separate git repository; its first commit is the
unmodified snapshot, and each later commit implements one or more design rules.

## Phase 3c additions

| File | Purpose | Paper |
|---|---|---|
| `wp3_openfga.py` | OpenFGA v1.22.1, run from its release binary: L1 over 512 tuple states; L2 revocation windows under four cache configurations | §10 |
| `e4_cost.py` with 1 worker; fork commit `b932d02` (`EVAL_ABLATE_DR5=1`) | one-worker cost comparison, and the DR5 ablation (decision log written inside the request transaction) | §10 |
| `e5_l3_probe.py` (29 checks: S1–S17, L1–L12) | extended L3 probe; the mutation rerun is in `results/e5v2/`, excluding the two ablation-switch mutants at `pep.py:153` | §9 |

## Phase 4 additions

| File | Purpose | Paper |
|---|---|---|
| `running_example.py` | evaluates the running example rule by rule in v1 (M_IMPL) and v2 (C9_FIX = F) | §3.1 |
| `runex_tikz.py` | writes the trace tables of the running-example figure from `running_example.json` | §3.1 |
| `e5_l3_probe.py` (38 checks: S1–S23, L1–L15) | final L3 probe. S22 and S23 lower the risk threshold to 40 for their duration. S19 and S21 create their states through the ORM. | §9, §10 |
| `e5_l3_mutation.py` → `phase4/results/e5v3/` | mutation of the final v2 enforcement and cache code | §10 |
| `e5_survivor_diffs.py` | prints the source change of each surviving mutant (input to the manual classification in `e5v3_survivor_classes.json`) | §10 |
| `summarize_phase4.py` | recomputes the Phase-4 numbers into `summary_phase4.json` | §§9–11 |
| `phase4_figures.py` | draws every results figure from the raw result files | Figs. of §§7–11 |

Fork commit `49d99a9` evaluates P_ctx before the owner rule, both in the PEP gate and in the document-read procedure. The cost study (Phase 3c) was run at commit `b932d02`, before this change.

E5v3 result (`phase4/results/summary_phase4.json`): 166 mutants (the 2 mutants of the cost-ablation switch are excluded); the repository suite kills 24, the probe 127, either 129; 37 survive. `phase4/results/e5v3_survivor_classes.json` gives the manual class and the reason for each survivor. 36 cannot change a decision, effect or record. One (`pep.py:122`, client IP set to `unknown`) drops the IP-change term of the risk score; no oracle varies the client IP.

Reproduce:
```
python summarize_phase4.py phase4/results <fork>/backend phase4/results/summary_phase4.json
python e5_survivor_diffs.py <fork>/backend phase4/results/e5v3/e5_l3_mutation.json phase4/results/summary_phase4.json
python3 phase4_figures.py phase3/results phase4/results paper/figs     # needs matplotlib
```

## Phase 5 additions

The final v2 is fork commit `6a26954` (patch 0009). Its backend is identical to commit `5b62818` (patch 0008); patch 0009 changes only the collaboration server.

| File | Purpose | Paper |
|---|---|---|
| `semantics.py` (updated) | chain F now contains `P_own` (owner may read and download inside her department), and `P_class` exempts that owner; requirements R2, R3 and R7 carry the owner exception of conflict C3 | §3, §5, App. A |
| `e1_differential.py` with `E1_OWN=1` | adds ownership to the world space (737,280 worlds on v2) | §RQ5 "Does it work?" |
| `wp1_coverage.py` with `COVER_OWN=1`; `wp1_genericity_check.py` with `OBS_ACT=read,download` | coverage with the owner atoms; criterion G for the v2 PDP, which also compares the action with `download` | §4, §RQ5 |
| `wp1_checker_selftest.py` | ten seeded violations of criterion G, applied to the PDP of v1 and of v2 | §4 |
| `e1c_document.py` | E1c: bounded-exhaustive check of the document-read procedure (604,800 worlds) against its transcription M_doc and R1, R2, R3, R6, DR4; `E1C_FIXED=1` selects the transcription of the final v2 | §RQ5 |
| `e1c_on_survivors.py` | E1c used as an oracle for the document survivors of E5v4 | §RQ4 |
| `e2_mixed.py` | reproduction of the mixed-view interleaving (Prop. "Mixed views") | §RQ2 |
| `e2_collab.py`, `f8/client.mjs`, `f8/package.json` | F8: runs the real backend and the real collaboration server, removes a collaborator and measures how long her open session survives | §RQ3 |
| `e3_boundary.py` | frozen-clock oracle for the three boundary mutants of the v1 PDP | §RQ4 |
| `e5_l3_probe.py` (45 checks: S1–S27, L1–L18) | final L3 probe; S24–S26 and L16–L18 are new | §RQ3 |
| `e5_l3_mutation.py` → `phase5/results/e5v4/` | mutation of the final v2 enforcement and cache code (now including the client-address middleware) | §RQ4 |
| `e5_heldout.py`, `e5h_survivor_diffs.py` → `phase5/results/e5h/` | held-out operators (SDL, RSW, ARG) against the frozen probe | §RQ4 |
| `wp5_cedar.py` (updated), `wp5_idiomatic.py`, `wp5_chain9_fix_idiomatic.cedar` | exact Cedar compilation with ownership (40 policies) and a hand-written 15-policy version, both checked on 737,280 requests | §RQ5 |
| `e4_cost.py`, `e4_summarize.py` (p99, mean throughput, 5xx count added) | one-worker cost re-run on the final v2 | §RQ5 |
| `summarize_phase5.py` | recomputes every Phase-5 number into `summary_phase5.json` | all |
| `phase5_figures.py` | draws the results figures from the raw files | Figs. |

Survivor classifications (by hand, with the reason for each mutant): `phase5/results/e5v4_survivor_classes.json` (39 survivors of E5v4) and `phase5/results/e5h_survivor_classes.json` (33 survivors of the held-out set).

## Phase 6 additions

The final v2 is fork commit `5102307` (patch 0013). Phase 6 changed v2 four times, each found by the method:

| Patch | Change | Found by |
|---|---|---|
| 0010 | assignments grant read only (P4: `action == read`), as the developer guide and the design document state (conflict C4) | provenance check of LP |
| 0011 | comment resolution and signing are decided like reading the document; the resolve route no longer fails with HTTP 500 | generated route inventory; probe L19 |
| 0012 | the document list decides every candidate with the document read procedure; delegation detail and list apply the listing scope | GET stranger sweep |
| 0013 | publishing, requesting approval and removing folders stay in the actor's scope | state sweep |

| File | Purpose |
|---|---|
| `semantics.py` (updated) | chain F: P4 grants read only; new requirement `LP_least_privilege_with_owner_exception` |
| `wp5_chain9_fix_idiomatic.cedar` (updated) | 12 policies (P4 read-only) |
| `e5_l3_probe.py` (57 checks: S1-S34, L1-L23) | S28-S34 and L19-L23 are new |
| `e7_cache_ops.py` | measures epsilon_b (commit to generation increment) under load with 1 and 2 workers, and a lost increment (hook fault injected in the launcher) |
| `l3_route_inventory.py` | the L3 inventory generated from FastAPI's routing table, with the decision procedures each handler can reach and the routes the harnesses exercise |
| `l3_stranger_sweep.py` | every in-scope GET route sent by subjects R forbids; flags responses that reveal content (markers by field kind) |
| `l3_state_sweep.py` | every in-scope state-changing route sent by subjects R forbids, against documents in every workflow state; flags any database change |
| `summarize_phase6.py`, `phase6_figures.py` | recompute every phase-6 number and draw the figures |

Results are in `results/phase6/`; results carried over from phase 5 (code unchanged since) are marked as such in `summary_phase6.json`.
