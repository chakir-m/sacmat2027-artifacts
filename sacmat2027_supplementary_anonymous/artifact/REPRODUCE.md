# How to re-run every experiment in the paper

This is the step-by-step guide. `README.md` lists what each script is for; this file says how to run it.

Times are those measured on a 2-vCPU / 8 GB Linux machine. Commands assume you are in the package root (the folder that contains `artifact/`, `results/`, `fork-patches/`, `paper/`). The numbers quoted as "expected" are those of the paper; they are also in `results/phase6/summary_phase6.json`.

---

## 0. What you need

| Tool | Version used | Needed for |
|---|---|---|
| Linux (Ubuntu 24.04 used) | — | everything |
| Python | 3.12.3 | everything |
| PostgreSQL | 16 | L2/L3, repository tests, mutation, F8, cost |
| Redis | 7 | L2/L3, repository tests, mutation, F8, cost |
| git | any | building v2 |
| Node.js | 22 | F8 (collaboration server) only |
| matplotlib (system Python) | 3.x | figures only |
| OpenFGA release binary | v1.22.1 | OpenFGA comparison only |
| Rust/cargo + cedar-examples (TinyTodo) | commit f4d2dbb | TinyTodo comparison only |
| Node.js + npm (`@backstage/plugin-permission-backend` RBAC 8.1.6) | — | Backstage comparison only |

---

## 1. Get the two versions of the system

**v1 (frozen snapshot).** Unzip the snapshot (the repository zip, SHA-256 prefix `fb7f20d137add710`). It is not included in the anonymous package.

```bash
mkdir -p ~/rerun && cd ~/rerun
unzip /path/to/snapshot.zip            # gives <snapshot-dir>/backend, <snapshot-dir>/hocuspocus, ...
export V1=~/rerun/<snapshot-dir>/backend
```

**v2 (evaluation fork).** Rebuild it from the snapshot plus the thirteen patches in `fork-patches/`. This was tested: the result is identical, file for file, to the fork used in the paper.

```bash
cp -r ~/rerun/<snapshot-dir> ~/rerun/v2 && cd ~/rerun/v2
git init -q && git add -A && git commit -qm "baseline: frozen snapshot"
git am /path/to/package/fork-patches/*.patch      # 0001 ... 0009
git log --oneline                                 # 10 commits; the top one is "F8: re-authorization loop now sees ..."
export V2=~/rerun/v2/backend
```

What each patch does:

| Patch | Content |
|---|---|
| 0001 | DR1, DR2 (chain F), DR3 (versioned, validity-aware grant cache, post-commit invalidation), DR5 (independent decision log) |
| 0002 | DR4 (single PEP gate, endpoint-derived action, document reads through the PDP), DR5 at the PEP, F9 ledger, F13 revocation authority |
| 0003, 0004 | F8: periodic re-authorization of collaboration sessions (0004 fixes a syntax error in 0003) |
| 0005 | switch used only by the cost ablation (`EVAL_ABLATE_DR5`, off by default) |
| 0006 | DR1 at the gate: P_ctx before the owner rule and before every document read |
| 0007 | owner rule moved into the PDP (rule P_own); client address passed to the document route |
| 0008 | a published document is decided by its linked object even after that object is deleted (found by E1c) |
| 0009 | F8 fix: the re-authorization loop now sees the open sessions under Hocuspocus 2.x (found by E2f) |
| 0010 | assignments grant read only (conflict C4) |
| 0011 | comment resolution and signing decided like reading the document (found by the generated inventory) |
| 0012 | document list and delegation views apply the single-object decisions (found by the GET sweep) |
| 0013 | publishing, requesting approval and removing folders stay in scope (found by the state sweep) |

The final v2 is patch 0013.

---

## 2. Python and Node environments

```bash
python3.12 -m venv ~/rerun/venv && source ~/rerun/venv/bin/activate
pip install -r $V1/requirements.txt
pip install hypothesis==6.170.14 z3-solver==5.3.3 cedarpy==4.12.2 \
            pytest==8.3.4 pytest-asyncio==0.24.0 pytest-cov==6.0.0 httpx==0.28.1
export PY=$(which python)
export ART=/path/to/package/artifact

# F8 only: the collaboration-server harness
mkdir -p ~/rerun/f8node && cp $ART/f8/package.json $ART/f8/client.mjs ~/rerun/f8node/
cd ~/rerun/f8node && npm install       # @hocuspocus/server and /provider 2.13.7, yjs 13.6.21, node-fetch 3.3.2, ws 8.18.0
```

---

## 3. Databases

The scripts expect this user and these databases:

```bash
sudo -u postgres psql -c "CREATE ROLE abac_admin LOGIN PASSWORD 'devpassword' SUPERUSER;"
for db in abac_test abac_e5 abac_f8 abac_perf; do sudo -u postgres createdb -O abac_admin $db; done
#   abac_test: repository tests, L2 runs     abac_e5: L3 probe
#   abac_f8:   F8 and the boundary oracle    abac_perf: cost study
redis-server --port 6379 --daemonize yes --save ''
echo '127.0.0.1 postgres' | sudo tee -a /etc/hosts   # the repository's integration tests use host "postgres"

export D=postgresql+asyncpg://abac_admin:devpassword@localhost:5432/abac_test
export DB=postgresql+asyncpg://abac_admin:devpassword@localhost:5432
```

Redis databases used: 0 (tests, cost), 2 (probe), 5 (F8, boundary oracle). **`e1b_state.py` flushes all of Redis**: run it when nothing else is running.

`artifact/run_with_services.sh <pgdata> <command>` does the same start-up inside a container. You don't need it if PostgreSQL and Redis are already running.

---

## 4. Re-run, section by section

Write new results into a fresh folder so you can compare them with the shipped ones:

```bash
export OUT=~/rerun/out && mkdir -p $OUT/v1 $OUT/v2
cd $ART
```

### RQ1: L1, rules and decisions (fast)

```bash
$PY e1_differential.py $V1 $OUT/v1                        # ~15 s; 245,760 worlds
E1_EXT=1 $PY e1_differential.py $V1 $OUT/v1               # completed world space, 368,640 worlds
E1_EXT=1 E1_OWN=1 $PY e1_differential.py $V2 $OUT/v2      # with ownership, 737,280 worlds
$PY e6_smt.py $OUT/v1 && E6_EXT=1 $PY e6_smt.py $OUT/v1   # z3 proofs, < 1 s
$PY wp1_genericity_check.py $V1/app/services/pdp.py $V1/app/services/risk.py $OUT/v1/wp1_genericity.json
OBS_ACT=read,download $PY wp1_genericity_check.py $V2/app/services/pdp.py $V2/app/services/risk.py $OUT/v2/wp1_genericity.json
mkdir -p ~/rerun/pdp1 ~/rerun/pdp2
cp $V1/app/services/{pdp,risk}.py ~/rerun/pdp1/; cp $V2/app/services/{pdp,risk}.py ~/rerun/pdp2/
$PY wp1_checker_selftest.py ~/rerun/pdp1 ~/rerun/st1 $OUT/v1/wp1_checker_selftest.json
OBS_ACT=read,download $PY wp1_checker_selftest.py ~/rerun/pdp2 ~/rerun/st2 $OUT/v2/wp1_checker_selftest.json
$PY wp1_coverage.py $OUT/v1 && COVER_BASE=1 $PY wp1_coverage.py $OUT/v1
COVER_OWN=1 $PY wp1_coverage.py $OUT/v2                   # with the owner atoms
$PY wp7_alt_readings.py $OUT/v1                           # both readings of conflicts C1, C2
$PY running_example.py $OUT/running_example.json          # Ana, Dan, Lea
$PY e1c_document.py $V2 $OUT/v2/e1c_document_v2.json      # ~2 min; document procedure, 604,800 worlds
```

Expected: v2 agrees with chain F on all 737,280 worlds; LP as written fails in 648 owner worlds, LP with the owner exception (the requirement) holds. Criterion G holds on v1 (82 occurrences) and v2 (96); the self-test flags 10 of 10 seeded violations in both. Coverage with the owner atoms: 4,320 satisfiable vectors, all realised. E1c on the final v2: 604,800 / 604,800 agreement with M_doc and no violation (set `E1C_FIXED=1` to compare with the transcription of the final v2; without it the reference is the transcription of the version before patch 0008).

Compare with `results/phase6/e1_v2/`, `e6/`, `wp1/`, `wp1_*_v2.json`, `wp7/`, `running_example.json`, `e1c_document_v2.json` (v1's criterion G files are in `results/phase5/`).

### RQ2: L2, state and staleness (needs PostgreSQL + Redis)

```bash
$PY e1b_state.py $V1 $OUT/v1 $D                              # cold-cache state check, 420 worlds (flushes Redis)
E1B_CHAIN=C9_FIX $PY e1b_state.py $V2 $OUT/v2 $D             # same on v2
for p in audit enforce revoke expiry race; do
  E2_REPS=10 $PY e2_runtime.py $V1 $OUT/v1 $D $p             # ~12 min in total at n=3; longer at 10
done
for p in audit enforce revoke expiry race; do $PY e2_runtime.py $V2 $OUT/v2 $D $p; done
$PY e2_mixed.py $V1 $DB/abac_f8 redis://localhost:6379/5 $OUT/v1/e2_mixed.json 10   # mixed-view interleaving
$PY e2_mixed.py $V2 $DB/abac_f8 redis://localhost:6379/5 $OUT/v2/e2_mixed.json 10
```

Expected: E1b 0 mismatches on both versions. Mixed views: 10 of 10 unjustified allows on v1, 0 of 10 on v2.

Compare with `results/phase3/e2_n10/` (v1), `results/phase3/fork/` (v2), `results/phase6/e1b_v2/` and `results/phase5/e2_mixed_v{1,2}.json`.

### RQ3: L3, enforcement (the 57-check probe, ~30 s each) and F8

```bash
$PY e5_l3_probe.py $V1 $DB/abac_e5 redis://localhost:6379/2 $OUT/probe_v1.json   # 57 checks since phase 6
$PY e5_l3_probe.py $V2 $DB/abac_e5 redis://localhost:6379/2 $OUT/probe_v2.json

# F8: one collaboration session per trial; ports 8010 (backend) and 1240 (collaboration server)
$PY e2_collab.py $V1 $V1/../hocuspocus/server.mjs ~/rerun/f8node $OUT/v1/e2_collab.json 10 30
$PY e2_collab.py $V2 $V2/../hocuspocus/server.mjs ~/rerun/f8node $OUT/v2/e2_collab.json 10 30
```

Expected:
- probe, v2: `E5_PROBE PASS`, exit code 0 (34 safety and 23 liveness checks).
- probe, v1: fails 31 of the 34 safety checks (it passes S8, S18 and S20), plus L11, L19 and L23. L11 fails only because S15 has already revoked the delegation, L23 only because S33 has already published the document, and L19 because comment resolution fails with HTTP 500 in v1.
- F8, v2: 10 of 10 sessions closed after the collaborator is removed, within the 5 s re-check period (paper: 1.86–4.79 s), close code 4403. v1: 0 of 10 closed within 30 s. In both, the document API itself already answers 403.
- To see the bug fixed by patch 0009, run v2 with `results/phase5/f8/server_v2_before_fix.mjs` as the server: 0 sessions closed.

Compare with `results/phase6/probe_v{1,2}.json` and `results/phase5/f8/`.

### Our repository's own tests

```bash
cd $V1 && PYTHONPATH=$ART/plugins ENVIRONMENT=test SECRET_KEY=ci_test_secret_key_32_chars_minimum_xx \
  STORAGE_BACKEND=local DATABASE_URL=$D REDIS_URL=redis://localhost:6379/0 \
  $PY -m pytest -q -p no_ratelimit tests/      # v1: 138 passed, 2 skipped
cd $V2 && (same command)                       # v2: 137 passed, 2 skipped, 1 failed
```

The one v2 failure is
`test_conformance.py::TestP4NeedToKnow::test_phi_minus_assigned_analyst_write_not_in_actions`. It expects P5 to be the deciding rule; in v2, P7 denies first, by design. The paper says this. `DATABASE_URL` must be `abac_test`: two integration tests read decision rows from that database.

The plugin `plugins/no_ratelimit.py` only lifts the login rate limit and adds the CSRF header. It does not change the application.

### RQ4: mutation analysis (slow)

v1 decision logic (79 non-equivalent mutants). Run the two shards in parallel; this takes hours:

```bash
mkdir -p ~/rerun/work
$PY e3_mutation.py $V1 ~/rerun/work $OUT/v1 $PY $ART 0/2 &
$PY e3_mutation.py $V1 ~/rerun/work $OUT/v1 $PY $ART 1/2; wait
$PY e3_state_oracle.py $V1 ~/rerun/work $OUT/v1 $PY $ART $D
$PY e3_integration.py  $V1 ~/rerun/work $OUT/v1 $PY $ART $ART/plugins
$PY e3_boundary.py     $V1 ~/rerun/e3b $OUT/e3_boundary_v1.json      # frozen-clock oracle, ~1 min
```

Expected (`e3_boundary`): mutants 80, 82 and 88 are all killed (B1, B2 and B3 respectively).

v2 enforcement and cache code (159 points, 157 mutants after excluding the 2 of the ablation switch; about 1.5 h on a quiet machine; it can be resumed if stopped), the E1c oracle on its document survivors, and the held-out operators (111 points, 109 mutants; about 1 h):

```bash
$PY e5_l3_mutation.py $V2 ~/rerun/e5work $OUT/e5v4 $PY $ART $ART/plugins
$PY e5_survivor_diffs.py $V2 $OUT/e5v4/e5_l3_mutation.json
$PY e1c_on_survivors.py $V2 ~/rerun/e1cs $OUT/e1c_on_e5v4_survivors.json $PY 4 12 13 18 30 31 32   # ~15 min
$PY e5_heldout.py $V2 ~/rerun/e5hwork $OUT/e5h $PY $ART $ART/plugins
$PY e5h_survivor_diffs.py $V2 $OUT/e5h/e5_heldout.json
```

Expected (`summary_phase6.json`; the phase-6 run of the final v2 gives the same counts as phase 5):
- `E5v4`: 157 mutants; killed by the repository tests 21, by the probe 116, by either 118; 39 survivors.
- `E1c_on_E5v4_survivors`: 424, 434 (two mutants) and 442 killed; 446 (three mutants) agree on every world.
- `E5_heldout`: 109 mutants; killed by the repository tests 34, by the probe 76, by either 76; 33 survivors.

The survivors were classified by hand from the output of the two `*_survivor_diffs.py` scripts: `results/phase6/e5v4_survivor_classes.json` and `e5h_survivor_classes.json` give the class and the reason for each one. Check them the same way.

### RQ5: cost (needs a quiet machine; results vary by hardware)

One server worker, 16 closed-loop clients, 1,000 requests × 3 repetitions per workload, two interleaved runs per version:

```bash
# arguments: <backend> <label> <db-url> <redis-url> <port> <workers> <out-dir>
mkdir -p $OUT/e4; export E4_N=1000 E4_REPS=3
$PY e4_cost.py $V1 base1w_r1  $DB/abac_perf redis://localhost:6379/0 8001 1 $OUT/e4
$PY e4_cost.py $V2 final1w_r1 $DB/abac_perf redis://localhost:6379/0 8002 1 $OUT/e4
$PY e4_cost.py $V1 base1w_r2  $DB/abac_perf redis://localhost:6379/0 8001 1 $OUT/e4
$PY e4_cost.py $V2 final1w_r2 $DB/abac_perf redis://localhost:6379/0 8002 1 $OUT/e4
$PY e4_summarize.py $OUT/e4 $OUT/e4/summary_base1w_vs_final1w.json base1w final1w
```

Absolute latencies will differ on other hardware; compare ratios. Compare with `results/phase6/e4/` (three runs per version; the commands above show two, add `_r3` the same way). (The earlier cost study, at patch 0005, is in `results/phase3/`.)

### RQ5: Cedar compilation and external systems

```bash
$PY wp5_cedar.py $OUT                  # M_IMPL 36 policies, 368,640/368,640; F (C9_FIX) 40 policies, 737,280/737,280
$PY wp5_idiomatic.py $OUT              # hand-written 12-policy version of F, 737,280/737,280
$PY wp3_openfga.py /path/to/openfga-v1.22.1 $OUT/openfga.json       # needs the release binary
$PY wp3_tinytodo.py <cedar-examples>/tinytodo <tinytodo-binary> ~/rerun/tt $OUT/tinytodo.json
# Backstage: copy wp3_backstage_rbac.test.js into a Backstage RBAC 8.1.6 checkout and run its test runner
```

Compare with `results/phase6/wp5/` and `results/phase3/wp3/`.


### Phase 6: route inventory, sweeps and cache operations

```bash
$PY l3_route_inventory.py $V2 $ART $OUT/inventory_v2.json        # seconds; 152 API routes, 100 in scope
$PY l3_route_inventory.py $V1 $ART $OUT/inventory_v1.json
$PY l3_stranger_sweep.py $V2 $OUT/inventory_v2.json $OUT/sweep_v2.json      # ~1 min (abac_f8, Redis db 5)
$PY l3_stranger_sweep.py $V1 $OUT/inventory_v1.json $OUT/sweep_v1.json
$PY l3_state_sweep.py $V2 $OUT/inventory_v2.json $OUT/state_sweep_v2.json   # ~15 min on a quiet machine
$PY l3_state_sweep.py $V1 $OUT/inventory_v1.json $OUT/state_sweep_v1.json
$PY e7_cache_ops.py $V2 ~/rerun/e7 $OUT/e7_cache_ops.json 200 5            # ~25 min; port 8020; uses Redis db 5
```

Expected:
- inventory: 152 API routes, 100 in scope; v1 has six in-scope routes that reach no decision procedure, v2 three (an access graph documented as public, aggregate statistics, document templates).
- GET sweep: v2 reveals no content to the forbidden subjects (names and titles on five routes); v1 reveals content on six routes.
- state sweep: on v2 the only database change by a forbidden subject is a folder created by an employee of the same department (no requirement covers folders); v1 changes state on routes that include publishing, escalation, folder removal, signing and assignment revocation.
- E7: epsilon_b median below 1 ms and maximum below 5 ms with 1 and 2 workers; with the hook's Redis connection failing, the revoked grant works until the entry's lifetime (about 120 s) runs out.

---

## 5. Recompute the paper's numbers and figures from the raw files

You don't need to re-run anything for this step. It checks that every number and figure in the paper follows from the shipped raw results:

```bash
cd $ART
$PY summarize_phase3.py ../results/phase3 results ~/rerun/summary_phase3.json
$PY summarize_phase5.py ../results/phase5 $V2 ~/rerun/summary_phase5.json   # phase-5 numbers (earlier v2)
$PY summarize_phase6.py ../results/phase5 ../results/phase6 $V2 ~/rerun/summary_phase6.json
python3 phase6_figures.py ../results/phase3 ../results/phase6 ~/rerun/figs    # system python with matplotlib
diff <(python3 -m json.tool ../results/phase6/summary_phase6.json) <(python3 -m json.tool ~/rerun/summary_phase6.json)
```

`~/rerun/figs/figure_data_used.json` lists every value drawn in the figures. The only expected differences in the `diff` are absolute paths.

---

## 6. What is expected to differ in a re-run

- **Timings:** staleness windows, F8 windows, latencies and the race counts are timing-dependent. The bounds (Theorem "Staleness") should hold, but individual values will change.
- **Mutation:** the mutant sets and the kill counts are deterministic for the same code. A test that is flaky on your machine can change a count by one.
- **Time of day:** E1c and two probe checks use the off-hours risk term; the scripts set the threshold from the current hour, so the results do not depend on it.
- **Unaffected:** the L1, E1c, SMT, coverage, criterion G and Cedar results are exact and should be identical.
