"""Phase 4: every results figure of the paper, drawn from the raw result files (no hand-entered values).
Usage: python phase4_figures.py <phase3-results> <phase4-results> <out-dir>
"""
import json, os, statistics as st, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator

P3, P4, OUT = sys.argv[1:4]
os.makedirs(OUT, exist_ok=True)
J = lambda *p: json.load(open(os.path.join(*p)))
plt.rcParams.update({"font.family": "serif", "font.size": 7, "axes.titlesize": 7.5, "axes.labelsize": 7,
                     "legend.fontsize": 6, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
                     "axes.spines.top": False, "axes.spines.right": False, "pdf.fonttype": 42,
                     "axes.linewidth": 0.6, "lines.linewidth": 0.9})
V1, V2, GREY = "#c0392b", "#1f6fb2", "#7f8c8d"
COL = 3.33
S = J(P3, "summary_phase3.json")
used = {}


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


# ---------------------------------------------------------------- L1: requirements and coverage
def fig_l1():
    v1 = S["E1_ext"]["invariant_violations_all"]
    v1api = S["E1_ext"]["invariant_violations_api_reachable"]
    v2 = S["fork_E1"]["invariant_violations_all"]
    keys = [("R2", "I2_classification"), ("R4", "I4_analyst_delegation_liveness"),
            ("R5", "I5_cross_dept_only_delegated_actions"), ("R6", "I6_risk_deny"),
            ("R7", "I7_justified_allow"), ("LP", "PAPER_analyst_least_privilege")]
    fig, (a, b) = plt.subplots(1, 2, figsize=(COL * 2.05, 1.7), gridspec_kw={"width_ratios": [1.5, 1]})
    x = range(len(keys)); w = 0.27
    ya = [v1.get(k, 0) for _, k in keys]; yb = [v1api.get(k, 0) for _, k in keys]; yc = [v2.get(k, 0) for _, k in keys]
    a.bar([i - w for i in x], [max(y, 0.8) for y in ya], w, color=V1, label="v1, all 368,640 worlds")
    a.bar(list(x), [max(y, 0.8) for y in yb], w, color="#e6a39b", label="v1, API-reachable")
    a.bar([i + w for i in x], [max(y, 0.8) for y in yc], w, color=V2, label="v2, all worlds")
    for i, (p, q, r) in enumerate(zip(ya, yb, yc)):
        for dx, y in ((-w, p), (0, q), (w, r)):
            a.text(i + dx, max(y, 0.8) * 1.15, f"{y:,}" if y else "0", ha="center", va="bottom", fontsize=4.8, rotation=90)
    a.set_yscale("log"); a.set_ylim(0.7, 3e7); a.set_xticks(list(x)); a.set_xticklabels([n for n, _ in keys])
    a.set_ylabel("violating worlds"); a.set_title("(a) Requirement violations (R1, R3: none)")
    a.legend(frameon=False, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.0), handlelength=1.0, columnspacing=0.8)
    cv = S["coverage"]
    labels = ["all vectors", "API-reachable"]
    sat = [cv["all"]["satisfiable"], cv["api"]["satisfiable"]]
    pub = [cv["all"]["satisfiable"] - cv["all"]["missing_published"], cv["api"]["satisfiable"] - cv["api"]["missing_published"]]
    ext = [cv["all"]["realised_ext"], cv["api"]["realised_ext"]]
    xb = range(2); w = 0.26
    b.bar([i - w for i in xb], sat, w, color=GREY, label="satisfiable (z3)")
    b.bar(list(xb), pub, w, color="#e6a39b", label="realised, earlier $W$")
    b.bar([i + w for i in xb], ext, w, color=V2, label="realised, completed $W$")
    for i in xb:
        for dx, y in ((-w, sat[i]), (0, pub[i]), (w, ext[i])):
            b.text(i + dx, y + 20, f"{y:,}", ha="center", va="bottom", fontsize=5)
    b.set_xticks(list(xb)); b.set_xticklabels(labels); b.set_ylim(0, 1800); b.set_ylabel("observation vectors")
    b.set_title("(b) Coverage of observation vectors"); b.legend(frameon=False, loc="upper right")
    fig.tight_layout(w_pad=1.2)
    save(fig, "fig_l1.pdf")
    used["l1"] = {"v1_all": ya, "v1_api": yb, "v2_all": yc, "sat": sat, "pub": pub, "ext": ext}


# ---------------------------------------------------------------- L2: staleness, OpenFGA, race
def fig_l2():
    rv = J(P3, "e2_n10", "e2_revoke.json"); ex = J(P3, "e2_n10", "e2_expiry.json"); ra = J(P3, "e2_n10", "e2_race.json")
    fig, (a, b, c) = plt.subplots(1, 3, figsize=(COL * 2.1, 1.75), gridspec_kw={"width_ratios": [1.35, 1.0, 0.75]})
    a.plot([0, 60], [60, 0], ls="--", color=GREY, lw=0.7); a.plot([0, 120], [120, 0], ls=":", color=GREY, lw=0.9)
    series = [("deleg. revoked", rv["E2b_delegation_revocation"], "window_s", "o", V1),
              ("deleg. expired", ex["E2c_delegation_expiry"], "window_after_expiry_s", "s", "#16a085"),
              ("assign. expired", ex["E2d_assignment_expiry"], "window_after_expiry_s", "^", "#e67e22")]
    for lab, rows, key, m, colr in series:
        a.scatter([t["delta_s"] for t in rows], [t[key] for t in rows], s=6, marker=m, color=colr, label=lab, lw=0)
    rf = ra["E2e_race_forced_interleaving"]
    a.scatter([0] * len(rf), [t["window_s"] for t in rf], s=9, marker="D", color="#8e44ad", label="assign. revoked, race", lw=0)
    a.set_xlabel(r"cache age $\delta$ at grant end (s)"); a.set_ylabel("window (s)")
    a.set_title(r"(a) v1: measured window vs. $\tau-\delta$"); a.set_xlim(-5, 125); a.set_ylim(-3, 128)
    a.legend(frameon=False, loc="upper right", markerscale=1.3)
    of = J(P3, "wp3", "openfga.json")["O2_L2_revocation"]
    b.plot([0, 10], [10, 0], ls="--", color=GREY, lw=0.7)
    marks = {"B_query_cache_10s": ("o", V2, "check cache"), "C_cache_plus_controller": ("x", "#16a085", "+ cache controller"),
             "D_cache_higher_consistency": ("s", V1, "HIGHER_CONSISTENCY"), "A_default": ("^", GREY, "default (no cache)")}
    for cfg, rows in of.items():
        m, colr, lab = marks[cfg]
        off = {"B_query_cache_10s": -0.25, "C_cache_plus_controller": 0.25, "D_cache_higher_consistency": 0.5, "A_default": -0.5}[cfg]
        b.scatter([r["delta_s"] + off for r in rows], [r["window_s"] for r in rows], s=6, marker=m, color=colr, label=lab, lw=0.6 if m == "x" else 0)
    b.set_xlabel(r"cache age $\delta$ (s)"); b.set_ylabel("window (s)"); b.set_xlim(-1.5, 19); b.set_ylim(-0.5, 11)
    b.set_xticks([0, 5, 10]); b.set_title(r"(b) OpenFGA 1.22.1, $\tau=10$ s"); b.legend(frameon=False, loc="upper right", fontsize=5, handletextpad=0.2)
    r4 = S["E4"]["race"]
    c.bar([0, 1], [r4["base"]["allow_after_commit"], r4["fork"]["allow_after_commit"]], 0.6, color=[V1, V2])
    for i, k in enumerate(("base", "fork")):
        c.text(i, r4[k]["allow_after_commit"] + 3, f'{r4[k]["allow_after_commit"]}/{r4[k]["trials"]}', ha="center", fontsize=6)
    c.set_xticks([0, 1]); c.set_xticklabels(["v1", "v2"]); c.set_ylim(0, 120); c.set_ylabel("revocations re-admitted")
    c.set_title("(c) Two-worker race")
    fig.tight_layout(w_pad=0.8)
    save(fig, "fig_l2.pdf")
    used["l2"] = {"race": r4, "n_points_v1": sum(len(r[1]) for r in series) + len(rf)}


# ---------------------------------------------------------------- L3: probe matrix v1 / v2
def fig_l3():
    p1, p2 = J(P4, "probe_v1.json"), J(P4, "probe_v2.json")
    order = sorted(p2, key=lambda k: (k[0] != "S", int(k.split("_")[0][1:])))
    fig, ax = plt.subplots(figsize=(COL * 2.05, 0.95))
    for j, k in enumerate(order):
        for i, p in enumerate((p1, p2)):
            ok = p[k]["pass"]
            ax.add_patch(plt.Rectangle((j, 1 - i), 0.92, 0.88, color=("#d5e8d4" if ok else V1)))
            if not ok:
                ax.text(j + 0.46, 1 - i + 0.44, "×", ha="center", va="center", color="white", fontsize=6)
    ax.set_xlim(-0.1, len(order)); ax.set_ylim(-0.05, 2)
    ax.set_yticks([1.44, 0.44]); ax.set_yticklabels(["v1", "v2"])
    ax.set_xticks([j + 0.46 for j in range(len(order))]); ax.set_xticklabels([k.split("_")[0] for k in order], rotation=90, fontsize=5.5)
    ax.tick_params(length=0); [s.set_visible(False) for s in ax.spines.values()]
    nS = sum(k.startswith("S") for k in order)
    ax.axvline(nS - 0.04, color="black", lw=0.6)
    ax.text(nS / 2, 2.05, "safety checks (PDP denies: no effect may happen)", ha="center", fontsize=6)
    ax.text(nS + (len(order) - nS) / 2, 2.05, "liveness checks (PDP allows)", ha="center", fontsize=6)
    save(fig, "fig_l3.pdf")
    f1 = [k for k in order if not p1[k]["pass"]]; f2 = [k for k in order if not p2[k]["pass"]]
    used["l3"] = {"checks": len(order), "safety": nS, "v1_failed": f1, "v2_failed": f2}


# ---------------------------------------------------------------- cost
def fig_cost():
    d = J(P3, "e4", "ablation", "summary_base1w_vs_fork1w.json")["workloads"]
    names = [("decide_hit", "decision\nhit"), ("decide_miss", "decision\nmiss"), ("pep_allow", "file\nallow"),
             ("pep_deny", "file\ndeny"), ("doc_read", "doc.\nread"), ("asg_create", "assign.\ncreate")]
    fig, ax = plt.subplots(figsize=(COL, 1.6))
    w = 0.38
    for i, (k, _) in enumerate(names):
        r = d[k]["per_run_median_ms"]
        b = [v for n, v in r.items() if n.startswith("base")]; f = [v for n, v in r.items() if n.startswith("fork")]
        mb, mf = d[k]["median_base_ms"], d[k]["median_fork_ms"]
        ax.bar(i - w / 2, mb, w, color=V1, label="v1" if i == 0 else None)
        ax.bar(i + w / 2, mf, w, color=V2, label="v2" if i == 0 else None)
        ax.errorbar(i - w / 2, mb, yerr=[[mb - min(b)], [max(b) - mb]], color="black", lw=0.6, capsize=1.5)
        ax.errorbar(i + w / 2, mf, yerr=[[mf - min(f)], [max(f) - mf]], color="black", lw=0.6, capsize=1.5)
        ax.text(i + w / 2, max(f) + 6, f"{d[k]['ratio_median']:.2f}×", ha="center", fontsize=5.5)
    ax.set_xticks(range(len(names))); ax.set_xticklabels([n for _, n in names]); ax.set_ylabel("median latency (ms)")
    ax.set_ylim(0, 320); ax.legend(frameon=False, loc="upper left", ncol=2)
    save(fig, "fig_cost.pdf")
    used["cost"] = {k: (d[k]["median_base_ms"], d[k]["median_fork_ms"], d[k]["ratio_median"]) for k, _ in names}


# ---------------------------------------------------------------- mutation (E3 decision logic; E5 enforcement)
def fig_mut():
    e3 = S["E3"]
    p = os.path.join(P4, "summary_phase4.json")
    if not os.path.exists(p):
        return
    e5 = J(p)["E5v3"]
    cls = J(P4, "e5v3_survivor_classes.json")
    fig, (a, b, c) = plt.subplots(1, 3, figsize=(COL * 2.1, 1.75), gridspec_kw={"width_ratios": [1, 1.25, 1.1]})
    n = e3["non_equivalent"]
    bars = [("repo\nunit", e3["killed_existing_tests"]), ("repo\nall", e3["killed_full_repository_suite"]),
            ("L1", e3["killed_E1"]), ("L1∪L2", e3["killed_E1_or_E1b"])]
    a.bar(range(4), [v / n * 100 for _, v in bars], 0.6, color=[GREY, GREY, V2, V2])
    for i, (_, v) in enumerate(bars):
        a.text(i, v / n * 100 + 2, f"{v}/{n}", ha="center", fontsize=5.5)
    a.set_xticks(range(4)); a.set_xticklabels([l for l, _ in bars], fontsize=5); a.set_ylim(0, 115)
    a.set_ylabel("mutation score (%)"); a.set_title("(a) v1 decision logic")
    byf = e5["by_file"]; files = list(byf)
    short = {f: f.split("/")[-1].replace(".py", "") for f in files}
    both = [byf[f]["both"] for f in files]; po = [byf[f]["probe_only"] for f in files]
    ro = [byf[f]["repo_only"] for f in files]; sv = [len(byf[f]["survive"]) for f in files]
    y = range(len(files))
    b.barh(y, both, color="#2c3e50", label="both")
    b.barh(y, po, left=both, color=V2, label="L3 probe only")
    b.barh(y, ro, left=[i + j for i, j in zip(both, po)], color="#95a5a6", label="repo only")
    b.barh(y, sv, left=[i + j + k for i, j, k in zip(both, po, ro)], color="#f5b7b1", label="survived")
    b.set_yticks(list(y)); b.set_yticklabels([short[f] for f in files], fontsize=5.5); b.invert_yaxis()
    b.set_xlabel("mutants"); b.set_title(f"(b) v2 enforcement code ({e5['mutants']} mutants)")
    b.set_xlim(0, 82); b.set_xticks([0, 20, 40]); b.legend(frameon=False, fontsize=5, loc="lower right")
    order = [k for k in cls["classes"]]
    vals = [len(cls["classes"][k]["mutants"]) for k in order]
    colors = [GREY if cls["classes"][k]["harmless"] else V1 for k in order]
    c.barh(range(len(order)), vals, color=colors)
    for i, v in enumerate(vals):
        c.text(v + 0.3, i, str(v), va="center", fontsize=5.5)
    c.set_yticks(range(len(order))); c.set_yticklabels([cls["classes"][k]["label"] for k in order], fontsize=5.2)
    c.invert_yaxis(); c.set_xlabel("survivors"); c.set_title(f"(c) The {sum(vals)} survivors")
    fig.tight_layout(w_pad=0.6)
    save(fig, "fig_mut.pdf")
    used["mut"] = {"e5": {k: e5[k] for k in ("mutants", "killed_repo", "killed_probe", "killed_either")}, "classes": dict(zip(order, vals))}


def fig_mut_compact():
    """Column-width version for the 10-page paper: v2 enforcement and cache mutants per file, by killing oracle."""
    p = os.path.join(P4, "summary_phase4.json")
    if not os.path.exists(p):
        return
    e5 = J(p)["E5v3"]
    byf = e5["by_file"]; files = list(byf)
    short = {f: f.split("/")[-1].replace(".py", "") for f in files}
    both = [byf[f]["both"] for f in files]; po = [byf[f]["probe_only"] for f in files]
    ro = [byf[f]["repo_only"] for f in files]; sv = [len(byf[f]["survive"]) for f in files]
    fig, b = plt.subplots(figsize=(COL, 1.55))
    y = range(len(files))
    b.barh(y, both, color="#2c3e50", label="repo tests and L3 probe")
    b.barh(y, po, left=both, color=V2, label="L3 probe only")
    b.barh(y, ro, left=[i + j for i, j in zip(both, po)], color="#95a5a6", label="repo tests only")
    b.barh(y, sv, left=[i + j + k for i, j, k in zip(both, po, ro)], color="#f5b7b1", label="survived")
    for i, f in enumerate(files):
        b.text(both[i] + po[i] + ro[i] + sv[i] + 0.6, i, f"{byf[f]['n']}", va="center", fontsize=5.5)
    b.set_yticks(list(y)); b.set_yticklabels([short[f] for f in files], fontsize=6); b.invert_yaxis()
    b.set_xlabel(f"mutants of the v2 enforcement and cache code (n = {e5['mutants']})", fontsize=6)
    b.set_xlim(0, 46); b.set_xticks([0, 10, 20, 30, 40])
    b.legend(frameon=False, fontsize=5.2, loc="lower center", bbox_to_anchor=(0.45, 1.0), ncol=4,
             handlelength=1.0, columnspacing=0.8)
    fig.tight_layout()
    save(fig, "fig_mut_compact.pdf")
    used["mut_compact"] = {f: (byf[f]["n"], byf[f]["both"], byf[f]["probe_only"], byf[f]["repo_only"], len(byf[f]["survive"])) for f in files}


for f in (fig_l1, fig_l2, fig_l3, fig_cost, fig_mut, fig_mut_compact):
    f()
json.dump(used, open(os.path.join(OUT, "figure_data_used.json"), "w"), indent=1, default=str)
print(json.dumps(used, default=str)[:1500])
