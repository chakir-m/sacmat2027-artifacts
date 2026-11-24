"""Writes the rule-by-rule trace table of the running example (Figure) from running_example.json."""
import json, sys
d = json.load(open(sys.argv[1])); out = open(sys.argv[2], "w")
cases = [("a_ana_reads_assigned_report", "(a)"), ("b1_dan_writes_o_before", "(b$_1$)"),
         ("b2_dan_writes_o_after_asg_and_read_delegation", "(b$_2$)"),
         ("c1_ana_unassigned_0200_five_failed_logins", "(c$_1$)"), ("c2_same_but_assigned", "(c$_2$)")]
name = {"ADMIN": "Admin", "P1": "$P_1$", "P_class": "$\\Pc$", "P2": "$P_2$", "P3": "$P_3$", "P4": "$P_4$",
        "P5": "$P_5$", "P6": "$P_6$", "P_ctx": "$\\Px$", "P7": "$P_7$", "P_own": "$\\Po$"}
def cell(rows, rid):
    first = None
    for i, (r, eff, v) in enumerate(rows):
        if v:
            first = i; break
    i = [r for r, _, _ in rows].index(rid)
    r, eff, v = rows[i]
    if i < first: return "$\\cdot$"
    if i == first: return "\\cellcolor{%s}\\textbf{%s}" % ("green!20" if eff == "allow" else "red!20", eff)
    return ""
for ver, title in (("v1", "v1 (\\chain)"), ("v2", "v2 ($\\mathcal{F}$)")):
    order = [r for r, _, _ in d[cases[0][0]][ver]["trace"]]
    out.write("\\begin{tabular}{@{}l@{\\;}" + "c" * len(cases) + "@{}}\n\\toprule\n")
    out.write("\\multicolumn{%d}{@{}l}{%s} \\\\\n\\midrule\n" % (len(cases) + 1, title))
    out.write("rule & " + " & ".join(c for _, c in cases) + " \\\\\n\\midrule\n")
    for rid in order:
        out.write(name[rid] + " & " + " & ".join(cell(d[k][ver]["trace"], rid) for k, _ in cases) + " \\\\\n")
    out.write("\\bottomrule\n\\end{tabular}%\n")
    if ver == "v1": out.write("\\hspace{3mm}%\n")
