"""Figures printed in the manuscript "Retained keys in pseudonym recycling",
drawn only from results/recycling/*.json of PoS-v1 release v3.7.0.

Run (one command, from a checkout of the tagged release):

    python3 paper/make_figures.py . paper/figs

Inputs are read-only; outputs are PDF figures plus figs/figure_values.json,
which records every number shown in a figure annotation or quoted in the text
that describes a figure, so that it can be checked against the archive.

Figure-number map (manuscript figure -> output file <- result files : keys)

  Fig. 4  fig_e1.pdf      <- E1.json  : cells[sweep=core, density=10, share=0.05, lifetime=900]
                              v2v_receiver_rate, rsu_rate, reports_forgery_naming_honest,
                              reports_beacon_naming_honest, honest_named_by_forgery_reports,
                              honest_named_by_beacon_reports, honest_reported, honest_revoked
  Fig. 5  fig_e1x.pdf     <- E1x.json : cells[strategy, lifetime] forged_sent, v2v_receiver_rate,
                              honest_revoked; E2x.json : cells[mode=recycle] seconds_to_last_accepted
  Fig. 6  fig_e4.pdf      <- E4.json  : equivalence["<d>/attack_free/tracker_link_rate: recycle vs <m>"]
                              (mean_diff, ci90), cells[mode, density] forged_sent, forged_accepted_v2v,
                              per_seed[].load.steady_state (operation counts), calibration.op_costs_s;
                              SUMO_lust_motorway.json, SUMO_motorway.json : the same keys
  Graphical abstract fig_summary.pdf <- E4.json (as Fig. 6, ring, 10 veh/km)

  Not printed in the manuscript (drawn for the results page of the release):
  fig_e1r.pdf <- E1r.json; fig_e1s.pdf <- E1s.json; fig_e3b.pdf <- E3b.json, E3bi.json;
  fig_e3.pdf <- E3.json; fig_e5.pdf <- E5.json, E4.json size_estimate_standard.

Conventions: one fixed colour per issuance mode and per strategy; whiskers are
95 % bootstrap intervals over seeds unless stated otherwise (Fig. 6 (a)
draws the 90 % paired t intervals that match the equivalence test); a cell with
no attempt behind it is drawn as a gap marked "n/a", never as a zero.  CPU time
in Fig. 6 (c) and the graphical abstract is computed from the archived
operation counts under one common set of coefficients, those measured for the
ring E4 run, so that the ring and the traces are comparable.
"""
import json, sys, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import NullFormatter, NullLocator

REPO = sys.argv[1]
OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
R = lambda n: json.load(open(f"{REPO}/results/recycling/{n}.json"))
VALUES = {}

BLUE, ORANGE, AQUA, YELLOW, MAGENTA, GREEN, VIOLET, RED = (
    "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948")
MODES = ["recycle", "fresh", "fresh_vgk", "fresh_pm", "rekey", "window"]
MODE_COL = {"recycle": BLUE, "fresh": ORANGE, "fresh_vgk": AQUA, "fresh_pm": YELLOW, "rekey": VIOLET, "window": MAGENTA}
MODE_LBL = {"recycle": "recycle", "fresh": "fresh", "fresh_vgk": "fresh (vehicle keys)", "fresh_pm": "fresh (vehicle keys, PM-signed)",
            "rekey": "rekey", "window": "window"}
STRAT_COL = {"S1": BLUE, "S2": ORANGE, "S3": AQUA}
STRAT_LBL = {"S1": "S1 remote shadow", "S2": "S2 co-located ghost", "S3": "S3 gap filler"}
INK, QUIET, GRID = "#0b0b0b", "#52514e", "#d9d8d3"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.titlesize": 8.5, "axes.labelsize": 8,
    "axes.edgecolor": QUIET, "axes.linewidth": 0.6, "axes.spines.top": False, "axes.spines.right": False,
    "xtick.color": QUIET, "ytick.color": QUIET, "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
    "legend.fontsize": 7.5, "legend.frameon": False, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.5, "axes.axisbelow": True, "figure.dpi": 150, "savefig.bbox": "tight",
    "pdf.fonttype": 42,
})
W1, W2 = 3.5, 7.2


def isna(c, k): return c.get(k) is None or c[k].get("mean") is None
def m(c, k): return c[k]["mean"]
def errs(cells, k, scale=1.0):
    lo = [0 if isna(c, k) else scale * (c[k]["mean"] - c[k]["lo"]) for c in cells]
    hi = [0 if isna(c, k) else scale * (c[k]["hi"] - c[k]["mean"]) for c in cells]
    return [lo, hi]
def vals(cells, k, scale=1.0): return [np.nan if isna(c, k) else scale * m(c, k) for c in cells]
def bars(ax, x, v, width, color, label=None, yerr=None, **kw):
    ax.bar(x, v, width, color=color, label=label, yerr=yerr, error_kw=dict(ecolor=INK, lw=0.6, capsize=2),
           edgecolor="white", linewidth=0.8, **kw)
def na_marks(ax, xs, v, y=0, fontsize=6.0):
    for xi, vi in zip(xs, v):
        if np.isnan(vi):
            ax.annotate("n/a", (xi, y), ha="center", va="bottom", fontsize=fontsize, color=QUIET)
def panel_label(ax, s): ax.set_title(s, loc="left", fontweight="bold")
def rec(key, cell, k, nd=1):
    """store a figure value with its interval"""
    x = cell[k]
    VALUES[key] = {"mean": round(x["mean"], nd), "lo": None if x.get("lo") is None else round(x["lo"], nd),
                   "hi": None if x.get("hi") is None else round(x["hi"], nd)}
STRATS = ("S1", "S2", "S3")
LIFETIMES = (300, 900, 3600)

# ------------------------------------------------------------------ printed-figure style
# Figures 4 to 6 follow a classic plotting style: a full black frame round each
# panel, light grid, framed legend inside the panel, lower-case axis labels,
# markers with capped whiskers.  Colours: blue / green / magenta for three
# series (passes the colour-vision check on all pairs); the six modes use an
# order that passes it on adjacent pairs, with distinct markers as a second cue.
C_BLUE, C_GREEN, C_MAG, C_ORANGE, C_PURPLE, C_OCHRE = "#3b75af", "#519e3e", "#c94f7c", "#e0812f", "#7b5ea7", "#b8901c"
PRINT = {"font.family": "DejaVu Sans", "font.size": 9, "axes.titlesize": 9.5, "axes.titleweight": "normal",
         "axes.labelsize": 9.5, "xtick.labelsize": 8.8, "ytick.labelsize": 8.8, "legend.fontsize": 8.2,
         "axes.edgecolor": "black", "axes.linewidth": 0.8, "axes.spines.top": True, "axes.spines.right": True,
         "xtick.color": "black", "ytick.color": "black", "axes.labelcolor": "black", "text.color": "black",
         "xtick.direction": "out", "ytick.direction": "out", "axes.grid": True, "grid.color": "#dcdcdc",
         "grid.linewidth": 0.7, "legend.frameon": True, "legend.framealpha": 0.92, "legend.edgecolor": "#b0b0b0",
         "legend.fancybox": True, "lines.linewidth": 1.6, "lines.markersize": 6, "errorbar.capsize": 3}
S_COL = {"S1": C_BLUE, "S2": C_GREEN, "S3": C_MAG}
S_MRK = {"S1": "s", "S2": "^", "S3": "o"}
S_LBL = {"S1": "S1, remote shadow", "S2": "S2, co-located ghost", "S3": "S3, gap filler"}
M_COL = {"recycle": C_BLUE, "fresh": C_ORANGE, "fresh_vgk": C_PURPLE, "fresh_pm": C_GREEN, "rekey": C_MAG, "window": C_OCHRE}
M_MRK = {"fresh": "o", "fresh_vgk": "s", "fresh_pm": "^"}
def ptitle(ax, s): ax.set_title(s, loc="left", pad=5)
def pbars(ax, x, v, width, color, label=None, yerr=None, **kw):
    ax.bar(x, v, width, color=color, label=label, yerr=yerr, edgecolor="black", linewidth=0.5,
           error_kw=dict(ecolor="black", lw=0.8, capsize=2.5), **kw)

# ------------------------------------------------------------------ Fig. 4: E1
e1 = [c for c in R("E1")["cells"] if c["sweep"] == "core" and c["density"] == 10 and c["share"] == 0.05 and c["lifetime"] == 900]
hon = m(e1[0], "population_honest")
with plt.rc_context(PRINT):
    fig, axs = plt.subplots(1, 3, figsize=(W2, 2.75))
    ax = axs[0]; x = np.arange(3); w = 0.26
    for i, (pl, lbl, col) in enumerate([(False, "receivers, rule off", C_BLUE), (True, "receivers, rule on", C_GREEN)]):
        cells = [next(c for c in e1 if c["strategy"] == s and c["plausibility"] == pl) for s in STRATS]
        pbars(ax, x + (i - 1) * w, vals(cells, "v2v_receiver_rate", 100), w, col, lbl, yerr=errs(cells, "v2v_receiver_rate", 100))
    cells = [next(c for c in e1 if c["strategy"] == s and c["plausibility"]) for s in STRATS]
    pbars(ax, x + w, vals(cells, "rsu_rate", 100), w, C_MAG, "RSU, ledger check", yerr=errs(cells, "rsu_rate", 100))
    ax.set_ylim(0, 150); ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("forgeries accepted (%)"); ptitle(ax, "(a) acceptance")
    ax.legend(loc="upper center", ncol=1, handlelength=1.2, borderpad=0.35, labelspacing=0.25)
    ax = axs[1]; w = 0.34
    pbars(ax, x - w / 2, vals(cells, "reports_forgery_naming_honest"), w, C_BLUE, "raised by a forgery", yerr=errs(cells, "reports_forgery_naming_honest"))
    pbars(ax, x + w / 2, vals(cells, "reports_beacon_naming_honest"), w, C_GREEN, "raised by holder's beacon", yerr=errs(cells, "reports_beacon_naming_honest"))
    for i, c in enumerate(cells):
        for k, dx in (("reports_forgery_naming_honest", -w / 2), ("reports_beacon_naming_honest", w / 2)):
            ax.annotate(f"{m(c,k):.0f}", (x[i] + dx, c[k]['hi'] + 6), ha="center", fontsize=8, color="black")
    ax.set_ylim(0, 480); ax.set_ylabel("wrongful reports per run"); ptitle(ax, "(b) reports by route")
    ax.legend(loc="upper right", handlelength=1.2, borderpad=0.35, labelspacing=0.25)
    ax = axs[2]; w = 0.26
    pbars(ax, x - w, vals(cells, "honest_named_by_forgery_reports"), w, C_BLUE, "named by forgeries", yerr=errs(cells, "honest_named_by_forgery_reports"))
    pbars(ax, x, vals(cells, "honest_named_by_beacon_reports"), w, C_GREEN, "named by own beacons", yerr=errs(cells, "honest_named_by_beacon_reports"))
    pbars(ax, x + w, vals(cells, "honest_revoked"), w, C_MAG, "revoked (either route)", yerr=errs(cells, "honest_revoked"))
    for i, c in enumerate(cells):
        ax.annotate(f"{m(c,'honest_revoked'):.1f}", (x[i] + w, c['honest_revoked']['hi'] + 1.2), ha="center", fontsize=8, color="black")
    ax.set_ylim(0, 80); ax.set_yticks([0, 10, 20, 30, 40, 50, 60]); ax.set_ylabel("honest vehicles per run"); ptitle(ax, "(c) honest vehicles named")
    ax.legend(loc="upper right", handlelength=1.2, borderpad=0.35, labelspacing=0.25)
    for a in axs:
        a.set_xticks(x); a.set_xticklabels(STRATS); a.set_xlabel("former-holder strategy"); a.set_xlim(-0.55, 2.55)
    fig.subplots_adjust(wspace=0.36)
    fig.savefig(f"{OUT}/fig_e1.pdf"); plt.close(fig)
s1 = cells[0]
for k in ("v2v_receiver_rate", "rsu_rate"):
    for c in cells: rec(f"fig4_e1/{c['strategy']}/{k}", c, k, 4)
for k in ("reports_forgery_naming_honest", "reports_beacon_naming_honest", "honest_named_by_forgery_reports",
          "honest_named_by_beacon_reports", "honest_reported", "honest_revoked", "population_honest"):
    rec(f"fig4_e1/S1/{k}", s1, k)

# ------------------------------------------------------------------ Fig. 5: E1x + E2x
e1x = R("E1x")["cells"]; e2x = R("E2x")["cells"]
def lt_cells(s): return [next(c for c in e1x if c["strategy"] == s and c["lifetime"] == lt) for lt in LIFETIMES]
LT = np.array(LIFETIMES, dtype=float)
def lt_axis(ax):
    ax.set_xscale("log"); ax.set_xlim(220, 4900); ax.set_xticks(LT); ax.set_xticklabels(["300", "900", "3,600"])
    ax.xaxis.set_minor_formatter(NullFormatter()); ax.set_xlabel("certificate lifetime (s)")
def sline(ax, s, k, scale=1.0, nd=1, tag=None):
    cs = lt_cells(s)
    ax.errorbar(LT, vals(cs, k, scale), yerr=errs(cs, k, scale), color=S_COL[s], marker=S_MRK[s], label=S_LBL[s],
                ms=6, capsize=3, elinewidth=1.0)
    if tag:
        for c in cs: rec(f"fig5_e1x/{s}/{c['lifetime']}/{k}", c, k, nd)
with plt.rc_context(PRINT):
    fig, axs = plt.subplots(2, 2, figsize=(W2, 4.9))
    ax = axs[0, 0]
    for s in STRATS: sline(ax, s, "forged_sent", nd=0, tag=True)
    ax.set_yscale("log"); ax.set_ylim(600, 50000); ax.set_ylabel("forgeries sent per run"); ptitle(ax, "(a) attempts")
    ax = axs[0, 1]
    for s in STRATS: sline(ax, s, "v2v_receiver_rate", 100, nd=4, tag=True)
    ax.set_ylim(0, 105); ax.set_ylabel("receiver checks accepting (%)"); ptitle(ax, "(b) acceptance")
    ax.legend(loc="lower right", handlelength=2.0, borderpad=0.4)
    ax = axs[1, 0]
    for s in STRATS: sline(ax, s, "honest_revoked", tag=(s != "S3"))
    ax.set_ylim(-5, 105); ax.set_ylabel(f"honest vehicles revoked (of {m(lt_cells('S1')[0], 'population_honest'):.1f})")
    ptitle(ax, "(c) wrongful revocations")
    ax = axs[1, 1]
    cs2 = [next(c for c in e2x if c["mode"] == "recycle" and c["lifetime"] == lt) for lt in LIFETIMES]
    ax.errorbar(LT, vals(cs2, "seconds_to_last_accepted"), yerr=errs(cs2, "seconds_to_last_accepted"), color=C_BLUE, marker="s",
                ms=6, capsize=3, elinewidth=1.0, label="vehicle revoked at 60 s, recycle")
    for i, c in enumerate(cs2):
        rec(f"fig5_e1x/E2x/{c['lifetime']}/seconds_to_last_accepted", c, "seconds_to_last_accepted", 0)
        ax.annotate(f"{m(c,'seconds_to_last_accepted'):.0f} s", (LT[i], m(c, "seconds_to_last_accepted") + 28), ha="center", fontsize=8, color="black")
    ax.axhline(540, color="black", ls=":", lw=1.0, label="end of the 600 s run")
    ax.set_ylim(0, 720); ax.set_ylabel("revoked vehicle still accepted (s)"); ptitle(ax, "(d) after revocation")
    ax.legend(loc="lower right", handlelength=2.0, borderpad=0.4)
    for a in axs.flat: lt_axis(a)
    fig.subplots_adjust(hspace=0.5, wspace=0.3)
    fig.savefig(f"{OUT}/fig_e1x.pdf"); plt.close(fig)

# ------------------------------------------------------------------ results page: E1r
e1r = R("E1r")["cells"]
fig, axs = plt.subplots(1, 2, figsize=(W2, 2.6))
rules = [f'{c["reports"]} / {c["distinct_rsus"]}' for c in e1r]
x = np.arange(len(e1r)); w = 0.2
ax = axs[0]
for i, (key, lbl, col) in enumerate([("S1_short", "S1, 120 s", BLUE), ("S1_long", "S1, 600 s", VIOLET), ("S2_short", "S2, 120 s", ORANGE), ("S2_long", "S2, 600 s", YELLOW)]):
    cs = [c[key] for c in e1r]
    bars(ax, x + (i - 1.5) * w, vals(cs, "honest_revoked"), w, col, lbl, yerr=errs(cs, "honest_revoked"))
ax.set_xticks(x); ax.set_xticklabels(rules); ax.set_xlabel("revocation rule: reports / distinct RSUs"); ax.set_ylabel(f"honest vehicles revoked per run (of {m(e1r[0]['S1_short'],'population_honest'):.1f})")
ax.set_ylim(0, 110); ax.set_yticks([0, 25, 50, 75, 100]); panel_label(ax, "(a) honest vehicles wrongly revoked")
h, l = ax.get_legend_handles_labels(); fig.legend(h, l, loc="upper center", ncol=4, bbox_to_anchor=(0.5, 1.03), fontsize=7)
ax = axs[1]
cs = [c["misbehaver"] for c in e1r]
bars(ax, x, vals(cs, "seconds_to_revocation"), 0.55, AQUA, yerr=errs(cs, "seconds_to_revocation"))
for i, c in enumerate(cs): ax.annotate(f"{m(c,'seconds_to_revocation'):.0f} s", (x[i], c['seconds_to_revocation']['hi'] + 8), ha="center", fontsize=7, color=INK)
ax.set_xticks(x); ax.set_xticklabels(rules); ax.set_xlabel("revocation rule: reports / distinct RSUs"); ax.set_ylabel("genuine misbehaver survives (s)"); ax.set_ylim(0, 320)
panel_label(ax, "(b) genuine misbehaver survival")
fig.subplots_adjust(top=0.86)
fig.savefig(f"{OUT}/fig_e1r.pdf"); plt.close(fig)

# ------------------------------------------------------------------ results page: E1s detection-side sensitivity
e1s = R("E1s")["cells"]
names = [c["variant"] for c in e1s]
fig, axs = plt.subplots(1, 3, figsize=(W2, 2.9), sharey=True, gridspec_kw=dict(width_ratios=[1.25, 1.1, 0.9]))
y = np.arange(len(e1s))[::-1]; h = 0.36
ax = axs[0]
for i, s in enumerate(("S1", "S2")):
    cs = [c[s] for c in e1s]
    ax.barh(y + (0.5 - i) * h, vals(cs, "honest_revoked"), h, color=STRAT_COL[s], label=STRAT_LBL[s],
            xerr=errs(cs, "honest_revoked"), error_kw=dict(ecolor=INK, lw=0.6, capsize=2), edgecolor="white", linewidth=0.8)
    for yi, c, nm in zip(y + (0.5 - i) * h, cs, names):
        ax.annotate(f"{m(c,'honest_revoked'):.1f}", (c["honest_revoked"]["hi"] + 1, yi), va="center", fontsize=6.0, color=INK)
        rec(f"e1s/{s}/{nm}/honest_revoked", c, "honest_revoked")
ax.set_yticks(y); ax.set_yticklabels(names, fontsize=6.8); ax.set_xlim(0, 58)
ax.set_xlabel(f"honest vehicles revoked in 120 s (of {m(e1s[0]['S1'], 'population_honest'):.1f})"); ax.grid(axis="y", visible=False)
panel_label(ax, "(a) wrongful revocations")
h7, l7 = ax.get_legend_handles_labels()
ax = axs[1]
for i, s in enumerate(("S1", "S2")):
    cs = [c[s] for c in e1s]
    ax.barh(y + (0.5 - i) * h, vals(cs, "forged_sent"), h, color=STRAT_COL[s], xerr=errs(cs, "forged_sent"),
            error_kw=dict(ecolor=INK, lw=0.6, capsize=2), edgecolor="white", linewidth=0.8)
    for yi, c in zip(y + (0.5 - i) * h, cs):
        ax.annotate(f"{m(c,'forged_sent'):.0f}", (c["forged_sent"]["hi"] + 20, yi), va="center", fontsize=6.0, color=INK)
ax.set_xlim(0, 1700); ax.set_xlabel("messages sent per run"); ax.grid(axis="y", visible=False); panel_label(ax, "(b) attempts")
ax = axs[2]
cs = [c["misbehaver_matched"] for c in e1s]
ax.barh(y, vals(cs, "seconds_to_revocation"), 0.55, color=AQUA, edgecolor="white", linewidth=0.8)
for yi, c, cc in zip(y, cs, e1s):
    a = cc["attack_free"]
    ax.annotate(f"{m(c,'seconds_to_revocation'):.0f} s; FP {100*m(a,'honest_rejected_implausible_v2v')/m(a,'honest_received_v2v'):.2f} %",
                (m(c, "seconds_to_revocation") + 2, yi), va="center", fontsize=5.8, color=INK)
    rec(f"e1s/misbehaver/{cc['variant']}/seconds_to_revocation", c, "seconds_to_revocation", 0)
ax.set_xlim(0, 160); ax.set_xlabel("revoked after (s); attack-free FP rate"); ax.grid(axis="y", visible=False)
panel_label(ax, "(c) genuine misbehaver")
fig.legend(h7, l7, loc="upper center", ncol=2, bbox_to_anchor=(0.55, 1.03), fontsize=6.8)
fig.subplots_adjust(wspace=0.16, top=0.86)
fig.savefig(f"{OUT}/fig_e1s.pdf"); plt.close(fig)

# ------------------------------------------------------------------ results page: E3b + E3bi
e3b = R("E3b")["cells"]; e3bi = R("E3bi")["cells"]
ENT = [("pki", "PKI"), ("pm", "PM"), ("rsu", "RSU"), ("cloud", "cloud")]
fig, axs = plt.subplots(1, 3, figsize=(W2, 2.5), gridspec_kw=dict(width_ratios=[1.1, 1.3, 1.3]))
ax = axs[0]; x = np.arange(4); w = 0.26
for i, (mode, col) in enumerate([("recycle", BLUE), ("fresh", ORANGE), ("fresh_vgk", AQUA)]):
    cs = [next(c for c in e3b if c["mode"] == mode and c["entity"] == e and c["strategy"] == "offset") for e, _ in ENT]
    bars(ax, x + (i - 1) * w, vals(cs, "key_share"), w, col, MODE_LBL[mode], yerr=errs(cs, "key_share"))
ax.set_xticks(x); ax.set_xticklabels([l for _, l in ENT]); ax.set_ylim(0, 1.35); ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0]); ax.set_ylabel("share of keys in use held")
ax.legend(loc="upper center", fontsize=6.4, ncol=1); panel_label(ax, "(a) key custody")
for j, (metric, title, ylabel) in enumerate([("receiver_rate", "(b) receiver checks accepting", "share of receiver checks"), ("blame_rate", "(c) RSU reports the holder", "share of forgeries")]):
    ax = axs[j + 1]; x = np.arange(3); w = 0.2
    for i, (e, lbl) in enumerate(ENT):
        cs = [next(c for c in e3b if c["mode"] == "recycle" and c["entity"] == e and c["strategy"] == s) for s in ("offset", "near", "silent")]
        bars(ax, x + (i - 1.5) * w, vals(cs, metric), w, [BLUE, ORANGE, AQUA, YELLOW][i], f"insider at the {lbl}", yerr=errs(cs, metric))
        ci = [next(c for c in e3bi if c["mode"] == "recycle" and c["entity"] == e and c["strategy"] == s) for s in ("offset", "near", "silent")]
        ax.plot(x + (i - 1.5) * w, vals(ci, metric), "D", ms=3.2, mfc="white", mec=INK, mew=0.7, label="one insider alone" if i == 0 else None, zorder=5)
    ax.set_xticks(x); ax.set_xticklabels(["offset\n40 m", "near\n10 m", "silent\nperiod"]); ax.set_ylim(0, 1.12); ax.set_ylabel(ylabel)
    if j == 1: ax.legend(loc="upper right", fontsize=6.0)
    panel_label(ax, title)
fig.subplots_adjust(wspace=0.4)
fig.savefig(f"{OUT}/fig_e3b.pdf"); plt.close(fig)

# ------------------------------------------------------------------ results page: E3
e3 = R("E3")["cells"]
def table(d, order): return next(c for c in e3 if c["density"] == d and c["cloud_order"] == order)["table"]
ROWS = [("tracker", "outside tracker (A1)", "kept"), ("rsu", "one RSU", "kept"), ("pm", "one PM", "kept"), ("cloud", "cloud, upload order kept", "kept"),
        ("cloud", "cloud, shuffled before upload", "shuffled"), ("tracker+pm", "tracker + one PM (A4)", "kept"), ("tracker+cloud", "tracker + cloud, order kept (A4)", "kept")]
METRICS = [("link_rate", "link rate", BLUE), ("precision", "precision", ORANGE), ("correct_identity_beacon_share", "beacon-seconds attributed to the right identity", AQUA), ("ambiguous_identity_beacon_share", "beacon-seconds in an ambiguous cluster", MAGENTA), ("correct_identity_driven_share", "driven time attributed to the right identity", VIOLET)]
fig, axs = plt.subplots(1, 2, figsize=(W2, 3.3), sharey=True)
for j, dens in enumerate((10, 40)):
    ax = axs[j]; y = np.arange(len(ROWS))[::-1]; h = 0.16
    for i, (metric, lbl, col) in enumerate(METRICS):
        cells = [table(dens, o)[k] for k, _, o in ROWS]
        v = vals(cells, metric)
        ax.barh(y + (2 - i) * h, v, h, color=col, label=lbl, xerr=errs(cells, metric), error_kw=dict(ecolor=INK, lw=0.6, capsize=2), edgecolor="white", linewidth=0.8)
        for yi, vi in zip(y + (2 - i) * h, v):
            if np.isnan(vi): ax.annotate("n/a", (0.01, yi), va="center", fontsize=6, color=QUIET)
    ax.set_yticks(y); ax.set_yticklabels([l for _, l, _ in ROWS]); ax.set_xlim(0, 1.05); ax.set_xlabel("share (ten seeds, 95 % intervals)")
    ax.grid(axis="y", visible=False); panel_label(ax, f"({'ab'[j]}) {dens} veh/km")
h_, l_ = axs[0].get_legend_handles_labels(); fig.legend(h_, l_, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.07), fontsize=6.8)
fig.subplots_adjust(top=0.84, wspace=0.08)
fig.savefig(f"{OUT}/fig_e3.pdf"); plt.close(fig)

# ------------------------------------------------------------------ Fig. 6: E4 ring + SUMO
e4 = R("E4"); e4c = e4["cells"]
lustF = R("SUMO_lust_motorway"); motF = R("SUMO_motorway")
COMMON = e4["calibration"]["op_costs_s"]
OPS = {"signatures": "sign", "verifications": "verify", "keygens": "keygen", "encryptions": "encrypt", "decryptions": "decrypt"}
def op_cost(ld, cal):
    t = sum(ld.get(k, 0) * cal[o] for k, o in OPS.items())
    return t + ld.get("encrypted_bytes", 0) * cal.get("encrypt_per_byte", 0) + ld.get("decrypted_bytes", 0) * cal.get("decrypt_per_byte", 0)
def common_cpu(cell, own_cal, entity):
    """CPU-s per 1,000 veh-h of ``entity`` under the common (ring) coefficients:
    the run's own figure scaled by the ratio of costs of its archived operation counts."""
    own = m(cell, f"{entity}_cpu_s_per_1000_veh_h")
    if not own:
        return 0.0
    num = sum(op_cost(p["load"]["steady_state"][entity], COMMON) for p in cell["per_seed"])
    den = sum(op_cost(p["load"]["steady_state"][entity], own_cal) for p in cell["per_seed"])
    return own * num / den
SCN = [("ring\n10", [c for c in e4c if c["density"] == 10], "10/", e4),
       ("ring\n40", [c for c in e4c if c["density"] == 40], "40/", e4),
       ("LuST", lustF["E4"], "", lustF), ("motor-\nway", motF["E4"], "", motF)]
SC_LBL = ["ring\n10/km", "ring\n40/km", "LuST\ntrace", "motorway\ntrace"]
with plt.rc_context(PRINT):
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    fig, axs = plt.subplots(2, 2, figsize=(W2, 4.9))
    x = np.arange(4)
    ax = axs[0, 0]; w = 0.2
    ax.axhline(0, color="black", lw=0.8)
    for yy in (-1, 1): ax.axhline(yy, color="black", ls=":", lw=1.1)
    for i, mode in enumerate(["fresh", "fresh_vgk", "fresh_pm"]):
        mu, lo, hi = [], [], []
        for name, _, pre, F in SCN:
            q = F["equivalence"][f"{pre}attack_free/tracker_link_rate: recycle vs {mode}"]
            mu.append(100 * q["mean_diff"]); lo.append(100 * (q["mean_diff"] - q["ci90"][0])); hi.append(100 * (q["ci90"][1] - q["mean_diff"]))
            VALUES[f"fig6_e4/{name.replace(chr(10), ' ')}/recycle-{mode}"] = {"mean": round(100 * q["mean_diff"], 2), "ci90": [round(100 * q["ci90"][0], 2), round(100 * q["ci90"][1], 2)], "equivalent": q["equivalent"]}
        ax.errorbar(x + (i - 1) * w, mu, yerr=[lo, hi], fmt=M_MRK[mode], ms=6, color=M_COL[mode], ecolor=M_COL[mode],
                    capsize=3, elinewidth=1.0, label=mode)
    ax.plot([], [], color="black", ls=":", lw=1.1, label="±1 point margin")
    ax.set_ylim(-1.5, 2.4); ax.set_yticks([-1, -0.5, 0, 0.5, 1])
    ax.set_ylabel("recycle minus mode (points)"); ptitle(ax, "(a) link rate, attack-free")
    ax.legend(loc="upper center", ncol=2, handlelength=1.6, borderpad=0.35, columnspacing=1.0, labelspacing=0.25, prop={"family": "monospace", "size": 8.0})
    ax = axs[0, 1]; w = 0.24
    for i, mode in enumerate(["recycle", "rekey", "window"]):
        cs = [next(c for c in cells if c["mode"] == mode) for _, cells, _, _ in SCN]
        pbars(ax, x + (i - 1) * w, vals(cs, "forged_accepted_v2v"), w, M_COL[mode], mode, yerr=errs(cs, "forged_accepted_v2v"))
        if mode == "rekey":
            for xi, c in zip(x + (i - 1) * w, cs):
                ax.annotate(f"{m(c,'forged_accepted_v2v'):.0f}", (xi, 10), ha="center", va="bottom", fontsize=8, color="black")
    ax.set_ylim(0, 1250); ax.set_ylabel("forgeries accepted per run"); ptitle(ax, "(b) impersonation under S2")
    ax.legend(loc="upper center", ncol=3, handlelength=1.2, borderpad=0.35, columnspacing=0.8, prop={"family": "monospace", "size": 8.2})
    ax.annotate("fresh modes:\nno target (n/a)", (0.97, 0.58), xycoords="axes fraction", ha="right", va="top", fontsize=8.2)
    ax = axs[1, 0]; w = 0.13
    for i, mode in enumerate(MODES):
        cs = [next(c for c in cells if c["mode"] == mode) for _, cells, _, _ in SCN]
        cals = [F["calibration"]["op_costs_s"] for _, _, _, F in SCN]
        pki = [common_cpu(c, cal, "pki") for c, cal in zip(cs, cals)]
        pm = [common_cpu(c, cal, "pm") for c, cal in zip(cs, cals)]
        for (name, _, _, _), a_, b_ in zip(SCN, pki, pm):
            VALUES[f"fig6_e4/{name.replace(chr(10), ' ')}/{mode}/cpu_common"] = {"pki": round(a_, 1), "pm": round(b_, 1)}
        ax.bar(x + (i - 2.5) * w, pki, w, color=M_COL[mode], edgecolor="black", linewidth=0.4)
        ax.bar(x + (i - 2.5) * w, pm, w, bottom=pki, color=M_COL[mode], hatch="////", edgecolor="white", linewidth=0.4)
        ax.bar(x + (i - 2.5) * w, np.array(pki) + np.array(pm), w, fill=False, edgecolor="black", linewidth=0.4)
    ax.set_ylim(0, 110); ax.set_ylabel("CPU-s per 1,000 vehicle-hours"); ptitle(ax, "(c) issuance load, PKI and PMs")
    for a in (axs[0, 0], axs[0, 1], axs[1, 0]):
        a.set_xticks(x); a.set_xticklabels(SC_LBL); a.set_xlabel("scenario")
    ax = axs[1, 1]; ax.axis("off")
    hm = [Patch(facecolor=M_COL[k], edgecolor="black", linewidth=0.4, label=k) for k in MODES]
    l1 = ax.legend(handles=hm, title="issuance mode, panel (c)", loc="upper left", bbox_to_anchor=(0.03, 1.0), alignment="left",
                   handlelength=1.4, ncol=2, prop={"family": "monospace", "size": 8.2})
    ax.add_artist(l1)
    hk = [Patch(facecolor="#9a9a9a", edgecolor="black", linewidth=0.4, label="solid: PKI"),
          Patch(facecolor="#9a9a9a", hatch="////", edgecolor="white", label="hatched: PMs")]
    ax.legend(handles=hk, title="share of the bar, panel (c)", loc="upper left", bbox_to_anchor=(0.03, 0.42), alignment="left", handlelength=1.4)
    fig.subplots_adjust(hspace=0.62, wspace=0.3)
    fig.savefig(f"{OUT}/fig_e4.pdf"); plt.close(fig)

# ------------------------------------------------------------------ results page: E5
e5 = R("E5")["cells"]
VAR = [("window", "window (holder-bound certificate, old key)", MAGENTA), ("rekey", "rekey (holder-bound certificate, new key)", VIOLET)]
fig, axs = plt.subplots(1, 3, figsize=(W2, 2.6), gridspec_kw=dict(width_ratios=[1.4, 1, 1]))
ax = axs[0]; x = np.arange(3); w = 0.38
for i, (v, lbl, col) in enumerate(VAR):
    cs = [next(c for c in e5 if c["variant"] == v and c["strategy"] == s) for s in STRATS]
    vv = vals(cs, "forged_v2v_accepted")
    bars(ax, x + (i - 0.5) * w, vv, w, col, lbl, yerr=errs(cs, "forged_v2v_accepted"))
    for xi, c, val in zip(x + (i - 0.5) * w, cs, vv):
        top = val if val == 0 else c['forged_v2v_accepted']['hi']
        ax.annotate(f"{val:,.0f}\nof {m(c,'forged_sent'):,.0f}" if val else f"0/{m(c,'forged_sent'):,.0f}", (xi, top + 25), ha="center", va="bottom", fontsize=5.2, color=INK)
        rec(f"e5/{v}/{c['strategy']}/forged_sent", c, "forged_sent", 0)
        rec(f"e5/{v}/{c['strategy']}/forged_v2v_accepted", c, "forged_v2v_accepted", 0)
ax.set_xticks(x); ax.set_xticklabels(["S1", "S2", "S3"]); ax.set_ylim(0, 1400)
ax.set_ylabel("forged messages accepted per run"); panel_label(ax, "(a) forgeries accepted")
h5, l5 = ax.get_legend_handles_labels()
ax = axs[1]; w = 0.36
VAR2 = [("window", "window"), ("rekey", "rekey"), ("fresh_vgk", "fresh,\nveh. keys")]
cs = [next(c for c in e5 if c["variant"] == v and c["strategy"] == "S2") for v, _ in VAR2]
pki = vals(cs, "pki_signatures"); pm = vals(cs, "pm_signatures")
ax.bar(x, pki, w, color="#8a8986", label="at the PKI", edgecolor="white", linewidth=0.8)
ax.bar(x, pm, w, bottom=pki, color="#c9c8c3", label="at the PMs", edgecolor="white", linewidth=0.8)
kg = [m(c, 'vehicle_keygens_per_vehicle_per_round') for c in cs]
for i, c in enumerate(cs):
    ax.annotate(f"{pki[i]:,.0f} + {pm[i]:,.0f}", (x[i], pki[i] + pm[i] + 40), ha="center", fontsize=5.8, color=INK)
ax.set_xticks(x); ax.set_xticklabels([l for _, l in VAR2])
for i in range(3): ax.annotate(f"{kg[i]:.0f} key gen./veh./round", (x[i], 60), ha="center", va="bottom", rotation=90, fontsize=5.6, color=INK)
ax.set_ylabel("signatures per run"); ax.set_ylim(0, 1900)
ax.legend(loc="upper left", fontsize=6.0); panel_label(ax, "(b) signatures")
ax = axs[2]
rows = e4["size_estimate_standard"]["rows"]
def sz(mode, share): return next(r for r in rows if r["mode"] == mode and abs(r["full_cert_share"] - share) < 1e-9)["bytes_per_cam"]
x2 = np.arange(2); w = 0.36
ax.bar(x2 - w / 2, [sz("recycle", 1.0), sz("recycle", 0.1)], w, color=BLUE, label="recycle, fresh", edgecolor="white", linewidth=0.8)
ax.bar(x2 + w / 2, [sz("rekey", 1.0), sz("rekey", 0.1)], w, color=VIOLET, label="rekey, window", edgecolor="white", linewidth=0.8)
for i, sh in enumerate((1.0, 0.1)):
    ax.annotate(f"{sz('rekey', sh)/sz('recycle', sh):.2f}x", (x2[i] + w / 2, sz("rekey", sh) + 8), ha="center", fontsize=6.5, color=INK)
    ax.annotate(f"{sz('recycle', sh):.0f}", (x2[i] - w / 2, sz("recycle", sh) + 8), ha="center", fontsize=6.5, color=INK)
    VALUES[f"e5/bytes/{sh}"] = {"recycle": sz("recycle", sh), "rekey": sz("rekey", sh)}
ax.set_xticks(x2); ax.set_xticklabels(["cert. in\nevery CAM", "cert. in\n1 CAM of 10"], fontsize=7); ax.set_ylabel("bytes per CAM (standards model)"); ax.set_ylim(0, 620)
ax.legend(loc="upper right", fontsize=6.3); panel_label(ax, "(c) message size")
fig.legend(h5, l5, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.04), fontsize=6.8)
fig.subplots_adjust(wspace=0.5, bottom=0.2, top=0.82)
fig.savefig(f"{OUT}/fig_e5.pdf"); plt.close(fig)

# ------------------------------------------------------------------ graphical abstract
with plt.rc_context(PRINT):
    fig, ax = plt.subplots(figsize=(W2, 2.5))
    c10 = {c["mode"]: c for c in e4c if c["density"] == 10}
    diffs = {k: (0.0 if k == "recycle" else -100 * e4["equivalence"][f"10/attack_free/tracker_link_rate: recycle vs {k}"]["mean_diff"]) for k in MODES}
    cal10 = e4["calibration"]["op_costs_s"]
    axes_ = [("link rate minus recycle\n(points, attack-free)", diffs, None),
             ("forgeries accepted\nper run (S2)", {k: (np.nan if m(c10[k], "forged_sent") == 0 else m(c10[k], "forged_accepted_v2v")) for k in MODES}, 200),
             ("honest vehicles\nrevoked per run", {k: m(c10[k], "honest_revoked") for k in MODES}, 10),
             ("PKI CPU-s per\n1,000 veh-h", {k: common_cpu(c10[k], cal10, "pki") for k in MODES}, 45),
             ("PM CPU-s per\n1,000 veh-h", {k: common_cpu(c10[k], cal10, "pm") for k in MODES}, 70)]
    x = np.arange(len(axes_)); w = 0.13
    for i, mode in enumerate(MODES):
        hts = []
        for _, d, top in axes_:
            v = d[mode]
            hts.append(np.nan if (isinstance(v, float) and np.isnan(v)) else (0.5 + v / 2.0 if top is None else v / top))
        ax.bar(x + (i - 2.5) * w, hts, w, color=M_COL[mode], label=MODE_LBL[mode], edgecolor="black", linewidth=0.4)
        for j, (_, d, top) in enumerate(axes_):
            v = d[mode]
            if isinstance(v, float) and np.isnan(v):
                ax.annotate("n/a", (x[j] + (i - 2.5) * w, 0.02), ha="center", fontsize=5.8, rotation=90, va="bottom", color=QUIET); continue
            ax.annotate(f"{v:+.2f}" if top is None else (f"{v:.1f}" if top < 20 else f"{v:.0f}"), (x[j] + (i - 2.5) * w, hts[j] + 0.02), ha="center", fontsize=5.8, rotation=90, va="bottom", color=INK)
    ax.set_xticks(x); ax.set_xticklabels([a for a, _, _ in axes_], fontsize=7); ax.set_yticks([]); ax.set_ylim(0, 1.45); ax.grid(False)
    ax.legend(loc="upper center", ncol=6, fontsize=6.4, bbox_to_anchor=(0.5, 1.0), columnspacing=1.0, handlelength=1.2)
    ax.set_title("Six issuance modes on the same traffic (ring, 10 veh/km, ten seeds): recycling saves authority load at the cost of accountability", fontsize=8.0, loc="left")
    fig.savefig(f"{OUT}/fig_summary.pdf"); plt.close(fig)

json.dump(VALUES, open(f"{OUT}/figure_values.json", "w"), indent=1, sort_keys=True)
print("done:", len(VALUES), "figure values")
