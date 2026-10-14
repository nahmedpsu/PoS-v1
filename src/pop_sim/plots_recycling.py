"""Figures of the pseudonym recycling study (one per experiment)."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .plots import C_POET, C_POW, C_POW1, C_REF, _save  # noqa: E402

C_V2 = "#2A7F62"
MODE_COLORS = {"recycle": C_REF, "fresh": C_POW, "fresh_vgk": C_POW1, "fresh_pm": "#8c6d31", "rekey": C_V2, "window": C_POET}


def _v(d, k: str = "mean") -> float:
    """A summary statistic, NaN when not applicable (nothing measured), so a
    0/0 cell is drawn as a gap, never as zero (review R02)."""
    x = d.get(k) if isinstance(d, dict) else None
    return float("nan") if x is None else float(x)


def _ci(ax, x, cells, key, **kw):
    y = [_v(c[key]) for c in cells]
    lo = [_v(c[key]) - _v(c[key], "lo") for c in cells]
    hi = [_v(c[key], "hi") - _v(c[key]) for c in cells]
    ax.errorbar(x, y, yerr=[lo, hi], capsize=3, marker="o", **kw)


def fig_e1(res: dict, path: Path) -> Path:
    cells = [c for c in res["cells"] if c["sweep"] == "core"]
    fig, all_axes = plt.subplots(1, 4, figsize=(18, 4.2))
    # strategy bars at the core cell (plausibility on, 900 s): honest vehicles reported and revoked
    bar_ax, axes = all_axes[0], all_axes[1:]
    core = [next((c for c in cells if c["strategy"] == st and c["plausibility"] and c["lifetime"] == 900), None)
            for st in ("S1", "S2", "S3")]
    for i, (key, col, lab) in enumerate((("honest_reported", C_POW, "honest vehicles reported"),
                                         ("honest_revoked", C_REF, "honest vehicles revoked"))):
        ys = [_v(c[key]) if c else 0 for c in core]
        err = [[_v(c[key]) - _v(c[key], "lo") if c else 0 for c in core],
               [_v(c[key], "hi") - _v(c[key]) if c else 0 for c in core]]
        bar_ax.bar([j + (i - 0.5) * 0.35 for j in range(3)], ys, width=0.35, yerr=err, capsize=3, color=col, label=lab)
    bar_ax.set_xticks(range(3), ["S1", "S2", "S3"])
    bar_ax.set_ylabel("vehicles per run (mean, 95 % CI)")
    bar_ax.set_title("Accountability failure by strategy (120 s)", fontsize=10)
    bar_ax.legend(fontsize=7)
    for st, color in zip(("S1", "S2", "S3"), (C_REF, C_POET, C_POW1)):
        for pl, ls in ((False, "-"), (True, "--")):
            sub = sorted([c for c in cells if c["strategy"] == st and c["plausibility"] == pl], key=lambda c: c["lifetime"])
            if not sub:
                continue
            x = [c["lifetime"] for c in sub]
            _ci(axes[0], x, sub, "exposure_span_mean_s", color=color, linestyle=ls, label=f"{st}, plausibility {'on' if pl else 'off'}")
            _ci(axes[1], x, sub, "v2v_receiver_rate", color=color, linestyle=ls, label=f"{st}, plausibility {'on' if pl else 'off'}")
            _ci(axes[2], x, sub, "reports_naming_honest", color=color, linestyle=ls, label=f"{st}, plausibility {'on' if pl else 'off'}")
    for ax, t, yl in zip(axes, ("Contiguous exposure window", "Forged messages accepted by V2V receivers", "Reports naming honest vehicles (all routes)"),
                         ("seconds (mean, 95 % CI)", "receiver acceptance rate", "misbehaviour reports per run")):
        ax.set_xscale("log")
        ax.set_xlabel("Certificate lifetime (s)")
        ax.set_ylabel(yl)
        ax.set_title(t, fontsize=10)
    axes[0].legend(fontsize=7)
    fig.suptitle("E1 - former-holder impersonation under recycling (ledger attribution)")
    return _save(fig, path)


def fig_e1x(res: dict, path: Path) -> Path:
    cells = res["cells"]
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.2))
    for st, color in zip(("S1", "S2", "S3"), (C_REF, C_POET, C_POW1)):
        sub = sorted([c for c in cells if c["strategy"] == st], key=lambda c: c["lifetime"])
        if not sub:
            continue
        x = [c["lifetime"] for c in sub]
        _ci(axes[0], x, sub, "exposure_span_mean_s", color=color, label=st)
        _ci(axes[1], x, sub, "v2v_receiver_rate", color=color, label=st)
        _ci(axes[2], x, sub, "pki_renewals", color=color, label=st)
    for ax, t in zip(axes, ("Contiguous exposure window (s)", "Forged messages accepted by V2V receivers",
                            "PKI certificate renewals per run")):
        ax.set_xscale("log")
        ax.set_xlabel("Certificate lifetime (s)")
        ax.set_title(t, fontsize=10)
    axes[0].legend(fontsize=8)
    fig.suptitle(f"E1x - impersonation over a {res['rounds'] * 30} s horizon (certificates expire and are renewed)")
    return _save(fig, path)


def fig_e2(res: dict, path: Path) -> Path:
    modes = list(dict.fromkeys(c.get("mode", "recycle") for c in res["cells"]))
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for mode in modes:
        cells = sorted((c for c in res["cells"] if c.get("mode", "recycle") == mode), key=lambda c: c["lifetime"])
        x = [c["lifetime"] for c in cells]
        col = MODE_COLORS.get(mode, C_REF)
        _ci(axes[0], x, cells, "post_revocation_accepted", color=col, label=mode)
        _ci(axes[1], x, cells, "seconds_to_last_accepted", color=col, label=mode)
    for ax, lab in zip(axes, ("V2V-accepted messages after revocation", "seconds until the last accepted message")):
        ax.set_xscale("log")
        ax.set_xlabel("Certificate lifetime (s)")
        ax.set_ylabel(lab)
        ax.legend(fontsize=8)
    fig.suptitle("E2 - a revoked vehicle keeps being believed by other vehicles, in every issuance mode")
    return _save(fig, path)


def fig_e3(res: dict, path: Path) -> Path:
    cells = res["cells"]
    fig, axes = plt.subplots(1, len(cells), figsize=(4.5 * len(cells), 4.4), sharey=True)
    if len(cells) == 1:
        axes = [axes]
    for ax, c in zip(axes, cells):
        ents = ["tracker", "rsu", "pm", "cloud", "pki"]
        alone = [_v(c["table"][e]["link_rate"]) for e in ents]
        with_tr = [_v(c["table"]["tracker"]["link_rate"])] + [_v(c["table"][f"tracker+{e}"]["link_rate"]) for e in ents[1:]]
        ident = [_v(c["table"][e]["identity_rate"]) for e in ents]
        x = range(len(ents))
        ax.bar([i - 0.27 for i in x], alone, width=0.27, color=C_POW, label="alone: link rate")
        ax.bar([i for i in x], with_tr, width=0.27, color=C_V2, label="with tracker: link rate")
        ax.bar([i + 0.27 for i in x], ident, width=0.27, color=C_REF, label="alone: identity rate")
        ax.set_xticks(list(x))
        ax.set_xticklabels(ents)
        ax.set_ylim(0, 1.02)
        ax.set_title(f"{c['density']} veh/km, cloud upload order {c['cloud_order']}", fontsize=10)
    axes[0].legend(fontsize=7)
    fig.suptitle("E3 - what each insider can link (recycle mode)")
    _save(fig, path)
    # identity attribution split (review R15, G07): shares of observed beacon-seconds
    kept = [c for c in cells if c["cloud_order"] == "kept"]
    combos = ["rsu", "pm", "tracker+rsu", "tracker+pm", "all"]
    fig, axes = plt.subplots(1, len(kept), figsize=(6 * len(kept), 4.4), sharey=True)
    if len(kept) == 1:
        axes = [axes]
    for ax, c in zip(axes, kept):
        bottom = [0.0] * len(combos)
        for key, col, lab in (("correct_identity_beacon_share", C_V2, "right identity"),
                              ("wrong_identity_beacon_share", C_REF, "wrong identity"),
                              ("ambiguous_identity_beacon_share", C_POET, "ambiguous (several identities)")):
            ys = [_v(c["table"][e][key]) if e in c["table"] else 0.0 for e in combos]
            ax.bar(range(len(combos)), ys, bottom=bottom, color=col, label=lab)
            bottom = [b + y for b, y in zip(bottom, ys)]
        ax.set_xticks(range(len(combos)), combos, rotation=20)
        ax.set_ylim(0, 1.02)
        ax.set_ylabel("share of observed beacon-seconds")
        ax.set_title(f"{c['density']} veh/km", fontsize=10)
    axes[0].legend(fontsize=8)
    fig.suptitle("E3 - identity attribution of observed beacon-seconds, by entity (recycle, upload order kept)")
    return _save(fig, path.with_name(path.stem + "_attribution" + path.suffix))


def fig_e4(res: dict, path: Path) -> Path:
    cells = res["cells"]
    dens = sorted({c["density"] for c in cells})
    modes = [m for m in MODE_COLORS if any(c["mode"] == m for c in cells)]
    metrics = [("tracker_link_rate", "Tracker link rate, attack-free (matched traffic)"),
               ("forged_accepted_v2v", "Forged messages accepted (V2V); gap = no attempts"),
               ("insider_pm_link_rate", "PM insider link rate"), ("pki_cpu_s_per_1000_veh_h", "PKI CPU-s per 1,000 veh per h"),
               ("pm_cpu_s_per_1000_veh_h", "PM CPU-s per 1,000 veh per h"), ("bytes_per_vehicle_per_round", "Bytes per vehicle per round")]
    fig, axes = plt.subplots(2, 3, figsize=(14, 8))
    for ax, (key, title) in zip(axes.flat, metrics):
        for i, m in enumerate(modes):
            src = res.get("privacy_attack_free") or cells if key == "tracker_link_rate" else cells
            sub = [next(c for c in src if c["mode"] == m and c["density"] == d) for d in dens]
            xs = [j + (i - len(modes) / 2) * 0.15 for j in range(len(dens))]
            ys = [_v(c[key]) for c in sub]
            err = [[_v(c[key]) - _v(c[key], "lo") for c in sub], [_v(c[key], "hi") - _v(c[key]) for c in sub]]
            ax.bar(xs, ys, width=0.15, yerr=err, capsize=2, color=MODE_COLORS[m], label=m)
        ax.set_xticks(range(len(dens)))
        ax.set_xticklabels([f"{d} veh/km" for d in dens])
        ax.set_title(title, fontsize=10)
    axes.flat[0].legend(fontsize=7)
    fig.suptitle(f"E4 - issuance modes against every axis (attacker strategy {res['strategy']}, 95 % CI over seeds)")
    return _save(fig, path)


def fig_e5(res: dict, path: Path) -> Path:
    cells = res["cells"]
    variants = [v for v in ("window", "rekey", "fresh_vgk") if any(c["variant"] == v for c in cells)]
    strategies = sorted({c["strategy"] for c in cells})
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for i, v in enumerate(variants):
        sub = [next(c for c in cells if c["variant"] == v and c["strategy"] == s) for s in strategies]
        xs = [j + (i - 1) * 0.25 for j in range(len(strategies))]
        axes[0].bar(xs, [_v(c["v2v_message_rate"]) for c in sub], width=0.25, color=MODE_COLORS[v], label=v)
        axes[1].bar(xs, [_v(c["pm_signatures"]) + _v(c["pki_signatures"]) for c in sub], width=0.25, color=MODE_COLORS[v], label=v)
    for ax, t in zip(axes, ("Forged messages accepted by V2V receivers (rate)", "Authority signatures per run (PKI + PM)")):
        ax.set_xticks(range(len(strategies)))
        ax.set_xticklabels(strategies)
        ax.set_title(t, fontsize=10)
    axes[0].legend(fontsize=8)
    fig.suptitle("E5 - the fix (rekey) against its ablation (window) and fresh vehicle-generated keys")
    return _save(fig, path)


def fig_summary(res: dict, path: Path) -> Path:
    """One figure for the README: the four outcome cases."""
    e4 = res["E4"]["cells"]
    d = min(c["density"] for c in e4)
    modes = [m for m in MODE_COLORS if any(c["mode"] == m for c in e4)]
    rows = [next(c for c in e4 if c["mode"] == m and c["density"] == d) for m in modes]
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    af = res["E4"].get("privacy_attack_free") or e4
    af_rows = [next(c for c in af if c["mode"] == m and c["density"] == d) for m in modes]
    axes[0].bar(modes, [_v(r.get("forged_accepted_v2v", r.get("forged_v2v_accepted"))) for r in rows],
                color=[MODE_COLORS[m] for m in modes])
    axes[0].set_title("Forged messages accepted (A2, V2V); gap = no attempts", fontsize=9)
    axes[1].bar(modes, [_v(r["tracker_link_rate"]) for r in af_rows], color=[MODE_COLORS[m] for m in modes])
    axes[1].set_ylim(0, 1)
    axes[1].set_title("Tracker link rate, attack-free (A1)", fontsize=9)
    axes[2].bar(modes, [_v(r["pki_cpu_s_per_1000_veh_h"]) for r in rows], color=[MODE_COLORS[m] for m in modes])
    axes[2].set_title("PKI CPU-seconds per 1,000 vehicles per hour")
    fig.suptitle(f"Is pseudonym recycling ever worth it?  ({d} veh/km, {rows[0]['seeds']} seeds)")
    return _save(fig, path)


def fig_e1r(res: dict, path: Path) -> Path:
    """E1r: honest vehicles revoked and the misbehaver's time to revocation, per revocation rule."""
    cells = res["cells"]
    labels = [c["rule"] for c in cells]
    x = list(range(len(cells)))
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.4))
    ax = axes[0]
    w = 0.2
    series = [(st, label) for st in ("S1", "S2") for label in ("short", "long") if f"{st}_{label}" in cells[0]]
    for i, (st, label) in enumerate(series):
        key = f"{st}_{label}"
        sub = [c[key] for c in cells]
        vals = [_v(c["honest_revoked_share"]) * 100 for c in sub]
        lo = [v - _v(c["honest_revoked_share"], "lo") * 100 for v, c in zip(vals, sub)]
        hi = [_v(c["honest_revoked_share"], "hi") * 100 - v for v, c in zip(vals, sub)]
        off = (i - (len(series) - 1) / 2) * w
        ax.bar([xx + off for xx in x], vals, w, yerr=[lo, hi], color=C_REF if st == "S1" else C_POW,
               hatch="" if label == "short" else "//", alpha=0.65 if label == "short" else 0.95,
               label=f"{st}, {sub[0]['sim_seconds']} s", capsize=2)
    ax.set_xticks(x, labels, rotation=30, ha="right")
    ax.set_ylim(0, 140)
    ax.set_ylabel("vehicles revoked (%)")
    ax.set_title("Wrongful revocations caused by former holders")
    ax.legend(loc="upper center", ncol=4, fontsize=7)
    ax = axes[1]
    for st, col in (("S1", C_REF), ("S2", C_POW)):
        key = f"{st}_long"
        if key in cells[0]:
            _ci(ax, x, [c[key] for c in cells], "reports_naming_honest", color=col, label=f"{st}, {cells[0][key]['sim_seconds']} s")
    ax.set_xticks(x, labels, rotation=30, ha="right")
    ax.set_ylabel("reports naming honest vehicles (all routes)")
    ax.set_title("Wrongful reports filed")
    ax.legend(fontsize=8)
    ax = axes[2]
    _ci(ax, x, [c["misbehaver"] for c in cells], "seconds_to_revocation", color=C_V2, label="seconds until revoked")
    ax.set_xticks(x, labels, rotation=30, ha="right")
    ax.set_ylabel(f"seconds ({cells[0]['misbehaver']['sim_seconds']} s horizon)")
    ax.set_title("Genuine misbehaver (oracle attribution)")
    ax.set_ylim(0, 1.5 * max(_v(c["misbehaver"]["seconds_to_revocation"], "hi") for c in cells))
    ax2 = ax.twinx()
    ax2.plot(x, [_v(c["misbehaver"]["revoked_within_horizon"]) * 100 for c in cells], "k--", marker="s",
             label="revoked within horizon (%)")
    ax2.set_ylim(0, 130)
    ax2.set_ylabel("revoked within horizon (%)")
    ax.legend(loc="upper left", fontsize=8)
    ax2.legend(loc="lower right", fontsize=8)
    fig.suptitle("E1r: the revocation rule (k clone reports from m distinct RSUs)")
    fig.tight_layout()
    return _save(fig, path)


def fig_sumo(res: dict, path: Path) -> Path:
    """E1 and E4 on a SUMO trace: receivers fooled per strategy; link rate, forgeries and PKI load per mode."""
    info = res["trace_info"]
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.4))
    ax = axes[0]
    e1 = res["E1"]
    x = list(range(len(e1)))
    ax.bar(x, [100 * _v(c["v2v_receiver_rate"]) for c in e1], 0.5, color=C_REF, label="V2V receivers accepting (%)")
    ax.bar([xx + 0.3 for xx in x], [100 * _v(c["rsu_rate"]) for c in e1], 0.3, color=C_POW, label="RSU accepting (%)")
    ax.set_xticks([xx + 0.15 for xx in x], [c["strategy"] for c in e1])
    ax.set_ylim(0, 140)
    ax.set_title("E1 on the trace: forgeries accepted")
    ax.legend(loc="upper left", fontsize=8)
    ax2 = ax.twinx()
    ax2.plot(x, [_v(c["honest_revoked"]) for c in e1], "k--", marker="s", label="honest vehicles revoked")
    ax2.set_ylim(0, max(1.0, 1.4 * max(_v(c["honest_revoked"]) for c in e1)))
    ax2.set_ylabel("honest vehicles revoked per run")
    ax2.legend(loc="upper right", fontsize=8)
    e4 = res["E4"]
    x = list(range(len(e4)))
    cols = [MODE_COLORS.get(c["mode"], C_REF) for c in e4]
    ax = axes[1]
    ax.bar(x, [_v(c["tracker_link_rate"]) for c in e4], 0.6, color=cols)
    for xx, c in zip(x, e4):
        ax.plot([xx, xx], [_v(c["tracker_link_rate"], "lo"), _v(c["tracker_link_rate"], "hi")], color="k")
    ax.set_xticks(x, [c["mode"] for c in e4], rotation=20)
    ax.set_ylim(0, 1.05)
    ax.set_title("E4 on the trace: outside tracker link rate")
    ax = axes[2]
    ax.bar(x, [_v(c.get("forged_accepted_v2v", c.get("forged_v2v_accepted"))) for c in e4], 0.6, color=cols, label="forged messages accepted (V2V)")
    ax.set_xticks(x, [c["mode"] for c in e4], rotation=20)
    ax.set_ylabel("forged messages accepted per run")
    ax.set_ylim(0, max(1.0, 1.5 * max(_v(c.get("forged_accepted_v2v", c.get("forged_v2v_accepted"))) for c in e4)))
    ax2 = ax.twinx()
    ax2.plot(x, [_v(c["pki_cpu_s_per_1000_veh_h"]) for c in e4], "k--", marker="o", label="PKI CPU-s per 1,000 veh-h")
    ax2.set_ylim(0, max(1.0, 1.5 * max(_v(c["pki_cpu_s_per_1000_veh_h"]) for c in e4)))
    ax2.set_ylabel("PKI CPU-s per 1,000 vehicle-hours")
    ax.legend(loc="upper left", fontsize=8)
    ax2.legend(loc="upper right", fontsize=8)
    ax.set_title("E4 on the trace: forgeries and PKI load")
    fig.suptitle(f"{res['experiment']}: {info['window_vehicles_seen']} vehicles, {info['window_density_per_km']:.1f} veh/km, "
                 f"{info['corridor_m'] / 1000:.1f} km, {res['rounds'] * 30} s")
    fig.tight_layout()
    return _save(fig, path)


def fig_e3b(res: dict, path: Path) -> Path:
    """E3b: key share per mode and entity; receivers accepting the insider's forgeries per strategy."""
    cells = res["cells"]
    modes = list(dict.fromkeys(c["mode"] for c in cells))
    ents = list(dict.fromkeys(c["entity"] for c in cells))
    strats = list(dict.fromkeys(c["strategy"] for c in cells))
    ent_cols = {"pki": C_POW, "pm": C_REF, "rsu": C_POW1, "cloud": C_POET}
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.4))
    w = 0.8 / len(ents)
    ax = axes[0]
    x = list(range(len(modes)))
    for i, ent in enumerate(ents):
        vals = [next(c for c in cells if c["mode"] == m and c["entity"] == ent and c["strategy"] == strats[0])["key_share"] for m in modes]
        ax.bar([xx + (i - (len(ents) - 1) / 2) * w for xx in x], [_v(v) for v in vals], w,
               yerr=[[_v(v) - _v(v, "lo") for v in vals], [_v(v, "hi") - _v(v) for v in vals]],
               color=ent_cols.get(ent, C_REF), label=ent.upper() if ent == "pki" else ent, capsize=2)
    ax.set_xticks(x, modes)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("share of pseudonyms in use")
    ax.set_title("Keys in use the insider holds", fontsize=10)
    ax.legend(fontsize=8, ncol=4, loc="upper center")
    ax = axes[1]
    x = list(range(len(strats)))
    for i, ent in enumerate(ents):
        vals = [next(c for c in cells if c["mode"] == "recycle" and c["entity"] == ent and c["strategy"] == st)["receiver_rate"] for st in strats]
        ax.bar([xx + (i - (len(ents) - 1) / 2) * w for xx in x], [_v(v) for v in vals], w,
               yerr=[[_v(v) - _v(v, "lo") for v in vals], [_v(v, "hi") - _v(v) for v in vals]],
               color=ent_cols.get(ent, C_REF), label=ent.upper() if ent == "pki" else ent, capsize=2)
    ax.set_xticks(x, [{"offset": "40 m from holder", "near": "10 m from holder", "silent": "holder's silent period"}.get(st, st) for st in strats])
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("share of receivers in range that accept")
    ax.set_title(f"Recycle mode: receivers accepting the insider's forgery ({res['forgeries_per_round']} per round)", fontsize=10)
    ax.legend(fontsize=8, ncol=4, loc="upper center")
    fig.suptitle("E3b: insiders holding vehicle signing keys")
    fig.tight_layout()
    return _save(fig, path)
