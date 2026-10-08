"""Figures of the pseudonym recycling study (one per experiment)."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .plots import C_POET, C_POW, C_POW1, C_REF, _save  # noqa: E402

C_V2 = "#2A7F62"
MODE_COLORS = {"recycle": C_REF, "fresh": C_POW, "fresh_vgk": C_POW1, "rekey": C_V2, "window": C_POET}


def _ci(ax, x, cells, key, **kw):
    y = [c[key]["mean"] for c in cells]
    lo = [c[key]["mean"] - c[key]["lo"] for c in cells]
    hi = [c[key]["hi"] - c[key]["mean"] for c in cells]
    ax.errorbar(x, y, yerr=[lo, hi], capsize=3, marker="o", **kw)


def fig_e1(res: dict, path: Path) -> Path:
    cells = [c for c in res["cells"] if c["sweep"] == "core"]
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.2))
    for st, color in zip(("S1", "S2", "S3"), (C_REF, C_POET, C_POW1)):
        for pl, ls in ((False, "-"), (True, "--")):
            sub = sorted([c for c in cells if c["strategy"] == st and c["plausibility"] == pl], key=lambda c: c["lifetime"])
            if not sub:
                continue
            x = [c["lifetime"] for c in sub]
            _ci(axes[0], x, sub, "exposure_mean_s", color=color, linestyle=ls, label=f"{st}, plausibility {'on' if pl else 'off'}")
            _ci(axes[1], x, sub, "v2v_receiver_rate", color=color, linestyle=ls, label=f"{st}, plausibility {'on' if pl else 'off'}")
            _ci(axes[2], x, sub, "victims_blamed", color=color, linestyle=ls, label=f"{st}, plausibility {'on' if pl else 'off'}")
    for ax, t, yl in zip(axes, ("Exposure window per recycled pseudonym", "Forged messages accepted by V2V receivers", "Innocent holders blamed by RSUs"),
                         ("seconds (mean, 95 % CI)", "receiver acceptance rate", "misbehaviour reports naming the victim")):
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
        _ci(axes[0], x, sub, "exposure_mean_s", color=color, label=st)
        _ci(axes[1], x, sub, "v2v_receiver_rate", color=color, label=st)
        _ci(axes[2], x, sub, "pki_renewals", color=color, label=st)
    for ax, t in zip(axes, ("Exposure window per recycled pseudonym (s)", "Forged messages accepted by V2V receivers",
                            "PKI certificate renewals per run")):
        ax.set_xscale("log")
        ax.set_xlabel("Certificate lifetime (s)")
        ax.set_title(t, fontsize=10)
    axes[0].legend(fontsize=8)
    fig.suptitle(f"E1x - impersonation over a {res['rounds'] * 30} s horizon (certificates expire and are renewed)")
    return _save(fig, path)


def fig_e2(res: dict, path: Path) -> Path:
    cells = sorted(res["cells"], key=lambda c: c["lifetime"])
    fig, ax = plt.subplots(figsize=(7, 4.2))
    x = [c["lifetime"] for c in cells]
    _ci(ax, x, cells, "post_revocation_accepted", color=C_REF, label="V2V-accepted messages after revocation")
    ax2 = ax.twinx()
    _ci(ax2, x, cells, "seconds_to_last_accepted", color=C_POW, label="seconds until the last accepted message")
    ax.set_xscale("log")
    ax.set_xlabel("Certificate lifetime (s)")
    ax.set_ylabel("messages", color=C_REF)
    ax2.set_ylabel("seconds", color=C_POW)
    ax.set_title("E2 - a revoked vehicle keeps being believed by other vehicles")
    return _save(fig, path)


def fig_e3(res: dict, path: Path) -> Path:
    cells = res["cells"]
    fig, axes = plt.subplots(1, len(cells), figsize=(4.5 * len(cells), 4.4), sharey=True)
    if len(cells) == 1:
        axes = [axes]
    for ax, c in zip(axes, cells):
        ents = ["tracker", "rsu", "pm", "cloud", "pki"]
        alone = [c["table"][e]["link_rate"]["mean"] for e in ents]
        with_tr = [c["table"]["tracker"]["link_rate"]["mean"]] + [c["table"][f"tracker+{e}"]["link_rate"]["mean"] for e in ents[1:]]
        ident = [c["table"][e]["identity_rate"]["mean"] for e in ents]
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
    return _save(fig, path)


def fig_e4(res: dict, path: Path) -> Path:
    cells = res["cells"]
    dens = sorted({c["density"] for c in cells})
    modes = [m for m in MODE_COLORS if any(c["mode"] == m for c in cells)]
    metrics = [("tracker_link_rate", "Outside tracker link rate"), ("forged_v2v_accepted", "Forged messages accepted (V2V)"),
               ("insider_pm_link_rate", "PM insider link rate"), ("pki_cpu_s_per_1000_veh_h", "PKI CPU-s per 1,000 veh per h"),
               ("pm_cpu_s_per_1000_veh_h", "PM CPU-s per 1,000 veh per h"), ("bytes_per_vehicle_per_round", "Bytes per vehicle per round")]
    fig, axes = plt.subplots(2, 3, figsize=(14, 8))
    for ax, (key, title) in zip(axes.flat, metrics):
        for i, m in enumerate(modes):
            sub = [next(c for c in cells if c["mode"] == m and c["density"] == d) for d in dens]
            xs = [j + (i - len(modes) / 2) * 0.15 for j in range(len(dens))]
            ys = [c[key]["mean"] for c in sub]
            err = [[c[key]["mean"] - c[key]["lo"] for c in sub], [c[key]["hi"] - c[key]["mean"] for c in sub]]
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
        axes[0].bar(xs, [c["v2v_message_rate"]["mean"] for c in sub], width=0.25, color=MODE_COLORS[v], label=v)
        axes[1].bar(xs, [c["pm_signatures"]["mean"] + c["pki_signatures"]["mean"] for c in sub], width=0.25, color=MODE_COLORS[v], label=v)
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
    axes[0].bar(modes, [r["forged_v2v_accepted"]["mean"] for r in rows], color=[MODE_COLORS[m] for m in modes])
    axes[0].set_title("Forged messages accepted (A2, V2V)")
    axes[1].bar(modes, [r["tracker_link_rate"]["mean"] for r in rows], color=[MODE_COLORS[m] for m in modes])
    axes[1].set_ylim(0, 1)
    axes[1].set_title("Outside tracker link rate (A1)")
    axes[2].bar(modes, [r["pki_cpu_s_per_1000_veh_h"]["mean"] for r in rows], color=[MODE_COLORS[m] for m in modes])
    axes[2].set_title("PKI CPU-seconds per 1,000 vehicles per hour")
    fig.suptitle(f"Is pseudonym recycling ever worth it?  ({d} veh/km, {rows[0]['seeds']} seeds)")
    return _save(fig, path)
