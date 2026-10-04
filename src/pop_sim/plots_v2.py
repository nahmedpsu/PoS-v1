"""Figures for the PoP v2 experiments."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .plots import C_POET, C_POP, C_POW, C_POW1, C_REF, _save  # noqa: E402

C_V2 = "#2A7F62"
C_PBFT = "#8C564B"
C_RAFT = "#E377C2"
ALG_COLORS = {"pow2": C_POW, "poet": C_POET, "pop_v1": C_POP, "pop_v2": C_V2, "pbft": C_PBFT, "raft": C_RAFT}
ALG_NAMES = {"pow2": "PoW 2", "poet": "PoET", "pop_v1": "PoP v1 (server)", "pop_v2": "PoP v2 (VRF)",
             "pbft": "PBFT", "raft": "Raft"}


def fig_v2_election_cost(res: dict, path: Path) -> Path:
    rows = res["rows"]
    x = [r["nodes"] for r in rows]
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    ax.plot(x, [r["poet_total"] * 1e3 for r in rows], marker="o", color=C_POET, label="PoET, all nodes")
    ax.plot(x, [r["pop_v1_total"] * 1e3 for r in rows], marker="^", color=C_POP, label="PoP v1, server total")
    for sc, style in (("ecvrf", "-"), ("rsa-fdh", "--")):
        key = f"pop_v2_per_node_{sc}"
        if key in rows[0]:
            ax.plot(x, [r[key] * 1e3 for r in rows], marker="s", linestyle=style, color=C_V2,
                    label=f"PoP v2 ({sc}), one node: prove + verify winner")
    if "pop_v2_per_node_ecvrf" not in rows[0] and "pop_v2_per_node_rsa-fdh" not in rows[0]:
        ax.plot(x, [r["pop_v2_per_node"] * 1e3 for r in rows], marker="s", color=C_V2, label="PoP v2, one node (prove + verify winner)")
    ax.plot(x, [r["pop_v2_race"] * 1e3 for r in rows], marker="v", linestyle="--", color=C_V2, label="PoP v2, race over received values")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Nodes")
    ax.set_ylabel("Time per block (ms, log)")
    ax.set_title("Election cost vs network size")
    ax.legend(fontsize=8)
    return _save(fig, path)


def fig_v2_forks(res: dict, path: Path) -> Path:
    rows = res["rows"]
    lats = sorted({r["mean_latency"] for r in rows})
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    for lat in lats:
        sub = sorted([r for r in rows if r["mean_latency"] == lat], key=lambda r: r["time_limit"])
        ax.plot([r["time_limit"] for r in sub], [r["fork_probability"] for r in sub], marker="o",
                label=f"latency {lat*1e3:.0f} ms")
    ax.axvspan(0.01, 0.25, color="#DDDDDD", alpha=0.5, label="manuscript's timer range")
    ax.set_xscale("log")
    ax.set_xlabel("Time limit of the random short time (s)")
    ax.set_ylabel("Fork probability per block")
    ax.set_title(f"Timer-based election under propagation delay ({res['nodes']} nodes)")
    ax.legend(fontsize=8)
    return _save(fig, path)


def fig_v2_latency(res: dict, path: Path) -> Path:
    rows = res["rows"]
    x = [r["nodes"] for r in rows]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for alg, color in ALG_COLORS.items():
        axes[0].plot(x, [r[alg] * 1e3 for r in rows], marker="o", color=color, label=ALG_NAMES[alg])
        axes[1].plot(x, [r["messages"][alg] for r in rows], marker="o", color=color, label=ALG_NAMES[alg])
    axes[0].set_xscale("log")
    axes[0].set_yscale("log")
    axes[0].set_xlabel("Nodes")
    axes[0].set_ylabel("Block latency (ms, log)")
    axes[0].set_title(f"Block latency, {res['mean_latency']*1e3:.0f} ms links, {res['loss']*100:.0f} % loss")
    axes[0].legend(fontsize=7)
    axes[1].set_xscale("log")
    axes[1].set_yscale("log")
    axes[1].set_xlabel("Nodes")
    axes[1].set_ylabel("Messages per block (log)")
    axes[1].set_title("Message complexity")
    return _save(fig, path)


def fig_v2_linkability(res: dict, path: Path) -> Path:
    rows = res["rows"]
    silents = sorted({r["silent_period"] for r in rows})
    trackers = res.get("trackers", ["nn"])
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), sharey=True)
    for ax, sync in zip(axes, (True, False)):
        for i, s in enumerate(silents):
            for tracker in trackers:
                sub = sorted([r for r in rows if r["synchronized"] == sync and r["silent_period"] == s
                              and r.get("tracker", "nn") == tracker], key=lambda r: r["density_per_km"])
                if not sub:
                    continue
                ax.plot([r["density_per_km"] for r in sub], [r["linking_success"] for r in sub],
                        marker="o" if tracker == trackers[0] else "x",
                        linestyle="-" if tracker == trackers[0] else ":", color=f"C{i}",
                        label=f"silent {s:.0f} s, {tracker} tracker")
        ax.set_xscale("log")
        ax.set_xlabel("Traffic density (vehicles / km / direction)")
        ax.set_title("Synchronized changes (mix zone)" if sync else "Unsynchronized changes")
        ax.set_ylim(0, 1.02)
        ax.legend(fontsize=8)
    axes[0].set_ylabel("Pseudonym changes linked by the tracker")
    fig.suptitle(f"Kinematic tracking across pseudonym changes (change every {res['change_period']} s, "
                 f"GPS noise {res['position_noise_m']} m)")
    return _save(fig, path)


def fig_v2_demand(res: dict, path: Path) -> Path:
    rows = res["rows"]
    periods = sorted({r["round_seconds"] for r in rows})
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for p in periods:
        sub = sorted([r for r in rows if r["round_seconds"] == p], key=lambda r: r["safety_stock"])
        axes[0].plot([r["safety_stock"] for r in sub], [r["stockouts"] for r in sub], marker="o", label=f"shuffle every {p} s")
        axes[1].plot([r["safety_stock"] for r in sub], [r["stock_per_vehicle"] for r in sub], marker="o", label=f"shuffle every {p} s")
    axes[0].set_xlabel("RSU safety stock (fraction above forecast)")
    axes[0].set_ylabel(f"Vehicles short of pseudonyms ({res['rounds']} rounds)")
    axes[0].set_title("Stock-outs")
    axes[1].set_xlabel("RSU safety stock (fraction above forecast)")
    axes[1].set_ylabel("Pseudonyms issued per vehicle")
    axes[1].set_title("Pseudonym stock the domain needs")
    axes[0].legend(fontsize=8)
    fig.suptitle(f"Demand-aware distribution, {res['density_per_km']} vehicles/km")
    return _save(fig, path)


def fig_v2_anchoring(res: dict, path: Path) -> Path:
    rows = res["rows"]
    x = [r["rsu_blocks"] for r in rows]
    fig, ax1 = plt.subplots(figsize=(7.5, 4.2))
    ax1.plot(x, [r["proof_bytes"] for r in rows], marker="o", color=C_POW1, label="proof size (bytes)")
    ax1.set_xscale("log")
    ax1.set_xlabel("RSU blocks covered by one anchor")
    ax1.set_ylabel("Allotment proof size (bytes)", color=C_POW1)
    ax2 = ax1.twinx()
    ax2.plot(x, [r["verify_seconds"] * 1e6 for r in rows], marker="s", color=C_REF, label="verification (us)")
    ax2.set_ylabel("Verification time (us)", color=C_REF)
    ax1.set_title("Blockchain of blockchains: cost of a cross-PM allotment proof")
    return _save(fig, path)


def fig_v2_sybil(res: dict, path: Path) -> Path:
    series = res["series"]
    fig, axes = plt.subplots(1, len(series), figsize=(4.2 * len(series), 4.2), sharey=True)
    if len(series) == 1:
        axes = [axes]
    for ax, (n, rows) in zip(axes, series.items()):
        k = [r["k_sybil"] for r in rows]
        ax.plot(k, [r["v1_lying"] for r in rows], marker="o", color=C_REF, label="PoP v1, attacker reports min timer")
        ax.plot(k, [r["v1_honest"] for r in rows], marker="^", color=C_POP, label="PoP v1, honest timers")
        ax.plot(k, [r["v2_vrf"] for r in rows], marker="s", color=C_V2, label="PoP v2, VRF (k keys)")
        ax.plot(k, [r["v2_pki_bound"] for r in rows], marker="v", color=C_POW, label="PoP v2, PKI-bound (1 certificate)")
        ax.plot(k, [r["analytic"] for r in rows], linestyle=":", color="black", label="k / (n + k)")
        ax.set_title(f"{n} honest nodes")
        ax.set_xlabel("Sybil identities k")
        ax.set_ylim(0, 1.02)
    axes[0].set_ylabel("Attacker's share of published blocks")
    axes[0].legend(fontsize=7)
    fig.suptitle("Sybil resistance of the election")
    return _save(fig, path)


def fig_v2_protocol(res: dict, path: Path) -> Path:
    runs = res["runs"]
    kinds = list(runs)
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    colors = [C_V2 if k == "popv2" else C_POP for k in kinds]
    axes[0].bar(kinds, [runs[k]["mean_pm_consensus_cpu"] * 1e3 for k in kinds], color=colors)
    axes[0].set_title("PM-chain election per round (ms)")
    axes[1].bar(kinds, [runs[k]["tracking"]["linking_success"] for k in kinds], color=colors)
    axes[1].set_ylim(0, 1)
    axes[1].set_title("Tracker's linking success")
    axes[2].bar(kinds, [runs[k]["stockouts"] for k in kinds], color=colors)
    axes[2].set_title("Stock-outs")
    fig.suptitle(f"End-to-end PoP v2 protocol, {res['rounds']} rounds, {runs[kinds[0]]['vehicles']} vehicles")
    return _save(fig, path)


# ------------------------------------------------------------ attacks / use cases
def fig_attacks(res: dict, path: Path) -> Path:
    by = {r["name"]: r for r in res["results"]}
    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    g = by["seed grinding"]["metrics"]
    budgets = sorted({int(k.split("=")[1]) for k in g["share"]})
    for mode, color, label in (("block_hash", C_REF, "seed = block hash (grindable)"), ("chained_vrf", C_V2, "seed = previous VRF output (v2)")):
        axes[0][0].plot(budgets, [g["share"][f"{mode}/budget={b}"] for b in budgets], marker="o", color=color, label=label)
    axes[0][0].axhline(g["fair_share"], linestyle=":", color="black", label="fair share 1/(n+1)")
    axes[0][0].set_xscale("log", base=2)
    axes[0][0].set_xlabel("Grinding budget (block variants tried)")
    axes[0][0].set_ylabel("Attacker's share of blocks")
    axes[0][0].set_title("Seed grinding")
    axes[0][0].legend(fontsize=8)
    w = by["block withholding (selfish winner)"]["metrics"]["by_attacker_fraction"]
    fr = sorted(w, key=float)
    axes[0][1].bar(fr, [w[f]["mean_block_delay"] * 1e3 for f in fr], color=C_V2)
    axes[0][1].set_xlabel("Fraction of nodes withholding their blocks")
    axes[0][1].set_ylabel("Mean block delay (ms)")
    axes[0][1].set_title("Block withholding: liveness cost")
    d = by["election server denial of service"]["metrics"]["availability"]
    ps = sorted(d, key=float)
    x = range(len(ps))
    axes[1][0].bar([i - 0.2 for i in x], [d[p]["v1_blocks"] for p in ps], width=0.4, color=C_POP, label="PoP v1 (server)")
    axes[1][0].bar([i + 0.2 for i in x], [d[p]["v2_blocks"] for p in ps], width=0.4, color=C_V2, label="PoP v2 (serverless)")
    axes[1][0].set_xticks(list(x))
    axes[1][0].set_xticklabels([f"{float(p)*100:.0f} %" for p in ps])
    axes[1][0].set_xlabel("Server downtime")
    axes[1][0].set_ylabel("Blocks produced (fraction of rounds)")
    axes[1][0].set_title("Election server denial of service")
    axes[1][0].legend(fontsize=8)
    f = by["fake-vehicle pseudonym flood"]["metrics"]
    cats = ["honest vehicles short", "fake vehicles served"]
    axes[1][1].bar([0 - 0.2, 1 - 0.2], [f["without_cert_check"]["honest_vehicles_short"], f["without_cert_check"]["fake_vehicles_served"]], width=0.4, color=C_REF, label="no certificate check")
    axes[1][1].bar([0 + 0.2, 1 + 0.2], [f["with_cert_check"]["honest_vehicles_short"], f["with_cert_check"]["fake_vehicles_served"]], width=0.4, color=C_V2, label="v2: certificate check")
    axes[1][1].set_xticks([0, 1])
    axes[1][1].set_xticklabels(cats)
    axes[1][1].set_title("Fake-vehicle pseudonym flood")
    axes[1][1].legend(fontsize=8)
    n_def = res["summary"].get("defended", 0)
    n_mit = res["summary"].get("mitigated", 0)
    n_vul = res["summary"].get("vulnerable", 0)
    fig.suptitle(f"Attack bench against PoP v2: {n_def} defended, {n_mit} mitigated, {n_vul} vulnerable")
    return _save(fig, path)


def fig_usecases(res: dict, path: Path) -> Path:
    rows = res["results"]
    names = [r["scenario"].replace("_", "\n") for r in rows]
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.4))
    link = [r["metrics"].get("linking_success") or 0 for r in rows]
    colors = [C_V2 if v < 0.35 else (C_POET if v < 0.7 else C_REF) for v in link]
    axes[0].bar(names, link, color=colors)
    axes[0].set_ylim(0, 1)
    axes[0].set_title("Tracker linking success")
    axes[0].tick_params(axis="x", labelsize=7)
    axes[1].bar(names, [r["metrics"].get("vehicles", 0) for r in rows], color=C_POW)
    axes[1].set_title("Vehicles simulated")
    axes[1].tick_params(axis="x", labelsize=7)
    axes[2].bar(names, [r["metrics"].get("wall_seconds_per_round", 0) for r in rows], color=C_POW1)
    axes[2].set_title("Wall time per shuffle round (s, one core)")
    axes[2].tick_params(axis="x", labelsize=7)
    fig.suptitle("PoP v2 deployment scenarios")
    return _save(fig, path)
