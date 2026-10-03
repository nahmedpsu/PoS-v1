"""Figures for the experiment results (matplotlib, headless)."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

C_POW = "#4C72B0"
C_POW1 = "#8172B2"
C_POET = "#DD8452"
C_POP = "#55A868"
C_REF = "#C44E52"


def _save(fig, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def fig7_pow1_time(res: dict, path: Path) -> Path:
    rows = res["rows"]
    fig, ax = plt.subplots(figsize=(7, 4))
    colors = [C_POW1 if not r["extrapolated"] else "#BBBBBB" for r in rows]
    ax.bar([r["puzzle"] for r in rows], [r["cpu_seconds"] for r in rows], color=colors)
    ax.set_yscale("log")
    ax.set_xlabel("Puzzle difficulty level")
    ax.set_ylabel("CPU time (s, log scale)")
    ax.set_title("Fig. 7 - Proof of Work 1: puzzle solving CPU time\n(grey = extrapolated beyond the guess budget)")
    return _save(fig, path)


def fig8_pow1_memory(res: dict, path: Path) -> Path:
    rows = res["rows"]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot([r["puzzle"] for r in rows], [r["peak_memory_kb"] for r in rows], marker="o", color=C_POW1)
    ax.set_xlabel("Puzzle difficulty level")
    ax.set_ylabel("Peak traced memory (KB)")
    ax.set_title("Fig. 8 - Proof of Work 1: memory per puzzle")
    return _save(fig, path)


def fig9_10_pow2(res: dict, path_prefix: Path) -> list[Path]:
    out = []
    for d, rows in res["series"].items():
        fig, ax = plt.subplots(figsize=(7, 4))
        x = [r["transactions"] for r in rows]
        ax.bar(x, [r["cpu_seconds"] for r in rows], width=60, color=C_POW)
        for r in rows:
            ax.annotate(f"{r['cpu_seconds']:.2f}", (r["transactions"], r["cpu_seconds"]), ha="center",
                        va="bottom", fontsize=7)
        ax.set_xlabel("Number of transactions")
        ax.set_ylabel("CPU time (s)")
        ax.set_title(f"Proof of Work 2 with difficulty level {d} (cf. Fig. 9 / 10)")
        out.append(_save(fig, Path(f"{path_prefix}_d{d}.png")))
    return out


def fig11_poet(res: dict, path: Path) -> Path:
    rows = res["rows"]
    fig, ax = plt.subplots(figsize=(7, 4))
    x = list(range(1, len(rows) + 1))
    ax.bar(x, [r["winner_time"] for r in rows], color=C_POET)
    ax.set_xticks(x)
    ax.set_xticklabels([r["winner"] for r in rows], rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("Random short time of the winner (s)")
    ax.set_title(f"Fig. 11 - Proof of Elapsed Time: winner nodes' time ({res['nodes']} nodes)")
    return _save(fig, path)


def fig12_pop(res: dict, path: Path) -> Path:
    rows = res["rows"]
    fig, ax = plt.subplots(figsize=(7, 4))
    x = list(range(1, len(rows) + 1))
    ax.bar(x, [r["winner_time"] for r in rows], color=C_POP)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{r['winner']}\n({r['miners']}/{res['nodes']} mine)" for r in rows], fontsize=7)
    ax.set_ylabel("Random short time of the winner (s)")
    ax.set_title(f"Fig. 12 - Proof of Pseudonym: winner nodes' time ({res['nodes']} nodes)")
    return _save(fig, path)


def fig13_comparison(res: dict, path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    groups = [("PoW 2 (d=%d)" % res["pow2_difficulty"], res["pow2"], C_POW),
              ("PoW 1", res["pow1"], C_POW1), ("Proof of Pseudonym", res["pop"], C_POP)]
    width = 0.08
    for gi, (name, vals, color) in enumerate(groups):
        for i, v in enumerate(vals):
            ax.bar(gi + (i - len(vals) / 2) * width, max(v, 1e-4), width=width, color=color,
                   label=name if i == 0 else None)
    ax.set_yscale("log")
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels([g[0] for g in groups])
    ax.set_ylabel("Time (s, log scale)")
    ax.set_title("Fig. 13 - PoW 1, PoW 2 and Proof of Pseudonym (10 runs each)")
    ax.legend()
    return _save(fig, path)


def fig14_block_time(res: dict, path: Path) -> Path:
    rows = res["rows"]
    x = [r["transactions"] for r in rows]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    axes[0].bar(x, [r["tB_pop"] for r in rows], width=60, color=C_POP)
    axes[0].set_title("Time cost of Proof of Pseudonym (tB)")
    axes[0].set_xlabel("Transactions")
    axes[0].set_ylabel("Time (s)")
    per_tx = [r for r in rows if "tB_pow2_per_tx" in r]
    if per_tx:
        axes[1].plot([r["transactions"] for r in per_tx], [r["tB_pow2_per_tx"] for r in per_tx], marker="o",
                     color=C_POW, label=f"PoW 2 d={res['pow2_difficulty']}, puzzle per transaction (this run)")
    axes[1].plot(x, [r["tB_pow2_per_block"] for r in rows], marker="o", linestyle="--", color=C_POW,
                 label=f"PoW 2 d={res['pow2_difficulty']}, one puzzle per block (this run)")
    axes[1].plot(x, [r["ref_bao2019"] for r in rows], marker="s", color=C_REF, label="PoW, Bao et al. [31]")
    axes[1].plot(x, [r["tB_pop"] for r in rows], marker="^", color=C_POP, label="Proof of Pseudonym")
    axes[1].set_title("Time cost of transactions: PoW vs PoP")
    axes[1].set_xlabel("Transactions")
    axes[1].set_ylabel("Time (s)")
    axes[1].legend(fontsize=8)
    fig.suptitle("Fig. 14 - Comparison of Proof of Pseudonym and the PoW-based scheme")
    return _save(fig, path)


def fig_scalability(res: dict, path: Path) -> Path:
    rows = res["rows"]
    fig, ax = plt.subplots(figsize=(7, 4))
    x = [r["nodes"] for r in rows]
    ax.plot(x, [r["poet_cpu_mean"] * 1e3 for r in rows], marker="o", color=C_POET, label="PoET (all nodes, O(n))")
    ax.plot(x, [r["pop_cpu_mean"] * 1e3 for r in rows], marker="^", color=C_POP, label="PoP total (selection + race + attestation)")
    ax.plot(x, [r["pop_race_mean"] * 1e3 for r in rows], marker="v", linestyle="--", color=C_POP, label="PoP race only (50 % of nodes, O(n/2))")
    ax.set_xscale("log")
    ax.set_xlabel("Nodes in the network")
    ax.set_ylabel("Election CPU time (ms)")
    ax.set_title("Election cost vs network size (Table 2)")
    ax.legend()
    return _save(fig, path)


def fig_protocol(res: dict, path: Path) -> Path:
    runs = res["runs"]
    kinds = list(runs)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    colors = {"pop": C_POP, "poet": C_POET, "pow2": C_POW, "pokw": C_POW1}
    axes[0].bar(kinds, [runs[k]["mean_pm_consensus_cpu"] for k in kinds], color=[colors[k] for k in kinds])
    axes[0].set_title("Mean PM-chain consensus time per shuffle round")
    axes[0].set_ylabel("Seconds")
    axes[1].bar(kinds, [runs[k]["mean_rsu_consensus_cpu"] for k in kinds], color=[colors[k] for k in kinds])
    axes[1].set_title("Mean RSU-chain consensus time per round (all PMs)")
    axes[1].set_ylabel("Seconds")
    fig.suptitle(f"Pseudonym shuffling protocol, {res['rounds']} rounds, per consensus")
    return _save(fig, path)
