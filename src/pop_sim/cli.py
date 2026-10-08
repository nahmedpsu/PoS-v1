"""Command line interface: ``python -m pop_sim --help``."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__, plots, plots_recycling, plots_v2
from . import experiments as ex
from . import experiments_recycling as exr
from . import experiments_sumo as exs
from . import experiments_v2 as ex2
from .shuffle import CONSENSUS_KINDS, ITSConfig, ITSSimulation
from .v2 import attacks as atk
from .v2 import usecases as uc
from .v2.mobility import RoadConfig


def _dump(obj: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, default=str))


def cmd_run(args: argparse.Namespace) -> int:
    out = Path(args.out)
    figs = Path(args.figures)
    quick = args.quick
    t0 = time.perf_counter()
    log = lambda m: print(f"[{time.perf_counter() - t0:7.1f}s] {m}", flush=True)  # noqa: E731

    log("PoW 1 (Fig. 7/8)")
    pow1 = ex.exp_pow1(max_guesses=200_000 if quick else 25_000_000)
    _dump(pow1, out / "pow1.json")
    plots.fig7_pow1_time(pow1, figs / "fig07_pow1_cpu_time.png")
    plots.fig8_pow1_memory(pow1, figs / "fig08_pow1_memory.png")

    log("PoW 2 (Fig. 9/10)")
    pow2 = ex.exp_pow2(difficulties=(2, 3) if quick else (3, 4),
                       tx_counts=tuple(range(100, 1001, 300)) if quick else tuple(range(100, 1001, 100)))
    _dump(pow2, out / "pow2.json")
    plots.fig9_10_pow2(pow2, figs / "fig09_10_pow2")

    log("PoET (Fig. 11)")
    poet = ex.exp_poet()
    _dump(poet, out / "poet.json")
    plots.fig11_poet(poet, figs / "fig11_poet_winners.png")

    log("Proof of Pseudonym (Fig. 12)")
    pop = ex.exp_pop()
    _dump(pop, out / "pop.json")
    plots.fig12_pop(pop, figs / "fig12_pop_winners.png")

    log("Comparison (Fig. 13)")
    comp = ex.exp_comparison(pow2, pow1, pop, pow2_difficulty=3)
    _dump(comp, out / "comparison.json")
    plots.fig13_comparison(comp, figs / "fig13_comparison.png")

    log("Block time (Fig. 14)")
    bt = ex.exp_block_time(pow2, pow2_difficulty=2 if quick else 3)
    _dump(bt, out / "block_time.json")
    plots.fig14_block_time(bt, figs / "fig14_block_time.png")

    log("Scalability")
    sc = ex.exp_scalability(rounds=5 if quick else 20)
    _dump(sc, out / "scalability.json")
    plots.fig_scalability(sc, figs / "fig_scalability.png")

    log("End-to-end protocol")
    proto = ex.exp_protocol(rounds=3 if quick else 5, pow_difficulty=2 if quick else 3)
    _dump(proto, out / "protocol.json")
    plots.fig_protocol(proto, figs / "fig_protocol.png")

    log("Security scenarios")
    sec = ex.exp_security()
    _dump(sec, out / "security.json")

    _dump({"version": __version__, "quick": quick, "machine": ex.machine_info(),
           "wall_seconds": time.perf_counter() - t0}, out / "run_info.json")
    log("done")
    return 0


def cmd_run_v2(args: argparse.Namespace) -> int:
    out = Path(args.out)
    figs = Path(args.figures)
    quick = args.quick
    t0 = time.perf_counter()
    log = lambda m: print(f"[{time.perf_counter() - t0:7.1f}s] {m}", flush=True)  # noqa: E731

    log("1. verifiable election cost")
    r = ex2.exp_v2_election_cost(node_counts=(10, 50) if quick else (10, 20, 50, 100, 200), rounds=3 if quick else 10)
    _dump(r, out / "v2_election_cost.json")
    plots_v2.fig_v2_election_cost(r, figs / "v2_election_cost.png")

    log("5. forks under propagation delay")
    r = ex2.exp_v2_forks(rounds=60 if quick else 300)
    _dump(r, out / "v2_forks.json")
    plots_v2.fig_v2_forks(r, figs / "v2_forks.png")

    log("5/7. consensus latency incl. PBFT and Raft")
    r = ex2.exp_v2_latency(rounds=10 if quick else 50, pow2_difficulty=2 if quick else 3)
    _dump(r, out / "v2_latency.json")
    plots_v2.fig_v2_latency(r, figs / "v2_latency.png")

    log("2. measured linkability")
    r = ex2.exp_v2_linkability(densities=(2, 10, 40) if quick else (2, 5, 10, 20, 40, 80),
                               seconds=90 if quick else 300)
    _dump(r, out / "v2_linkability.json")
    plots_v2.fig_v2_linkability(r, figs / "v2_linkability.png")

    log("3. demand-aware distribution")
    r = ex2.exp_v2_demand(safety_stocks=(0.0, 0.25) if quick else (0.0, 0.1, 0.25, 0.5),
                          round_seconds=(20, 80) if quick else (20, 40, 80), rounds=3 if quick else 6)
    _dump(r, out / "v2_demand.json")
    plots_v2.fig_v2_demand(r, figs / "v2_demand.png")

    log("4. chain anchoring")
    r = ex2.exp_v2_anchoring(rsu_blocks=(10, 100) if quick else (10, 50, 100, 500, 1000))
    _dump(r, out / "v2_anchoring.json")
    plots_v2.fig_v2_anchoring(r, figs / "v2_anchoring.png")

    log("6. Sybil analysis")
    r = ex2.exp_v2_sybil(rounds=300 if quick else 2000)
    _dump(r, out / "v2_sybil.json")
    plots_v2.fig_v2_sybil(r, figs / "v2_sybil.png")

    log("end-to-end PoP v2 protocol")
    r = ex2.exp_v2_protocol(rounds=2 if quick else 5)
    _dump(r, out / "v2_protocol.json")
    plots_v2.fig_v2_protocol(r, figs / "v2_protocol.png")

    _dump({"version": __version__, "quick": quick, "machine": ex.machine_info(),
           "wall_seconds": time.perf_counter() - t0}, out / "v2_run_info.json")
    log("done")
    return 0


def cmd_attacks(args: argparse.Namespace) -> int:
    res = atk.run_all(quick=args.quick)
    _dump(res, Path(args.out) / "attacks.json")
    plots_v2.fig_attacks(res, Path(args.figures) / "attacks.png")
    for r in res["results"]:
        print(f"{r['outcome']:10s} {r['category']:10s} {r['name']}")
    print("summary:", res["summary"], f"({res['wall_seconds']:.1f} s)")
    return 0 if res["summary"].get("vulnerable", 0) == 0 else 1


def cmd_usecases(args: argparse.Namespace) -> int:
    res = uc.run_all(quick=args.quick)
    _dump(res, Path(args.out) / "usecases.json")
    plots_v2.fig_usecases(res, Path(args.figures) / "usecases.png")
    for r in res["results"]:
        print(f"{r['scenario']:22s} {r['verdict']}")
    print(f"({res['wall_seconds']:.1f} s)")
    return 0


def cmd_recycling(args: argparse.Namespace) -> int:
    """E1-E6 of the pseudonym recycling study."""
    out = Path(args.out)
    figs = Path(args.figures)
    seeds = [int(x) for x in args.seeds.split(",")] if args.seeds else None
    t0 = time.perf_counter()
    log = lambda m: print(f"[{time.perf_counter() - t0:7.1f}s] {m}", flush=True)  # noqa: E731
    quick = args.quick
    seeds = tuple(seeds) if seeds else ((1, 2) if quick else exr.DEFAULT_SEEDS)
    rounds = 2 if quick else 4
    res = {"config": {"seeds": list(seeds), "rounds": rounds, "quick": quick}}
    steps = [
        ("E1 impersonation", lambda: exr.exp_e1_impersonation(seeds, rounds, lifetimes=(300, 3600), extra_density_sweep=(2, 40), extra_share_sweep=(0.05,)) if quick else exr.exp_e1_impersonation(seeds, rounds), plots_recycling.fig_e1, "E1"),
        ("E2 revocation", lambda: exr.exp_e2_revocation(seeds, rounds, lifetimes=(300, 3600)) if quick else exr.exp_e2_revocation(seeds, rounds), plots_recycling.fig_e2, "E2"),
        ("E3 insider", lambda: exr.exp_e3_insider(seeds, rounds, densities=(10,)) if quick else exr.exp_e3_insider(seeds, rounds), plots_recycling.fig_e3, "E3"),
        ("E4 modes", lambda: exr.exp_e4_modes(seeds, rounds, densities=(10,)) if quick else exr.exp_e4_modes(seeds, rounds), plots_recycling.fig_e4, "E4"),
        ("E5 fix", lambda: exr.exp_e5_fix(seeds, rounds, strategies=("S2", "S3")) if quick else exr.exp_e5_fix(seeds, rounds), plots_recycling.fig_e5, "E5"),
    ]
    if args.only_long:
        if not (args.long or args.sensitivity):
            args.long = args.sensitivity = True
        for key in ("E1", "E2", "E3", "E4", "E5", "E6"):
            res[key] = json.loads((out / f"{key}.json").read_text())
        steps = []
    for name, fn, plot, key in steps:
        log(name)
        r = fn()
        res[key] = r
        _dump(r, out / f"{key}.json")
        plot(r, figs / f"{key}.png")
    if not args.only_long:
        log("E6 bench re-check (oracle vs ledger attribution)")
        res["E6"] = exr.exp_e6_bench_recheck(quick=quick)
        _dump(res["E6"], out / "E6.json")
    if args.long:
        log("E1x / E2x: 600 s horizon so certificates expire")
        res["E1x"] = exr.exp_e1_lifetime_long(seeds, rounds=4 if quick else 20, lifetimes=(300, 3600) if quick else (300, 900, 3600),
                                              strategies=("S3",) if quick else ("S1", "S2", "S3"))
        _dump(res["E1x"], out / "E1x.json")
        plots_recycling.fig_e1x(res["E1x"], figs / "E1x.png")
        res["E2x"] = exr.exp_e2_long(seeds, rounds=4 if quick else 20, lifetimes=(300, 3600) if quick else (300, 900, 3600))
        _dump(res["E2x"], out / "E2x.json")
        plots_recycling.fig_e2(res["E2x"], figs / "E2x.png")
    if args.sensitivity:
        log("E1r: the revocation rule (k reports from m RSUs)")
        res["E1r"] = exr.exp_e1_revocation_rule(seeds, rounds=rounds, long_rounds=4 if quick else 20,
                                                rules=((1, 1), (3, 2)) if quick else exr.REVOCATION_RULES)
        _dump(res["E1r"], out / "E1r.json")
        plots_recycling.fig_e1r(res["E1r"], figs / "E1r.png")
    plots_recycling.fig_summary(res, figs / "summary.png")
    res["wall_seconds"] = time.perf_counter() - t0
    _dump({k: v for k, v in res.items() if k in ("config", "wall_seconds")} | {"E6_changed": res["E6"]["changed"]},
          out / "run_info.json")
    log("done")
    return 0


def cmd_recycling_sumo(args: argparse.Namespace) -> int:
    """E1 and E4 on a SUMO trace."""
    seeds = tuple(int(x) for x in args.seeds.split(",")) if args.seeds else ((1, 2) if args.quick else exr.DEFAULT_SEEDS)
    res = exs.exp_sumo(args.trace, args.corridor, args.name, seeds=seeds, rounds=2 if args.quick else args.rounds,
                       strategies=("S2",) if args.quick else ("S1", "S2", "S3"),
                       modes=("recycle", "rekey") if args.quick else exs.ISSUANCE_MODES)
    _dump(res, Path(args.out) / f"SUMO_{args.name}.json")
    plots_recycling.fig_sumo(res, Path(args.figures) / f"SUMO_{args.name}.png")
    info = res["trace_info"]
    print(f"{res['experiment']}: {info['vehicles_total']} vehicles, {info['density_per_km']:.1f} veh/km on "
          f"{info['corridor_m'] / 1000:.1f} km, {res['wall_seconds']:.0f} s")
    for c in res["E1"]:
        print(f"  E1 {c['strategy']}: receivers accept {100 * c['v2v_receiver_rate']['mean']:.1f} %, "
              f"blamed {c['victims_blamed']['mean']:.0f}, honest revoked {c['honest_revoked']['mean']:.1f}")
    for c in res["E4"]:
        print(f"  E4 {c['mode']:9s}: link rate {c['tracker_link_rate']['mean']:.3f}, forged accepted "
              f"{c['forged_v2v_accepted']['mean']:.0f}, PKI {c['pki_cpu_s_per_1000_veh_h']['mean']:.1f} CPU-s/1000 veh-h")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """Run the protocol from a JSON configuration (any ITSConfig field)."""
    spec = json.loads(Path(args.config).read_text())
    spec = {k: v for k, v in spec.items() if not k.startswith("_")}
    rounds = spec.pop("rounds", 5)
    if "road" in spec and spec["road"] is not None:
        spec["road"] = RoadConfig(**spec["road"])
    cfg = ITSConfig(**spec)
    sim = ITSSimulation(cfg)
    t0 = time.perf_counter()
    sim.run(rounds)
    s = sim.summary()
    s["wall_seconds"] = time.perf_counter() - t0
    s["vehicles"] = len(sim.vehicles)
    text = json.dumps(s, indent=1, default=str)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    cfg = ITSConfig(n_pm=args.pms, rsus_per_pm=args.rsus, vehicles_per_rsu=args.vehicles,
                    pseudonyms_per_vehicle=args.pseudonyms, consensus=args.consensus,
                    malicious_vehicles=args.malicious, seed=args.seed, mobility=args.mobility,
                    silent_period=3.0 if args.mobility else 0.0, position_noise_m=3.0 if args.mobility else 0.0)
    sim = ITSSimulation(cfg)
    print(f"ITS domain: {len(sim.pms)} PMs, {len(sim.rsus)} RSUs, {len(sim.vehicles)} vehicles, "
          f"{len(sim.pki.issued_pids)} pseudonyms, consensus={cfg.consensus}")
    for _ in range(args.rounds):
        r = sim.run_round()
        print(f"round {r.round}: {r.messages} msgs ({r.rejected_messages} rejected), "
              f"{r.shuffled} pseudonyms shuffled, PM block by {r.pm_winner} "
              f"({r.pm_miners}/{len(sim.pms)} mining, {r.pm_consensus_cpu*1e3:.1f} ms), "
              f"{r.rsu_blocks} RSU blocks, {r.reassigned_to_previous_holder} returned to a previous holder")
    s = sim.summary()
    if s["tracking"]:
        print("tracker:", json.dumps(s["tracking"]))
        print("stockouts:", s["stockouts"], "anchoring:", json.dumps(s["anchoring"]))
    print("PM chain:", s["pm_chain_blocks"], "blocks, valid =", s["pm_chain_valid"])
    print("RSU chains:", s["rsu_chain_blocks"], "valid =", s["rsu_chains_valid"])
    print("linkability:", json.dumps(s["linkability"]))
    if s["revocations"]:
        print("revocations:", json.dumps(s["revocations"]))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pop_sim", description="Proof of Pseudonym simulation (PoS v1)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run all experiments and write results/ and figures/")
    r.add_argument("--quick", action="store_true", help="small budgets (seconds instead of minutes)")
    r.add_argument("--out", default="results")
    r.add_argument("--figures", default="figures")
    r.set_defaults(func=cmd_run)
    r2 = sub.add_parser("run-v2", help="run the PoP v2 experiments and write results/v2 and figures/v2")
    r2.add_argument("--quick", action="store_true")
    r2.add_argument("--out", default="results/v2")
    r2.add_argument("--figures", default="figures/v2")
    r2.set_defaults(func=cmd_run_v2)
    a = sub.add_parser("attacks", help="execute the attack bench against PoP v2 (exit 1 if anything is vulnerable)")
    a.add_argument("--quick", action="store_true")
    a.add_argument("--out", default="results/v2")
    a.add_argument("--figures", default="figures/v2")
    a.set_defaults(func=cmd_attacks)
    u = sub.add_parser("usecases", help="run the deployment scenarios")
    u.add_argument("--quick", action="store_true")
    u.add_argument("--out", default="results/v2")
    u.add_argument("--figures", default="figures/v2")
    u.set_defaults(func=cmd_usecases)
    rc = sub.add_parser("recycling", help="run the pseudonym recycling study (E1-E6)")
    rc.add_argument("--quick", action="store_true")
    rc.add_argument("--seeds", default=None, help="comma-separated seeds (default 1..10, or 1,2 with --quick)")
    rc.add_argument("--long", action="store_true", help="also run E1x/E2x over a 600 s horizon (certificates expire)")
    rc.add_argument("--sensitivity", action="store_true", help="also run E1r: the revocation rule (k reports from m RSUs)")
    rc.add_argument("--only-long", action="store_true",
                    help="skip E1-E6 (their results must already exist) and run only --long / --sensitivity (both if neither is set)")
    rc.add_argument("--out", default="results/recycling")
    rc.add_argument("--figures", default="figures/recycling")
    rc.set_defaults(func=cmd_recycling)
    rs = sub.add_parser("recycling-sumo", help="E1 and E4 of the recycling study on a SUMO FCD trace")
    rs.add_argument("--trace", required=True, help="SUMO --fcd-output file")
    rs.add_argument("--corridor", required=True, help="corridor JSON (see experiments_sumo.py)")
    rs.add_argument("--name", required=True, help="scenario name used in the output file names")
    rs.add_argument("--seeds", default=None, help="comma-separated seeds (default 1..10, or 1,2 with --quick)")
    rs.add_argument("--rounds", type=int, default=4)
    rs.add_argument("--quick", action="store_true")
    rs.add_argument("--out", default="results/recycling")
    rs.add_argument("--figures", default="figures/recycling")
    rs.set_defaults(func=cmd_recycling_sumo)
    b = sub.add_parser("bench", help="run the protocol from a JSON configuration file")
    b.add_argument("config")
    b.add_argument("--out", default=None, help="write the summary JSON here instead of stdout")
    b.set_defaults(func=cmd_bench)
    d = sub.add_parser("demo", help="trace a few shuffle rounds of the protocol")
    d.add_argument("--consensus", choices=CONSENSUS_KINDS, default="pop")
    d.add_argument("--pms", type=int, default=2)
    d.add_argument("--rsus", type=int, default=3)
    d.add_argument("--vehicles", type=int, default=5)
    d.add_argument("--pseudonyms", type=int, default=3)
    d.add_argument("--rounds", type=int, default=3)
    d.add_argument("--malicious", type=int, default=1)
    d.add_argument("--seed", type=int, default=1)
    d.add_argument("--mobility", action="store_true", help="vehicles drive on a ring road (PoP v2 mode)")
    d.set_defaults(func=cmd_demo)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
