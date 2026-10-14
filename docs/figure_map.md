# Figure-to-data map

Back to the [README](../README.md). Every figure is drawn only from the JSON
file next to it in the table, by the named function; the command regenerates
both. From 3.6.0 every recycling result file carries its own `provenance`
(commit, version, command line, whether the source differed from the commit
and a SHA-256 of that difference) and `calibration` (the measured cost
coefficients and the environment they were measured in); `run_info.json` only
describes the last run (review G09). One entry point runs everything:
`scripts/reproduce.sh`.

From 3.7.0 (review H06) provenance is captured when the command starts and says
so (`provenance_capture: "command start"`; 3.6.0 files without that field
recorded the commit when they were written). The source inventory covers `src`,
`config`, `scripts`, `pyproject.toml`, the `requirements*` pins and the
`Dockerfile`, untracked files included; when it differs from the commit, the
difference (tracked diff plus untracked files in full) is archived as
`results/provenance/<sha256>.json`, named by the `source_snapshot_sha256` the
result records. SUMO result files record the content hash of each trace they
read (`traces`, the same hash as `config/sumo/CONTENT_SHA256SUMS`).

Scientific values are deterministic for a given seed and source; wall-clock
timings, the cost calibration and the provenance metadata are not, and are
excluded from any comparison of outputs.

## v1 reproduction (`pop-sim run`)

| Figure | Data | Function |
|---|---|---|
| `figures/fig07_pow1_cpu_time.png` | `results/pow1.json` | `plots.fig7_pow1_time` |
| `figures/fig08_pow1_memory.png` | `results/pow1.json` | `plots.fig8_pow1_memory` |
| `figures/fig09_10_pow2_d3.png`, `_d4.png` | `results/pow2.json` | `plots.fig9_10_pow2` |
| `figures/fig11_poet_winners.png` | `results/poet.json` | `plots.fig11_poet` |
| `figures/fig12_pop_winners.png` | `results/pop.json` | `plots.fig12_pop` |
| `figures/fig13_comparison.png` | `results/comparison.json` | `plots.fig13_comparison` |
| `figures/fig14_block_time.png` | `results/block_time.json` | `plots.fig14_block_time` |
| `figures/fig_scalability.png` | `results/scalability.json` | `plots.fig_scalability` |
| `figures/fig_protocol.png` | `results/protocol.json` | `plots.fig_protocol` |

## PoP v2 (`pop-sim run-v2`, `attacks`, `usecases`)

| Figure | Data | Function |
|---|---|---|
| `figures/v2/v2_election_cost.png` | `results/v2/v2_election_cost.json` | `plots_v2.fig_v2_election_cost` |
| `figures/v2/v2_forks.png` | `results/v2/v2_forks.json` | `plots_v2.fig_v2_forks` |
| `figures/v2/v2_latency.png` | `results/v2/v2_latency.json` | `plots_v2.fig_v2_latency` |
| `figures/v2/v2_linkability.png` | `results/v2/v2_linkability.json` | `plots_v2.fig_v2_linkability` |
| `figures/v2/v2_demand.png` | `results/v2/v2_demand.json` | `plots_v2.fig_v2_demand` |
| `figures/v2/v2_anchoring.png` | `results/v2/v2_anchoring.json` | `plots_v2.fig_v2_anchoring` |
| `figures/v2/v2_sybil.png` | `results/v2/v2_sybil.json` | `plots_v2.fig_v2_sybil` |
| `figures/v2/v2_protocol.png` | `results/v2/v2_protocol.json` | `plots_v2.fig_v2_protocol` |
| `figures/v2/attacks.png` | `results/v2/attacks.json` | `plots_v2.fig_attacks` |
| `figures/v2/usecases.png` | `results/v2/usecases.json` (mean and 95 % CI over 10 seeds) | `plots_v2.fig_usecases` |

## Recycling study (`pop-sim recycling`, `recycling-sumo`)

| Figure | Data (key) | Function | Command |
|---|---|---|---|
| `figures/recycling/E1.png` | `results/recycling/E1.json` (`cells`; first panel: core cells, plausibility on, 900 s) | `plots_recycling.fig_e1` | `recycling --only E1` |
| `figures/recycling/E2.png` | `results/recycling/E2.json` | `plots_recycling.fig_e2` | `recycling --only E2` |
| `figures/recycling/E3.png` | `results/recycling/E3.json` | `plots_recycling.fig_e3` | `recycling --only E3` |
| `figures/recycling/E3_attribution.png` | `results/recycling/E3.json` (`*_identity_beacon_share`, upload order kept) | `plots_recycling.fig_e3` | `recycling --only E3` |
| `figures/recycling/E3b.png` | `results/recycling/E3b.json` | `plots_recycling.fig_e3b` | `recycling --only E3b` |
| `figures/recycling/E4.png` | `results/recycling/E4.json` (`privacy_attack_free` for the link rate, `cells` for the rest) | `plots_recycling.fig_e4` | `recycling --only E4` |
| `figures/recycling/E5.png` | `results/recycling/E5.json` | `plots_recycling.fig_e5` | `recycling --only E5` |
| `figures/recycling/E1x.png`, `E2x.png` | `results/recycling/E1x.json`, `E2x.json` | `fig_e1x`, `fig_e2` | `recycling --only-long --long` |
| `figures/recycling/E1r.png` | `results/recycling/E1r.json` | `plots_recycling.fig_e1r` | `recycling --only-long --sensitivity` |
| `figures/recycling/summary.png` | `E4.json` (`privacy_attack_free`, `cells`) | `plots_recycling.fig_summary` | any `recycling` run |
| `figures/recycling/SUMO_<name>.png` | `results/recycling/SUMO_<name>.json` | `plots_recycling.fig_sumo` | `recycling-sumo --name <name>` |
| (tables only) | `results/recycling/SUMO_returns_motorway.json`, `SUMO_realizations_motorway.json` | none | `recycling-sumo --returns`, several `--trace` |
| (tables only) | `results/recycling/E1s.json`, `E1q.json`, `E3bi.json` (3.7.0) | none | `recycling --only E1s`, `--only E1q`, `--only E3bi` |

Rates drawn as gaps are cells with no attempts (not applicable), never zeros.
Per-seed numerators and denominators sit under `per_seed` in every recycling
result cell.

## Repository figures and manuscript figures

The figures above are the repository's own; the manuscript's figures are laid
out separately and the manuscript source is not part of this repository. The
repository now draws the two layouts the follow-up review compared directly:
the strategy bars of honest vehicles reported and revoked (first panel of
`E1.png`) and the identity-attribution split (`E3_attribution.png`). Any other
manuscript figure must be drawn from the result fields named in the
manuscript's caption; a figure-number map belongs with the manuscript source.
