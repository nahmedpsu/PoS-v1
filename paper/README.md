# Figures printed in the manuscript

This folder draws every data figure printed in the manuscript "Retained keys in
pseudonym recycling: impersonation, wrongful revocation and the cost of fresh
issuance in a ledger-based vehicular protocol" from the archived result files of
this release. It reads `results/recycling/*.json` and nothing else.

From the repository root, with the locked environment installed
(`pip install -r requirements.lock`):

    python3 paper/make_figures.py . paper/figs

Outputs (PDF) and the manuscript figure each one is printed as:

| Manuscript | File | Result files and keys |
|---|---|---|
| Fig. 4 | `fig_e1.pdf` | `E1.json` cells with sweep=core, density=10, share=0.05, lifetime=900: `v2v_receiver_rate`, `rsu_rate`, `reports_forgery_naming_honest`, `reports_beacon_naming_honest`, `honest_named_by_forgery_reports`, `honest_named_by_beacon_reports`, `honest_reported`, `honest_revoked`, `population_honest` |
| Fig. 5 | `fig_e1x.pdf` | `E1x.json` cells by strategy and lifetime: `forged_sent`, `v2v_receiver_rate`, `honest_revoked`; `E2x.json` mode=recycle: `seconds_to_last_accepted` |
| Fig. 6 | `fig_e4.pdf` | `E4.json`, `SUMO_lust_motorway.json`, `SUMO_motorway.json`: `equivalence["…attack_free/tracker_link_rate: recycle vs <mode>"]` (`mean_diff`, `ci90`); cells by mode: `forged_sent`, `forged_accepted_v2v`, `per_seed[].load.steady_state`; `calibration.op_costs_s` |
| Graphical abstract | `fig_summary.pdf` | `E4.json` as Fig. 6, ring at 10 veh/km |

The script also draws `fig_e1r.pdf`, `fig_e1s.pdf`, `fig_e3b.pdf`, `fig_e3.pdf` and `fig_e5.pdf`, which are not printed in the manuscript; their data are tabulated in `docs/recycling_results.md`.

Figures 1 to 3 (architecture, attack strategies, simulator) are diagrams drawn in the manuscript source and use no data.

`figure_values.json`, written beside the figures, records every number shown
in a figure annotation with its interval, so that it can be checked against the
archive.

Whiskers are 95 % bootstrap intervals over seeds, except in Fig. 6 (a), which
draws the 90 % paired t intervals of the equivalence test. CPU time in Fig. 6 (c)
and in the graphical abstract is computed from the archived operation counts of
each run under one common set of coefficients, those measured for the ring E4
run (`E4.json` `calibration.op_costs_s`); each result file keeps its own
coefficients.
