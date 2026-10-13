#!/usr/bin/env bash
# One entry point for every result in the repository (review R24).
#   scripts/reproduce.sh            all experiments (several hours on one core)
#   scripts/reproduce.sh --quick    the CI smoke version (minutes)
# Each result file records the commit, version, command line, calibration of
# the cost coefficients and whether deterministic signing was in effect.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
Q=""; [ "${1:-}" = "--quick" ] && Q="--quick"
python -m pop_sim run $Q                       # v1 reproduction      -> results/, figures/
python -m pop_sim run-v2 $Q                    # PoP v2               -> results/v2/, figures/v2/
python -m pop_sim attacks $Q
python -m pop_sim usecases $Q
python -m pop_sim recycling $Q --long --sensitivity      # E1-E6, E1x/E2x, E1r -> results/recycling/
if [ -z "$Q" ]; then
  bash scripts/make_sumo_traces.sh traces
  python -m pop_sim recycling-sumo --trace traces/lust_motorway.fcd.xml --corridor config/sumo/lust_motorway.corridor.json --name lust_motorway
  python -m pop_sim recycling-sumo --trace traces/motorway.fcd.xml --corridor config/sumo/motorway.corridor.json --name motorway
  python -m pop_sim recycling-sumo --returns --trace traces/motorway.fcd.xml --corridor config/sumo/motorway.corridor.json --name motorway
  python -m pop_sim recycling-sumo --trace "$(ls traces/motorway_seed*.fcd.xml | paste -sd,)" \
      --corridor config/sumo/motorway.corridor.json --name motorway
fi
