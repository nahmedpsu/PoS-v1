#!/usr/bin/env bash
# Rebuild every SUMO trace the study uses and verify it (review R24).
# Requires Eclipse SUMO 1.28.0 (pip install -r requirements-sumo.lock) and git.
# Checksums cover the trace content after SUMO's header comment, which holds
# a timestamp and file paths and so differs on every run.
set -euo pipefail
OUT=${1:-traces}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SUMO_BIN=$(python -c "import sumo, os; print(os.path.join(os.path.dirname(sumo.__file__), 'bin'))")
mkdir -p "$OUT" && cd "$OUT"

# 1. netgenerate motorway: original trace (SUMO default seed) and five realizations
"$SUMO_BIN/netgenerate" --grid --grid.x-number=2 --grid.y-number=1 --grid.x-length=6000 \
    --default.lanenumber=3 --default.speed=36.1 --no-turnarounds -o motorway.net.xml
FLOWS="$ROOT/config/sumo/motorway.flows.rou.xml"
"$SUMO_BIN/sumo" -n motorway.net.xml -r "$FLOWS" --begin 0 --end 1500 --step-length 1 \
    --fcd-output motorway.fcd.xml --device.fcd.begin 600 --no-step-log --no-warnings
for sd in 1 2 3 4 5; do
  "$SUMO_BIN/sumo" -n motorway.net.xml -r "$FLOWS" --begin 0 --end 1500 --step-length 1 --seed "$sd" \
      --fcd-output "motorway_seed$sd.fcd.xml" --device.fcd.begin 600 --no-step-log --no-warnings
done

# 2. LuST (Luxembourg SUMO Traffic, MIT licence), pinned commit, morning peak on the motorway corridor
if [ ! -d LuSTScenario ]; then
  git clone --filter=blob:none --sparse https://github.com/lcodeca/LuSTScenario.git
  (cd LuSTScenario && git checkout 5edb7ecb9ad196c39172b6eb95d19ed789f4b1a6 && git sparse-checkout set scenario)
fi
(cd LuSTScenario/scenario && "$SUMO_BIN/sumo" -c dua.actuated.sumocfg --begin 28200 --end 29520 \
    --fcd-output "$PWD/../../lust_motorway.fcd.xml" --device.fcd.begin 28800 \
    --fcd-output.filter-edges.input-file "$ROOT/config/sumo/lust_fcd_edges.txt" \
    --summary-output /dev/null --tripinfo-output /dev/null --no-step-log --no-warnings)

# 3. verify
fail=0
while read -r sum name; do
  got=$(sed '1,/^-->/d' "$name" | sha256sum | cut -d' ' -f1)
  if [ "$got" = "$sum" ]; then echo "ok        $name"; else echo "MISMATCH  $name"; fail=1; fi
done < "$ROOT/config/sumo/CONTENT_SHA256SUMS"
exit $fail
