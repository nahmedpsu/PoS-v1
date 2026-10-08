# Pseudonym recycling study: is recycling ever worth it?

`pop-sim recycling` runs six experiments (E1 to E6) that answer one question with
measured evidence: does recycling pseudonyms through the privacy-manager cloud, as
the Proof of Pseudonym manuscript proposes, beat issuing fresh ones on any axis
(privacy, security, authority load), and what does a safe version cost?  Results go
to `results/recycling/` and `figures/recycling/`; the numbers are in
[recycling_results.md](recycling_results.md).

## Threat model

| Adversary | Capability | Not allowed | Code |
|---|---|---|---|
| A1 outside tracker | Hears every beacon (pid, position, speed, heading, time) with GPS noise | No keys, no ledger | `v2/tracker_kalman.py` |
| A2 former holder | Keeps the private key of every pseudonym it held; transmits anywhere at any time | Cannot forge certificates | `v2/recycling_attacks.py` |
| A3 curious insider | Honest-but-curious RSU, PM or cloud: follows the protocol, keeps everything it sees | Does not deviate or forge | `v2/insider.py` |
| A4 collusion | A1 plus one A3 | Same as its parts | `v2/insider.py` (`tracker+pm` etc.) |

Starting facts, read from the code: a recycled `Pseudonym` travels with its
private key (`Pseudonym.to_wire` carries it); only RSUs check reuse, through
the ledger; the ledger maps every pseudonym to the holder's permanent identity;
and `RSU.receive_message` used to be told the true sender (oracle attribution).

## Metrics (`v2/metrics.py`)

* **forged_acceptance**: share of A2's forged messages accepted, by V2V receivers
  (per message and per receiver) and by RSUs.
* **exposure_window_s**: per recycled pseudonym, the seconds during which forgeries
  were accepted by at least one V2V receiver (mean, p95).
* **post_revocation_accepted**: V2V-accepted messages of a revoked vehicle after
  revocation, and seconds until the last one.
* **link_rate(entity)**: share of true pseudonym changes the entity links; the same
  definition as the tracker's `changes_linked_correctly / pseudonym_changes`.
* **precision**, **identity_rate**, **trajectory_coverage** of an identity clustering.
* **authority_load**: signatures, key generations and bytes at PKI, PMs, RSUs and
  vehicles, converted to CPU-seconds per 1,000 vehicles per hour.
* **stockouts** and **bytes_per_vehicle_per_round**.

Identity nodes are *holdings*: a recycled pid is a different node for every holder
(`pid#epoch`), so linking metrics never count a recycled pid as linking its holders.

## Mechanisms added (all behind config flags whose defaults reproduce v2.2.1)

| Flag | What it does |
|---|---|
| `attribution="ledger"` | The RSU attributes a message to the ledger's current holder of its pseudonym, as a real RSU must; a report names that holder. Unsigned or wrongly signed messages are dropped without a report. |
| `v2v=True` | Vehicle-to-vehicle receivers within `v2v_range_m` verify certificate and signature only (`v2/v2v.py`); `v2v_plausibility=True` adds the local two-places-at-once rule. Cryptographic checks are cached per message. |
| `former_holders=k`, `former_holder_strategy` | A2 adversaries: S1 remote shadow, S2 co-located ghost (claims a position `ghost_offset_m` from the victim while physically in range), S3 gap filler (between holders). |
| `issuance` | `recycle` (the manuscript), `fresh` (PKI issues new sets every round, used sets retired), `fresh_vgk` (vehicle-generated keys, PKI only signs), `rekey` (recycled pid, fresh vehicle key, PM-signed holder-bound certificate), `window` (ablation: holder certificate, key unchanged). |
| `pseudonym_lifetime` | Certificate lifetime; recycled certificates near expiry are renewed by PKI and counted as its work. |
| `revoked_keep_transmitting=True` | A revoked vehicle keeps beaconing under the pseudonyms it holds. |
| `shuffle_before_upload=True` | The one-line fix for the cloud-order leak. |

Receivers in `rekey` and `window` modes require a holder-bound certificate
(`pid, pk, [t_start, t_end]`, PM-signed, PM certified by PKI) whose window contains
the current time, and verify the message under the certificate's key.

## Experiments

| Exp | RQ | Factors | Output |
|---|---|---|---|
| E1 impersonation | RQ1 | strategy, plausibility, certificate lifetime, density, attacker share | forged acceptance, exposure window, victims blamed |
| E2 revocation | RQ2 | certificate lifetime | messages accepted after revocation, time to last |
| E3 insider | RQ3 | entity alone and with A1, density, cloud upload order | link rate, precision, identity rate, trajectory coverage |
| E4 modes | RQ4 | issuance mode, density | every axis, paired Wilcoxon tests against recycle |
| E5 fix | RQ4 | window vs rekey vs fresh_vgk, strategy | forgeries accepted, added cost |
| E6 bench re-check | all | the 18-attack bench under oracle vs ledger attribution | outcome changes |
| E1x / E2x (`--long`) | RQ1, RQ2 | 600 s horizon, certificate lifetime | as E1 and E2, with renewals |
| E1r (`--sensitivity`) | RQ1 | revocation rule (k reports from m RSUs), strategy, horizon | honest vehicles revoked, wrongful reports, misbehaver's time to revocation |
| SUMO (`recycling-sumo`) | RQ1, RQ4 | scenario (LuST motorway, netgenerate motorway) | E1 core cell and E4 on a real trace |

Every cell reports the mean with a 95 % bootstrap confidence interval over seeds
(10 by default, 2 with `--quick`). Modes share the same traffic for a given seed
(the GPS noise generator is separate from the protocol's), so E4 compares pairs.

## Pre-registered outcome cases (written before the full run)

The conclusion is decided from E4 and E5 by these cases, in this order:

1. **Recycling is dominated.** A1 linkability equal across modes, A2 forgeries
   non-zero only under recycle (and window), and fresh issuance costs the PKI less
   than one CPU-second per 1,000 vehicles per hour. Then recycling is not worth it
   and safe recycling (rekey) only moves signing from the PKI to the PMs.
2. **Recycling earns its place as a load shift.** PKI load under fresh issuance is
   material at city scale. Then rekey is the recommended design and the paper
   quantifies its added PM load.
3. **The framing result.** S2 forgeries are accepted and the RSU blames the victim
   under ledger attribution. Then accountability, the property the ledger was meant
   to provide, fails under recycling.
4. **The cloud ordering leak.** E3 shows the cloud clusters pids from upload order.
   Reported with its one-line fix as a secondary finding.

## Reproducing

```bash
PYTHONPATH=src python -m pop_sim recycling --quick       # about a minute, 2 seeds
PYTHONPATH=src python -m pop_sim recycling               # 10 seeds, tens of minutes
PYTHONPATH=src python -m pop_sim recycling --seeds 1,2,3,4,5
```

Each JSON file names its factors and seeds; every figure is drawn from the JSON
only.

`--long` (or `--only-long` when E1-E6 already exist) adds E1x and E2x: the
impersonation and revocation experiments over a 600 s horizon (20 rounds), long
enough for 300 s certificates to expire and be renewed inside a run. Renewal
re-certifies every pseudonym in circulation (relocated, in PM stock, in RSU stock)
whose certificate would expire before the next shuffle; it keeps the key, as the
manuscript's recycling does.

## SUMO traces: two real scenarios (version 3.2.0)

`v2/mobility_sumo.py` reads SUMO floating-car-data output (`sumo --fcd-output`)
and drives the simulation with it in place of the synthetic ring. The protocol's
road model is one-dimensional, so a trace is mapped onto a corridor: the lane
position along an ordered edge sequence (`"mode": "lane"`), or the projection of
(x, y) on an axis between two points (`"mode": "xy"`, a junction-free motorway
section). Every vehicle that ever enters the corridor is provisioned at build time
and is allotted pseudonyms at the first round after it appears; a straight corridor
never wraps distances around. `pop-sim recycling-sumo` runs E1 (core cell) and E4
(all modes, paired over seeds) on a trace; the trace fixes the traffic and the seeds
vary the keys, the choice of former holders and the GPS noise.

```bash
PYTHONPATH=src python -m pop_sim recycling-sumo --trace lust_motorway.fcd.xml \
    --corridor config/sumo/lust_motorway.corridor.json --name lust_motorway
```

Two scenarios are run and reported in [recycling_results.md](recycling_results.md):

* **LuST motorway** (Luxembourg SUMO Traffic scenario, Codeca et al., MIT licence):
  the longest connected chain of `highway.motorway` edges of `lust.net.xml`, one
  carriageway, 19.0 km, 33 edges with 3 to 4 lanes, at the morning peak (SUMO time
  28,800 to 29,519 s, 08:00 to 08:12, after a 600 s warm-up). The scenario files are
  not shipped (413 MB); `config/sumo/lust_motorway.corridor.json` names the edges,
  and the trace is reproduced with
  `sumo -c dua.actuated.sumocfg --begin 28200 --end 29520 --fcd-output trace.xml
  --device.fcd.begin 28800 --fcd-output.filter-edges.input-file edges.txt`
  (`edges.txt`: one `edge:<id>` line per corridor edge).
* **netgenerate motorway**: a 6 km three-lane motorway with two carriageways
  (`netgenerate --grid --grid.x-number=2 --grid.y-number=1 --grid.x-length=6000
  --default.lanenumber=3 --default.speed=36.1 --no-turnarounds`), demand of 3,000
  cars and 400 trucks per hour per direction with speed-factor spread
  (`config/sumo/motorway.flows.rou.xml`), 900 s of trace after a 600 s warm-up,
  both carriageways projected on one axis (`config/sumo/motorway.corridor.json`).

Both were produced with Eclipse SUMO 1.28.0 (`pip install eclipse-sumo`).

## The revocation rule (E1r, version 3.2.0)

E1 revokes a vehicle on its first clone report, which is the manuscript's rule
(Algorithm 5: a clone report goes PM to CA and the certificate is revoked). A
reviewer will ask whether the wrongful revocations survive a stricter rule.
`revocation_reports` and `revocation_distinct_rsus` make the PM wait for k reports
from at least m different RSUs before it asks the PKI to revoke; `pop-sim recycling
--sensitivity` runs E1r over (k, m) in {1/1, 2/1, 3/1, 5/1, 2/2, 3/2, 3/3} and
measures, per rule: honest vehicles revoked and wrongful reports filed by S1 and S2
former holders (120 s and 600 s, ledger attribution), and on the other side of the
trade the time a genuine misbehaver (the E2 vehicle, oracle attribution) survives
before the rule is met.

## Related work the fix depends on (go/no-go reading)

The fix the study recommends, re-keying on every transfer (`rekey`), only matters
as a contribution if the swapping and recycling designs in the literature do not
already do it. Two 2023 designs were checked.

* **Mdee, Khan, Seo and Kim, "Security Compliant and Cooperative Pseudonyms
  Swapping for Location Privacy Preservation in VANETs", IEEE TVT 72(8), 2023
  (DOI 10.1109/TVT.2023.3254660).** Vehicles hold one non-swappable pseudonym and a
  set of swappable ones; neighbours swap a swappable pseudonym inside a mix-context
  without RSUs, and both report the new vehicle-to-pseudonym mapping to the authority
  for accountability. The full text is paywalled; the mechanism is confirmed from the
  papers that cite it: the short-term pseudonym's *private key is handed over* with
  the pseudonym (the swap is "multiple interactions" ending with the private key
  swapped and a confirmation broadcast), and one 2025 paper names that key handover
  as the security risk its own design avoids. So Mdee et al. do not re-key: the new
  holder signs with a key the former holder still has, and accountability rests on
  the authority's record of who holds what, exactly the ledger attribution E1 breaks.
  **Go**: the former-holder result and the rekey fix apply to it unchanged.
* **Salin, "Pseudonym Swapping with Secure Accumulators and Double Diffie-Hellman
  Rounds in Cooperative Intelligent Transport Systems", CRiSIS 2022, LNCS 13857,
  Springer 2023 (DOI 10.1007/978-3-031-31108-6_17).** Closed access; only the
  abstract and the citation contexts of later papers were readable, and the author's
  2025 doctoral thesis lists the paper but excludes its text. The abstract places
  the signature keys in the hardware security module *and* in a secure accumulator
  that proves a key is valid, and swaps under two Diffie-Hellman rounds; nothing
  readable says whether the swapped pseudonym's key is re-derived for the new holder
  or moved as is. **Unverified**: if the double Diffie-Hellman rounds derive a fresh
  per-holder key, that paper already has the `rekey` idea for swapping (not for
  cloud recycling), and the study's claim should be narrowed to "re-keying is
  missing from recycling designs, and is what the swapping literature's safe variant
  does"; if they only authenticate the handover, the claim stands as written. The
  chapter needs to be read in full before submission.
