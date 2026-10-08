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
only. SUMO trace import (the plan's optional step 11) is not implemented.
