# Pseudonym recycling study: results

Back to the [README](../README.md). Design and pre-registered outcome cases in
[recycling.md](recycling.md). All numbers below come from `results/recycling/*.json`,
produced by `pop-sim recycling` with ten seeds per cell and four rounds of 30 s
(two PMs, six RSUs, 5 km ring road, three pseudonyms per vehicle, 3 s silence after
each change, 3 m GPS noise, ledger attribution, vehicle-to-vehicle receivers within
300 m). Every cell is the mean over seeds with a 95 % bootstrap confidence interval.

The horizon matters for two results and is stated where it does: 120 s of traffic is
shorter than every certificate lifetime tested, so no certificate expires inside a run.

## E1. A former holder can impersonate the new holder (RQ1)

Five percent of vehicles keep the private key of every pseudonym they held and sign
under those pseudonyms after recycling. Ten vehicles per km unless stated.

| Strategy | Receivers that accept the forgery (plausibility off / on) | RSU accepts | Exposure window per pseudonym (mean, p95) | Innocent holders blamed per run | Honest vehicles revoked per run |
|---|---|---|---|---|---|
| S1 remote shadow | 100 % / 96.5 % | 70 % | 32.6 s, 61 s | 223 | 33 |
| S2 co-located ghost | 100 % / 77 % | 65 % | 14 s, 30 s | 38 | 6 |
| S3 gap filler | 100 % / 99.5 % | 0 % | 38 s, 69 s | 0 | 0 |

* Vehicle-to-vehicle receivers accept every forgery: they check the certificate and
  the signature, and the former holder has both. The local plausibility rule removes
  3.5 % of S1 and 23 % of S2 acceptances, those at receivers that also heard the real
  holder; S3 is untouched because nobody else is using the pseudonym.
* The RSU, which has the ledger, still accepts 65 to 70 % of S1 and S2 forgeries:
  the forger's first message under a pseudonym sets the ledger's last-seen position,
  and from then on the *real* holder is the one that looks cloned.
* That is the accountability failure: under ledger attribution the RSU reports the
  current holder for every clone it detects. S1 produces 223 reports against innocent
  vehicles per run and gets 33 of about 100 honest vehicles revoked; S2 gets 6
  revoked. The attacker itself is never named.
* Certificate lifetime (300, 900, 3600 s) does not change any of this within the
  horizon: the exposure window is set by the recycling period (how long a pseudonym
  sits with, or between, holders), not by the certificate.
* Density from 2 to 80 vehicles per km and attacker share from 1 to 10 % move the
  counts proportionally and the rates not at all (acceptance 96 to 97 % for S1,
  74 to 77 % for S2, 99.5 % or more for S3).

![E1](../figures/recycling/E1.png)

## E2. Revocation does not reach other vehicles (RQ2)

One vehicle is caught by an RSU and revoked after the first round. It keeps
transmitting from the copies it kept. For every lifetime tested, other vehicles accept
all 60 of its later messages for the remaining 60 s of the run: revocation lives in
the ledger and the CRL, which V2V receivers never consult, and the certificates it
holds stay valid until they expire (longer than the run in every cell).

![E2](../figures/recycling/E2.png)

## E3. What each insider can link (RQ3)

Recycle mode, ten seeds. Link rate is the share of a vehicle's pseudonym changes the
entity joins correctly; identity rate is the share of vehicles whose cluster carries a
permanent identity; coverage is the share of a vehicle's driven seconds attributed to
its largest cluster.

| Entity | Link rate (10 / 40 veh/km) | Precision | Identity rate | Coverage |
|---|---|---|---|---|
| Outside tracker (A1) | 0.96 / 0.90 | 0.92 / 0.73 | 0 | 0.91 / 0.79 |
| One RSU | 0.15 | 1.00 | 0.52 | 0.22 |
| One PM | 0.49 | 1.00 | 0.84 | 0.53 |
| Cloud, upload order kept | 0.73 | 1.00 | 0 | 0.25 |
| Cloud, order shuffled before upload | 0.01 / 0.002 | 0.01 | 0 | 0.09 |
| PKI | 0 | 1.00 | 0 | 0.08 |
| Tracker + one PM (A4) | 0.98 / 0.95 | 0.80 / 0.21 | 0.84 | 0.95 / 0.90 |
| Tracker + cloud (order kept) | 0.99 / 0.98 | 0.78 / 0.16 | 0 | 0.96 / 0.93 |

* A single PM already names the owner of 84 % of the vehicles in its domain, by
  construction of the ledger. With the tracker it attributes 95 % of every vehicle's
  driving to a named owner. The ledger, not the recycling, creates this exposure: the
  same numbers hold in every issuance mode (E4).
* The cloud-order leak is real: because `RSU.collect_used` returns one vehicle's
  pseudonyms consecutively and the PM uploads in that order, the cloud links 73 % of
  changes with perfect precision before it shuffles anything. Shuffling at the PM
  before upload (`shuffle_before_upload=True`, one line) removes it (1 %).
* Collusion precision falls at 40 vehicles per km (0.21 for tracker + PM): the
  tracker's wrong links merge the PM's correct clusters into larger wrong ones. A
  careful colluder would weight the ledger's edges above the tracker's.

![E3](../figures/recycling/E3.png)

## E4. Issuance modes against every axis (RQ4)

Attacker strategy S2, plausibility on, 900 s certificates, ten paired seeds.

| Axis | recycle | fresh | fresh_vgk | rekey | window |
|---|---|---|---|---|---|
| Outside tracker link rate, 10 veh/km | 0.975 | 0.966 | 0.965 | 0.974 | 0.975 |
| Outside tracker link rate, 40 veh/km | 0.904 | 0.902 | 0.903 | 0.907 | 0.904 |
| Forged messages accepted (V2V), 10 / 40 veh/km | 104 / 502 | 0 / 0 | 0 / 0 | 0 / 0 | 104 / 502 |
| Innocent holders blamed, 10 / 40 veh/km | 38 / 172 | 0 | 0 | 0 | 38 / 172 |
| PM insider link rate | 0.49 | 0.49 | 0.49 | 0.49 | 0.49 |
| PKI CPU-s per 1,000 veh per h (steady state) | 0 | 54 | 18 | 0 | 0 |
| PM CPU-s per 1,000 veh per h | 0.3 | 0.1 | 0.1 | 18 | 18 |
| PKI signatures per run, 10 / 40 veh/km | 0 | 1,164 / 4,697 | 1,158 / 4,688 | 0 | 0 |
| PM signatures per run, 10 / 40 veh/km | 16 | 8 | 8 | 1,170 / 4,703 | 1,141 / 4,566 |
| Vehicle key generations per vehicle per round | 0 | 0 | 3 | 3 | 0 |
| Bytes per vehicle per round | 11.9 k | 12.0 k | 12.1 k | 23.9 k | 23.6 k |
| Stock-outs per run | 0.9 | 1.3 | 0 | 1.5 | 0.9 |

Paired Wilcoxon tests (ten seeds, same traffic in every mode): forged acceptances
recycle vs fresh, fresh_vgk and rekey, p = 0.005 with effect size 1.0 at both
densities; PKI load recycle vs fresh and fresh_vgk, p = 0.005; tracker link rate
recycle vs fresh at 10 veh/km, p = 0.009 with recycle *higher* by 0.9 points, and no
significant difference at 40 veh/km.

Reading it against the pre-registered cases:

1. **A1 linkability is equal across modes** (within a point; recycling is if
   anything slightly worse). Recycling buys no privacy against an eavesdropper.
2. **A2 forgeries are non-zero only under recycle and window.** Fresh, fresh_vgk
   and rekey are at zero across ten seeds and two densities.
3. **The PKI load of fresh issuance is 54 CPU-seconds per 1,000 vehicles per hour**
   (18 with vehicle-generated keys), against the pre-registered threshold of one. The
   literal threshold of case 1 is not met: at 30 s rounds with three pseudonyms per
   vehicle, fresh issuance is 360 certificates per vehicle-hour, 1.5 % of one core
   per 1,000 vehicles, 15 cores for a million vehicles. Recycling's steady-state PKI
   cost inside the horizon is zero because no certificate came up for renewal; at the
   lifetime scale it is one signature per circulating pseudonym per lifetime, about
   four per vehicle-hour for 3,600 s certificates, roughly a hundredth of fresh
   issuance.
4. **Safe recycling is fresh issuance with the signing moved to the PMs.** `rekey`
   costs the PMs 18 CPU-s per 1,000 vehicle-hours, exactly fresh_vgk's PKI cost, the
   same three key generations per vehicle per round, and twice the bytes per message
   (the holder certificate rides along; a digest after first sight would recover
   that). The pseudonym label it keeps adds nothing measurable.

So the outcome is case 2 with case 3 as the headline: recycling earns its place only
as a load shift, and in exchange it breaks accountability (E1: the ledger blames the
victim) and makes revocation unenforceable at vehicles (E2).

![E4](../figures/recycling/E4.png)

## E5. The fix and its ablation (RQ4)

Ten vehicles per km, 900 s certificates, plausibility off (the receiver's weakest
setting), ten seeds. `window` binds the recycled pseudonym to a holder window but
keeps the shared key; `rekey` also gives each holder a fresh key; `fresh_vgk` issues
fresh pseudonyms with vehicle-generated keys.

| Variant | S1 forgeries sent / accepted | S2 sent / accepted | S3 sent / accepted | Innocent holders blamed (S1 / S2) | PM signatures per run | Vehicle key generations per vehicle per round | Bytes per vehicle per round |
|---|---|---|---|---|---|---|---|
| window | 739 / 739 | 104 / 104 | 471 / 0 | 223 / 38 | 990 to 1,170 | 0 | 22 to 24 k |
| rekey | 926 / 0 | 117 / 0 | 471 / 0 | 0 / 0 | 1,170 | 3 | 24 k |
| fresh_vgk | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 8 | 3 | 12 k |

* The window alone stops only the gap filler (S3): a former holder cannot present a
  certificate for a time when it did not hold the pseudonym. It stops nothing else,
  because the current holder's window certificate is public (it rides in every
  message) and the former holder still has the key it binds.
* Re-keying stops all three strategies at every seed, and with it the wrongful
  reports: zero innocent holders blamed.
* Its cost against fresh vehicle-generated keys: the same three key generations per
  vehicle per round, the same number of signatures (moved from the PKI to the PMs),
  and twice the bytes per message, because the holder certificate has to travel with
  each message until receivers cache it. Nothing is left that the recycled label
  buys.

![E5](../figures/recycling/E5.png)

## E6. The attack bench under ledger attribution

The eighteen attacks of `pop-sim attacks` rerun with `attribution="ledger"` instead
of the oracle attribution v2.2.1 used. One outcome changes: *revoked vehicle keeps
transmitting* goes from defended to vulnerable. Under ledger attribution the
malicious vehicle's replay is attributed to the pseudonym's current holder, so the
honest holder is revoked and the attacker is not; it then keeps its pseudonyms and
keeps transmitting. The other seventeen outcomes are unchanged (13 defended, 4
mitigated). The bench's default stays oracle so that the v2.2.1 numbers remain
reproducible, and this finding is reported here rather than hidden by the default.

## The answer

Recycling is not worth it on any axis the manuscript claims, and it costs two
properties the manuscript promises:

* **Privacy against an eavesdropper**: no better than fresh issuance (E4; one point
  worse at 10 veh/km).
* **Security**: a former holder forges accepted messages under every strategy (E1),
  and the ledger-based accountability turns those forgeries into revocations of the
  innocent current holder (E1, E6). Fresh issuance has nothing to forge.
* **Revocation**: unenforceable at vehicles for as long as the certificates live (E2),
  which is a property of certificate lifetime, not of recycling, but recycling makes
  the key a shared secret so the damage spreads to every past holder.
* **Authority load**: the only axis recycling wins. Fresh issuance costs the PKI 54
  CPU-seconds per 1,000 vehicle-hours at 30 s rounds (18 with vehicle-generated
  keys); recycling costs it a signature per circulating pseudonym per certificate
  lifetime. If that load matters, the safe form of recycling (`rekey`) delivers it
  by making the PMs do the signing, at which point it is fresh issuance by another
  authority with a bigger message.
* **Insider exposure** is the same in every mode: the ledger, not the recycling,
  lets a PM name 84 % of its vehicles, and the cloud's upload order leaks 73 % of
  the pseudonym changes until the PM shuffles before uploading (E3).

![Summary](../figures/recycling/summary.png)

## Limitations

* 120 s horizons: certificate expiry and renewal never occur inside a run, so the
  lifetime axis of E1 is flat and E2's persistence is bounded by the run, not by the
  certificate. Longer runs are a parameter change (`rounds`), not a code change.
* Ring road, no intersections (the tracker's easiest case) and a tracker that is
  strong but not optimal; both bias the privacy numbers in the same direction for
  every mode, so the mode comparison stands.
* One attacker model per run; mixed strategies and adaptive attackers are not run.
* No SUMO traces (optional step 11 of the plan).
