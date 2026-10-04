# Attack bench and deployment scenarios for PoP v2

`pop-sim attacks` executes sixteen attacks against the implementation and
reads the outcome from what honest nodes accept. `pop-sim usecases` runs the
protocol in seven concrete settings. Both write JSON to `results/v2/` and a
figure to `figures/v2/`; the measured numbers are in the README.

## Attacks

| # | Attack | Category | What the attacker does | Defence in v2 | Outcome |
|---|---|---|---|---|---|
| 1 | Value forgery / proof theft | consensus | Claims a smaller value, reuses the winner's proof, uses an uncertified key, picks its own seed | VRF proof bound to the certified key, chain position and seed; value recomputed from the proof | defended |
| 2 | Seed grinding | consensus | As previous winner, tries many block variants so its next VRF value is small | Seed = previous winner's VRF output, not the block hash | defended (block-hash seed is shown vulnerable) |
| 3 | Block withholding | consensus | Attacker-controlled winners stay silent | Independent timers: the next-smallest value publishes | mitigated (delay only) |
| 4 | Equivocation | consensus | Two blocks for one height with the same proof | (key, seed) -> hash memory; second block rejected, node reported | defended |
| 5 | Proof replay | consensus | An old valid proof at a new height | Seed includes the height and the previous output | defended |
| 6 | Election server DoS | consensus | Takes the v1 server down | v2 has no server | defended (v1 loses blocks) |
| 7 | Sybil election keys | consensus | 50 self-generated VRF keys | Only PKI-certified keys may publish | defended |
| 8 | Network partition | consensus | Splits the PM network | Deterministic fork rule converges; losing side's blocks wasted | mitigated |
| 9 | Pseudonym replay | protocol | OBU reuses a returned pseudonym | Ledger state; RSU flags, PM reports, PKI revokes | defended |
| 10 | Pseudonym cloning | protocol | Copied pseudonym used in two places | Ledger plausibility (60 m/s bound) and holder binding | defended |
| 11 | Forged pseudonym / package | protocol | Self-minted credentials offered to RSU and PM | Certificate must verify under the real PKI key; ledger must hold an allotment | defended |
| 12 | Fake-vehicle flood | protocol | 30 forged-certificate vehicles request sets | RSU allots only to PKI-certified, unrevoked vehicles | defended |
| 13 | Revoked vehicle persists | protocol | Keeps using held pseudonyms, asks for new ones | Held pseudonyms retired in the ledger on revocation; certificate check refuses new sets | defended |
| 14 | RSU chain rewrite | protocol | RSU edits a transaction and re-hashes its chain | PM-block anchors no longer match | defended |
| 15 | Curious RSU | protocol | Reads neighbours' transactions | Encrypted for the PM | defended |
| 16 | Location tracking | privacy | Links beacons by kinematics across changes | Dense traffic, synchronized changes, silence | mitigated (measured) |

"Mitigated" means the attack has a bounded, measured effect: withholding costs
waiting time, a partition costs the losing side's blocks, tracking succeeds on
sparse roads and is reduced in dense synchronized zones. The bench exits with
status 1 if any attack is `vulnerable`, so CI runs it.

## Deployment scenarios

| Scenario | Setting | Question it answers |
|---|---|---|
| `urban_intersection` | 2 km around a signalised intersection, 60 veh/km, 30 km/h, shuffle every 20 s, 5 s silence | Does shuffling in a dense zone defeat a tracker, and at what stock? |
| `highway` | 12 km, 4 veh/km, 110 km/h, shuffle every 60 s | Is a sparse fast road protected? |
| `rural_night` | 6 km, 1 veh/km | What happens to a lone vehicle? |
| `cross_pm_roaming` | Two PMs on a ring; vehicles cross the boundary | Can a vehicle prove its allotment to a foreign PM, and at what cost? |
| `toll_service_access` | Gantry / charging point authenticates by pseudonym | Can a service verify a vehicle without learning who it is? |
| `incident_revocation` | Three misbehaving vehicles across two PMs | How fast is detection, revocation and CRL propagation; are honest vehicles hit? |
| `city_scale` | 4 PMs x 5 RSUs, 20 km, 20 veh/km | What does a district cost per round on one core? |

Each result carries the full configuration so it can be re-run with
`pop-sim bench` after editing a parameter.
