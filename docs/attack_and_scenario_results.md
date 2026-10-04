# Attack bench and deployment scenario results

Back to the [README](../README.md). Mechanisms in [attacks_and_usecases.md](attacks_and_usecases.md).

## Attack bench

`pop-sim attacks` executes sixteen attacks against the implementation and reads
the outcome from what honest nodes accept. It exits non-zero if any attack
succeeds, so CI runs it on every push. Full table and mechanisms in
[attacks_and_usecases.md](attacks_and_usecases.md); raw output in
`results/v2/attacks.json`. Result of the full run: **13 defended, 3 mitigated,
0 vulnerable**.

| Attack | What was tried | Measured outcome |
|---|---|---|
| Value forgery / proof theft | Claim a smaller value, reuse the winner's proof, use an uncertified key, choose the seed | 0 of 4 accepted, honest block accepted |
| Seed grinding | Previous winner tries 1 to 64 block variants to lower its next value | Block-hash seed: share rises from 0.12 to 0.38. Chained VRF seed (v2): stays at 0.11 (fair share 0.10) |
| Block withholding | 0 to 50 % of nodes never publish when they win | 0 attacker blocks; mean block delay 46 ms to 95 ms; no round without a block |
| Equivocation | Two blocks, one proof | Second block rejected, node reported |
| Proof replay | Old proof at a new height | Rejected |
| Election server DoS | Server down 10 to 90 % of the time | v1 produces 89 % to 11 % of its blocks; v2 100 % |
| Sybil election keys | 50 self-generated keys publish blocks | 0 accepted |
| Network partition | Two halves elect for 10 heights | 10 wasted blocks, deterministic convergence on healing |
| Pseudonym replay | 2 OBUs reuse returned pseudonyms | Both revoked, 0 honest vehicles revoked |
| Pseudonym cloning | Copied pseudonym 4 km away one second later, and from another sender | Both rejected (clone check, holder binding) |
| Forged pseudonym / package | Self-minted credentials to RSU and PM | Unknown pseudonym; package rejected |
| Fake-vehicle flood | 30 forged-certificate vehicles at one RSU | Without the check: 10 fakes served, 5 honest vehicles short. With v2's check: 0 and 0, 60 requests refused |
| Revoked vehicle persists | Keeps transmitting, asks for new sets | 0 messages accepted, no new sets |
| RSU chain rewrite | RSU edits a transaction and re-hashes its chain | Detected from the PM-level anchors |
| Curious RSU | Reads neighbours' transactions | 0 of 6 opened |
| Location tracking | Kalman/GNN tracker across changes | Sparse road 100 % linked; dense synchronized zone with 10 s silence 48 %; same zone unsynchronized 62 % |

![Attacks](../figures/v2/attacks.png)

Four of these defences did not exist before the bench was written and were added
because it found them necessary: the chained VRF seed (grinding), equivocation
detection, the certificate check at allotment (flood), and the ledger clone check.

## Deployment scenarios

`pop-sim usecases` runs the protocol in seven settings an operator might deploy it
in (`results/v2/usecases.json`, configurations included so each can be re-run with
`pop-sim bench`). Linking success is the fraction of pseudonym changes a kinematic
tracker follows; below 0.35 is reported as adequate, above 0.7 as insufficient.

| Scenario | Setting | Vehicles | Linking | Stock-outs | Round (one core) | Verdict |
|---|---|---|---|---|---|---|
| Urban intersection | 2 km, 60 veh/km, 30 km/h, shuffle 20 s, 5 s silence | 237 | 0.35 | 0 | 0.5 s | Adequate, just: the right place to shuffle; 10 s silence gives margin |
| Highway | 12 km, 4 veh/km, 110 km/h, shuffle 60 s | 72 | 0.78 | 8 | 0.7 s | Insufficient: tracker follows for 73 s on average; needs silence at entries/exits |
| Rural night | 6 km, 1 veh/km | 11 | 0.61 | 0 | 0.1 s | A lone vehicle is tracked for 50 of 60 s; shuffling alone does not help |
| Cross-PM roaming | Two PMs on a 6 km ring | 72 | 0.81 | 0 | 0.3 s | 42 crossings; 36 anchored proofs verified (1.4 KB, 19 us); 6 fell back to the ledger |
| Toll / service access | Gantry authenticates by pseudonym | 65 | n/a | n/a | n/a | 63 accepted, 2 revoked rejected, 137 us per check, 0 permanent identities exposed |
| Incident revocation | 3 misbehaving vehicles, 2 PMs | 72 | n/a | n/a | n/a | 3 of 3 revoked within 2 rounds, 0 honest vehicles affected, CRL of 3 |
| City scale | 4 PMs x 5 RSUs, 20 km, 20 veh/km | 784 | 0.70 | 1 | 2.7 s | 11,760 signed CAMs per 30 s round, PM election 0.4 ms: one core keeps up with a district |

Linking success is against the Kalman/GNN tracker (the conservative adversary).

![Scenarios](../figures/v2/usecases.png)

What the scenarios say together: PoP v2 is a good fit where the manuscript places it
(dense urban zones, service access, revocation across operators, roaming between
PMs), and the simulation puts numbers on where it is not enough on its own (sparse,
fast roads), where the operator must add silent periods at junctions or accept that
pseudonym change does not provide location privacy.

