import random

from pop_sim.consensus import PoPServer, mine_pow2, poet_elect, pokw_mine, solve_pow1, verify_election
from pop_sim.consensus.pow1 import puzzle_position
from pop_sim.consensus.pow2 import verify_pow2


def test_pow1_finds_short_puzzle_and_counts_guesses():
    r = solve_pow1("0a", charset="0ab")
    assert r.found and r.puzzle == "0a"
    assert r.guesses == puzzle_position("0a", "0ab") == 2
    assert r.search_space == 9


def test_pow1_extrapolates_when_budget_exceeded():
    r = solve_pow1("zz", charset="abcdefghijklmnopqrstuvwxyz", max_guesses=10)
    assert not r.found and r.guesses == 10
    assert r.extrapolated_seconds is not None and r.cpu_seconds > 0


def test_pow2_meets_difficulty_and_verifies():
    r = mine_pow2("abc", 2, timestamp=1.0)
    assert r.block_hash.startswith("00")
    assert verify_pow2("abc", 1.0, r.nonce, 2)
    assert not verify_pow2("abc", 1.0, r.nonce + 1, 2) or mine_pow2("abc", 2, timestamp=1.0, start_nonce=r.nonce + 1).nonce != r.nonce


def test_poet_smallest_time_wins():
    ids = [f"N{i}" for i in range(10)]
    r = poet_elect(ids, rng=random.Random(3))
    assert r.winner in ids
    assert r.winner_time == min(r.times.values())
    assert len(r.times) == 10


def test_pokw_uses_random_kernel():
    ids = [f"N{i}" for i in range(8)]
    r = pokw_mine(ids, "data", 1, rng=random.Random(1))
    assert len(r.kernel) == 4 and r.winner in r.kernel
    assert r.per_node[r.winner].hashes == min(x.hashes for x in r.per_node.values())


def test_pop_threshold_never_below_half():
    server = PoPServer(rng=random.Random(5))
    for i in range(20):
        server.connect(f"N{i}")
    for _ in range(50):
        r = server.elect()
        assert 50 <= r.threshold_percent <= 100
        assert r.miners >= 10 and r.miners == PoPServer.miners_for(20, r.threshold_percent)
        assert r.winner in r.mining_list
        assert r.winner_time == min(r.times.values())
        assert set(r.times) == set(r.mining_list)


def test_pop_unselected_nodes_learn_nothing():
    server = PoPServer(rng=random.Random(2))
    for i in range(10):
        server.connect(f"N{i}")
    r = server.elect(threshold_percent=50)
    for nid, node in server.clients.items():
        if nid not in r.mining_list:
            assert node.short_time is None and not node.selected


def test_pop_election_attestation():
    server = PoPServer(rng=random.Random(9))
    for i in range(6):
        server.connect(f"N{i}")
    r = server.elect()
    proof = r.proof()
    assert verify_election(proof, server.keys.pk_hex)
    assert not verify_election({**proof, "winner": "N-fake"}, server.keys.pk_hex)
    forged = {**proof, "winner": next(n for n in proof["mining_list"] if n != proof["winner"])} \
        if len(proof["mining_list"]) > 1 else {**proof, "attestation": "00"}
    assert not verify_election(forged, server.keys.pk_hex)
