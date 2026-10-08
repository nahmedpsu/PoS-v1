from pop_sim.shuffle import ITSConfig, ITSSimulation
from pop_sim.v2.mobility_sumo import Corridor, TraceRoad, parse_fcd, synthetic_fcd


def test_parse_and_corridor_mapping(tmp_path):
    path = tmp_path / "trace.xml"
    lengths = synthetic_fcd(str(path), vehicles=5, seconds=10)
    frames = parse_fcd(str(path))
    assert len(frames) == 10 and len(frames[0].vehicles) == 5
    road = TraceRoad(frames, Corridor("lane", ["e0", "e1", "e2"], lengths), n_rsu=3)
    assert road.cfg.length_m == 3000.0 and len(road.vehicles) == 5
    x0 = {v.vid: v.x for v in road.vehicles}
    road.step()
    assert road.t == 1.0 and all(0 <= v.x < 3000 for v in road.vehicles)
    moved = sum(1 for v in road.vehicles if abs(v.x - x0[v.vid]) > 0)
    assert moved == 5
    # a vehicle on an edge outside the corridor is ignored
    road2 = TraceRoad(frames, Corridor("lane", ["e0"], lengths), n_rsu=1)
    assert all(v.x < 1000 for v in road2.vehicles)


def test_xy_corridor_projection(tmp_path):
    path = tmp_path / "trace.xml"
    synthetic_fcd(str(path), vehicles=4, seconds=3, edges=("e0",), edge_len=500.0)
    road = TraceRoad(parse_fcd(str(path)), Corridor("xy", axis=((0.0, 0.0), (500.0, 0.0))), n_rsu=2)
    assert road.cfg.length_m == 500.0 and len(road.vehicles) == 4
    assert all(v.rsu in (0, 1) for v in road.vehicles)


def test_simulation_runs_on_a_trace(tmp_path):
    path = tmp_path / "trace.xml"
    lengths = synthetic_fcd(str(path), vehicles=12, seconds=45, seed=3)
    road = TraceRoad(parse_fcd(str(path)), Corridor("lane", ["e0", "e1", "e2"], lengths), n_rsu=2)
    cfg = ITSConfig(n_pm=1, rsus_per_pm=2, consensus="pop", mobility=True, round_seconds=20,
                    pseudonyms_per_vehicle=2, seed=3, v2v=True)
    sim = ITSSimulation(cfg, road=road)
    assert len(sim.vehicles) == 12
    sim.run(2)
    s = sim.summary()
    assert s["pm_chain_valid"] and s["rsu_chains_valid"]
    assert s["tracking"]["beacons"] > 0 and s["recycling"]["v2v"]["accepted"] > 0
