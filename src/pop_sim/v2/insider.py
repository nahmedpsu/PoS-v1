"""Insider linkability: what each entity of the scheme can link, alone and
together with the outside tracker.

One linker serves every adversary.  Each source of evidence adds "same
vehicle" edges between pseudonyms (and between a pseudonym and a permanent
identity when the entity knows it); union-find turns the edges into
identity clusters; ``cluster_metrics`` scores them.  A1, A3 and A4 differ
only in which edges they receive, so the comparison is fair by construction.

Evidence each entity holds in this code base (verified against the source):

* RSU     - the pseudonyms it handed to each certified vehicle (``RSU.allot_log``)
* PM      - its RSUs' shared ledger, so pid -> permanent id for its domain
* cloud   - the uploads as ordered pid lists (``PrivacyManager.upload_log``);
            if the order groups one vehicle's returned pseudonyms together, the
            cloud can cluster them before shuffling (a hypothesis the experiment tests)
* PKI     - revocation reports naming vehicle and pid
* tracker - the kinematic links it decided (``linked_pairs``)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .metrics import UnionFind, cluster_metrics


@dataclass
class Evidence:
    rsu_allots: dict[str, list[tuple[str, str]]] = field(default_factory=dict)   # rsu -> [(pid, vid)]
    pm_domains: dict[str, list[tuple[str, str]]] = field(default_factory=dict)   # pm -> [(pid, vid)]
    cloud_uploads: list[list[str]] = field(default_factory=list)                 # ordered pid lists
    pki_reports: list[tuple[str, str]] = field(default_factory=list)             # (pid, vid)
    tracker_pairs: list[tuple[str, str]] = field(default_factory=list)           # (old pid, new pid)
    histories: dict[str, list[str]] = field(default_factory=dict)                # vid -> pids in order
    truth_of_pid: dict[str, str] = field(default_factory=dict)
    pid_seconds: dict[str, float] = field(default_factory=dict)
    group_size: int = 3                                                          # cloud's guess of pseudonyms per vehicle


ENTITIES = ("tracker", "rsu", "pm", "cloud", "pki")


def edges_for(entity: str, ev: Evidence, member: str | None = None) -> list[tuple[str, str]]:
    """The "same vehicle" edges one entity can draw.  ``member`` restricts an
    RSU or PM entity to one instance (the first one by default)."""
    if entity == "tracker":
        return list(ev.tracker_pairs)
    if entity == "rsu":
        rsus = [member] if member else sorted(ev.rsu_allots)[:1]
        return [(pid, vid) for r in rsus for pid, vid in ev.rsu_allots.get(r, [])]
    if entity == "pm":
        pms = [member] if member else sorted(ev.pm_domains)[:1]
        return [(pid, vid) for m in pms for pid, vid in ev.pm_domains.get(m, [])]
    if entity == "pki":
        return list(ev.pki_reports)
    if entity == "cloud":
        out = []
        k = max(1, ev.group_size)
        for upload in ev.cloud_uploads:
            for i in range(0, len(upload) - 1):
                if (i + 1) % k:                       # consecutive pids within a run of k
                    out.append((upload[i], upload[i + 1]))
        return out
    raise ValueError(entity)


def link(ev: Evidence, entities: list[str], member: str | None = None) -> dict:
    uf = UnionFind()
    for pid in ev.truth_of_pid:
        uf.find(pid)
    for e in entities:
        for a, b in edges_for(e, ev, member):
            uf.union(a, b)
    m = cluster_metrics(uf, ev.histories, ev.truth_of_pid, ev.pid_seconds)
    m["entities"] = list(entities)
    return m


def full_table(ev: Evidence) -> dict:
    """Every entity alone and every entity together with the tracker."""
    out = {}
    for e in ENTITIES:
        out[e] = link(ev, [e])
    for e in ENTITIES[1:]:
        out[f"tracker+{e}"] = link(ev, ["tracker", e])
    out["all"] = link(ev, list(ENTITIES))
    return out
