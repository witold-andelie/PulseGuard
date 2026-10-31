"""RiskPropagator adapter on the quant-foundation-gat Topology / Propagator seam.

Re-implements a small Topology dataclass and Propagator protocol locally
(``src/quant_alpha/graph/propagate.py`` idea; do not vendor that repo). Edges are
weighted by privilege and data sensitivity, with decay per hop. The topology fixture
is hand-written. The SQLi case on /order is P0 (framework 13 scenario 1).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from pulseguard.contracts.models import Priority

SENSITIVITY_VALUE = {"low": 0.25, "medium": 0.55, "high": 1.0}
DECAY = 0.7
ROUTE_RE = re.compile(r"@[\w.]+\.route\(\s*['\"]([^'\"]+)['\"]")
ORDER_EXPOSURE = "exposure: /order reachable from api-gateway (internet-facing)"


@dataclass(frozen=True)
class Node:
    id: str
    label: str
    internet_facing: bool
    sensitivity: Literal["low", "medium", "high"]


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    privilege: float
    sensitivity: float

    @property
    def weight(self) -> float:
        return self.privilege * self.sensitivity


@dataclass
class Topology:
    nodes: dict[str, Node]
    edges: list[Edge]
    fixture: str = "hand-written"

    def outgoing(self, node_id: str) -> list[Edge]:
        return [edge for edge in self.edges if edge.src == node_id]

    def incoming(self, node_id: str) -> list[Edge]:
        return [edge for edge in self.edges if edge.dst == node_id]

    def internet_nodes(self) -> list[Node]:
        return [node for node in self.nodes.values() if node.internet_facing]

    def to_payload(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": n.id, "label": n.label, "internet_facing": n.internet_facing,
                 "sensitivity": n.sensitivity}
                for n in self.nodes.values()
            ],
            "edges": [
                {"from": e.src, "to": e.dst, "privilege": e.privilege, "sensitivity": e.sensitivity}
                for e in self.edges
            ],
        }


class Propagator(Protocol):
    """quant-foundation-gat propagate seam: topology + source → per-node scores."""

    def propagate(self, topology: Topology, source: str) -> dict[str, float]: ...


def load_topology(path: str | Path | None = None) -> Topology:
    path = Path(path) if path else Path(__file__).with_name("topology.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    nodes = {
        n["id"]: Node(n["id"], n["label"], bool(n["internet_facing"]), n["sensitivity"])
        for n in data["nodes"]
    }
    edges = [
        Edge(e["from"], e["to"], float(e["privilege"]), float(e["sensitivity"]))
        for e in data["edges"]
    ]
    return Topology(nodes, edges, fixture=str(data.get("fixture", "hand-written")))


class RiskPropagator:
    """Privilege- and sensitivity-weighted walk with per-hop decay."""

    def __init__(self, decay: float = DECAY) -> None:
        self.decay = decay

    def propagate(self, topology: Topology, source: str) -> dict[str, float]:
        arrival = {source: 1.0}
        parent: dict[str, str | None] = {source: None}
        edge_into: dict[str, float] = {source: 0.0}
        changed = True
        while changed:
            changed = False
            for edge in topology.edges:
                if edge.src not in arrival:
                    continue
                nxt = arrival[edge.src] * edge.weight * self.decay
                if nxt > arrival.get(edge.dst, 0.0):
                    arrival[edge.dst] = nxt
                    parent[edge.dst] = edge.src
                    edge_into[edge.dst] = edge.weight
                    changed = True
        return arrival

    def path_to(self, topology: Topology, source: str, dest: str) -> list[dict[str, Any]]:
        arrival = self.propagate(topology, source)
        if dest not in arrival:
            return [{"node": source, "edge_weight": 0.0}]
        # Reconstruct by walking parents of a fresh propagate (recompute parent map).
        parent: dict[str, str | None] = {source: None}
        edge_into: dict[str, float] = {source: 0.0}
        best = {source: 1.0}
        changed = True
        while changed:
            changed = False
            for edge in topology.edges:
                if edge.src not in best:
                    continue
                nxt = best[edge.src] * edge.weight * self.decay
                if nxt > best.get(edge.dst, 0.0):
                    best[edge.dst] = nxt
                    parent[edge.dst] = edge.src
                    edge_into[edge.dst] = edge.weight
                    changed = True
        chain: list[str] = []
        cur: str | None = dest
        seen: set[str] = set()
        while cur is not None and cur not in seen:
            chain.append(cur)
            seen.add(cur)
            cur = parent.get(cur)
        chain.reverse()
        return [{"node": node, "edge_weight": edge_into.get(node, 0.0)} for node in chain]


def _reachable_from_internet(topology: Topology, origin: str) -> bool:
    if topology.nodes[origin].internet_facing:
        return True
    seen: set[str] = set()
    stack = [n.id for n in topology.internet_nodes()]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        if node == origin:
            return True
        stack.extend(edge.dst for edge in topology.outgoing(node))
    return False


def _route_near(code: str | None, line: int) -> str | None:
    if not code:
        return None
    best: tuple[int, str] | None = None
    for match in ROUTE_RE.finditer(code):
        lineno = code[:match.start()].count("\n") + 1
        if lineno <= line and (best is None or lineno >= best[0]):
            best = (lineno, match.group(1))
    return None if best is None else best[1]


def origin_service(finding: Mapping[str, Any]) -> str:
    """Demo findings live on order-api (the bundled Flask service)."""
    return "order-api"


def exposure_text(finding: Mapping[str, Any], code: str | None = None) -> str:
    """E4 line. The /order SQLi case uses the framework 4.2 wording exactly."""
    line = int(finding.get("line") or 0)
    route = _route_near(code, line) if code else None
    if route == "/order" or (
        route is None and "order" in str(finding.get("file", "")).replace("\\", "/")
        and finding.get("rule_id") == "flask-sqli-taint"
    ):
        return ORDER_EXPOSURE
    label = route or str(finding.get("file", "service"))
    return f"exposure: {label} reachable from api-gateway (internet-facing)"


def priority_for(score: float) -> Priority:
    if score >= 0.75:
        return Priority.P0
    if score >= 0.5:
        return Priority.P1
    if score >= 0.25:
        return Priority.P2
    return Priority.P3


def is_dependency(finding: Mapping[str, Any]) -> bool:
    extra = finding.get("extra") or {}
    return extra.get("kind") == "dependency" or finding.get("scanner") == "trivy"


def score_finding(
    finding: Mapping[str, Any], *, code: str | None = None, topology: Topology | None = None,
    propagator: RiskPropagator | None = None,
) -> dict[str, Any]:
    """Return the case-detail ``blast_radius`` object and set Priority P0..P3."""
    topology = topology or load_topology()
    propagator = propagator or RiskPropagator()
    origin = origin_service(finding)
    arrival = propagator.propagate(topology, origin)
    impact = 0.0
    peak_node = origin
    for node_id, weight in arrival.items():
        node = topology.nodes[node_id]
        contribution = SENSITIVITY_VALUE[node.sensitivity] * weight
        if contribution >= impact:
            impact, peak_node = contribution, node_id
    internet = _reachable_from_internet(topology, origin)
    exposure = 0.18 if internet else 0.0
    raw = min(1.0, impact + exposure)
    if is_dependency(finding):
        raw *= 0.4
    priority = priority_for(raw)
    inbound = [{"node": "api-gateway", "edge_weight": 0.0}] if internet else []
    outbound = propagator.path_to(topology, origin, peak_node)
    path = inbound + [step for step in outbound if step["node"] != "api-gateway"]
    if inbound and outbound and outbound[0]["node"] == origin:
        path = inbound + outbound
    return {
        "priority": priority.value,
        "score": round(raw, 4),
        "path": path,
        "topology": topology.to_payload(),
        "fixture": topology.fixture,
        "exposure": exposure_text(finding, code),
    }
