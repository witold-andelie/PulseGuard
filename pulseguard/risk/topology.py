"""Deterministic topology checks for quant-foundation-gat's ``graph/propagate.py`` seam.

Local S3 implementation of framework sections 3 and 12: neural proposals must pass
the JSON contract and graph invariants before they reach blast-radius propagation.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

# The diagram uses a deliberately small DOT subset: quoted ids and quoted attributes.
_STATEMENT = re.compile(
    r'^\s*"(?P<src>[\w-]+)"\s*(?:->\s*"(?P<dst>[\w-]+)"\s*)?'
    r'\[(?P<attrs>(?:[^"\]]|"(?:[^"\\]|\\.)*")*)\]\s*;', re.M,
)
_ATTRIBUTE = re.compile(r'(\w+)\s*=\s*("(?:[^"\\]|\\.)*")')


def topology_schema() -> dict[str, Any]:
    """Load the local service contract alongside ``risk/topology.json``."""
    return json.loads(Path(__file__).with_name("topology.schema.json").read_text(encoding="utf-8"))


def _dot_topology(path: Path) -> dict[str, Any]:
    """Read the annotated subset in ``docs/architecture/landscape.dot`` without Graphviz."""
    nodes = []
    edges = []
    for statement in _STATEMENT.finditer(path.read_text(encoding="utf-8")):
        attrs = {key: json.loads(value) for key, value in
                 _ATTRIBUTE.findall(statement["attrs"])}
        if attrs.get("topology") == "context":
            continue
        if statement["dst"] is not None:
            edges.append({
                "from": statement["src"], "to": statement["dst"],
                "privilege": float(attrs["privilege"]),
                "sensitivity": float(attrs["sensitivity"]),
            })
        else:
            facing = attrs["internet_facing"]
            if facing not in ("true", "false"):
                raise ValueError("invalid internet_facing annotation")
            nodes.append({
                "id": statement["src"], "label": attrs["service_label"],
                "internet_facing": facing == "true", "sensitivity": attrs["sensitivity"],
            })
    data = {"nodes": nodes, "edges": edges}
    if not validate_topology(data)["ok"]:
        raise ValueError("DOT annotations violate the topology contract")
    return data


def cross_check_dot(data: dict[str, Any], path: Path) -> dict[str, Any]:
    """Compare service ids, directed edges, and their risk attributes with the DOT source."""
    expected = _dot_topology(path)

    def agreement(kind: str) -> dict[str, Any]:
        def index(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
            return {(item["id"] if kind == "nodes" else f'{item["from"]}->{item["to"]}'): item
                    for item in items}

        actual = index(data[kind])
        reference = index(expected[kind])
        common = actual.keys() & reference.keys()
        different = sorted(key for key in common if actual[key] != reference[key])
        missing = sorted(reference.keys() - actual.keys())
        extra = sorted(actual.keys() - reference.keys())
        return {"matched": len(common) - len(different), "missing": len(missing),
                "extra": len(extra), "different": len(different),
                "missing_ids": missing, "extra_ids": extra, "different_ids": different}

    nodes, edges = agreement("nodes"), agreement("edges")
    ok = all(part[key] == 0 for part in (nodes, edges)
             for key in ("missing", "extra", "different"))
    return {"status": "matched" if ok else "mismatch", "nodes": nodes, "edges": edges}


def validate_topology(
    data: Any, *, service_id: str = "order-api", dot_path: Path | None = None,
) -> dict[str, Any]:
    """Falsify malformed graphs; return deterministic, JSON-serializable validation evidence."""
    errors = []
    for error in Draft202012Validator(topology_schema()).iter_errors(data):
        location = "/".join(str(part) for part in error.absolute_path) or "$"
        # Avoid echoing model/provider content in reasons.
        errors.append(f"schema:{location}:{error.validator}")
    report: dict[str, Any] = {"ok": False, "errors": sorted(errors),
                              "dot": {"status": "not_checked"}}
    if errors:
        return report
    ids = [node["id"] for node in data["nodes"]]
    known = set(ids)
    if len(ids) != len(known):
        errors.append("duplicate_node_ids")
    if service_id not in known:
        errors.append("scanned_service_missing")
    if not any(node["internet_facing"] for node in data["nodes"]):
        errors.append("no_internet_facing_node")
    pairs = []
    for edge in data["edges"]:
        pairs.append((edge["from"], edge["to"]))
        if edge["from"] not in known or edge["to"] not in known:
            errors.append("unknown_edge_node")
        if not all(math.isfinite(edge[key]) for key in ("privilege", "sensitivity")):
            errors.append("non_finite_edge_weight")
    if len(pairs) != len(set(pairs)):
        errors.append("duplicate_edges")
    if dot_path is not None and not errors:
        try:
            report["dot"] = cross_check_dot(data, dot_path)
            if report["dot"]["status"] != "matched":
                errors.append("dot_mismatch")
        except (OSError, UnicodeError, ValueError, KeyError) as exc:
            report["dot"] = {"status": "unavailable", "error": type(exc).__name__}
            errors.append("dot_source_invalid")
    report.update(ok=not errors, errors=sorted(set(errors)))
    return report
