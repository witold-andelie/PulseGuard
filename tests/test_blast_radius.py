from pulseguard.risk.blast_radius import ORDER_EXPOSURE, load_topology, score_finding


def test_order_sqli_is_p0_and_dependency_is_p2():
    topo = load_topology()
    assert topo.fixture == "hand-written"
    code = '@app.route("/order")\ndef order():\n    rows = conn.execute(q)\n'
    sqli = score_finding(
        {"file": "routes.py", "line": 3, "rule_id": "flask-sqli-taint", "scanner": "semgrep",
         "extra": {}},
        code=code, topology=topo,
    )
    assert sqli["priority"] == "P0"
    assert sqli["fixture"] == "hand-written"
    assert sqli["exposure"] == ORDER_EXPOSURE
    assert any(n["id"] == "api-gateway" and n["internet_facing"] for n in sqli["topology"]["nodes"])
    assert any(n["id"] == "clearing-ledger-db" and n["sensitivity"] == "high"
               for n in sqli["topology"]["nodes"])
    path_ids = [step["node"] for step in sqli["path"]]
    assert "api-gateway" in path_ids and "order-api" in path_ids
    dep = score_finding(
        {"file": "requirements.txt", "line": 0, "rule_id": "CVE-2024-0001", "scanner": "trivy",
         "extra": {"kind": "dependency", "package": "demo-lib"}},
        topology=topo,
    )
    assert dep["priority"] in ("P2", "P3")
