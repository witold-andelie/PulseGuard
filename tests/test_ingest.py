from pulseguard.ingest import merge_findings


def test_semgrep_and_bandit_same_location_become_one_case():
    semgrep = {
        "file": "routes.py", "line": 37, "scanner": "semgrep", "rule_id": "flask-sqli-taint",
        "extra": {},
        "trace": [
            {"kind": "source", "line": 32, "content": "order_id = request.args.get(\"id\")"},
            {"kind": "sink", "line": 37, "content": "conn.execute(q)"},
        ],
    }
    bandit_order = {
        "file": "routes.py", "line": 32, "scanner": "bandit", "rule_id": "B608",
        "extra": {"test_id": "B608"}, "trace": [],
    }
    bandit_cast = {
        "file": "routes.py", "line": 50, "scanner": "bandit", "rule_id": "B608",
        "extra": {"test_id": "B608"}, "trace": [],
    }
    trivy = {
        "file": "requirements.txt", "line": 0, "scanner": "trivy", "rule_id": "CVE-1",
        "extra": {"kind": "dependency"}, "trace": [],
    }
    merged = merge_findings([bandit_order, semgrep, bandit_cast, trivy])
    scanners = {(item["scanner"], item["line"]) for item in merged}
    assert ("semgrep", 37) in scanners
    assert ("bandit", 50) in scanners
    assert ("trivy", 0) in scanners
    assert ("bandit", 32) not in scanners
    primary = next(item for item in merged if item["scanner"] == "semgrep")
    assert "bandit" in primary["extra"]["also_reported_by"]
