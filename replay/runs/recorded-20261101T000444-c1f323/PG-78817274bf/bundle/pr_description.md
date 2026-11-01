## [PulseGuard] Fix flask-sqli-taint in routes.py

Case `PG-78817274bf` · run mode **LIVE**

**Rationale:** Replace string-concatenated SQL with a parameterised query to prevent SQL injection while preserving behavior for valid ids.

- Adjudicator score: 0.95
- Cited evidence: E2, E1, E4, E3
- Sandbox: passed
- Approval: approve by security-engineer (recording)

### Finding
{
  "case_id": "PG-78817274bf",
  "fingerprint": "78817274bf32e8e10f9c4018eb830fe0063a0269b166c7669aa166b1e029999e",
  "rule_id": "flask-sqli-taint",
  "scanner": "semgrep",
  "severity": "high",
  "message": "Untrusted input from flask.request.args reaches the SQL text of conn.execute() without sanitisation (possible SQL injection, CWE-89). Use a parameterised query.",
  "file": "routes.py",
  "line": 37,
  "state": "confirmed",
  "evidence_ids": [
    "E1",
    "E2",
    "E3",
    "E4",
    "E5"
  ],
  "trace": [
    {
      "kind": "source",
      "line": 32,
      "content": "order_id = request.args.get(\"id\")"
    },
    {
      "kind": "intermediate",
      "line": 35,
      "content": "q = \"SELECT id, item, qty FROM orders WHERE id = '\" + order_id + \"'\""
    },
    {
      "kind": "sink",
      "line": 37,
      "content": "rows = conn.execute(q).fetchall()  # @vuln sqli"
    }
  ],
  "extra": {
    "also_reported_by": [
      "bandit"
    ]
  }
}

### Verdict
{
  "is_exploitable": true,
  "score": 0.95,
  "band": "confirmed",
  "cited_evidence": [
    "E2",
    "E1",
    "E4",
    "E3"
  ],
  "step1_dataflow": "Taint from request.args.get flows into q and reaches conn.execute.",
  "step2_constraint": "No sanitizer, cast, or bound was applied on the path.",
  "step3_context": "The /order route is internet-facing via api-gateway.",
  "step4_verdict": "Unsanitized user input in SQL is exploitable.",
  "role": "adjudicator",
  "model": "muse-spark-1.3-contributor",
  "case_id": "PG-78817274bf"
}

### Sandbox report
{
  "passed": true,
  "rescan_before": 1,
  "rescan_after": 0,
  "pytest_ok": true,
  "pytest_tail": "...                                                                      [100%]\n3 passed in 0.14s\n",
  "diff": "--- a/routes.py\n+++ b/routes.py\n@@ -32,9 +32,9 @@\n     order_id = request.args.get(\"id\")\n     if order_id is None:\n         return jsonify({\"error\": \"missing id\"}), 400\n-    q = \"SELECT id, item, qty FROM orders WHERE id = '\" + order_id + \"'\"\n+    q = \"SELECT id, item, qty FROM orders WHERE id = ?\"\n     conn = get_db()\n-    rows = conn.execute(q).fetchall()  # @vuln sqli\n+    rows = conn.execute(q, (order_id,)).fetchall()  # @vuln sqli\n     return jsonify([dict(r) for r in rows])\n \n \n",
  "errors": [],
  "feedback": ""
}