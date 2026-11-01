## [PulseGuard] Fix CVE-2026-25645 in requirements.txt

Case `PG-d8c671afbb` · run mode **LIVE**

**Rationale:** Bump requests 2.31.0 → 2.33.0 (deterministic; no model call).

- Adjudicator score: 1.0
- Cited evidence: E1, E2, E3
- Sandbox: passed
- Approval: approve by policy:auto

### Finding
{
  "case_id": "PG-d8c671afbb",
  "fingerprint": "d8c671afbb2bf446cfa6a99ebaaa36394301f35099f9c74a009df60bc238d940",
  "rule_id": "CVE-2026-25645",
  "scanner": "trivy",
  "severity": "medium",
  "message": "requests 2.31.0: 3 CVEs, fixed in 2.33.0",
  "file": "requirements.txt",
  "line": 0,
  "state": "confirmed",
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "trace": [],
  "cve_id": "CVE-2026-25645",
  "extra": {
    "kind": "dependency",
    "package": "requests",
    "installed_version": "2.31.0",
    "fixed_version": "2.33.0",
    "cve_id": "CVE-2026-25645",
    "manifest": "requirements.txt",
    "report": "scan/trivy-report.json",
    "recorded": true,
    "cve_ids": [
      "CVE-2024-35195",
      "CVE-2024-47081",
      "CVE-2026-25645"
    ]
  }
}

### Verdict
{
  "is_exploitable": true,
  "score": 1.0,
  "band": "confirmed",
  "cited_evidence": [
    "E1",
    "E2",
    "E3"
  ],
  "step1_dataflow": "Dependency requests==2.31.0; ['CVE-2024-35195', 'CVE-2024-47081', 'CVE-2026-25645'] present in RECORDED Trivy report.",
  "step2_constraint": "Highest recorded fixed version: 2.33.0.",
  "step3_context": "Report scan/trivy-report.json; label RECORDED, Trivy 0.76.1, scanned at 2026-10-31T21:44:44.2259288+01:00.",
  "step4_verdict": "Recorded CVEs and fixed version confirmed; deterministic manifest bump.",
  "role": "verifier",
  "model": "none",
  "case_id": "PG-d8c671afbb"
}

### Sandbox report
{
  "passed": true,
  "rescan_before": 1,
  "rescan_after": 0,
  "pytest_ok": true,
  "pytest_tail": "...                                                                      [100%]\n3 passed in 0.17s\n",
  "diff": "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -2,4 +2,4 @@\n pytest>=8\n # @vuln dependency: CVE-2024-35195, fixed in requests 2.32.0 (scan-only demo pin).\n # This manifest is scanner input; do not install it into the PulseGuard/test environment.\n-requests==2.31.0\n+requests==2.33.0",
  "errors": [],
  "feedback": ""
}