"""Scripted adapters for the revio model/scanner seams; no model or Semgrep required."""

import json
from pathlib import Path
from types import SimpleNamespace

from pulseguard.agents.llm import LLMResponse
from pulseguard.scanners.semgrep import DataflowTrace, SemgrepResult, TraceLine

PATCH = {
    "ops": [
        {"path": "routes.py",
         "old": """q = "SELECT id, item, qty FROM orders WHERE id = '" + order_id + "'" """.strip(),
         "new": 'q = "SELECT id, item, qty FROM orders WHERE id = ?"'},
        {"path": "routes.py", "old": "conn.execute(q).fetchall()",
         "new": "conn.execute(q, (order_id,)).fetchall()"},
    ],
    "rationale": "Bind the untrusted order id as a query parameter.", "attempt": 1,
}


def verdict(score=0.95):
    return {
        "is_exploitable": score >= 0.7, "score": score, "cited_evidence": ["E1", "E2", "E3"],
        "step1_dataflow": "The order id reaches the SQL argument.",
        "step2_constraint": "No sanitizer matches this path.",
        "step3_context": "The Flask route accepts request parameters.",
        "step4_verdict": "The score determines the next review step.",
    }


class FakeLLM:
    model = "scripted-test-model"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def chat(self, system, user, *, schema, session=None, images: list[Path] | None = None):
        self.calls.append({"system": system, "user": user, "schema": schema, "session": session,
                           "images": list(images) if images is not None else None})
        if not self.responses:
            raise AssertionError("unexpected model call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return LLMResponse(
            json.dumps(response) if isinstance(response, dict) else response,
            self.model, 12.5, {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        )


class FakeScanner:
    def __init__(self, counts=None):
        self.counts = list(counts) if counts is not None else None
        self.targets = []

    def run(self, target):
        path = Path(target) / "routes.py"
        lines = path.read_text(encoding="utf-8").splitlines()

        def line_with(text):
            index = next(i for i, line in enumerate(lines) if text in line)
            return TraceLine(index + 1, lines[index].strip())

        source = line_with('request.args.get("id")')
        intermediate = line_with('q = "SELECT')
        sink = line_with("conn.execute(q)")
        return [SemgrepResult(
            "flask-sqli-taint", str(path), sink.line, sink.line,
            "SQL injection", "ERROR", sink.content,
            DataflowTrace(source, [intermediate], sink),
        )]

    def count(self, target, rule_id=None):
        self.targets.append(Path(target))
        if self.counts is not None:
            return self.counts.pop(0)
        return int("conn.execute(q).fetchall()" in
                   (Path(target) / "routes.py").read_text(encoding="utf-8"))


class EchoScanner:
    """Reproduces ``finding['fingerprint']`` so verify's re-run check can pass in graph tests."""

    def __init__(self, finding):
        self.finding = finding
        self.targets = []

    def run(self, target):
        self.targets.append(Path(target))
        return [SimpleNamespace(fingerprint=self.finding["fingerprint"])]

    def count(self, target, rule_id=None):
        self.targets.append(Path(target))
        return 1


def low_verdict():
    return verdict(0.1)
