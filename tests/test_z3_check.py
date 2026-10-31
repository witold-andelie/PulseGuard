"""ST-1 z3 validator solving against the labelled demo_target/z3_cases table."""

from pulseguard.contracts.models import Finding
from pulseguard.evidence import build_hard_evidence, constraint_item
from pulseguard.falsify.z3_check import check_validators, extract_validators
from pulseguard.paths import REPO_ROOT
from pulseguard.scanners.semgrep import DataflowTrace, TraceLine
from pulseguard.verify import check_validator_lines, verify_finding
from tests.fakes import EchoScanner

CASES = REPO_ROOT / "demo_target" / "z3_cases"


def _lines(name: str) -> tuple[str, list[str], str]:
    rel = f"demo_target/z3_cases/{name}"
    code = (REPO_ROOT / rel).read_text(encoding="utf-8")
    return code, code.splitlines(), rel


def _source_sink(lines: list[str]) -> tuple[int, int]:
    source = next(i for i, line in enumerate(lines, 1) if "request.args.get" in line)
    sink = next(i for i, line in enumerate(lines, 1) if line.strip() == "return order_id")
    return source, sink


def _check(name: str):
    code, lines, rel = _lines(name)
    source, sink = _source_sink(lines)
    return check_validators(code, source_line=source, sink_line=sink, file=rel)


def test_alnum_class_is_unsat():
    result = _check("alnum_unsat.py")
    assert result.result == "unsat"
    assert result.claim is True
    assert result.witness is None
    assert result.model == r"^[A-Za-z0-9_-]{1,12}$"
    item = constraint_item(result)
    assert item is not None
    assert item.evidence_id == "E6"
    assert item.kind == "constraint"
    assert item.text == r"validator model: ^[A-Za-z0-9_-]{1,12}$ admits a quote? unsat"


def test_quote_class_is_sat_with_quote_witness():
    result = _check("quote_sat.py")
    assert result.result == "sat"
    assert result.claim is True
    assert result.witness == "'"
    item = constraint_item(result)
    assert item is not None
    assert item.text == r"validator model: ^[A-Za-z0-9_\-' ]{1,32}$ admits a quote? sat"


def test_length_only_is_sat_with_classic_payload():
    result = _check("length_sat.py")
    assert result.result == "sat"
    assert result.claim is True
    assert result.witness == "' OR 1=1"
    assert len(result.witness) <= 8
    item = constraint_item(result)
    assert item is not None
    assert item.text == "validator model: length <= 8 admits a quote? sat"


def test_lookahead_is_unknown_and_makes_no_claim():
    result = _check("lookahead_unknown.py")
    assert result.result == "unknown"
    assert result.claim is False
    assert result.witness is None
    assert result.validators
    item = constraint_item(result)
    assert item is not None
    assert item.text == (
        r"validator model: ^(?=.*[A-Z])[A-Za-z0-9]{1,12}$ admits a quote? unknown")
    assert item.payload["claim"] is False


def test_unanchored_match_and_backreference_are_unknown():
    unanchored = (
        "import re\n"
        "def f():\n"
        "    order_id = request.args.get('id', '')\n"
        "    if not re.match(r'[A-Za-z]+', order_id):\n"
        "        return None\n"
        "    return order_id\n"
    )
    backref = (
        "import re\n"
        "def f():\n"
        "    order_id = request.args.get('id', '')\n"
        "    if not re.fullmatch(r'^(.)\\1$', order_id):\n"
        "        return None\n"
        "    return order_id\n"
    )
    for code in (unanchored, backref):
        result = check_validators(code, source_line=3, sink_line=6, file="case.py")
        assert result.result == "unknown"
        assert result.claim is False
        assert result.validators


def test_no_validators_omits_e6():
    code, lines, rel = _lines("alnum_unsat.py")
    # A line range that never sees the regex still has the source assignment.
    empty = check_validators(code, source_line=1, sink_line=1, file=rel)
    assert empty.result == "unknown"
    assert empty.claim is False
    assert constraint_item(empty) is None


def test_extracted_validator_line_is_exact():
    code, lines, rel = _lines("alnum_unsat.py")
    source, sink = _source_sink(lines)
    validators = extract_validators(code, source, sink, file=rel)
    assert validators
    regex = next(v for v in validators if v.kind == "regex")
    assert regex.text == lines[regex.line - 1]
    assert r"^[A-Za-z0-9_-]{1,12}$" in regex.pattern


def test_build_hard_evidence_appends_e6_when_code_supplied():
    code, lines, rel = _lines("alnum_unsat.py")
    source, sink = _source_sink(lines)
    finding = Finding(
        case_id="PG-z3alnum", fingerprint="ab" * 16, rule_id="flask-sqli-taint",
        file=rel, line=sink, state="raw", evidence_ids=[],
        trace=[
            {"kind": "source", "line": source, "content": lines[source - 1].strip()},
            {"kind": "sink", "line": sink, "content": lines[sink - 1].strip()},
        ],
    )
    trace = DataflowTrace(
        TraceLine(source, lines[source - 1].strip()), [],
        TraceLine(sink, lines[sink - 1].strip()),
    )
    items = build_hard_evidence(finding, trace, code=code)
    e6 = next(item for item in items if item.evidence_id == "E6")
    assert e6.text.endswith("unsat")


def test_validator_lines_check_pass_and_fail():
    code, lines, rel = _lines("alnum_unsat.py")
    source, sink = _source_sink(lines)
    result = check_validators(code, source_line=source, sink_line=sink, file=rel)
    item = constraint_item(result)
    evidence = [item.model_dump()]
    assert check_validator_lines(evidence, REPO_ROOT)["ok"]
    broken = [item.model_dump()]
    broken[0]["payload"]["validators"][0]["text"] = "not the validator"
    assert not check_validator_lines(broken, REPO_ROOT)["ok"]
    assert check_validator_lines([], REPO_ROOT)["ok"]


def test_verify_finding_includes_validator_lines(tmp_path):
    (tmp_path / "routes.py").write_text("sink()\n", encoding="utf-8")
    finding = {
        "file": "routes.py", "line": 1, "fingerprint": "ab" * 16, "scanner": "semgrep",
        "extra": {}, "trace": [{"kind": "sink", "line": 1, "content": "sink()"}],
    }
    evidence = [{"evidence_id": "E1", "kind": "rule_source", "text": "x",
                 "payload": {"file": "routes.py", "line": 1, "source": "sink()"}}]
    report = verify_finding(
        finding, evidence=evidence, cited=["E1"], target=tmp_path,
        scanner=EchoScanner(finding),
    )
    assert report["ok"]
    assert "validator_lines" in {c["name"] for c in report["checks"]}


def test_graph_evidence_node_puts_e6_in_the_adjudicator_block():
    from pulseguard.agents.graph import GraphDeps, build_graph

    code, lines, rel = _lines("alnum_unsat.py")
    source, sink = _source_sink(lines)
    finding = {
        "case_id": "PG-z3graph", "fingerprint": "cd" * 16, "rule_id": "flask-sqli-taint",
        "scanner": "semgrep", "file": rel, "line": sink, "state": "raw", "evidence_ids": [],
        "trace": [
            {"kind": "source", "line": source, "content": lines[source - 1].strip()},
            {"kind": "sink", "line": sink, "content": lines[sink - 1].strip()},
        ],
    }
    seen: dict[str, str] = {}

    def adjudicate(state):
        seen["block"] = state["evidence_block"]
        return {"is_exploitable": False, "score": 0.05, "band": "false_positive",
                "cited_evidence": ["E6"], "role": "adjudicator", "model": "fake",
                "step1_dataflow": "-", "step2_constraint": "-", "step3_context": "-",
                "step4_verdict": "-"}

    deps = GraphDeps(adjudicate=adjudicate, scanner=EchoScanner(finding), target_root=REPO_ROOT)
    build_graph(deps).compile().invoke({"finding": finding, "code": code})
    assert "[E6] validator model: ^[A-Za-z0-9_-]{1,12}$ admits a quote? unsat" in seen["block"]
