"""ST-1 governance: symbolic checks can veto, never decide a neural verdict."""

from copy import deepcopy

import pytest

import pulseguard.agents.graph as graph_module
from eval.labels import extract_labels
from pulseguard.agents.bands import Bands
from pulseguard.agents.graph import GraphDeps, build_graph
from pulseguard.agents.prompts import ADJUDICATOR_SYSTEM, SKEPTIC_SYSTEM
from pulseguard.contracts.models import Finding
from pulseguard.evidence import (
    CODE_HEADER,
    HEADER,
    LIMITS_HEADER,
    build_hard_evidence,
    constraint_item,
    render_block,
)
from pulseguard.falsify.z3_check import check_validator_dominance, check_validators, sink_context
from pulseguard.paths import REPO_ROOT
from pulseguard.scanners.semgrep import DataflowTrace, TraceLine
from pulseguard.verify import check_cited_evidence
from tests.fakes import EchoScanner, FakeLLM, verdict

SQL_STRING = '"SELECT id FROM orders WHERE id = \'" + order_id + "\'"'
SQL_NUMERIC = '"SELECT id FROM orders WHERE id = " + order_id'


def program(expression=SQL_STRING, guard=None):
    guard = guard if guard is not None else (
        '    if not re.fullmatch(r"^[0-9]{1,8}$", order_id):\n        return None\n')
    return ('import re\ndef lookup():\n    order_id = request.args.get("id", "")\n'
            + guard + '    return ' + expression + '\n')


def solve(code):
    return check_validators(code, source_line=3, sink_line=len(code.splitlines()))


@pytest.mark.parametrize(("expression", "context"), [
    (SQL_STRING, "string"), (SQL_NUMERIC, "numeric"),
    ('f"SELECT id FROM orders WHERE id = \'{order_id}\'"', "string"),
    ('f"SELECT id FROM orders WHERE id = {order_id}"', "numeric"),
    ('f"SELECT id FROM {order_id}"', "unknown"),
    ('"SELECT id FROM orders WHERE id = {}".format(order_id)', "unknown"),
    ('f"SELECT id FROM orders WHERE id = {order_id!r}"', "unknown"),
    ('"SELECT id FROM orders WHERE id = \'" + escape(order_id) + "\'"', "unknown"),
    ('order_id', "unknown"),
    ('"SELECT id FROM orders WHERE id = \'" + order_id', "unknown"),
])
def test_sink_context_and_result_question(expression, context):
    code = program(expression)
    result = solve(code)
    assert result.context == context
    assert result.to_dict()["context"] == context
    assert sink_context(code, 3, len(code.splitlines()))["context"] == context
    if context == "unknown":
        assert result.result == "unknown" and not result.claim
        assert constraint_item(result) is None
    else:
        assert result.result == "unsat"
        assert context + " sink" in result.question
        assert result.question in constraint_item(result).text


def test_numeric_digit_regex_is_unsat_but_length_alone_admits_unquoted_injection():
    digits = solve(program(SQL_NUMERIC))
    assert digits.needle == r"[^0-9\s]" and digits.result == "unsat"
    assert constraint_item(digits).text == (
        "validator model: ^[0-9]{1,8}$ admits a character other than digits and whitespace "
        "(numeric sink)? unsat")
    bounded = solve(program(SQL_NUMERIC, '    if len(order_id) > 8:\n        return None\n'))
    assert bounded.result == "sat" and bounded.witness == "1 OR 1=1"


def test_quote_free_alnum_is_not_proof_for_numeric_context():
    result = solve(program(SQL_NUMERIC).replace("[0-9]", "[A-Za-z0-9]"))
    assert result.result == "sat" and any(ch not in "0123456789" for ch in result.witness)


def test_execute_argument_and_query_alias_are_classified():
    code = program(SQL_NUMERIC).replace('    return "SELECT', '    query = "SELECT')
    code += '    return conn.execute(query)\n'
    result = solve(code)
    assert result.context == "numeric" and result.result == "unsat"
    assert check_validator_dominance(
        code, source_line=3, sink_line=len(code.splitlines()))["dominates"]
    changed = code.replace('    return conn.execute',
                           '    query += request.args.get("other")\n    return conn.execute')
    assert solve(changed).context == "unknown"


def test_numeric_unicode_digits_are_unknown_but_final_newline_is_only_whitespace():
    unicode_digits = solve(program(SQL_NUMERIC).replace("[0-9]", r"\d"))
    assert not unicode_digits.claim
    newline = solve(program(SQL_NUMERIC).replace("re.fullmatch", "re.match"))
    assert newline.result == "unsat" and newline.witness is None


def test_query_captured_before_guard_is_not_used_to_veto():
    code = program(SQL_NUMERIC)
    code = code.replace('    if not re.fullmatch',
                        '    query = ' + SQL_NUMERIC + '\n    if not re.fullmatch')
    code = code.replace('    return ' + SQL_NUMERIC, '    return query')
    check = check_validator_dominance(code, source_line=3, sink_line=len(code.splitlines()))
    assert not check["dominates"] and "captured before" in check["reason"]


def test_reversed_lower_bound_is_not_a_dominating_upper_bound():
    code = program(SQL_NUMERIC, '    if not (0 < len(order_id)):\n        return None\n')
    check = check_validator_dominance(code, source_line=3, sink_line=len(code.splitlines()))
    assert not check["dominates"]


def test_conjunction_requires_every_validator_to_dominate():
    guard = ('    if not re.fullmatch(r"^[0-9]{1,8}$", order_id):\n        return None\n'
             '    if len(order_id) > 8:\n        return None\n')
    code = program(SQL_NUMERIC, guard)
    assert check_validator_dominance(
        code, source_line=3, sink_line=len(code.splitlines()))["dominates"]
    conditional = code.replace('    if len(order_id) > 8:\n        return None',
                               '    if enabled:\n        if len(order_id) > 8:\n'
                               '            return None')
    assert not check_validator_dominance(
        conditional, source_line=3, sink_line=len(conditional.splitlines()))["dominates"]


@pytest.mark.parametrize("exit_statement", ["return None", "raise ValueError()", "abort(400)"])
def test_top_level_exit_guard_dominates(exit_statement):
    code = program().replace("return None", exit_statement)
    if exit_statement == "abort(400)":
        code = code.replace("import re", "import re; from flask import abort")
    result = check_validator_dominance(code, source_line=3, sink_line=6)
    assert result == {"dominates": True,
                      "reason": "same-variable top-level exit guards dominate",
                      "guard_line": 4, "sink_line": 6}


@pytest.mark.parametrize("guard", [
    '    if enabled:\n        if not re.fullmatch(r"^[0-9]{1,8}$", order_id):\n'
    '            return None\n',
    '    for _ in things:\n        if not re.fullmatch(r"^[0-9]{1,8}$", order_id):\n'
    '            return None\n',
    '    other = request.args.get("other")\n'
    '    if not re.fullmatch(r"^[0-9]{1,8}$", other):\n        return None\n',
    '    def helper():\n        if not re.fullmatch(r"^[0-9]{1,8}$", order_id):\n'
    '            return None\n    helper()\n',
    '    try:\n        if not re.fullmatch(r"^[0-9]{1,8}$", order_id):\n'
    '            raise ValueError()\n    except ValueError:\n        pass\n',
    '    if re.fullmatch(r"^[0-9]{1,8}$", order_id):\n        return None\n',
    '    if not re.fullmatch(r"^[0-9]{1,8}$", order_id):\n        log_error()\n',
    '    if not re.fullmatch(r"^[0-9]{1,8}$", order_id) and enabled:\n        return None\n',
])
def test_non_dominating_guards(guard):
    code = program(guard=guard)
    result = check_validator_dominance(code, source_line=3, sink_line=len(code.splitlines()))
    assert not result["dominates"] and result["reason"]


@pytest.mark.parametrize("change", [
    'order_id = request.args.get("new")', 'order_id += " OR 1=1"',
    '(order_id := request.args.get("new"))', 'order_id = transform(order_id)',
    'order_id[0] = "x"', 'mutate(order_id)',
    'if enabled:\n        order_id = request.args.get("new")',
])
def test_reassignment_or_mutation_disables_dominance(change):
    code = program().replace('    return "SELECT', '    ' + change + '\n    return "SELECT')
    result = check_validator_dominance(code, source_line=3, sink_line=len(code.splitlines()))
    assert not result["dominates"]


def case(name="alnum_unsat.py"):
    rel = "demo_target/z3_cases/" + name
    code = (REPO_ROOT / rel).read_text(encoding="utf-8")
    lines = code.splitlines()
    source = next(i for i, line in enumerate(lines, 1) if "request.args.get" in line)
    sink = next(i for i, line in enumerate(lines, 1) if line.strip().startswith('return "SELECT'))
    finding = Finding(case_id="PG-z3gov", fingerprint="ab" * 16, scanner="semgrep",
                      rule_id="flask-sqli-taint", file=rel, line=sink,
                      trace=[{"kind": kind, "line": line, "content": lines[line - 1].strip()}
                             for kind, line in (("source", source), ("sink", sink))])
    trace = DataflowTrace(TraceLine(source, lines[source - 1].strip()), [],
                          TraceLine(sink, lines[sink - 1].strip()))
    return code, finding, trace


def run_graph(score=0.95, cited=None, bypass=None, name="alnum_unsat.py", bands=None):
    code, finding, _ = case(name)
    response = verdict(score)
    if cited is not None:
        response["cited_evidence"] = cited
    llm = FakeLLM([response])
    deps = GraphDeps(llm=llm, target_root=REPO_ROOT, scanner=EchoScanner(finding.to_payload()))
    if bands is not None:
        deps.bands = bands
    state = {"finding": finding.to_payload(), "code": code, "evidence": bypass or []}
    result = build_graph(deps).compile(interrupt_before=["blast"]).invoke(state)
    assert len(llm.calls) == 1
    return result


def test_unsat_veto_escalates_high_score_and_keeps_neural_score():
    state = run_graph()
    assert state["z3_veto"] == "applied"
    assert state["finding"]["state"] == "escalated"
    assert state["band"] == state["verdict"]["band"] == "abstained"
    assert state["verdict"]["score"] == 0.95
    assert state["verification"]["ok"]  # Citation/location/rerun checks precede veto.
    assert state["events"][-1]["attributes"] == {
        "run_mode": "LIVE", "reason": "contradicts symbolic evidence E6", "check": "z3_veto"}
    assert "patchset" not in state and "blast_radius" not in state


def test_unsat_never_decides_false_positive():
    high = run_graph(0.95)
    low = run_graph(0.05, cited=["E6"])
    assert high["finding"]["state"] != "false_positive"
    assert low["finding"]["state"] == "false_positive"
    assert low["verdict"]["score"] == 0.05 and low["verdict"]["band"] == "false_positive"
    assert low["events"][-1]["resource"] == "adjudicator"


@pytest.mark.parametrize(("status", "case_id", "overrides"), [
    ("witnessed", "PG-z3gov", True), ("not_witnessed", "PG-z3gov", False),
    ("failed", "PG-z3gov", False), ("witnessed", "PG-other", False),
])
def test_only_case_bound_witnessed_e5_overrides_veto(status, case_id, overrides):
    e5 = {"evidence_id": "E5", "kind": "poc", "text": "PoC witness: fixture",
          "payload": {"status": status, "case_id": case_id}}
    state = run_graph(bypass=[e5])
    assert state["finding"]["state"] == ("confirmed" if overrides else "escalated")
    if overrides:
        assert state["z3_veto"] == "passed"
        assert state["events"][-1]["activity"] == "VERIFIED"
        assert state["events"][-1]["attributes"]["z3_veto"] == "passed"


def test_veto_uses_configured_confirmed_threshold():
    state = run_graph(0.85, bands=Bands(confirmed_at=0.8))
    assert state["finding"]["state"] == "escalated"


@pytest.mark.parametrize(("name", "expected"), [
    ("numeric_unsat.py", "escalated"), ("numeric_length_sat.py", "confirmed"),
    ("conditional_guard.py", "confirmed"), ("lookahead_unknown.py", "confirmed"),
])
def test_graph_veto_is_limited_to_dominating_unsat(name, expected):
    state = run_graph(name=name)
    assert state["finding"]["state"] == expected
    if expected == "confirmed":
        assert state["z3_veto"] == "not_applicable"
        assert state["events"][-1]["activity"] == "VERIFIED"
        assert state["events"][-1]["attributes"]["z3_veto"] == "not_applicable"


def test_later_poc_keeps_e5_before_analysis_limits(monkeypatch):
    code, finding, trace = case("lookahead_unknown.py")
    limits = []
    items = build_hard_evidence(finding, trace, code=code, analysis_limits=limits)
    result = {"case_id": finding.case_id, "status": "not_witnessed",
              "detail": "PoC witness: fake; inconclusive"}
    monkeypatch.setattr(graph_module, "witness", lambda *args, **kwargs: result)
    graph = build_graph(GraphDeps(target_root=REPO_ROOT))
    update = graph.nodes["poc"].runnable.invoke({
        "case_id": finding.case_id, "finding": finding.to_payload(), "code": code,
        "evidence_block": render_block(items, code, analysis_limits=limits),
        "analysis_limits": limits, "evidence": [item.model_dump() for item in items],
        "patchset": {"ops": [{"path": finding.file, "old": "x", "new": "y"}],
                     "rationale": "fake patch", "attempt": 1},
    })
    block = update["evidence_block"]
    assert block.index("[E5]") < block.index(LIMITS_HEADER) < block.index(CODE_HEADER)


def test_unknown_is_an_analysis_limit_and_not_an_evidence_id():
    code, finding, trace = case("lookahead_unknown.py")
    limits = []
    items = build_hard_evidence(finding, trace, code=code, analysis_limits=limits)
    assert "E6" not in [item.evidence_id for item in items]
    assert len(limits) == 2
    assert limits[0]["status"] == "not_covered"
    assert limits[1]["id"] == "L2" and limits[1]["status"] == "unknown"
    assert "lookahead" in limits[1]["reason"]
    block = render_block(items, code, analysis_limits=limits)
    assert block.index(HEADER) < block.index(LIMITS_HEADER) < block.index(CODE_HEADER)
    assert "[L2] z3 validator check: solver_status=unknown, reason=unsupported regex" in block
    state = run_graph(0.05, name="lookahead_unknown.py")
    assert state["analysis_limits"] == limits
    assert "L1" not in state["finding"]["evidence_ids"]


@pytest.mark.parametrize("score", [0.05, 0.5, 0.95])
@pytest.mark.parametrize("citation", ["L1", "E6", "E999"])
def test_citing_limit_unknown_or_missing_id_abstains_every_band(score, citation):
    state = run_graph(score, cited=[citation], name="lookahead_unknown.py")
    assert state["band"] == state["verdict"]["band"] == "abstained"
    assert state["finding"]["state"] == "escalated"
    assert not state["verification"]["ok"]
    # L1 is also rejected by the model response's E-id-only JSON contract.
    if citation != "L1":
        assert state["verdict"]["score"] == score


@pytest.mark.parametrize("item", [
    {"evidence_id": "L1", "payload": {}},
    {"evidence_id": "E6", "claim": False, "payload": {}},
    {"evidence_id": "E6", "payload": {"claim": False}},
    {"evidence_id": "E6", "payload": {"result": "unknown"}},
    {"evidence_id": "E6", "payload": {"solver_status": "unknown"}},
])
def test_non_claim_items_are_uncitable_even_if_present(item):
    assert not check_cited_evidence([item["evidence_id"]], [deepcopy(item)])["ok"]


def test_limits_prompt_and_ui_wording():
    for prompt in (ADJUDICATOR_SYSTEM, SKEPTIC_SYSTEM):
        assert "L-ids are limits" in prompt
        assert "never" in prompt
    js = (REPO_ROOT / "web/app.js").read_text(encoding="utf-8")
    assert "Not covered (analysis limit)" in js
    assert "data.analysis_limits" in js and "limit.reason" in js
    css = (REPO_ROOT / "web/style.css").read_text(encoding="utf-8")
    assert ".analysis-limits" in css and "dashed" in css


def test_z3_fixtures_do_not_change_the_eval_corpus():
    sites = extract_labels(REPO_ROOT / "demo_target")
    assert len(sites) == 27
    assert sum(site.label == "vuln" for site in sites) == 14
    for path in (REPO_ROOT / "demo_target/z3_cases").glob("*.py"):
        code = path.read_text(encoding="utf-8")
        assert "@vuln" not in code and "@safe" not in code and ".execute(" not in code
