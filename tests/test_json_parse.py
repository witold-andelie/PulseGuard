import json

import pytest

from pulseguard.agents.adjudicator import VerdictParseError, adjudicate, parse_verdict
from pulseguard.agents.json_parse import parse_json_response
from pulseguard.contracts.models import Finding
from pulseguard.contracts.validate import assert_payload
from tests.fakes import FakeLLM, verdict


@pytest.mark.parametrize("text", [
    '{"is_exploitable":true,"score":0.8}',
    'Here is the verdict: {"is_exploitable":true,"score":0.8} Done.',
    '~~~{"is_exploitable":true,"score":0.8}~~~',
    '{"is_exploitable":true,"score":0.8,"step1_dataflow":"truncated',
    'is_exploitable: true, score=8e-1',
])
def test_tolerant_decision_parsing(text):
    parsed = parse_json_response(text)
    assert parsed["is_exploitable"] is True
    assert parsed["score"] == 0.8


def test_fences_and_thinking_are_removed():
    text = '<think>{"score":0.1}</think>\n' + chr(96) * 3 + 'json\n{"score":0.9}\n'
    text += chr(96) * 3
    assert parse_json_response(text) == {"score": 0.9}


def test_truncated_member_keeps_earlier_decisions():
    parsed = parse_json_response(
        '{"is_exploitable":false,"score":0.2,"cited_evidence":["E1"],"tail":'
    )
    assert parsed["score"] == 0.2
    assert parsed["cited_evidence"] == ["E1"]


@pytest.mark.parametrize("text", [None, "", "unparseable", '<think>{"score":0.9}'])
def test_no_decision_or_unfinished_thought(text):
    assert parse_json_response(text) is None


def test_parsed_verdict_validates(sample_run):
    payload = {**sample_run["cases"][0]["verdicts"][0], "score": 0.7}
    verdict = parse_verdict(json.dumps(payload), model="test")
    assert verdict.band == "confirmed"
    assert verdict.cited_evidence == payload["cited_evidence"]
    assert_payload("verdict", verdict.to_payload())


@pytest.mark.parametrize("text", [
    '{"score":NaN}', '{"score":true}', '{"score":"bad"}',
    '{"score":0.9,"is_exploitable":"false"}',
    '{"score":0.9,"cited_evidence":"E1"}',
])
def test_invalid_verdict_fails_closed(text):
    with pytest.raises(VerdictParseError):
        parse_verdict(text, model="test")


def test_bracketed_citations_normalised_and_system_fields_overridden():
    payload = {**verdict(), "cited_evidence": ["[E1] source request", "[E2]", "E3"],
               "model": "PulseGuard-4.3", "band": "false_positive", "role": "skeptic",
               "case_id": "invented"}
    result = parse_verdict(json.dumps(payload), model="actual-model", case_id="actual-case")
    assert result.cited_evidence == ["E1", "E2", "E3"]
    assert result.band == "confirmed" and result.role == "adjudicator"
    assert result.model == "actual-model" and result.case_id == "actual-case"


@pytest.mark.parametrize("citations", [
    ["E1", "E1"], ["[E1] source", "E1"], ["E1 text"], ["e1"],
    ["[E1]text"], ["[E1, E2]"], [{"id": "E1"}], "E1",
])
def test_invalid_citations_become_uncertain(sample_finding, citations):
    payload = {**verdict(), "cited_evidence": citations}
    result = adjudicate(Finding.model_validate(sample_finding), "evidence",
                        llm=FakeLLM([payload]))
    assert result.band == "uncertain"


@pytest.mark.parametrize("score", [9.8, -0.1, float("inf"), float("nan")])
def test_local_score_bounds_cannot_be_bypassed(sample_finding, score):
    payload = {**verdict(), "score": score}
    result = adjudicate(Finding.model_validate(sample_finding), "evidence",
                        llm=FakeLLM([payload]))
    assert result.band == "uncertain"
    assert result.score == 0.5
