import pytest

from pulseguard.agents.adjudicator import VerdictParseError, parse_verdict
from pulseguard.agents.json_parse import parse_json_response
from pulseguard.contracts.validate import assert_payload


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


def test_parsed_verdict_validates():
    verdict = parse_verdict('{"score":0.7,"cited_evidence":["E1","E1"]}', model="test")
    assert verdict.band == "confirmed"
    assert verdict.cited_evidence == ["E1"]
    assert_payload("verdict", verdict.to_payload())


@pytest.mark.parametrize("text", [
    '{"score":NaN}', '{"score":true}', '{"score":"bad"}',
    '{"score":0.9,"is_exploitable":"false"}',
    '{"score":0.9,"cited_evidence":"E1"}',
])
def test_invalid_verdict_fails_closed(text):
    with pytest.raises(VerdictParseError):
        parse_verdict(text, model="test")
