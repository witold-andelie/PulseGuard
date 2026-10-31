from pulseguard.agents.skeptic import abstained_verdict, challenge, parse_skeptic, resolution
from pulseguard.contracts.models import Finding
from tests.fakes import FakeLLM, verdict


def test_resolution_resolve_vs_abstain():
    assert resolution("confirmed", "confirmed", True) == "confirmed"
    assert resolution("false_positive", "false_positive", True) == "false_positive"
    assert resolution("confirmed", "confirmed", False) == "abstained"
    assert resolution("confirmed", "false_positive", True) == "abstained"
    assert resolution("uncertain", "uncertain", True) == "abstained"
    assert resolution("confirmed", None, True) == "confirmed"
    assert resolution("confirmed", None, False) == "abstained"
    assert resolution("false_positive", None, True) == "false_positive"


def test_skeptic_argues_opposite_and_sets_role(sample_finding):
    llm = FakeLLM([{**verdict(0.15), "is_exploitable": False}])
    finding = Finding.model_validate(sample_finding)
    result = challenge(finding, "=== HARD EVIDENCE ===\n[E1] x", verdict(0.95), llm=llm)
    assert result.role == "skeptic"
    assert result.band == "false_positive"
    assert "opposite" in llm.calls[0]["system"].lower() or "Skeptic" in llm.calls[0]["system"]
    assert "0.95" in llm.calls[0]["user"]


def test_parse_skeptic_role_and_unusable_reply(sample_finding):
    parsed = parse_skeptic(
        '{"is_exploitable":false,"score":0.1,"cited_evidence":["E1"],'
        '"step1_dataflow":"a","step2_constraint":"b","step3_context":"c","step4_verdict":"d"}',
        model="t", case_id="PG-1")
    assert parsed.role == "skeptic"
    finding = Finding.model_validate(sample_finding)
    llm = FakeLLM(["not json"])
    result = challenge(finding, "block", verdict(), llm=llm)
    assert result.band == "abstained"


def test_abstained_verdict_contract():
    v = abstained_verdict("m", "PG-1", "reason", role="verifier")
    assert v.band == "abstained" and v.role == "verifier"
