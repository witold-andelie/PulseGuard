import pytest

from pulseguard.contracts.models import Event, Finding, PatchSetModel, Verdict
from pulseguard.contracts.validate import ContractError, assert_payload, check_all_schemas


def test_all_schemas_are_2020_12_valid():
    assert set(check_all_schemas()) == {"finding", "verdict", "patchset", "event"}


def test_sample_payloads_and_pydantic_mirrors(sample_run):
    case = sample_run["cases"][0]
    samples = [
        ("finding", Finding, case["finding"]),
        ("verdict", Verdict, case["verdicts"][0]),
        ("patchset", PatchSetModel, case["patches"][0]["patchset"]),
        ("event", Event, case["events"][0]),
    ]
    for name, model, payload in samples:
        assert_payload(name, payload)
        parsed = model.model_validate(payload).model_dump(mode="json", exclude_none=True)
        assert_payload(name, parsed)


@pytest.mark.parametrize(("name", "payload"), [
    ("finding", {}), ("verdict", {"score": 1.1}),
    ("patchset", {"ops": [], "rationale": "test", "attempt": 4}),
    ("event", {"seq": -1, "ts": "yesterday"}),
])
def test_bad_contracts_are_rejected(name, payload):
    with pytest.raises(ContractError):
        assert_payload(name, payload)


def test_invalid_finding_state_and_extra_fields(sample_finding):
    for change in ({"state": "auto_approved"}, {"unexpected": "value"}):
        with pytest.raises(ContractError):
            assert_payload("finding", {**sample_finding, **change})
