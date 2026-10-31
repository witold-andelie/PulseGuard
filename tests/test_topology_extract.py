"""S3 proposal/falsification checks for the quant-foundation-gat topology seam; FakeLLM only."""

import json
from copy import deepcopy

import httpx
import pytest
from jsonschema import Draft202012Validator

from pulseguard.agents.llm import LLMResponse, VisionUnsupportedError
from pulseguard.agents.topology_extract import DEFAULT_IMAGE, extract_topology
from pulseguard.risk.blast_radius import load_topology, score_finding, topology_from_result
from pulseguard.risk.topology import cross_check_dot, topology_schema, validate_topology
from tests.fakes import FakeLLM
from tests.test_llm import client

DOT = DEFAULT_IMAGE.with_suffix(".dot")
FINDING = {"file": "routes.py", "line": 3, "rule_id": "flask-sqli-taint", "scanner": "semgrep"}
CODE = '@app.route("/order")\ndef order():\n    rows = conn.execute(q)\n'


@pytest.fixture
def topology():
    return load_topology().to_payload()


def test_topology_schema_is_valid_and_fixture_conforms(topology):
    schema = topology_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(topology)
    assert validate_topology(topology)["ok"]


def test_true_topology_is_accepted_with_image_and_dot_evidence(topology):
    llm = FakeLLM([topology])
    result = extract_topology(llm=llm, session="pg-case-topology")
    assert result["source"] == "extracted"
    assert result["topology"] == topology
    assert result["model"] == llm.model
    assert result["validation"]["ok"] is True
    assert result["validation"]["errors"] == []
    assert result["validation"]["dot"]["status"] == "matched"
    for kind in ("nodes", "edges"):
        assert result["validation"]["dot"][kind] == {
            "matched": 6, "missing": 0, "extra": 0, "different": 0,
            "missing_ids": [], "extra_ids": [], "different_ids": [],
        }
    call = llm.calls[0]
    assert call["images"] == [DEFAULT_IMAGE]
    assert call["session"] == "pg-case-topology"
    assert "order-api" in call["user"]
    assert "nodes" in call["schema"]["properties"]
    assert DOT.read_text(encoding="utf-8") not in call["user"]


@pytest.mark.parametrize(("case", "reason"), [
    ("root", "schema:$:type"), ("missing_keys", "schema:$:required"),
    ("extra_keys", "schema:$:additionalProperties"),
    ("empty_nodes", "schema:nodes:minItems"), ("bad_label", "schema:nodes/0/label:minLength"),
    ("bad_id", "schema:nodes/0/id:pattern"),
    ("bad_facing", "schema:nodes/0/internet_facing:type"),
    ("bad_sensitivity", "schema:nodes/0/sensitivity:enum"),
    ("duplicate_ids", "duplicate_node_ids"), ("unknown_from", "unknown_edge_node"),
    ("unknown_to", "unknown_edge_node"), ("duplicate_edges", "duplicate_edges"),
    ("negative_privilege", "schema:edges/0/privilege:minimum"),
    ("high_privilege", "schema:edges/0/privilege:maximum"),
    ("negative_sensitivity", "schema:edges/0/sensitivity:minimum"),
    ("high_sensitivity", "schema:edges/0/sensitivity:maximum"),
    ("boolean_weight", "schema:edges/0/privilege:type"),
    ("string_weight", "schema:edges/0/privilege:type"),
    ("no_internet", "no_internet_facing_node"), ("no_service", "scanned_service_missing"),
    ("dot_mismatch", "dot_mismatch"),
])
def test_invalid_proposals_select_fixture_with_reason(topology, case, reason):
    data = deepcopy(topology)
    if case == "root":
        data = []
    elif case == "missing_keys":
        del data["edges"]
    elif case == "extra_keys":
        data["invented"] = "untrusted"
    elif case == "empty_nodes":
        data["nodes"] = []
    elif case == "bad_label":
        data["nodes"][0]["label"] = ""
    elif case == "bad_id":
        data["nodes"][0]["id"] = "bad id"
    elif case == "bad_facing":
        data["nodes"][0]["internet_facing"] = "true"
    elif case == "bad_sensitivity":
        data["nodes"][0]["sensitivity"] = "critical"
    elif case == "duplicate_ids":
        data["nodes"].append(deepcopy(data["nodes"][0]))
    elif case in ("unknown_from", "unknown_to"):
        data["edges"][0][case.removeprefix("unknown_")] = "invented"
    elif case == "duplicate_edges":
        data["edges"].append(deepcopy(data["edges"][0]))
    elif case in (
        "negative_privilege", "high_privilege", "negative_sensitivity", "high_sensitivity",
    ):
        bound, key = case.split("_")
        data["edges"][0][key] = -0.1 if bound == "negative" else 1.1
    elif case in ("boolean_weight", "string_weight"):
        data["edges"][0]["privilege"] = True if case == "boolean_weight" else "0.5"
    elif case == "no_internet":
        for node in data["nodes"]:
            node["internet_facing"] = False
    elif case == "no_service":
        data["nodes"] = [node for node in data["nodes"] if node["id"] != "order-api"]
        data["edges"] = []
    elif case == "dot_mismatch":
        data["edges"][0]["privilege"] = 0.1
    llm = FakeLLM([json.dumps(data)])
    result = extract_topology(llm=llm)
    assert result["source"] == "fixture"
    assert result["topology"] == topology
    assert result["validation"]["ok"] is False
    assert reason in result["validation"]["errors"]
    assert len(llm.calls) == 1


@pytest.mark.parametrize("reply", [
    "not JSON", '{"nodes":[', '{} trailing',
    '{"nodes":[],"nodes":[],"edges":[]}',
    '{"nodes":[],"edges":[],"weight":NaN}',
    '{"nodes":[],"edges":[],"weight":Infinity}',
    '{"nodes":[],"edges":[],"weight":-Infinity}',
])
def test_malformed_or_ambiguous_json_is_never_repaired(reply, topology):
    result = extract_topology(llm=FakeLLM([reply]))
    assert result["source"] == "fixture" and result["topology"] == topology
    assert result["validation"]["errors"] == ["invalid_json"]


def test_finite_weight_checks_do_not_depend_on_json_parser(topology):
    topology["edges"][0]["privilege"] = float("nan")
    assert "non_finite_edge_weight" in validate_topology(topology)["errors"]


@pytest.mark.parametrize("error", [VisionUnsupportedError(422), RuntimeError("secret-credential")])
def test_provider_failure_is_safe_fixture_fallback(topology, error):
    result = extract_topology(llm=FakeLLM([error]))
    assert result["source"] == "fixture" and result["topology"] == topology
    reason = "vision_unsupported" if isinstance(error, VisionUnsupportedError) else "model_error"
    assert result["validation"]["errors"] == [reason]
    assert result["validation"]["provider"]["error"] == type(error).__name__
    assert "secret-credential" not in json.dumps(result)


def test_fake_sdk_vision_rejection_reaches_fixture(topology):
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(400, json={"error": {"message": "images not supported"}})

    result = extract_topology(llm=client(handler))
    assert len(calls) == 1
    assert result["source"] == "fixture" and result["topology"] == topology
    assert result["validation"]["errors"] == ["vision_unsupported"]
    assert result["validation"]["provider"]["status_code"] == 400


def test_actual_response_model_is_recorded(topology):
    class RoutedLLM(FakeLLM):
        def chat(self, *args, **kwargs):
            response = super().chat(*args, **kwargs)
            return LLMResponse(response.text, "actual-response-model", 1.0)

    assert extract_topology(llm=RoutedLLM([topology]))["model"] == "actual-response-model"


def test_dot_is_optional_and_missing_explicit_source_falls_back(tmp_path, topology):
    image = tmp_path / "other.png"
    image.write_bytes(DEFAULT_IMAGE.read_bytes())
    result = extract_topology(image, llm=FakeLLM([topology]))
    assert result["source"] == "extracted"
    assert result["validation"]["dot"] == {"status": "not_checked"}
    missing = extract_topology(image, llm=FakeLLM([topology]), dot_path=tmp_path / "missing.dot")
    assert missing["source"] == "fixture"
    assert missing["validation"]["errors"] == ["dot_source_invalid"]
    assert missing["validation"]["dot"]["error"] == "FileNotFoundError"


@pytest.mark.parametrize("text", ["digraph broken {}", 'digraph x { "order-api" [label="oops"]; }'])
def test_invalid_dot_source_cannot_be_accepted(tmp_path, topology, text):
    dot = tmp_path / "invalid.dot"
    dot.write_text(text, encoding="utf-8")
    result = extract_topology(llm=FakeLLM([topology]), dot_path=dot)
    assert result["source"] == "fixture"
    assert result["validation"]["errors"] == ["dot_source_invalid"]


def test_dot_counts_missing_extra_and_changed_attributes(topology):
    topology["nodes"] = [node for node in topology["nodes"] if node["id"] != "internal-jobs"]
    topology["nodes"][0]["label"] = "Changed gateway label"
    topology["nodes"].append({"id": "extra", "label": "Extra", "internet_facing": False,
                              "sensitivity": "low"})
    topology["edges"].pop()
    topology["edges"][0]["privilege"] = 0.1
    topology["edges"].append({"from": "order-api", "to": "extra",
                              "privilege": 0.1, "sensitivity": 0.1})
    result = cross_check_dot(topology, DOT)
    assert result["status"] == "mismatch"
    for kind in ("nodes", "edges"):
        assert {key: result[kind][key] for key in ("matched", "missing", "extra", "different")} == {
            "matched": 4, "missing": 1, "extra": 1, "different": 1,
        }
    assert result["nodes"]["missing_ids"] == ["internal-jobs"]
    assert result["edges"]["extra_ids"] == ["order-api->extra"]


def test_extracted_topology_matches_fixture_p0_with_provenance(topology):
    extraction = extract_topology(llm=FakeLLM([topology]))
    scored = score_finding(FINDING, code=CODE, topology=extraction)
    baseline = score_finding(FINDING, code=CODE)
    assert scored["priority"] == baseline["priority"] == "P0"
    for key in ("score", "path", "topology", "exposure"):
        assert scored[key] == baseline[key]
    assert scored["source"] == "extracted"
    assert scored["validation"] == extraction["validation"]
    assert "fixture" not in scored
    assert "source" not in baseline and "validation" not in baseline
    assert baseline["fixture"] == "hand-written"
    assert score_finding(FINDING, code=CODE, topology=topology_from_result(extraction)) == scored


def test_injected_fallback_keeps_reason_and_fixture_label():
    extraction = extract_topology(llm=FakeLLM([{}]))
    scored = score_finding(FINDING, topology=extraction)
    assert scored["priority"] == "P0" and scored["fixture"] == "hand-written"
    assert "source" not in scored
    assert scored["validation"] == extraction["validation"]


def test_result_adapter_rejects_unvalidated_or_mutated_extractions(topology):
    extraction = extract_topology(llm=FakeLLM([topology]))
    extraction["topology"]["edges"][0]["privilege"] = 100
    with pytest.raises(ValueError, match="deterministic validation"):
        topology_from_result(extraction)
    extraction["topology"] = topology
    extraction["validation"]["ok"] = False
    with pytest.raises(ValueError, match="deterministic validation"):
        topology_from_result(extraction)
    extraction["source"] = "invented"
    with pytest.raises(ValueError, match="unknown topology source"):
        topology_from_result(extraction)
    extraction["source"] = "extracted"
    extraction["validation"] = None
    with pytest.raises(ValueError, match="validation evidence"):
        topology_from_result(extraction)
