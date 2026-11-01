"""Executable label sanity checks and independent corpus denominators; no model calls."""

import ast
import importlib
import sqlite3
from types import SimpleNamespace

import pytest
from flask import Flask

from eval.ablation import run_ablation
from eval.labels import extract_labels
from eval.report import render_markdown
from pulseguard.paths import REPO_ROOT
from pulseguard.scanners.bandit import BanditRunner
from pulseguard.scanners.semgrep import DataflowTrace, SemgrepResult, TraceLine
from tests.fakes import FakeLLM, verdict

TARGET = REPO_ROOT / "demo_target"
MODULES = ("bypasses", "safes", "flows", "comment_upstream", "comment_reviewer")


@pytest.fixture
def client():
    app = Flask(__name__)
    app.testing = True
    conn = sqlite3.connect(":memory:")
    conn.executescript("CREATE TABLE orders(id INTEGER PRIMARY KEY, item TEXT, qty INTEGER);"
                       "INSERT INTO orders VALUES (1, 'apple', 1), (2, 'pear', 2), (3, 'plum', 3);"
                       "CREATE TABLE saved_filters(token TEXT, value TEXT);")
    app.extensions["eval_db"] = conn
    for name in MODULES:
        module = importlib.import_module(f"demo_target.eval_cases.hard.{name}")
        app.register_blueprint(module.cases)
    with app.test_client() as test_client:
        yield test_client
    conn.close()


VULNERABLE = [
    ("regex_search", {"query_string": {"id": "1 OR 1=1"}}),
    ("regex_dollar_multiline", {"query_string": {"id": "1\nOR 1=1"}}),
    ("regex_match_prefix", {"query_string": {"id": "1 OR 1=1"}}),
    ("length_only", {"query_string": {"id": "1 OR 1=1"}}),
    ("case_allowlist_fallthrough", {"query_string": {"column": "id LIMIT 1"}}),
    ("different_variable", {"query_string": {"checked": "id", "column": "id LIMIT 1"}}),
    ("one_branch", {"query_string": {"id": "1 OR 1=1"}}),
    ("try_fallback", {"query_string": {"id": "1 OR 1=1"}}),
    ("validated_reassigned", {"headers": {"X-Column": "id LIMIT 1"}}),
    ("validated_concatenated", {"query_string": {"suffix": " LIMIT 1"}}),
    ("discarded_int", {"query_string": {"id": "1 OR 1=1"}}),
    ("quote_escape_numeric", {"query_string": {"id": "1 OR 1=1"}}),
    ("escape_format_numeric", {"query_string": {"id": "1 OR 1=1"}}),
    ("two_hop", {"method": "POST", "data": {"id": "1 OR 1=1"}}),
    ("misleading_helper", {"method": "POST", "json": {"id": "1 OR 1=1"}}),
    ("second_order", {"method": "POST", "json": {"filter": "1 OR 1=1"}}),
    ("comment_upstream", {"headers": {"X-Order": "1 OR 1=1"}}),
    ("comment_reviewer", {"cookie": "1 OR 1=1"}),
    ("path/1 OR 1=1", {}),
]


@pytest.mark.parametrize(("route", "options"), VULNERABLE)
def test_every_vulnerable_site_has_an_observable_sql_bypass(client, route, options):
    options = dict(options)
    if "cookie" in options:
        client.set_cookie("order", options.pop("cookie"))
    response = client.open("/hard/" + route, **options)
    assert response.status_code == 200
    identifier = route in {"case_allowlist_fallthrough", "different_variable",
                           "validated_reassigned", "validated_concatenated"}
    assert len(response.json) == (1 if identifier else 3)


@pytest.mark.parametrize(("route", "options", "expected"), [
    ("regex_fullmatch_patch", {"query_string": {"id": "1 OR 1=1"}}, []),
    ("try_failclosed_patch", {"query_string": {"id": "1 OR 1=1"}}, []),
    ("path_patch/1 OR 1=1", {}, []),
    ("second_order_patch", {"method": "POST", "json": {"filter": "1 OR 1=1"}}, []),
    ("dollar_final_newline", {"query_string": {"id": "1\n"}}, [[1]]),
    ("normalised_allowlist", {"query_string": {"column": "ID"}}, [[1], [2], [3]]),
    ("set_guard", {"query_string": {"column": "id LIMIT 1"}}, []),
    ("tuple_positive", {"query_string": {"column": "id LIMIT 1"}}, []),
    ("dict_get", {"query_string": {"column": "id LIMIT 1"}}, [[1], [2], [3]]),
    ("conditional_column", {"query_string": {"column": "id LIMIT 1"}}, [[1], [2], [3]]),
    ("positional_binding", {"method": "POST", "data": {"item": "' OR 1=1 --"}}, []),
    ("named_binding", {"method": "POST", "json": {"item": "' OR 1=1 --"}}, []),
    ("bound_builder", {"headers": {"X-Order": "1 OR 1=1"}}, []),
    ("constant_sql", {"query_string": {"ignored": "1 OR 1=1"}}, [[1], [2], [3]]),
])
def test_safe_controls_and_patches_preserve_query_structure(client, route, options, expected):
    response = client.open("/hard/" + route, **options)
    assert response.status_code == 200 and response.json == expected


@pytest.mark.parametrize(("route", "key", "error"), [
    ("dict_subscript", "column", KeyError), ("quoted_mapping", "column", KeyError),
    ("enum_column", "column", ValueError), ("integer_used", "id", ValueError),
    ("float_used", "qty", ValueError), ("helper_cast", "cookie", ValueError),
])
def test_safe_conversions_and_mappings_fail_closed(client, route, key, error):
    if key == "cookie":
        client.set_cookie("order", "1 OR 1=1")
    with pytest.raises(error):
        client.get("/hard/" + route, query_string={key: "1 OR 1=1"})


def test_executemany_binds_payload_as_data(client):
    value = "'); DROP TABLE orders; --"
    response = client.post("/hard/batch_binding", json={"items": [value]})
    assert response.status_code == 200 and response.json == {"inserted": 1}
    conn = client.application.extensions["eval_db"]
    assert conn.execute("SELECT item FROM orders WHERE id = 4").fetchone() == (value,)


def test_corpus_counts_labels_and_handlers_are_complete():
    original = extract_labels(TARGET, corpus="original")
    hard = extract_labels(TARGET, corpus="hard")
    combined = extract_labels(TARGET, corpus="all")
    assert (len(original), len(hard), len(combined)) == (27, 40, 67)
    assert sum(s.label == "vuln" for s in hard) == 19
    assert set(s.site_id for s in original).isdisjoint(s.site_id for s in hard)
    assert {s.site_id for s in combined} == {s.site_id for s in original + hard}
    for path in (TARGET / "eval_cases/hard").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        routes = {n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.decorator_list}
        labels = [s.function for s in hard if s.file == path.relative_to(TARGET).as_posix()]
        assert len(labels) == len(set(labels)) and routes == set(labels)


def test_combined_report_has_independent_counts_and_confusion_matrices():
    if not BanditRunner.available():
        pytest.skip("Bandit not installed (install the scan extra)")
    reports = {c: run_ablation(TARGET, modes=["bandit"], corpus=c)
               for c in ("original", "hard", "all")}
    assert reports["all"]["summary"]["sites"] == 67
    matrices = reports["all"]["modes"]["bandit"]["by_corpus"]
    for corpus in ("original", "hard"):
        assert matrices[corpus] == reports[corpus]["modes"]["bandit"]["metrics"]
        assert all(("eval_cases/hard/" in hit["file"]) == (corpus == "hard")
                   for hit in reports[corpus]["scanners"]["bandit"]["findings"])
    for key in ("tp", "fp", "fn", "tn"):
        assert reports["all"]["modes"]["bandit"]["metrics"][key] == sum(
            matrices[c][key] for c in matrices)
    markdown = render_markdown(reports["all"])
    assert "| combined | 67 | 33 | 34 |" in markdown
    assert "confusion counts by corpus" in markdown


def test_real_column_guard_reaches_fake_ablation_prompt_with_source_context():
    path = TARGET / "eval_cases/constraints.py"
    code = path.read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(code).body if isinstance(n, ast.FunctionDef)
              and n.name == "column_choice")
    lines = code.splitlines()
    source = next(i for i in range(fn.lineno, fn.end_lineno) if "request.args" in lines[i - 1])
    sink = fn.end_lineno
    flow = DataflowTrace(TraceLine(source, lines[source - 1]), [],
                         TraceLine(sink, lines[sink - 1]))
    hit = SemgrepResult("flask-sqli-taint", str(path), sink, sink, "SQLi", "ERROR",
                        lines[sink - 1], flow)
    client = FakeLLM([verdict(0.1)])
    report = run_ablation(TARGET, modes=["neurosymbolic"], corpus="original", llm=client,
                          semgrep=SimpleNamespace(run=lambda target: [hit]),
                          bandit=SimpleNamespace(run=lambda target: []))
    assert report["modes"]["neurosymbolic"]["model_calls"] == 1
    assert "allow-list membership guard @ L" in client.calls[0]["user"]
    assert "{id,item,qty}" in client.calls[0]["user"]
    assert "@safe" not in client.calls[0]["user"]


def test_model_candidate_union_and_hashes_exclude_unselected_corpus_files():
    path = TARGET / "eval_cases/hard/comment_upstream.py"
    line = next(s.line for s in extract_labels(TARGET, corpus="hard")
                if s.function == "comment_upstream")
    hit = SemgrepResult("flask-sqli-taint", str(path), line, line, "SQLi", "ERROR", "", None)
    client = FakeLLM([])
    report = run_ablation(TARGET, modes=["neurosymbolic"], corpus="original", llm=client,
                          semgrep=SimpleNamespace(run=lambda target: [hit]),
                          bandit=SimpleNamespace(run=lambda target: []))
    assert report["modes"]["neurosymbolic"]["model_calls"] == 0 and not client.calls
    assert report["scanners"]["semgrep"]["excluded_corpus_hits"] == 1
    assert not any(p.startswith("eval_cases/hard/") for p in report["corpus_sha256"])
