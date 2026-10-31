"""Hand-computed matrices for SymbAI-Taint ``src/evaluation/{metrics,reporter}.py`` reuse."""

import json
from pathlib import Path

import pytest

from eval.ablation import run_ablation
from eval.labels import Site
from eval.metrics import Metrics, compute_metrics
from eval.report import render_markdown, write_report


@pytest.mark.parametrize(("counts", "ratios"), [
    ((3, 2, 1, 2), (0.6, 0.75, 2 / 3, 0.5, 0.25)),
    ((0, 0, 4, 4), (0, 0, 0, 0, 1)),
    ((4, 4, 0, 0), (0.5, 1, 2 / 3, 1, 0)),
    ((4, 0, 0, 4), (1, 1, 1, 0, 0)),
    ((0, 0, 0, 0), (0, 0, 0, 0, 0)),
])
def test_hand_computed_metrics(counts: tuple[int, ...], ratios: tuple[float, ...]) -> None:
    result = Metrics(*counts).to_dict()
    assert list(result)[:4] == ["tp", "fp", "fn", "tn"]
    assert tuple(result[k] for k in ("tp", "fp", "fn", "tn")) == counts
    assert tuple(result[k] for k in ("precision", "recall", "f1", "fp_rate", "fn_rate")) == (
        pytest.approx(ratios))


def test_finite_site_universe_dedup_and_validation() -> None:
    sites = [Site("a.py", i + 1, f"f{i}", "vuln" if i < 4 else "safe", "sqli")
             for i in range(8)]
    flagged = [sites[i].site_id for i in (0, 1, 2, 4, 5, 5)]
    assert compute_metrics(sites, flagged) == Metrics(3, 2, 1, 2)
    with pytest.raises(ValueError, match="unknown site"):
        compute_metrics(sites, ["unlabelled"])
    with pytest.raises(ValueError, match="duplicate site"):
        compute_metrics([sites[0], sites[0]], [])
    for invalid in (-1, True, 1.5):
        with pytest.raises(ValueError, match="nonnegative integers"):
            Metrics(invalid, 0, 0, 0)


def test_reports_roundtrip_counts_first_and_missing_values(tmp_path: Path) -> None:
    (tmp_path / "cases.py").write_text("def route():\n    pass  # @safe sqli\n")
    report = run_ablation(tmp_path, modes=["llm", "neurosymbolic"])
    text = render_markdown(report)
    assert "**1** (**0 vulnerable**, **1 safe**)" in text
    assert text.index("| TP | FP | FN | TN |") < text.index("| Precision | Recall |")
    assert "| llm | not run |" in text and "| neurosymbolic | not run |" in text
    assert report["modes"]["llm"]["metrics"] is None
    assert "Small, author-written" in text and "Do not generalise" in text
    md, js = write_report(report, tmp_path / "output", name="example")
    assert md.read_text(encoding="utf-8") == text
    assert json.loads(js.read_text(encoding="utf-8")) == report
    assert next(iter(report)) == "summary"
    assert "cases.py" in report["corpus_sha256"]
    with pytest.raises(ValueError, match="filename stem"):
        write_report(report, tmp_path, name="../escaped")
