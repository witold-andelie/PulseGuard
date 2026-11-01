"""Counts-first JSON/Markdown adapted from SymbAI-Taint ``src/evaluation/reporter.py``."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.labels import Site, site_corpus

LIMITATION = (
    "Small, author-written set; these counts describe only this corpus. "
    "Do not generalise to production code or other vulnerability classes. "
    "Unlabelled scanner hits are audited separately, not counted as false positives."
)


def build_report(
    sites: list[Site], rows: dict[str, dict[str, Any]], *, target: str,
    scanners: dict[str, dict[str, Any]], corpus_hashes: dict[str, str],
    configuration: dict[str, Any],
) -> dict[str, Any]:
    """Keep the labelled universe, coverage, settings and source hashes reviewable."""
    classes = sorted({s.vulnerability_class for s in sites})

    def counts(group: list[Site]) -> dict[str, int]:
        return {"sites": len(group), "vulnerable": sum(s.label == "vuln" for s in group),
                "safe": sum(s.label == "safe" for s in group)}

    return {
        "summary": {**counts(sites), "by_class": {
            cls: counts([s for s in sites if s.vulnerability_class == cls]) for cls in classes}},
        "corpora": {corpus: counts([s for s in sites if site_corpus(s.file) == corpus])
                    for corpus in sorted({site_corpus(s.file) for s in sites})},
        "modes": rows,
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": target,
        "configuration": configuration,
        "scanners": scanners,
        "sites": [s.to_dict() for s in sites],
        "corpus_sha256": corpus_hashes,
        "limitations": LIMITATION,
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Use explicit status and missing cells, never zero-valued unrun metrics."""
    summary = report["summary"]
    lines = ["# PulseGuard evaluation", "",
             f"Labelled sites: **{summary['sites']}** "
             f"(**{summary['vulnerable']} vulnerable**, **{summary['safe']} safe**).", ""]
    lines += ["| Corpus | Sites | Vulnerable | Safe |", "| --- | ---: | ---: | ---: |"]
    for corpus, counts in report.get("corpora", {}).items():
        lines.append(f"| {corpus} | {counts['sites']} | "
                     f"{counts['vulnerable']} | {counts['safe']} |")
    if len(report.get("corpora", {})) > 1:
        lines.append(f"| combined | {summary['sites']} | "
                     f"{summary['vulnerable']} | {summary['safe']} |")
    lines += ["",
             "| Mode | Status | TP | FP | FN | TN | Precision | Recall | F1 | FP rate | FN rate |",
              "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for mode, row in report["modes"].items():
        metrics = row["metrics"]
        values = ([str(metrics[key]) for key in ("tp", "fp", "fn", "tn")]
                  + [f"{metrics[key]:.4f}" for key in
                     ("precision", "recall", "f1", "fp_rate", "fn_rate")]
                  if metrics is not None else ["—"] * 9)
        lines.append("| " + " | ".join([mode, row["status"], *values]) + " |")
    lines.extend(["", "## Coverage and run details", "",
                  f"Target: `{report['target']}`. Generated: {report['generated_at']}.", ""])
    for mode, row in report["modes"].items():
        if row.get("reason"):
            reason = str(row["reason"]).replace("\n", " ").replace("|", "\\|")
            lines.append(f"- {mode}: {reason}")
        elif row["status"] == "completed":
            lines.append(f"- {mode}: {row['candidates']} candidates; "
                         f"{row['model_calls']} model calls; "
                         f"{row['model_failures']} unusable replies.")
    for scanner, details in report["scanners"].items():
        if details["status"] == "completed":
            lines.append(f"- {scanner} {details['version']}: {details['hits']} raw hits; "
                         f"{details['matched_hits']} matched hits; "
                         f"{details['unmatched_hits']} unlabelled/unmatched hits.")
        else:
            lines.append(f"- {scanner}: {details['status']} ({details['reason']}).")
    lines.extend(["", "## Counts by class", "",
                  "| Class | Sites | Vulnerable | Safe |", "| --- | ---: | ---: | ---: |"])
    for cls, counts in summary["by_class"].items():
        lines.append(f"| {cls} | {counts['sites']} | {counts['vulnerable']} | {counts['safe']} |")
    for mode, row in report["modes"].items():
        if row["metrics"] is None:
            continue
        lines.extend(["", f"### {mode}: confusion counts by class", "",
                      "| Class | TP | FP | FN | TN |", "| --- | ---: | ---: | ---: | ---: |"])
        for cls, metrics in row["by_class"].items():
            lines.append(f"| {cls} | {metrics['tp']} | {metrics['fp']} | "
                         f"{metrics['fn']} | {metrics['tn']} |")
        lines.extend(["", f"### {mode}: confusion counts by corpus", "",
                      "| Corpus | TP | FP | FN | TN |", "| --- | ---: | ---: | ---: | ---: |"])
        for corpus, metrics in row.get("by_corpus", {}).items():
            lines.append(f"| {corpus} | {metrics['tp']} | {metrics['fp']} | "
                         f"{metrics['fn']} | {metrics['tn']} |")
    lines.extend(["", LIMITATION, "",
                  "Missing metrics mean **not run**, not zero. Zero denominators in completed "
                  "rows yield 0.0. JSON includes site decisions, source hashes and configuration.",
                  ""])
    return "\n".join(lines)


def write_report(
    report: dict[str, Any], out: str | Path, *, name: str = "ablation",
) -> tuple[Path, Path]:
    """Write matching UTF-8 artifacts; name must be a filename stem."""
    if not name or name in {".", ".."} or any(c in name for c in "/\\:"):
        raise ValueError("report name must be a filename stem")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    md, js = out / f"{name}.md", out / f"{name}.json"
    md.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    js.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                  encoding="utf-8", newline="\n")
    return md, js
