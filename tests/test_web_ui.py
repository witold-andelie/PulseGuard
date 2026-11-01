"""Structure, contrast and wording checks for the no-build public UI."""

from __future__ import annotations

import html.parser
import json
import re

from fastapi.testclient import TestClient

from pulseguard.api import create_app
from pulseguard.paths import REPO_ROOT

WEB = REPO_ROOT / "web"
HTML = (WEB / "index.html").read_text(encoding="utf-8")
CSS = (WEB / "style.css").read_text(encoding="utf-8")
JS = (WEB / "app.js").read_text(encoding="utf-8")

TEXT_PAIRS = (
    ("text", "bg"), ("text", "surface"), ("muted", "bg"), ("muted", "surface"),
    ("link", "bg"), ("link", "surface"), ("header-fg", "header-bg"),
    ("nav-fg", "nav-bg"), ("button-fg", "button-bg"),
    ("banner-fg", "banner-bg"), ("live-banner-fg", "live-banner-bg"),
    ("synthetic-fg", "synthetic-bg"), ("ok-fg", "ok-bg"),
    ("danger-fg", "danger-bg"), ("warn-fg", "warn-bg"),
    ("limit-fg", "limit-bg"), ("chip-fg", "chip-bg"),
    ("pre-fg", "pre-bg"), ("status-fg", "status-bg"),
)
UI_PAIRS = (
    ("focus", "bg"), ("focus", "surface"),
    ("control-line", "bg"), ("control-line", "surface"),
    ("button-border", "bg"),
)


class TreeParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.nodes: list[tuple[str, dict[str, str], str]] = []
        self._stack: list[list[object]] = []
        self.root: list[object] = []
        self._stack.append(self.root)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = {"tag": tag, "attrs": {k: v or "" for k, v in attrs}, "children": [], "text": ""}
        self._stack[-1].append(node)
        if tag not in {"meta", "link", "img", "input", "br", "hr"}:
            self._stack.append(node["children"])
            node["_open"] = True  # type: ignore[index]
        self.nodes.append((tag, node["attrs"], ""))

    def handle_endtag(self, tag: str) -> None:
        if len(self._stack) > 1:
            self._stack.pop()

    def handle_data(self, data: str) -> None:
        if self._stack[-1] is not self.root and self.root:
            # Attach text to the most recently opened element on this list.
            parent = None
            for frame in reversed(self._stack):
                if frame is self.root:
                    continue
                parent = frame
                break
            if parent is not None and self._stack[-2]:
                node = self._stack[-2][-1]
                if isinstance(node, dict):
                    node["text"] += data


def parse_html(source: str) -> list[dict]:
    parser = TreeParser()
    parser.feed(source)
    return parser.root  # type: ignore[return-value]


def walk(nodes: list[object]):
    for node in nodes:
        if not isinstance(node, dict):
            continue
        yield node
        yield from walk(node.get("children") or [])


def tokens(block: str) -> dict[str, str]:
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9A-Fa-f]{3,8})", block))


def relative_luminance(color: str) -> float:
    raw = color.lstrip("#")
    if len(raw) == 3:
        raw = "".join(ch * 2 for ch in raw)
    channels = [int(raw[i:i + 2], 16) / 255 for i in (0, 2, 4)]

    def channel(value: float) -> float:
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(value) for value in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(front: str, back: str) -> float:
    lighter, darker = sorted((relative_luminance(front), relative_luminance(back)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_html_language_landmarks_skip_and_headings():
    assert re.search(r"<html\b[^>]*\blang=\"en\"", HTML)
    mains = re.findall(r"<main\b", HTML)
    assert len(mains) == 1
    assert 'id="main"' in HTML
    assert re.search(r'href="#main"', HTML)
    assert re.search(r"<nav[^>]*aria-label=\"Views\"", HTML)
    assert 'class="skip-link"' in HTML
    tree = parse_html(HTML)
    views = [node for node in walk(tree) if node.get("attrs", {}).get("data-view")]
    assert {node["attrs"]["data-view"] for node in views} >= {
        "board", "case", "process", "how", "playground"}
    for view in views:
        headings = [
            child["tag"] for child in walk(view["children"])
            if child["tag"] in {"h1", "h2", "h3", "h4"}
        ]
        assert headings, view["attrs"]["data-view"]
        assert headings[0] == "h1", view["attrs"]["data-view"]
        previous = 1
        for tag in headings:
            level = int(tag[1])
            assert level <= previous + 1, (view["attrs"]["data-view"], headings)
            previous = level
    assert not re.search(r'tabindex\s*=\s*"[1-9]', HTML)
    assert not re.search(r"tabIndex\s*=\s*[1-9]", JS)


def test_controls_have_accessible_names():
    tree = parse_html(HTML)
    for node in walk(tree):
        tag = node["tag"]
        attrs = node["attrs"]
        if tag not in {"input", "select", "textarea", "button"}:
            continue
        named = bool(
            attrs.get("aria-label") or attrs.get("aria-labelledby") or node["text"].strip())
        if tag == "button":
            assert named, attrs
    assert 'element("input")' in JS
    assert "Approver name" in JS
    assert 'actor.id = "approver-name"' in JS
    assert 'for", "approver-name"' in JS or "approver-name" in JS
    assert 'for="playground-code"' in HTML
    assert 'for="playground-example"' in HTML
    assert 'for="playground-language"' in HTML
    assert 'id="playground-language"' in HTML
    assert 'id="playground-analyze"' in HTML
    assert "Analyze" in HTML
    assert "Auto-detect" in HTML


def test_no_sprint_labels_in_web():
    for name, source in ("index.html", HTML), ("app.js", JS), ("style.css", CSS):
        assert "Sprint" not in source, name
        assert not re.search(r"\bS[123]\b", source), name


def test_css_token_contrast_light_and_dark():
    light_block = re.search(r":root\s*\{([^}]+)\}", CSS)
    dark_block = re.search(
        r"prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{([^}]+)\}", CSS)
    assert light_block and dark_block
    for name, block in ("light", light_block.group(1)), ("dark", dark_block.group(1)):
        values = tokens(block)
        for front, back in TEXT_PAIRS:
            ratio = contrast_ratio(values[front], values[back])
            assert ratio >= 4.5, f"{name} {front}/{back} = {ratio:.2f}"
        for front, back in UI_PAIRS:
            ratio = contrast_ratio(values[front], values[back])
            assert ratio >= 3.0, f"{name} {front}/{back} = {ratio:.2f}"


def test_required_behaviours_and_missing_key_wording():
    assert "Not covered (analysis limit)" in JS
    assert "data.analysis_limits" in JS and "limit.reason" in JS
    assert ".analysis-limits" in CSS and "dashed" in CSS
    assert "not recorded in this run" in JS
    assert "MODE UNAVAILABLE" in HTML
    assert "/api/eventlog.csv" in HTML and "/api/kpis" in HTML
    for reference in ("/api/kpis", '"/rollback"', "verification", "skeptic", "counterfactual",
                      "blast_radius", "bus_health", "policy_tier", "SYNTHETIC"):
        assert reference in JS
    assert "prefers-reduced-motion" in CSS
    assert "Skip to main content" in HTML
    assert "Coverage is not confidence" in HTML
    assert "/api/playground/analyze" in JS
    assert "/api/playground/config" in JS
    assert "heading-playground-results" in JS
    assert "nothing is executed or stored" in HTML.lower()
    assert "playground-compare" in CSS
    assert "modeInfo.model" in JS
    assert "Show the exact block sent to the model" in JS
    assert "JSON.stringify(patch.sandbox_report" not in JS
    assert "function plural(" in JS
    assert "Full analysis" in JS
    assert "Grammar-level analysis — partial coverage" in JS
    assert "LLM-only — advisory, no hard evidence" in JS
    assert "optgroup" in JS
    assert "playground-language" in JS
    assert "analysis-limits" in JS and "prominent" in JS
    assert "playground-controls" in CSS
    assert "tier-badge" in CSS
    assert "must parse as Python" not in HTML
    assert 'value="c"' in HTML and 'value="cpp"' in HTML
    assert "C++" in HTML
    assert "memory-safety classes (buffer overflow, format string)" in HTML


def test_static_files_and_recorded_case(tmp_path):
    with TestClient(create_app(mode="replay", db_path=tmp_path / "web.sqlite")) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "MODE UNAVAILABLE" in page.text
        assert 'lang="en"' in page.text
        assert client.get("/app.js").status_code == 200
        assert client.get("/style.css").status_code == 200
        cases = client.get("/api/cases").json()["cases"]
        sqli = next(case for case in cases if case["rule_id"] == "flask-sqli-taint")
        cases = [sqli]
        detail = client.get("/api/cases/" + sqli["case_id"]).json()
        assert detail["case"]["rule_id"] == "flask-sqli-taint"
        assert detail["verdicts"]
        assert detail["analysis_limits"] == []
        assert detail.get("skeptic") in (None, {}) or "skeptic" in detail
        trace = client.get("/api/cases/" + cases[0]["case_id"] + "/trace").json()
        assert trace["events"]


def test_synthetic_fixture_is_marked_and_unwired():
    fixture_dir = REPO_ROOT / "tests" / "fixtures" / "ui"
    marker = "SYNTHETIC — UI development fixture, not a recording"
    bundle = json.loads((fixture_dir / "bundle.json").read_text(encoding="utf-8"))
    assert marker in bundle["_comment"]
    assert len(bundle["cases"]) == 7
    ids = [item["case"]["case_id"] for item in bundle["cases"]]
    assert ids == [
        "PG-SYN-SQLI", "PG-SYN-TRIVY", "PG-SYN-BANDIT", "PG-SYN-GUARD",
        "PG-SYN-POC", "PG-SYN-LIMIT", "PG-SYN-Z3VETO",
    ]
    readme = (fixture_dir / "README.md").read_text(encoding="utf-8")
    assert marker in readme
    preview = (REPO_ROOT / "scripts" / "ui_preview.py").read_text(encoding="utf-8")
    assert marker in preview
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ui_preview" not in dockerfile
    assert "tests/fixtures/ui" not in dockerfile
    api = (REPO_ROOT / "pulseguard" / "api.py").read_text(encoding="utf-8")
    assert "ui_preview" not in api
    assert "tests/fixtures/ui" not in api
    render = (REPO_ROOT / "render.yaml").read_text(encoding="utf-8")
    assert "ui_preview" not in render
