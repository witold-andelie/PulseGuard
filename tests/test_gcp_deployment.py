"""Local infrastructure contracts; no cloud/GitHub/Docker subprocesses or network calls."""

import io
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from deploy.gcp.health_check import check
from deploy.gcp.health_cors import HealthCors, create_app
from deploy.gcp.pages_endpoint import RENDER, cloud_run_url, latest_endpoint, publish_endpoint
from pulseguard.api import create_app as app_factory

ROOT = Path(__file__).resolve().parents[1]
CLOUD = "https://pulseguard-123.europe-west3.run.app"


@pytest.mark.parametrize("name", ["deploy-gcp", "pages", "health"])
def test_workflow_yaml_and_action_pins(name):
    workflow = yaml.safe_load((ROOT / f".github/workflows/{name}.yml").read_text())
    assert "on" in workflow and "jobs" in workflow
    for job in workflow["jobs"].values():
        assert job["timeout-minutes"] > 0
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])


def test_gcp_workflow_only_uses_trusted_ci_push_and_oidc():
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy-gcp.yml").read_text())
    assert workflow["on"]["workflow_run"]["workflows"] == ["CI"]
    assert workflow["on"]["workflow_run"]["branches"] == ["main"]
    assert workflow["permissions"] == {"id-token": "write", "contents": "read"}
    gate = workflow["jobs"]["deploy"]["if"]
    assert "conclusion == 'success'" in gate
    assert "event == 'push'" in gate
    assert "head_repository.full_name == github.repository" in gate


def test_budget_update_thresholds_replace_instead_of_accumulating():
    thresholds = json.loads((ROOT / "deploy/gcp/budget-thresholds.json").read_text())
    assert [rule["thresholdPercent"] for rule in thresholds] == [0.5, 0.9, 1.0]
    assert all(rule["spendBasis"] == "CURRENT_SPEND" for rule in thresholds)


def test_front_door_node_suite():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable; front-door JavaScript tests need Node >=18")
    # Run the node:test module directly so restricted Windows runners need no child isolation.
    result = subprocess.run([node, "tests/front_door.test.mjs"], cwd=ROOT,
                            capture_output=True, text=True, encoding="utf-8", timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


def test_shell_syntax_and_bootstrap_dry_run():
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash is unavailable")
    for path in ["deploy/gcp/bootstrap.sh", "deploy/gcp/deploy.sh"]:
        result = subprocess.run([bash, "-n", path], cwd=ROOT, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=10)
        if result.returncode and "CreateFileMapping" in result.stderr:
            pytest.skip("Windows sandbox blocks MSYS Bash shared-memory startup")
        assert result.returncode == 0, result.stderr
    # The default path exits before invoking gcloud, even if no account/SDK is configured.
    result = subprocess.run([bash, "deploy/gcp/bootstrap.sh"], cwd=ROOT,
                            capture_output=True, text=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr
    assert "no gcloud or other remote commands executed" in result.stdout


@pytest.mark.parametrize("path,origin,allowed", [
    ("/health", "https://witold-andelie.github.io", True),
    ("/health", "https://evil.example", False),
    ("/api/mode", "https://witold-andelie.github.io", False),
])
def test_cloud_run_health_cors_is_narrow_and_preserves_payload(tmp_path, path, origin, allowed):
    base = app_factory(db_path=tmp_path / "cases.sqlite")
    with TestClient(base) as original, TestClient(HealthCors(base)) as wrapped:
        expected = original.get(path)
        response = wrapped.get(path, headers={"Origin": origin})
        assert response.status_code == expected.status_code
        assert response.json() == expected.json()
        assert ("access-control-allow-origin" in response.headers) is allowed
        if allowed:
            assert response.headers["access-control-allow-origin"] == origin
            assert response.headers["cache-control"] == "no-store"


def test_cloud_run_factory_uses_original_app(monkeypatch, tmp_path):
    monkeypatch.setenv("PG_DB_PATH", str(tmp_path / "cases.sqlite"))
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200


def test_health_failure_only_when_no_complete_deployment_is_healthy():
    endpoints = {"cloudRun": CLOUD}
    table, healthy = check(endpoints, lambda url: 503 if url.startswith(CLOUD) else 200)
    assert healthy and "Cloud Run | 503 | 503 | Down" in table
    assert check(endpoints, lambda url: 200 if url.startswith(CLOUD) else 503)[1]
    assert not check(endpoints, lambda url: 503)[1]
    assert not check(endpoints, lambda url: 200 if url.endswith("/health") else 503)[1]
    assert check({}, lambda _: 200)[1]


def test_published_endpoint_also_populates_no_js_link(tmp_path):
    (tmp_path / "site").mkdir()
    shutil.copyfile(ROOT / "site/index.html", tmp_path / "site/index.html")
    publish_endpoint(CLOUD, tmp_path)
    assert json.loads((tmp_path / "site/endpoints.json").read_text()) == {
        "cloudRun": CLOUD, "render": RENDER,
    }
    html = (tmp_path / "site/index.html").read_text()
    assert f'id="cloud-run-link" href="{CLOUD}"' in html
    assert f'href="{RENDER}"' in html
    assert "<noscript>" in html and 'role="status"' in html


@pytest.mark.parametrize("value", [None, "", "http://x.run.app", "https://x.run.app.evil.test",
                                  "https://x.run.app/", "javascript:alert(1)"])
def test_endpoint_validation(value):
    assert cloud_run_url(value) == ""


@pytest.mark.parametrize("url", [CLOUD, "https://pulseguard-abcdefgh-ey.a.run.app"])
def test_supported_cloud_run_url_formats(url):
    assert cloud_run_url(url) == url


def test_artifact_loader_skips_forks_and_expired_artifacts(monkeypatch):
    repository = "witold-andelie/PulseGuard"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("endpoints.json", json.dumps({"cloudRun": CLOUD}))
    replies = iter([
        json.dumps({"workflow_runs": [
            {"head_repository": {"full_name": "fork/repo"}, "head_branch": "main", "id": 1},
            {"head_repository": {"full_name": repository}, "head_branch": "main", "id": 2},
        ]}).encode(),
        json.dumps({"artifacts": [
            {"name": "gcp-endpoint", "expired": True, "id": 3},
            {"name": "gcp-endpoint", "expired": False, "id": 4},
        ]}).encode(), archive.getvalue(),
    ])
    monkeypatch.setattr("deploy.gcp.pages_endpoint.get", lambda *_: next(replies))
    assert latest_endpoint(repository, "fake-token") == CLOUD
