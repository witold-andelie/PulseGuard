"""Recover only endpoint JSON from a trusted deployment artifact, without a bot commit."""

import io
import json
import os
import re
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

RENDER = "https://pulseguard-dufi.onrender.com"
ROOT = Path(__file__).resolve().parents[2]


def cloud_run_url(value) -> str:
    return value if isinstance(value, str) and re.fullmatch(
        r"https://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.run\.app", value
    ) else ""


def get(url: str, token: str) -> bytes:
    # Fetch GitHub's pre-signed artifact redirect without forwarding its bearer token.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code != 302:
            raise
        location = exc.headers["Location"]
        if not location.startswith("https://"):
            raise ValueError("Artifact redirect must use HTTPS") from exc
        with urllib.request.urlopen(location, timeout=20) as response:
            return response.read()


def latest_endpoint(repository: str, token: str) -> str:
    api = f"https://api.github.com/repos/{repository}"
    runs = json.loads(get(
        f"{api}/actions/workflows/deploy-gcp.yml/runs?status=success&branch=main&per_page=30", token
    ))
    for run in runs["workflow_runs"]:
        if run["head_repository"]["full_name"] != repository or run["head_branch"] != "main":
            continue
        artifacts = json.loads(get(f"{api}/actions/runs/{run['id']}/artifacts", token))
        for artifact in artifacts["artifacts"]:
            if artifact["name"] != "gcp-endpoint" or artifact["expired"]:
                continue
            archive = get(f"{api}/actions/artifacts/{artifact['id']}/zip", token)
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                info = bundle.getinfo("endpoints.json")
                if info.file_size > 4096:
                    raise ValueError("Endpoint artifact is too large")
                return cloud_run_url(json.loads(bundle.read(info)).get("cloudRun"))
    return ""


def publish_endpoint(url: str, root: Path = ROOT) -> None:
    url = cloud_run_url(url)
    (root / "site/endpoints.json").write_text(
        json.dumps({"cloudRun": url, "render": RENDER}, indent=2) + "\n", encoding="utf-8"
    )
    page = root / "site/index.html"
    text = page.read_text(encoding="utf-8")
    if url:
        text = text.replace('id="cloud-run-link" hidden href="#"',
                            f'id="cloud-run-link" href="{url}"')
        text = text.replace("Google Cloud link appears after its first deployment.",
                            "Choose either deployment, or wait for the automatic health check.")
    page.write_text(text, encoding="utf-8")


def main() -> None:
    try:
        url = latest_endpoint(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])
    except (urllib.error.URLError, TimeoutError, KeyError, TypeError, AttributeError,
            ValueError, zipfile.BadZipFile):
        print("::notice::No usable GCP endpoint artifact; publishing Render fallback.")
        url = ""
    publish_endpoint(url)


if __name__ == "__main__":
    main()
