"""Daily dual-deployment check. Only a complete outage returns a failure."""

import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from deploy.gcp.pages_endpoint import RENDER, ROOT, cloud_run_url


def status(url: str) -> int:
    for _ in range(2):
        try:
            with urllib.request.urlopen(url, timeout=45) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
    return 0


def check(endpoints: dict, probe=status) -> tuple[str, bool]:
    deployments = {"Cloud Run": cloud_run_url(endpoints.get("cloudRun")), "Render": RENDER}
    table = ["| Deployment | /health | /api/mode | Status |", "| --- | --- | --- | --- |"]
    any_healthy = False
    for name, url in deployments.items():
        if not url:
            table.append(f"| {name} | — | — | Not configured (expected) |")
            continue
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes = list(pool.map(probe, [url + "/health", url + "/api/mode"]))
        healthy = codes == [200, 200]
        any_healthy |= healthy
        table.append(f"| {name} | {codes[0]} | {codes[1]} | {'Healthy' if healthy else 'Down'} |")
    return "\n".join(table) + "\n", any_healthy


def main() -> None:
    table, healthy = check(json.loads((ROOT / "site/endpoints.json").read_text(encoding="utf-8")))
    print(table)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as output:
            output.write(table)
    if not healthy:
        raise SystemExit("Both deployments are unavailable")


if __name__ == "__main__":
    main()
