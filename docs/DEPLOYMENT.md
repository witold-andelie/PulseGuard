# Cloud Run alongside Render

This is an optional ST-3 deployment. Render at <https://pulseguard-dufi.onrender.com>
and the existing CI workflow continue independently. No infrastructure is provisioned by
the test suite. `bootstrap.sh` previews locally by default; only an owner running `--yes`
creates resources. The scripts were prepared without running gcloud, gh or Docker.

## Architecture and failover

```text
Browser -> GitHub Pages: https://witold-andelie.github.io/PulseGuard/
              | GET Cloud Run /health (15-second deadline)
              +-- HTTP 200 --> Cloud Run (europe-west3, REPLAY)
              +-- anything else --> existing Render (Frankfurt, REPLAY)

Push main -> existing CI succeeds -> Deploy GCP (GitHub OIDC -> deployer)
             -> buildx push -> image@sha256:... -> Cloud Run -> smoke tests
             -> endpoint artifact -> Pages publishes site/endpoints.json

Cumulative project budget -> Pub/Sub -> gen2 budget guard -> unlink project billing
Daily health workflow -> both deployments /health and /api/mode -> job summary
```

The Pages front door selects Cloud Run only when its `/health` returns an observable
HTTP 200. It falls back on a timeout, a platform error, a failed CORS check or a missing
endpoint configuration. Configuration fetching also has a 15-second deadline, including
the response body. Links and a status remain visible during the probe; a stop button
cancels automatic navigation. Without JavaScript, published pages contain ordinary links
to both deployments after the first successful GCP deployment. Before that, Render is
the available link. An expired/missing endpoint artifact publishes a Render-only page.
No model keys or credentials are sent to the browser.

Browsers need CORS to read Cloud Run's health status. `deploy/gcp/health_cors.py` is a
Cloud Run-only ASGI launch adapter, added to the image by `deploy.sh`. It permits only
`GET /health` from `https://witold-andelie.github.io`, preserves response status/body,
and disables caching for that probe. It does not enable cross-origin application APIs.
The application source, root Dockerfile and Render settings are unchanged.

Fallback happens on each visit to the **Pages URL**. A browser already inside Cloud Run
must revisit the front door if Cloud Run stops; existing requests/sessions are not migrated.
Direct Cloud Run bookmarks do not automatically fail over. Render may need time to wake
up from its free-plan idle state. Its permanent direct link remains available even if
Pages or JavaScript is unavailable. The deployments have separate ephemeral SQLite files;
they rebuild from the same replay bundle and do not share Playground counters or state.

## Identities and resource boundaries

| Identity | Grants |
| --- | --- |
| `pulseguard-run` | `secretmanager.secretAccessor` on the two model secrets only; no project roles |
| `pulseguard-deployer` | `run.admin` on the PulseGuard service; `artifactregistry.writer` on the PulseGuard repo; `iam.serviceAccountUser` on the runtime identity only |
| GitHub WIF principal | `iam.workloadIdentityUser` on deployer; provider condition requires repository `witold-andelie/PulseGuard` and ref `refs/heads/main` |
| `pulseguard-budget-guard` | `billing.projectManager` on this project only; no billing-account role |
| `pulseguard-budget-trigger` | Project `eventarc.eventReceiver`; `run.invoker` on the budget function's backing service only |
| `pulseguard-function-build` | Project `logging.logWriter`; repo `artifactregistry.writer`; conditional source-object reads for function-managed buckets in this project |
| Pub/Sub service agent | Token creation on the trigger identity only, for authenticated event delivery |
| Google budget publisher `billing-budget-alert@system.gserviceaccount.com` | Publish on the budget topic only |

Google-managed service agents also receive their platform-managed roles. Bootstrap is
run by the logged-in owner, who needs project creation, billing linkage, service/IAM
administration and billing-budget administration permissions. The GitHub deployer cannot
bootstrap other services or administer budgets. App builds run on GitHub's runner with
docker buildx; Cloud Build is used only for the bootstrap function build.

Service-level IAM needs an existing service. Bootstrap reserves it with Google's public
Cloud Run hello container, resolving its digest first. That placeholder is **private**, has
zero minimum instances, and is never published as the front-door endpoint. Bootstrap
does not replace an already-existing service. The first app deployment makes the service
public after model secret versions are present.

## Cost guardrails and trial expiry

Keep the **new Free Trial billing account unupgraded**. Google documents that its $300
credit lasts 90 days, and that exhausting it or reaching day 90 closes the unupgraded
trial account and stops its resources. There is no automatic paid upgrade or Google
Cloud usage charge during that unupgraded trial. See Google's
[Free Trial terms and expiry behavior](https://docs.cloud.google.com/free/docs/free-cloud-features).

The project budget is **300 USD cumulative by default** (`GCP_BUDGET_UNITS`, `GCP_BUDGET_CURRENCY`), starting on the first day of the bootstrap
month, with no end date or monthly reset. Re-running bootstrap preserves its original
start date. All credits are excluded from the budget calculation, so the budget measures
gross project consumption even while promotional credit pays for it. Thresholds are
50%, 90% and 100%, with default billing-recipient emails and Pub/Sub notifications.
Google requires budgets to use the billing account currency; bootstrap rejects an
account whose currency differs from `GCP_BUDGET_CURRENCY` rather than silently creating
a different currency budget. For a EUR trial account set `GCP_BUDGET_CURRENCY=EUR` and
`GCP_BUDGET_UNITS` to the EUR value of the trial credit. See
[budget flags](https://docs.cloud.google.com/sdk/gcloud/reference/billing/budgets/create).

The gen2 Python budget guard validates the configured budget name, currency and
finite actual amounts, then unlinks billing from its configured project when
`costAmount >= budgetAmount`. Forecasts and other budget names do not trigger shutdown.
The target project never comes from the notification. Already-disabled billing is a
no-op; API errors propagate for retries. Its own service account can disable only this
project's billing. It runs in the same project and will stop too when billing is disabled.
The approach follows Google's
[billing shutdown pattern](https://docs.cloud.google.com/billing/docs/how-to/disable-billing-with-notifications).

Budget reporting and Pub/Sub delivery are delayed; this is **not an exact $300 hard cap**.
The guard can overshoot or be unavailable, including after Google has already stopped the
project. The unupgraded Free Trial is the no-charge boundary. Upgrading the account removes
that protection and is outside this plan. Do not rerun bootstrap after shutdown: its
explicit billing-link step can re-enable billing on a still-open account.

Cloud Run keeps minimum 1 (`GCP_MIN_INSTANCES`, set 0 to scale to zero), maximum 2 instances at both service and revision level, 2 vCPU, 2 GiB, concurrency 20,
request timeout 300 seconds and request-based CPU billing. Revision overlap/platform
scaling can temporarily exceed the configured instance limit. See Google's
[maximum instance guidance](https://docs.cloud.google.com/run/docs/configuring/max-instances).
Registry storage,
function builds, logs, secrets and network usage can also consume credit. The budget
function has min 0 and max 1. One warm Cloud Run instance is billed while idle (roughly EUR 20-30 a month, paid from the trial
credit); it removes an ~8 s cold start that otherwise sends front-door visitors to Render.
No always-on SQL, load balancer or paid front-door service is added. Public unauthenticated traffic consumes credit. Playground's 1000 daily calls
are **per process** and reset on restart, so they are not an account-wide model spend
cap. Muse/NVIDIA provider charges are independent of Google Cloud trial credit.

On day 90, or earlier credit exhaustion, Pages stays hosted on GitHub and selects Render
as soon as the Cloud Run probe fails. It needs no Google credentials, timer or manual
change to do so. GitHub OIDC/authentication failures are noticed and skipped; deployment
errors explicitly identifying disabled/closed/suspended billing are also noticed and
skipped. Other build or smoke-test failures fail the GCP workflow for investigation.
The original CI and Render deployment are unaffected. The daily health job is green if
either deployment returns 200 from **both** endpoints, and fails only when neither does.

## Owner steps, in order

Use Bash (Git Bash, WSL or Linux), Python 3, a current Google Cloud SDK, GitHub CLI and
Docker with buildx for any local app deployment. `gcloud auth login` is already complete.
Review and merge these changes to `main` through your normal process before using the
new workflows. Nothing in this change commits, pushes, runs a cloud CLI or alters Render.

1. Confirm in the billing console that this is the new **unupgraded** trial, that its
   currency (set `GCP_BUDGET_CURRENCY`/`GCP_BUDGET_UNITS` to match), and note its real signup/expiry date. Generate a project id once;
   retain the same exported value for preview, apply and future owner commands:

   ```bash
   export PROJECT_ID="pulseguard-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
   export BILLING_ACCOUNT='REPLACE_WITH_NEW_TRIAL_BILLING_ACCOUNT_ID'
   export GCP_REGION=europe-west3
   bash deploy/gcp/bootstrap.sh
   bash deploy/gcp/bootstrap.sh --yes
   ```

   The preview makes **no remote calls**. Apply creates or reuses resources and updates
   grants, provider condition, function and budget. A failed apply can be rerun with
   the same project id while the trial is active; investigate the reported error first.
   New-project IAM/service-agent propagation can require a retry. No model secret
   values are read or generated. `pulseguard-gcp` is created with `--no-activate`;
   the selected/default gcloud configuration is never changed.

2. Add one version to each empty secret. Run in an interactive terminal with shell
   tracing disabled; enter the key at the hidden prompt, then Enter. Values travel
   over stdin, without appearing in history, output, arguments or repository files:

   ```bash
   set +x
   for secret in PG_PLAYGROUND_MUSE_API_KEY PG_PLAYGROUND_NEMOTRON_API_KEY; do
     read -r -s -p "Key for $secret: " key
     printf '\n'
     printf '%s' "$key" | gcloud --configuration=pulseguard-gcp --project="$PROJECT_ID" \
       secrets versions add "$secret" --data-file=-
     unset key
   done
   ```

   `--set-secrets` exposes those values only inside the Cloud Run runtime process.
   They are environment mappings because the existing application reads environment
   variables, not secret files. `latest` is resolved when an instance starts; add a new
   version and redeploy to rotate. An empty secret prevents app startup.

3. Set the five repository **variables**, using the exact `gh variable set` commands
   printed by bootstrap. Equivalent commands for the defaults are:

   ```bash
   PROJECT_NUMBER="$(gcloud --configuration=pulseguard-gcp --project="$PROJECT_ID" \
     projects describe "$PROJECT_ID" --format='value(projectNumber)')"
   gh variable set GCP_PROJECT_ID --repo witold-andelie/PulseGuard --body "$PROJECT_ID"
   gh variable set GCP_REGION --repo witold-andelie/PulseGuard --body europe-west3
   gh variable set GCP_WIF_PROVIDER --repo witold-andelie/PulseGuard \
     --body "projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/pulseguard-github/providers/github"
   gh variable set GCP_DEPLOYER_SA --repo witold-andelie/PulseGuard \
     --body "pulseguard-deployer@$PROJECT_ID.iam.gserviceaccount.com"
   gh variable set GCP_SERVICE --repo witold-andelie/PulseGuard --body pulseguard
   ```

   No Google service-account JSON key or GitHub secret is needed. Missing variables
   cause a notice and a successful no-op GCP job. WIF accepts `main` only; manual
   workflow dispatches must select `main`. Automatic deployment uses the exact SHA of
   a successful CI **push**, excluding pull requests and forks. `workflow_dispatch` is
   the explicit owner override and does not wait for a separate CI run.

4. Enable Pages once: **Repository Settings → Pages → Build and deployment → Source:
   GitHub Actions**. Allow the `github-pages` environment to deploy from `main` and
   ensure Actions are enabled. Then start the initial deployment:

   ```bash
   gh workflow run deploy-gcp.yml --repo witold-andelie/PulseGuard --ref main
   ```

   After the GCP run succeeds, its endpoint artifact triggers Pages publication.
   The service URL and immutable digest appear in the GCP job summary. Check the Pages
   workflow; if it ran before Pages was enabled, rerun it with:

   ```bash
   gh workflow run pages.yml --repo witold-andelie/PulseGuard --ref main
   gh workflow run health.yml --repo witold-andelie/PulseGuard --ref main
   ```

   Open <https://witold-andelie.github.io/PulseGuard/>. Confirm Cloud Run is selected,
   stop the redirect to inspect both links, disable JavaScript to inspect the ordinary
   links, and block the Cloud Run hostname in browser devtools to verify Render fallback.
   This outage simulation requires no cloud shutdown. Check keyboard focus, screen-reader
   announcements and both system color themes.

5. Verify the budget's project scope, amount and currency, cumulative period, excluded credits,
   thresholds, publisher grant and Eventarc delivery in the console. Check guard logs
   for received notifications. A synthetic event at/above the threshold **actually unlinks
   billing**; use local unit tests for that decision, not a live threshold message.
   Confirm no project-wide runtime/deployer roles were inherited. Keep Render live.

The app's non-secret Playground settings match the supplied owner settings: Muse base
`https://opencode.ai/inference/go/openai/v1`, model `muse-spark-1.3-contributor`, session
header `x-opencode-session`; Nemotron base `https://integrate.api.nvidia.com/v1`, model
`nvidia/nemotron-3-ultra-550b-a55b`, structured output `off`; daily calls `1000`.
`PG_MODE=replay` and `PG_DB_PATH=/tmp/pulseguard.sqlite` are set on every app deploy.

All bootstrap resource names have defaults at the top of the script. If you change the
repo/runtime/secret defaults, pass the matching `GCP_REPOSITORY`, `GCP_RUNTIME_ID`,
`GCP_MUSE_SECRET` and `GCP_NEMOTRON_SECRET` to `deploy.sh` and add those overrides to the
deployment workflow environment. The five printed GitHub variables cover the default
layout. Changing the repository/Pages owner also requires updating the CORS origin and
published Pages URL. The hardcoded fallback remains this existing Render service.

## Endpoint publication and local checks

`deploy.sh` writes `site/endpoints.json` only after both smoke tests pass; the workflow
uploads that single file as `gcp-endpoint` for 90 days. Pages and health jobs recover the
latest usable artifact from successful main-branch deployment runs in this repository.
They do not trust fork artifacts, execute downloaded code, forward tokens to artifact
storage, or commit generated files. Pages injects the validated URL into the ordinary
HTML link too, so no-JavaScript navigation works. If recovery fails, Render is retained.
Artifact recovery searches the most recent 30 successful deployment runs; a long series
of skipped runs or expired artifacts intentionally degrades to Render-only operation.

Local app deployment, if needed instead of Actions (this updates generated endpoint JSON
in the local checkout but does not publish Pages):

```bash
GCP_CONFIGURATION=pulseguard-gcp GCP_PROJECT_ID="$PROJECT_ID" bash deploy/gcp/deploy.sh
```

Local validation, using your existing environment:

```bash
python -m pytest -q -rs
python -m ruff check .
node tests/front_door.test.mjs
shellcheck deploy/gcp/bootstrap.sh deploy/gcp/deploy.sh
actionlint .github/workflows/deploy-gcp.yml .github/workflows/pages.yml .github/workflows/health.yml
```

Pytest parses the new workflow YAML, exercises budget decisions with fake CloudEvents,
checks the Cloud Run-only health adapter and artifact/health policies without network,
and runs the pure JavaScript suite with Node. Bash tests only parse scripts and execute
the bootstrap's default dry-run. No tests execute gcloud, gh, Docker or a remote probe.
Where a tool/runtime is unavailable, report its skip and run that check on Linux.

## Rollback and removal

For immediate demo access, use the existing Render link. To stop Cloud Run being chosen,
the owner can remove public invocation, making `/health` fail for anonymous browsers:

```bash
gcloud --configuration=pulseguard-gcp --project="$PROJECT_ID" run services remove-iam-policy-binding \
  pulseguard --region=europe-west3 --member=allUsers --role=roles/run.invoker
gh workflow disable deploy-gcp.yml --repo witold-andelie/PulseGuard
```

Disable automatic GCP deployment first if recovering an older healthy revision. List
revisions, select a previously verified one, then route traffic to it:

```bash
gcloud --configuration=pulseguard-gcp --project="$PROJECT_ID" run revisions list \
  --service=pulseguard --region=europe-west3
gcloud --configuration=pulseguard-gcp --project="$PROJECT_ID" run services update-traffic \
  pulseguard --region=europe-west3 --to-revisions=REPLACE_WITH_VERIFIED_REVISION=100
```

Image digests in job summaries allow the owner to redeploy a previously verified image.
SQLite is ephemeral; replay data is reseeded rather than migrated. For a deliberate
project shutdown, unlink its billing:

```bash
gcloud --configuration=pulseguard-gcp --project="$PROJECT_ID" billing projects unlink "$PROJECT_ID"
```

This also stops the budget function and other billable project resources. Leave the
trial account unupgraded; do not rerun bootstrap or relink billing afterward. Deleting
GCP resources or the project can be done later by the owner after reviewing retention
needs. Keep Pages, Render, and the original CI workflow enabled. No existing Render
resources, secrets or deploy settings need changing for this plan.
