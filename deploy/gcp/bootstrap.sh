#!/usr/bin/env bash
# Reimplemented from PerpPulse's foundation/application patterns; see attribution docs.
set -euo pipefail

# Keep PROJECT_ID stable between preview and apply. The owner generates its suffix once.
PROJECT_ID="${PROJECT_ID:-pulseguard-<random-suffix>}"
BILLING_ACCOUNT="${BILLING_ACCOUNT:-}"
REGION="${GCP_REGION:-europe-west3}"
CONFIGURATION="${GCP_CONFIGURATION:-pulseguard-gcp}"
SERVICE="${GCP_SERVICE:-pulseguard}"
REPOSITORY="${GCP_REPOSITORY:-pulseguard}"
RUNTIME_ID="${GCP_RUNTIME_ID:-pulseguard-run}"
DEPLOYER_ID="${GCP_DEPLOYER_ID:-pulseguard-deployer}"
GUARD_ID="${GCP_GUARD_ID:-pulseguard-budget-guard}"
BUILDER_ID="${GCP_BUILDER_ID:-pulseguard-function-build}"
TRIGGER_ID="${GCP_TRIGGER_ID:-pulseguard-budget-trigger}"
POOL="${GCP_WIF_POOL:-pulseguard-github}"
PROVIDER="${GCP_WIF_PROVIDER_ID:-github}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-witold-andelie/PulseGuard}"
GITHUB_REF="${GCP_GITHUB_REF:-refs/heads/main}"
MUSE_SECRET="${GCP_MUSE_SECRET:-PG_PLAYGROUND_MUSE_API_KEY}"
NEMOTRON_SECRET="${GCP_NEMOTRON_SECRET:-PG_PLAYGROUND_NEMOTRON_API_KEY}"
TOPIC="${GCP_BUDGET_TOPIC:-pulseguard-budget}"
BUDGET_PUBLISHER="${GCP_BUDGET_PUBLISHER:-billing-budget-alert@system.gserviceaccount.com}"
FUNCTION="${GCP_BUDGET_FUNCTION:-pulseguard-budget-guard}"
BUDGET_NAME="${GCP_BUDGET_NAME:-PulseGuard trial USD 300}"
BUDGET_AMOUNT="${GCP_BUDGET_AMOUNT:-300USD}"
# Open-ended, cumulative period: a monthly reset would not cap a 90-day trial.
BUDGET_START_DATE="${GCP_BUDGET_START_DATE:-$(date -u +%Y-%m-01)}"
PLACEHOLDER_IMAGE="${GCP_PLACEHOLDER_IMAGE:-us-docker.pkg.dev/cloudrun/container/hello:latest}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
APPLY=false
case "${1:-}" in
    --yes) APPLY=true ;;
    ""|--dry-run) ;;
    *) printf 'Usage: bash deploy/gcp/bootstrap.sh [--dry-run|--yes]\n' >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { echo 'Only one argument is supported.' >&2; exit 2; }

printf 'Project: %s\nBilling account: %s\nRegion: %s\nConfiguration: %s\n' \
    "$PROJECT_ID" "${BILLING_ACCOUNT:-<required for --yes>}" "$REGION" "$CONFIGURATION"
cat <<EOF
Plan: create/reuse the project, link its billing, enable APIs, create Docker repository
$REPOSITORY, empty model secrets and scoped identities. Reserve private Cloud Run service
$SERVICE, configure GitHub OIDC for $GITHUB_REPOSITORY at $GITHUB_REF, and deploy the
project billing kill-switch. Create/update cumulative $BUDGET_AMOUNT budget '$BUDGET_NAME'
from $BUDGET_START_DATE with 50/90/100% alerts on $TOPIC (credits excluded).
No app image is built here. Secret values are never read. Default gcloud configuration
is never changed. Re-running --yes can relink disabled billing; do not rerun after shutdown.
EOF
if ! "$APPLY"; then
    echo 'Dry run only: no gcloud or other remote commands executed. Apply with --yes.'
    exit 0
fi
[[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || {
    echo 'Set PROJECT_ID to a stable, globally unique project id (6-30 characters).' >&2; exit 2;
}
: "${BILLING_ACCOUNT:?Set BILLING_ACCOUNT to the NEW free-trial billing account id}"
[[ "$CONFIGURATION" != default ]] || { echo 'The default configuration is forbidden.' >&2; exit 2; }
command -v gcloud >/dev/null
command -v python3 >/dev/null
gc() { gcloud --configuration="$CONFIGURATION" --project="$PROJECT_ID" --quiet "$@"; }

# Login credentials are shared by configurations; copy only the selected account name.
account="$(gcloud config get-value account 2>/dev/null)"
[[ -n "$account" && "$account" != '(unset)' ]] || { echo 'Run gcloud auth login first.' >&2; exit 2; }
if ! gcloud config configurations describe "$CONFIGURATION" >/dev/null 2>&1; then
    gcloud config configurations create "$CONFIGURATION" --no-activate
fi
gc config set account "$account"
gc config set project "$PROJECT_ID"
gc config set run/region "$REGION"
currency="$(gc billing accounts describe "$BILLING_ACCOUNT" --format='value(currencyCode)')"
[[ "$currency" == USD ]] || {
    echo 'This plan requires a USD billing account; budgets must use the account currency.' >&2; exit 2;
}
if ! gc projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    gc projects create "$PROJECT_ID" --name=PulseGuard
fi
gc billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
gc services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com \
    iam.googleapis.com iamcredentials.googleapis.com secretmanager.googleapis.com \
    cloudbilling.googleapis.com billingbudgets.googleapis.com pubsub.googleapis.com \
    cloudfunctions.googleapis.com eventarc.googleapis.com cloudresourcemanager.googleapis.com \
    storage.googleapis.com logging.googleapis.com
project_number="$(gc projects describe "$PROJECT_ID" --format='value(projectNumber)')"
runtime="$RUNTIME_ID@$PROJECT_ID.iam.gserviceaccount.com"
deployer="$DEPLOYER_ID@$PROJECT_ID.iam.gserviceaccount.com"
guard="$GUARD_ID@$PROJECT_ID.iam.gserviceaccount.com"
builder="$BUILDER_ID@$PROJECT_ID.iam.gserviceaccount.com"
trigger="$TRIGGER_ID@$PROJECT_ID.iam.gserviceaccount.com"
if ! gc artifacts repositories describe "$REPOSITORY" --location="$REGION" >/dev/null 2>&1; then
    gc artifacts repositories create "$REPOSITORY" --location="$REGION" --repository-format=docker
fi
for id in "$RUNTIME_ID" "$DEPLOYER_ID" "$GUARD_ID" "$BUILDER_ID" "$TRIGGER_ID"; do
    if ! gc iam service-accounts describe "$id@$PROJECT_ID.iam.gserviceaccount.com" >/dev/null 2>&1; then
        gc iam service-accounts create "$id" --display-name="$id"
    fi
done
for secret in "$MUSE_SECRET" "$NEMOTRON_SECRET"; do
    if ! gc secrets describe "$secret" >/dev/null 2>&1; then
        gc secrets create "$secret" --replication-policy=user-managed --locations="$REGION"
    fi
    gc secrets add-iam-policy-binding "$secret" --member="serviceAccount:$runtime" \
        --role=roles/secretmanager.secretAccessor
done
gc artifacts repositories add-iam-policy-binding "$REPOSITORY" --location="$REGION" \
    --member="serviceAccount:$deployer" --role=roles/artifactregistry.writer
gc iam service-accounts add-iam-policy-binding "$runtime" --member="serviceAccount:$deployer" \
    --role=roles/iam.serviceAccountUser

# A service must exist before service-level IAM can be granted. Never replace a running app.
if ! gc run services describe "$SERVICE" --region="$REGION" >/dev/null 2>&1; then
    digest="$(gc artifacts docker images describe "$PLACEHOLDER_IMAGE" --format='value(image_summary.digest)')"
    [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Invalid placeholder digest.' >&2; exit 1; }
    placeholder_repo="${PLACEHOLDER_IMAGE%%@*}"
    placeholder_repo="${placeholder_repo%:*}"
    gc run deploy "$SERVICE" --region="$REGION" --image="$placeholder_repo@$digest" \
        --service-account="$runtime" --no-allow-unauthenticated --min=0 --max=2 \
        --min-instances=0 --max-instances=2 \
        --cpu=2 --memory=2Gi --concurrency=20 --timeout=300 --port=8080
fi
gc run services add-iam-policy-binding "$SERVICE" --region="$REGION" \
    --member="serviceAccount:$deployer" --role=roles/run.admin

if ! gc iam workload-identity-pools describe "$POOL" --location=global >/dev/null 2>&1; then
    gc iam workload-identity-pools create "$POOL" --location=global --display-name=PulseGuard-GitHub
fi
provider_args=(--location=global --workload-identity-pool="$POOL"
    --issuer-uri=https://token.actions.githubusercontent.com
    --attribute-mapping='google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref'
    --attribute-condition="assertion.repository == '$GITHUB_REPOSITORY' && assertion.ref == '$GITHUB_REF'")
if gc iam workload-identity-pools providers describe "$PROVIDER" --location=global \
    --workload-identity-pool="$POOL" >/dev/null 2>&1; then
    gc iam workload-identity-pools providers update-oidc "$PROVIDER" "${provider_args[@]}"
else
    gc iam workload-identity-pools providers create-oidc "$PROVIDER" "${provider_args[@]}"
fi
gc iam service-accounts add-iam-policy-binding "$deployer" --role=roles/iam.workloadIdentityUser \
    --member="principalSet://iam.googleapis.com/projects/$project_number/locations/global/workloadIdentityPools/$POOL/attribute.repository/$GITHUB_REPOSITORY"

if ! gc pubsub topics describe "$TOPIC" >/dev/null 2>&1; then
    gc pubsub topics create "$TOPIC"
fi
gc pubsub topics add-iam-policy-binding "$TOPIC" \
    --member="serviceAccount:$BUDGET_PUBLISHER" --role=roles/pubsub.publisher
gc projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$guard" \
    --role=roles/billing.projectManager --condition=None
gc projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$trigger" \
    --role=roles/eventarc.eventReceiver --condition=None
gc projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$builder" \
    --role=roles/logging.logWriter --condition=None
gc artifacts repositories add-iam-policy-binding "$REPOSITORY" --location="$REGION" \
    --member="serviceAccount:$builder" --role=roles/artifactregistry.writer
# Restrict build source access to function-managed source/upload buckets in this project.
gc projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$builder" \
    --role=roles/storage.objectViewer \
    --condition='title=function-build-sources,expression=resource.type == "storage.googleapis.com/Object" && (resource.name.startsWith("projects/_/buckets/gcf-v2-sources-") || resource.name.startsWith("projects/_/buckets/gcf-v2-uploads-") || resource.name.startsWith("projects/_/buckets/run-sources-"))'
# Provision the Pub/Sub agent explicitly for a new project; authenticated Eventarc delivery.
gc beta services identity create --service=pubsub.googleapis.com
gc iam service-accounts add-iam-policy-binding "$trigger" \
    --member="serviceAccount:service-$project_number@gcp-sa-pubsub.iam.gserviceaccount.com" \
    --role=roles/iam.serviceAccountTokenCreator
gc functions deploy "$FUNCTION" --gen2 --region="$REGION" --runtime=python312 \
    --source="$ROOT/deploy/gcp/budget_guard" --entry-point=cap_spending \
    --service-account="$guard" --trigger-service-account="$trigger" --trigger-topic="$TOPIC" \
    --build-service-account="projects/$PROJECT_ID/serviceAccounts/$builder" \
    --docker-repository="projects/$PROJECT_ID/locations/$REGION/repositories/$REPOSITORY" \
    --set-env-vars="TARGET_PROJECT_ID=$PROJECT_ID,BUDGET_NAME=$BUDGET_NAME" \
    --min-instances=0 --max-instances=1 --memory=256Mi --timeout=60s --retry \
    --no-allow-unauthenticated
function_service="$(gc functions describe "$FUNCTION" --gen2 --region="$REGION" --format='value(serviceConfig.service)')"
gc run services add-iam-policy-binding "${function_service##*/}" --region="$REGION" \
    --member="serviceAccount:$trigger" --role=roles/run.invoker

# Preserve the first start date on reruns, including reruns in a later month.
budget_json="$(gc billing budgets list --billing-account="$BILLING_ACCOUNT" --format=json)"
budget_row="$(printf '%s' "$budget_json" | python3 -c '
import json, sys
matches = [b for b in json.load(sys.stdin) if b["displayName"] == sys.argv[1]]
if len(matches) > 1: raise SystemExit("Duplicate budget names; resolve them before rerunning")
if matches:
    b = matches[0]
    d = b["budgetFilter"]["customPeriod"]["startDate"]
    print(b["name"], "{year:04}-{month:02}-{day:02}".format(**d))
' "$BUDGET_NAME")"
budget_action=(create)
threshold_args=(--threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0)
if [[ -n "$budget_row" ]]; then
    read -r budget_id BUDGET_START_DATE <<< "$budget_row"
    budget_action=(update "$budget_id")
    threshold_args=(--threshold-rules-from-file="$ROOT/deploy/gcp/budget-thresholds.json")
fi
gc billing budgets "${budget_action[@]}" --billing-account="$BILLING_ACCOUNT" \
    --display-name="$BUDGET_NAME" --budget-amount="$BUDGET_AMOUNT" --start-date="$BUDGET_START_DATE" \
    --credit-types-treatment=exclude-all-credits --filter-projects="projects/$PROJECT_ID" \
    "${threshold_args[@]}" \
    --notifications-rule-pubsub-topic="projects/$PROJECT_ID/topics/$TOPIC"

printf '\nAdd each secret from a hidden terminal prompt (never put values in command history):\n'
printf 'set +x\n'
for secret in "$MUSE_SECRET" "$NEMOTRON_SECRET"; do
    printf "read -r -s -p 'Key for %s: ' key; printf '\\\\n'; printf '%%s' \"\$key\" | gcloud --configuration=%q --project=%q secrets versions add %q --data-file=-; unset key\n" \
        "$secret" "$CONFIGURATION" "$PROJECT_ID" "$secret"
done
provider_path="projects/$project_number/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER"
printf '\nGitHub repository variables (no keys):\n'
names=(GCP_PROJECT_ID GCP_REGION GCP_WIF_PROVIDER GCP_DEPLOYER_SA GCP_SERVICE)
values=("$PROJECT_ID" "$REGION" "$provider_path" "$deployer" "$SERVICE")
for i in "${!names[@]}"; do
    printf '%s=%s\n' "${names[$i]}" "${values[$i]}"
    printf 'gh variable set %q --repo %q --body %q\n' "${names[$i]}" "$GITHUB_REPOSITORY" "${values[$i]}"
done
echo 'Custom repository/runtime/secret names must also be passed to deploy.sh; see DEPLOYMENT.md.'
