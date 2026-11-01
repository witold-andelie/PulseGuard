#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-${PROJECT_ID:-}}"
REGION="${GCP_REGION:-europe-west3}"
SERVICE="${GCP_SERVICE:-pulseguard}"
REPOSITORY="${GCP_REPOSITORY:-pulseguard}"
RUNTIME_ID="${GCP_RUNTIME_ID:-pulseguard-run}"
MUSE_SECRET="${GCP_MUSE_SECRET:-PG_PLAYGROUND_MUSE_API_KEY}"
NEMOTRON_SECRET="${GCP_NEMOTRON_SECRET:-PG_PLAYGROUND_NEMOTRON_API_KEY}"
IMAGE_NAME="${GCP_IMAGE_NAME:-pulseguard}"
IMAGE_TAG="${GCP_IMAGE_TAG:-${GITHUB_SHA:-$(date -u +%Y%m%dT%H%M%SZ)}}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${PROJECT_ID:?Set GCP_PROJECT_ID or PROJECT_ID}"
[[ $# -eq 0 ]] || { echo 'Usage: bash deploy/gcp/deploy.sh' >&2; exit 2; }
# Local owner: GCP_CONFIGURATION=pulseguard-gcp. Actions uses setup-gcloud's isolated config.
gcloud_args=(--project="$PROJECT_ID" --quiet)
if [[ -n "${GCP_CONFIGURATION:-}" ]]; then
    gcloud_args+=(--configuration="$GCP_CONFIGURATION")
fi
gc() { gcloud "${gcloud_args[@]}" "$@"; }
registry="$REGION-docker.pkg.dev"
image="$registry/$PROJECT_ID/$REPOSITORY/$IMAGE_NAME"
metadata="$(mktemp)"
trap 'rm -f -- "$metadata"' EXIT
cd "$ROOT"
echo "Building $image:$IMAGE_TAG for $SERVICE in $REGION"
# Docker stores only a short-lived access token, never a service-account key.
gc auth print-access-token | docker login -u oauth2accesstoken --password-stdin "https://$registry"
# Append only the Cloud Run launch adapter; the Render Dockerfile remains unchanged.
{
    cat Dockerfile
    printf '\nCOPY deploy/gcp/health_cors.py /app/health_cors.py\n'
    # shellcheck disable=SC2016 # PORT must expand only when the container starts.
    printf '%s\n' 'CMD ["sh", "-c", "exec uvicorn health_cors:create_app --factory --host 0.0.0.0 --port \"$PORT\""]'
} | docker buildx build --platform=linux/amd64 --file=- --tag="$image:$IMAGE_TAG" \
    --metadata-file="$metadata" --push .
digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$metadata")"
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Build did not return a valid image digest.' >&2; exit 1; }
immutable="$image@$digest"
echo "Deploying immutable image $immutable"
gc run deploy "$SERVICE" --region="$REGION" --image="$immutable" \
    --service-account="$RUNTIME_ID@$PROJECT_ID.iam.gserviceaccount.com" \
    --allow-unauthenticated --port=8080 --min=0 --max=2 --min-instances=0 --max-instances=2 \
    --cpu-throttling \
    --cpu=2 --memory=2Gi --concurrency=20 --timeout=300 \
    --set-env-vars='PG_MODE=replay,PG_DB_PATH=/tmp/pulseguard.sqlite,PG_PLAYGROUND_MUSE_BASE_URL=https://opencode.ai/inference/go/openai/v1,PG_PLAYGROUND_MUSE_NAME=muse-spark-1.3-contributor,PG_PLAYGROUND_MUSE_SESSION_HEADER=x-opencode-session,PG_PLAYGROUND_NEMOTRON_BASE_URL=https://integrate.api.nvidia.com/v1,PG_PLAYGROUND_NEMOTRON_NAME=nvidia/nemotron-3-ultra-550b-a55b,PG_PLAYGROUND_NEMOTRON_STRUCTURED=off,PG_PLAYGROUND_DAILY_CALLS=1000' \
    --set-secrets="PG_PLAYGROUND_MUSE_API_KEY=$MUSE_SECRET:latest,PG_PLAYGROUND_NEMOTRON_API_KEY=$NEMOTRON_SECRET:latest"
url="$(gc run services describe "$SERVICE" --region="$REGION" --format='value(status.url)')"
[[ "$url" =~ ^https://[a-z0-9-]+(\.[a-z0-9-]+)*\.run\.app$ ]] || { echo 'Unexpected Cloud Run URL.' >&2; exit 1; }
for path in /health /api/mode; do
    # curl takes each long option and its value as separate words (no "=" form).
    code="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --connect-timeout 10 --max-time 60 "$url$path")"
    [[ "$code" == 200 ]] || { printf 'Smoke test %s returned %s\n' "$path" "$code" >&2; exit 1; }
done
GCP_SERVICE_URL="$url" python3 - <<'PY'
import json
import os
from pathlib import Path

Path("site/endpoints.json").write_text(json.dumps({
    "cloudRun": os.environ["GCP_SERVICE_URL"],
    "render": "https://pulseguard-dufi.onrender.com",
}, indent=2) + "\n", encoding="utf-8")
PY
printf 'Service URL: %s\n' "$url"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'service_url=%s\nimage=%s\n' "$url" "$immutable" >> "$GITHUB_OUTPUT"
fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    # shellcheck disable=SC2016 # Backticks are Markdown delimiters, not shell substitutions.
    printf 'Cloud Run: [%s](%s)\n\nImage: `%s`\n' "$url" "$url" "$immutable" >> "$GITHUB_STEP_SUMMARY"
fi
