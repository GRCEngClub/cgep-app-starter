#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>] [--region <r>]
# Chain-of-custody check for one pipeline run. Three checks:
#   1. integrity     SHA-256 of the bundle matches the stored hash
#   2. authenticity  cosign verifies the signature came from THIS repo's grc-gate workflow
#   3. preservation  Object Lock retention on the bundle has not expired
# Prints "CHAIN INTACT" only if all three pass. Needs: aws CLI, cosign v2.x.
set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>] [--region <r>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-acme-health-intake-evidence-08fa0596}"
REGION="${AWS_REGION:-ca-central-1}"
PROFILE_ARG=""
# Only signatures made by this repo's grc-gate workflow (main or a PR merge ref) are accepted.
IDENTITY_REGEXP="${CERT_IDENTITY_REGEXP:-^https://github.com/RookwoodRan/rani-cgep-app-starter/.github/workflows/grc-gate.yml@refs/(heads/main|pull/[0-9]+/merge)$}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    --region)  REGION="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

# shellcheck disable=SC2086
aws $PROFILE_ARG --region "$REGION" s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json" >/dev/null

BUNDLE=$(ls evidence-*.tar.gz | head -1)
echo "Run ${RUN_ID}: ${BUNDLE}"

# 1. Integrity
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$($SHASUM "${BUNDLE}" | awk '{print $1}')
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  echo "FAIL: integrity - SHA-256 mismatch (bundle was altered)"; exit 1
fi
echo "OK   integrity   sha256 ${ACTUAL}"

# 2. Authenticity + timestamp (signature, Fulcio certificate, Rekor entry)
if ! cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp "${IDENTITY_REGEXP}" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"; then
  echo "FAIL: authenticity - signature does not verify for this repo's workflow"; exit 1
fi
echo "OK   authenticity"

# 3. Preservation (Object Lock retention still in the future)
# shellcheck disable=SC2086
RETAIN_UNTIL=$(aws $PROFILE_ARG --region "$REGION" s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
RETAIN_EPOCH=$(date -u -d "$RETAIN_UNTIL" +%s)
NOW_EPOCH=$(date -u +%s)
if (( RETAIN_EPOCH <= NOW_EPOCH )); then
  echo "FAIL: preservation - retention expired ${RETAIN_UNTIL}"; exit 1
fi
echo "OK   preservation retained until ${RETAIN_UNTIL}"

echo "CHAIN INTACT for run ${RUN_ID}"
