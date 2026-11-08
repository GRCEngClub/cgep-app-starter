#!/usr/bin/env bash
# scripts/policy-gate.sh
# Usage: policy-gate.sh --workspace <path> [--policy <dir>] [--evidence <dir>]
# Requires a saved tfplan inside the workspace (from terraform plan -out=tfplan).
# Runs every CMMC namespace with Conftest. The exit code of the gate is
# Conftest's exit code: non-zero if any policy denies.
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/policy-gate"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    --evidence)  EVIDENCE_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path> [--policy <dir>] [--evidence <dir>]" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

# Write plan.json next to tfplan. Use -chdir so a relative WORKSPACE path
# doesn't get doubled after a cd (a common bash footgun).
terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"
cp "$WORKSPACE/plan.json" "$EVIDENCE_DIR/plan.json"

# One namespace per CMMC practice / gap. Keep in sync with policies/*.rego.
NAMESPACES=(
  compliance.sc13_11_s3             # GAP-01  SC.L2-3.13.11
  compliance.sc13_11_dynamodb       # GAP-02  SC.L2-3.13.11
  compliance.sc13_8_tls             # GAP-03  SC.L2-3.13.8
  compliance.mp3_8_9_versioning     # GAP-04  MP.L2-3.8.9
  compliance.sc13_1_lambda_vpc      # GAP-05  SC.L2-3.13.1
  compliance.ac3_1_5_least_privilege # GAP-07 AC.L2-3.1.5
)

EXIT=0
{
  echo "["
  FIRST=1
  for ns in "${NAMESPACES[@]}"; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    # Capture JSON even when conftest exits non-zero; use that exit code for the gate.
    set +e
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json")
    STATUS=$?
    set -e
    [[ $STATUS -eq 0 ]] || EXIT=1
    printf '%s' "$OUT"
  done
  echo
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL"
  echo "See $EVIDENCE_DIR/conftest-results.json"
  # Print the violations so they show in terminal and CI logs.
  for ns in "${NAMESPACES[@]}"; do
    conftest test --policy "$POLICY_DIR" --namespace "$ns" --no-color "$WORKSPACE/plan.json" 2>&1 | grep FAIL || true
  done
fi
exit $EXIT
