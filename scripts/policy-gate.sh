#!/usr/bin/env bash
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/lab-3-4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

( cd "$WORKSPACE" && terraform show -json tfplan > plan.json )

EXIT=0
for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6; do
  echo "=== $ns ==="
  conftest test --policy "$POLICY_DIR" --namespace "$ns" "$WORKSPACE/plan.json" || EXIT=1
done

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL"
fi
exit $EXIT