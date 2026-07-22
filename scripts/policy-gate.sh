#!/usr/bin/env bash
# scripts/policy-gate.sh
#
# Adapted from cgep-labs/lab-3-4/scripts/policy-gate.sh: same shape, updated
# to the six SOC 2 policy namespaces this repo actually ships (see
# policies/*.rego). Runs conftest against a terraform plan, one namespace
# at a time, and fails closed if any namespace reports a failure.
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence"

NAMESPACES=(
  compliance.soc2.cc6_1_s3_kms
  compliance.soc2.cc6_1_dynamodb_kms
  compliance.soc2.cc6_7_s3_tls_only
  compliance.soc2.a1_2_s3_versioning
  compliance.soc2.cc6_3_iam_least_privilege
  compliance.soc2.cc6_6_lambda_vpc
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path> [--policy <dir>]" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )

EXIT=0
{
  echo "["
  FIRST=1
  for ns in "${NAMESPACES[@]}"; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json" || true)
    if echo "$OUT" | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if all(len(r.get("failures") or [])==0 for r in d) else 1)'; then : ; else EXIT=1 ; fi
    echo "$OUT"
  done
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT
