#!/bin/bash
# policy-gate.sh — runs Terraform plan and checks it against Rego policies
# Used in Lab 3.4 and wired into the GitHub Actions pipeline in Lab 4.3

set -euo pipefail

POLICY_DIR="$(cd "$(dirname "$0")/../policies" && pwd)"
TERRAFORM_DIR="$(cd "$(dirname "$0")/../terraform" && pwd)"
PLAN_FILE="/tmp/tfplan.json"

echo "============================================"
echo " GRC Policy Gate — SOC 2 Compliance Check"
echo "============================================"

# Step 1 — Run Terraform plan and save it
echo ""
echo "Step 1: Running terraform plan..."
cd "$TERRAFORM_DIR"
terraform plan -out=/tmp/tfplan.binary

# Step 2 — Convert plan to JSON so Conftest can read it
echo ""
echo "Step 2: Converting plan to JSON..."
terraform show -json /tmp/tfplan.binary > "$PLAN_FILE"
echo "Plan saved to $PLAN_FILE"

# Step 3 — Run Conftest against the plan
echo ""
echo "Step 3: Running policy checks..."
cd "$OLDPWD"
conftest test "$PLAN_FILE" \
  --policy "$POLICY_DIR" \
  --namespace policies.s3_kms_encryption \
  --namespace policies.s3_tls_enforcement \
  --namespace policies.s3_versioning \
  --namespace policies.lambda_vpc \
  --namespace policies.iam_no_wildcard

# Step 4 — Report result
EXIT_CODE=$?
echo ""
if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ All policy checks passed — safe to apply"
else
  echo "❌ Policy checks failed — fix gaps before deploying"
  exit 1
fi