# Phase 3: GitHub Actions Pipeline — Setup Checklist

Complete these steps **in order** before opening your first PR.

---

## Step 0a: Push to your GitHub fork

Your capstone repo: **https://github.com/tiffanymwr15/cgep-app-starter**

Complete these steps **in order** before opening your first PR.

---

## Step 0a: Push to your GitHub fork

Point `origin` at your fork and push all local work (GitHub currently only has the upstream starter):

```bash
cd "CGEP-Capstone/cgep-app-starter"
git remote set-url origin https://github.com/tiffanymwr15/cgep-app-starter.git
git remote -v

git add -A
git commit -m "Capstone Layers 1-3: GRC baseline, HIPAA policies, grc-gate pipeline"
git push -u origin main
```

OIDC trust policy uses `github_org = "tiffanymwr15"` and `github_repo = "cgep-app-starter"`.

---

## Step 0b: Remote state (required for CI)

GitHub runners do not have your local `terraform.tfstate`. Bootstrap remote state once, then migrate.

```bash
export AWS_PROFILE=capstone-deploy-user

# 1. Create state bucket + lock table
cd terraform/bootstrap
terraform init
terraform apply

# 2. Copy backend_snippet output into terraform/backend.tf
terraform output backend_snippet

# 3. Migrate existing local state to S3
cd ..
terraform init -migrate-state
terraform plan   # should show 0 to change
```

Confirm `terraform plan` shows **no changes** after migration.

---

## Step 1: Apply OIDC + IAM role

```bash
export AWS_PROFILE=capstone-deploy-user
cd terraform
VAULT=$(terraform output -raw evidence_vault_name)

cd oidc
cp terraform.tfvars.example terraform.tfvars
# Edit evidence_vault_name only (org/repo already set for tiffanymwr15/cgep-app-starter)

terraform init
terraform apply
```

Note the `role_arn` output.

---

## Step 2: Set GitHub repository variables

Repo → Settings → Secrets and variables → Actions → **Variables**:

| Name | Value |
|---|---|
| `AWS_ROLE_ARN` | Output from Step 1 |
| `EVIDENCE_VAULT` | `terraform output -raw evidence_vault_name` |

---

## Step 3: First green PR

1. Commit `.github/workflows/grc-gate.yml` and push a branch.
2. Open PR to `main`.
3. Confirm **plan-and-policy** job passes (Plan + Policy check).
4. Merge PR.
5. Confirm **plan-apply-sign-upload** job on `main` completes.
6. Verify vault:

```bash
VAULT=$(cd terraform && terraform output -raw evidence_vault_name)
bash scripts/verify-evidence.sh <RUN_ID> --vault "$VAULT" --profile capstone-deploy-user
```

---

## Step 4: Red PR (policy gate demo)

1. Branch from `main`, re-introduce one gap (e.g. change uploads SSE to `AES256` in `grc_gap_overrides.tf`).
2. Open PR — **policy check must fail** with `[164.312(...)]`.
3. Close PR without merging (keep in history for grader).

---

## Capstone five steps → workflow mapping

| Brief step | PR job | Main job |
|---|---|---|
| 1. Plan | yes | yes |
| 2. Policy check | yes | yes |
| 3. Apply | no | yes |
| 4. Sign | no | yes |
| 5. Upload | no | yes |
