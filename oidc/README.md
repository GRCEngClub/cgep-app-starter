# oidc/

Bootstrap module: the GitHub Actions OIDC trust, the `grc-gate` IAM role the pipeline assumes, and
the Terraform state bucket `terraform/backend.tf` points at. Applied once by hand, with its own
local state — not part of the CI-managed `terraform/` root module, and not applied by CI itself
(the pipeline can't create the very role it needs in order to authenticate).

## Applying from scratch

```bash
cd oidc
terraform init
terraform plan   # review: creates the IAM role + policy + state bucket
terraform apply
```

## If the GitHub OIDC provider already exists in the account

Some other automation (or an earlier lab) may have already created the
`token.actions.githubusercontent.com` OIDC provider. Check first:

```bash
aws iam list-open-id-connect-providers --profile <your-profile>
```

If it's there, import it instead of letting `apply` try (and fail) to create a duplicate:

```bash
terraform import aws_iam_openid_connect_provider.github \
  arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com
terraform apply
```

## After applying

Set the two repo variables `.github/workflows/grc-gate.yml` reads:

```bash
gh variable set AWS_ROLE_ARN --body "$(terraform output -raw role_arn)" --repo <org>/<repo>
gh variable set EVIDENCE_VAULT --body "<terraform/'s evidence_vault_bucket output>" --repo <org>/<repo>
```

And point `terraform/backend.tf` at this module's `tf_state_bucket` output, then
`terraform init -migrate-state` in `terraform/` to move local state into it.

## Why the role's policy isn't `ReadOnlyAccess`

CGE-P Lab 4.3's reference `oidc/main.tf` attaches the AWS-managed `ReadOnlyAccess` policy, because
its pipeline only ever runs `terraform plan` — never `apply`. This repo's pipeline has a real Apply
step (gated to merges on `main`), so the role needs real write permissions. `main.tf`'s
`aws_iam_role_policy.grc_gate` is scoped by AWS service and, where the API supports it, by resource
ARN pattern matching this workload's `acme-health-intake-*` naming — broad within each service, not
account-admin, but not full per-resource least privilege either. Tightening that further is listed
as a "next sprint" item in `WRITEUP.md`. The one statement that's unavoidably `Resource: "*"` is EC2
networking (VPC/subnet/route table/security group/endpoint create+delete) — most of those actions
don't support resource-level ARNs in IAM at all.
