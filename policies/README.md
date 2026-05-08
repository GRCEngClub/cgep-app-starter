# Compliance Policies

OPA/Rego policy library for the CGE-P capstone. Primary framework: SOC 2 Type II.

## Policy inventory

| File | Control | SOC 2 | Cloud | Severity | Checks |
|------|---------|-------|-------|----------|--------|
| sc28_encryption.rego | SC-28 | CC6.1 | AWS | High | S3 bucket has server-side encryption resource |
| sc28_encryption_aws.rego | SC-28 | CC6.1 | AWS | High | S3 bucket referenced by encryption config (plan-time) |
| ac3_no_public.rego | AC-3 | CC6.6 | AWS | Critical | S3 public access block, no open ports |
| ac3_no_public_aws.rego | AC-3 | CC6.6 | AWS | Critical | S3 public access block via config references |
| cm6_required_tags.rego | CM-6 | CC6.8 | AWS | Medium | Required compliance tags present |
| cm6_required_tags_aws.rego | CM-6 | CC6.8 | AWS | Medium | Required tags via tags_all (provider default_tags) |

## Running tests

opa test -v policies/

## Running against a plan

conftest test --policy policies --namespace compliance.sc28_aws plan.json
conftest test --policy policies --namespace compliance.ac3_aws plan.json
conftest test --policy policies --namespace compliance.cm6_aws plan.json