# Capstone Design Document
## Acme Health Patient Intake API — GRC Baseline

### Primary Framework: SOC 2 Type II

**Why SOC 2 over HIPAA or CMMC:**
Acme Health's stated near-term driver is enterprise customer trust — a paying customer has asked for a SOC 2 report. HIPAA compliance is a legal obligation but does not require external attestation on a fixed schedule; SOC 2 Type II does. CMMC Level 2 applies only if Acme pursues federal contracts, which is exploratory. SOC 2 is the right primary framework because it is what the business needs to close deals.

HIPAA controls are cross-referenced in OSCAL props where applicable. The gap remediation also satisfies HIPAA technical safeguards, but the primary control mapping is SOC 2 TSC.

### System Under Governance

The Acme Health Patient Intake API accepts POST /intake with patient PHI and writes to DynamoDB + S3. Resources in scope:
- `aws_s3_bucket.uploads` — PHI at rest (attachments)
- `aws_dynamodb_table.intake` — PHI at rest (submissions)
- `aws_lambda_function.intake` — trust boundary, processes PHI
- `aws_iam_role.lambda` / `aws_iam_role_policy.lambda_inline` — access control
- `aws_apigatewayv2_stage.default` — audit log surface

### Gap-to-Control Mapping

| Gap | SOC 2 TSC | Remediation Layer | Decision |
|---|---|---|---|
| GAP-01: S3 missing CMK | CC6.1 | Terraform + Policy | KMS CMK with rotation. Customer-controlled keys are required for SOC 2 CC6.1 logical access controls at the cryptographic layer. |
| GAP-02: DynamoDB missing CMK | CC6.1 | Terraform + Policy | Same CMK as GAP-01. One key, two resources — simpler key management story for auditors. |
| GAP-03: S3 missing TLS deny | CC6.7 | Terraform + Policy | Bucket policy with `aws:SecureTransport` deny. Transmission security is explicitly required by CC6.7. |
| GAP-04: S3 missing versioning | A1.2 | Terraform + Policy | Versioning enables point-in-time recovery of PHI overwrites. Satisfies A1.2 availability commitment. |
| GAP-05: Lambda not in VPC | CC6.6 | Terraform | VPC config with private subnets. Boundary protection. Cannot be enforced solely in policy because subnet IDs are runtime values. |
| GAP-06: Lambda no DLQ/X-Ray | CC7.2 | Terraform | DLQ for failed processing visibility. X-Ray for distributed tracing. CC7.2 requires monitoring of system components. |
| GAP-07: IAM over-broad | CC6.3 | Terraform + Policy | Least-privilege: specific DynamoDB actions (PutItem, GetItem, UpdateItem), specific S3 actions (PutObject, GetObject). |
| GAP-08: API GW no logging | CC7.2 | Terraform | CloudWatch access log group + stage access_log_settings. All API calls generate audit records. |

### Object Lock Mode Decision: GOVERNANCE

GOVERNANCE mode is used for the evidence vault. COMPLIANCE mode cannot be overridden by anyone, including account root. GOVERNANCE mode requires a specific IAM permission to override. For a 90-day lab environment, GOVERNANCE is appropriate because:
1. It still prevents accidental deletion by operators without the override permission
2. It allows the vault to be cleaned up when the lab ends without requiring AWS support
3. In production, COMPLIANCE mode would be the right choice; this is noted as a trade-off in the write-up

### Pipeline Decision: Apply on merge, no manual gate

The pipeline applies on merge to `main`. A manual approval gate post-merge adds friction without adding security if the policy gate already runs pre-merge. The policy gate is the control; the apply is the consequence. This is noted as a trade-off — in a regulated environment with a CAB process, a manual gate would be appropriate.

### What Was Not Closed

- **Authentication at the API layer** (Cognito/JWT) — out of scope per WORKLOAD.md
- **Patient data lifecycle** (deletion, export requests) — GDPR/HIPAA right-to-erasure gap, documented in WRITEUP.md
- **Multi-region failover** — out of scope per WORKLOAD.md
- **WAF on API Gateway** — GAP-08 partial close: logging and throttling added; WAF requires additional subscription and cost, noted as NEXT sprint item
