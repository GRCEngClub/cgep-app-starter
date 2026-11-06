# Design Doc: Acme Health GRC Capstone

*Week 1 design. This becomes the spine of WRITEUP.md.*

## Primary framework

CMMC Level 2, built on NIST SP 800-171 Rev. 3. NIST publishes 800-171 in OSCAL, so the chain from starter to policy to OSCAL to catalog stays unbroken. The starter's GAPS.md already maps every gap to a CMMC practice, so each Rego policy cites a real control ID.

## Gaps and where each gets fixed

| Gap | Description | CMMC practice | Terraform fix | Rego policy |
|---|---|---|---|---|
| GAP-01 | S3 uploads bucket not on a customer CMK | SC.L2-3.13.11 | SSE-KMS with our key | Yes |
| GAP-02 | DynamoDB table on AWS-owned key | SC.L2-3.13.11 | CMK on table | Yes |
| GAP-03 | No TLS-only bucket policy | SC.L2-3.13.8 | `aws:SecureTransport` deny | Yes |
| GAP-04 | No S3 versioning | MP.L2-3.8.9 | Enable versioning | Yes |
| GAP-05 | Lambda not in the starter's VPC | SC.L2-3.13.1 | Add `vpc_config` | Yes |
| GAP-07 | `dynamodb:*` and `s3:*` on Lambda role | AC.L2-3.1.5 | Scope the IAM policy | Yes |
| GAP-06 | No reserved concurrency, DLQ, X-Ray | SI.L2-3.14.6 | Not addressed | No |
| GAP-08 | No API access logging, throttling, WAF | AU.L2-3.3.1 | Not addressed | No |

GAP-06 and GAP-08 are deliberately left for another sprint and will be named in "What I didn't get to."

## Decisions to defend

- **Region:** ca-central-1 (Montreal). Closest to the operator, and keeps data in Canada. All required services are available there.
- **Object Lock mode:** GOVERNANCE. Tamper-resistant enough for a 30-day sandbox, while still allowing cleanup. COMPLIANCE would be stronger for chain of custody but cannot be undone before retention expires.
- **Apply:** automatically on merge to main. The Conftest gate is the control, and a bad apply is low-impact in a sandbox.
- **Accounts:** single AWS account. Production would use a separate evidence-vault account so a compromise of the audited account cannot rewrite evidence.
- **Terraform vs policy:** all six targeted gaps get both a Terraform fix and a Rego policy. Terraform closes the gap; the policy fails closed if anyone re-introduces it.

## Build order

1. Deploy the starter (`make creds`, `make deploy`, `make test`).
2. Terraform baseline: KMS, Object Lock evidence bucket, CloudTrail, gap fixes. Apply by hand from a feature branch.
3. Five or more Rego policies with tests; wire in Conftest via `policy-gate.sh`.
4. GitHub Actions pipeline: plan, policy check, apply, sign (Cosign), upload. One green PR, one red PR.
5. OSCAL component definition, validated with trestle.
6. WRITEUP.md and README.md.

## Open questions

- Confirm how `main.tf` is structured. Fixes to existing resources (DynamoDB encryption, Lambda VPC config) may mean editing it directly rather than using a separate `hardening.tf`.
