# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

My primary framework is **CMMC Level 2**, expressed through the NIST SP 800-171 requirements it is built on. I chose it over the HIPAA Security Rule and SOC 2 for three reasons. First, the starter's GAPS.md already maps each gap to a CMMC practice, so every Rego policy cites a real control ID instead of a loose analogy. Second, NIST publishes 800-171 as an official OSCAL catalog, so anyone can follow my component definition to the catalog and check each claim; I did not find an equivalent catalog published by the framework owners for SOC 2 or for the HIPAA Security Rule. Third, the controls Acme's gaps touch (cryptography, boundary protection, least privilege) are the families CMMC states most concretely, which kept each claim testable.

One caveat I want to state plainly. CMMC Level 2 is currently assessed against NIST SP 800-171 **Revision 2**, and the DoD has said it will move to Revision 3 through later rulemaking ([DoD CIO alignment document](https://dodcio.defense.gov/Portals/0/Documents/CMMC/CMMC-AlignmentNIST-Standards.pdf)). The OSCAL catalog I link is the Revision 3 catalog (`NIST_SP800-171_rev3_catalog.json`), because that is the version NIST publishes in OSCAL. For the five practices I claim, the requirement numbers are the same in both revisions (for example 3.13.11 and 03.13.11), so the CMMC practice IDs in my Rego policies and the Rev 3 control IDs in my OSCAL describe the same requirement. The wording differs slightly between revisions, and I say where that matters below.

## Control coverage

Six of the eight gaps in GAPS.md are closed in Terraform **and** enforced by a Rego policy. Terraform closes the gap; the policy fails closed if anyone reintroduces it. Two gaps are not addressed (see the last section).

| Gap | What was wrong | CMMC practice | NIST 800-171 Rev 3 | Terraform fix | Rego policy |
|---|---|---|---|---|---|
| GAP-01 | Uploads bucket on the AWS default key | SC.L2-3.13.11 | 03.13.11 | `hardening.tf`: SSE-KMS with our key (`kms.tf`, rotation on) | `sc13_11_s3_cmk.rego` |
| GAP-02 | DynamoDB table on an AWS-owned key | SC.L2-3.13.11 | 03.13.11 | `main.tf`: `server_side_encryption` with our key | `sc13_11_dynamodb_cmk.rego` |
| GAP-03 | No TLS-only bucket policy | SC.L2-3.13.8 | 03.13.08 | `hardening.tf`: deny when `aws:SecureTransport` is false (also on the vault) | `sc13_8_tls.rego` |
| GAP-04 | No S3 versioning | MP.L2-3.8.9 | 03.08.09 | `hardening.tf`: versioning enabled | `mp3_8_9_versioning.rego` |
| GAP-05 | Lambda outside the VPC | SC.L2-3.13.1 | 03.13.01 | `main.tf` + `lambda-vpc.tf`: private subnets, endpoints, locked-down security group | `sc13_1_lambda_vpc.rego` |
| GAP-07 | `dynamodb:*` and `s3:*` on the Lambda role | AC.L2-3.1.5 | 03.01.05 | `main.tf`: exact actions and resource ARNs | `ac3_1_5_least_privilege.rego` |
| GAP-06 | No concurrency limit, DLQ, or tracing | SI.L2-3.14.6 | n/a | Not addressed | None |
| GAP-08 | No API access logging, throttling, or WAF | AU.L2-3.3.1 | n/a | Not addressed | None |

Beyond the gaps, the baseline adds a customer-managed key for the evidence vault, an Object Lock evidence bucket, and a multi-region CloudTrail with log file validation.

**An honest note on GAP-04.** MP.L2-3.8.9 (and Rev 3's 03.08.09) is about protecting the confidentiality of backups. Versioning gives recoverability, not confidentiality; the stored versions are encrypted with the customer key, which is where the confidentiality comes from. It is the weakest mapping in my set, so the OSCAL marks it `partial` and the description says why.

**Policy design.** There are six policies, 35 tests, and one shared helper library. Each policy has a METADATA block with the control ID, framework, gap, severity, and remediation, and each deny message starts with the control ID. The policies read the `configuration` section of the Terraform plan, not the planned values. Configuration keeps constants and references even when a value is "known after apply", so the policies work on a fresh account and not only on an incremental plan. For the same reason, IAM and bucket policies must be written with `aws_iam_policy_document`; a policy written as a `jsonencode` string cannot be inspected at plan time, so the gate treats it as a failure.

## Design decisions

**Region: ca-central-1.** It is the closest region to me, keeps the data in Canada, and offers every service the stack uses. I set it in `variables.tf`, in the bootstrap stack, and in the pipeline, and pinned the apply role to it.

**Object Lock mode: GOVERNANCE, 30 days.** COMPLIANCE is the stronger chain-of-custody claim, because nobody (not even root) can delete evidence early. It also cannot be undone, and this is a sandbox I need to be able to tear down. GOVERNANCE lets a privileged human bypass the lock, so I closed the part of that gap I could control: the pipeline's apply role has an explicit deny on `s3:BypassGovernanceRetention`, object deletion, and changes to the lock configuration. The pipeline can add evidence but can never remove or unlock it. In production I would use COMPLIANCE.

**Apply automatically on merge.** The Conftest gate is the control, and in a sandbox the blast radius of a bad apply is small. I limited the deploy power instead of adding a human gate: pull requests assume a read-only plan role that cannot change anything, and only the `main` branch can assume the apply role, which is restricted to one region, to the services the stack uses, and to IAM roles named `acme-health-intake-*`. A branch ruleset on `main` requires a pull request and a passing `grc-gate` check, with an empty bypass list, so even I cannot merge a red change. For real PHI I would add a manual approval before apply.

**Single AWS account.** Everything lives in one account for this project. The cost is that a compromise of the audited account could in principle reach the evidence. For production I would put the vault in a separate account that the pipeline can write to but the workload account cannot touch.

**Terraform versus policy.** I did both for every targeted gap. Terraform is what actually fixes the infrastructure; the policy is what stops the fix from quietly regressing. A policy-only approach would block bad changes but leave the gap open today, and a Terraform-only approach would fix today and not notice tomorrow's regression.

**Other choices worth naming.**
- *Evidence is signed even when the gate fails.* The gate step records its result and lets the job continue; the last step turns that result into a red build. A blocked change is exactly the run an assessor wants a record of.
- *The OIDC trust lists both subject formats* (`repo:OWNER/REPO` and `repo:OWNER@ID/REPO@ID`), because GitHub issues the subject claim in either format depending on the repository, and a trust policy that lists only one can reject a valid run.
- *The deploy roles live in a separate `bootstrap/` Terraform root.* The main stack's own least-privilege policy would rightly flag the broad permissions a deploy role needs, and a pipeline should not be able to rewrite its own permissions.
- *Terraform state is in an S3 bucket* (versioned, encrypted, private, TLS only) with native lock files, so the laptop and the pipeline see the same state.
- *The CloudTrail log bucket is exempt from the customer-key and versioning policies only.* It holds audit logs, not PHI. It is still subject to the TLS policy.

## How the pipeline produces evidence

One workflow, `.github/workflows/grc-gate.yml`, runs as a single connected flow:

1. **Plan.** `terraform plan` produces the saved plan.
2. **Policy gate.** `scripts/policy-gate.sh` converts the plan to JSON and runs Conftest against all six policy namespaces. The result decides what happens next.
3. **Apply.** Only on a push to `main`, and only if the gate passed, the exact reviewed plan is applied.
4. **Sign.** The evidence folder (plan, gate results, run metadata) is bundled and signed keyless with Cosign; the signature, the Fulcio certificate, and the Rekor entry go into one file.
5. **Store.** The bundle, its SHA-256, the signature, and a receipt are written to the Object Lock vault.
6. **Enforce.** A final step fails the build if the gate failed, so signing happens either way.

Runs an assessor can verify (all in the vault `acme-health-intake-evidence-08fa0596`):

| Run | What it shows |
|---|---|
| `42547179941` | PR #1, green: the whole baseline, plan role, gate passed, apply skipped by design |
| `42550227346` | PR #2, **red**: a regression suspending uploads versioning was blocked by `[MP.L2-3.8.9]`; apply skipped; evidence still signed and stored |
| `42706911885` | Merge to `main`, **real apply**: gate passed, the apply role changed the PHI key's labels in AWS (1 changed), then the run was signed and stored |

`bash scripts/verify-evidence.sh 42706911885` re-checks three things: the SHA-256 recomputes, the Cosign signature verifies against this repository's workflow identity, and the Object Lock retention is still in the future. Each of the runs above prints `CHAIN INTACT`. The OSCAL component links its claims to these bundles by vault URI, version ID, and hash, and `python scripts/build_oscal.py --check` confirms every link resolves and every hash matches.

I also learned that the first merge to `main` (run `42548157532`) applied nothing, because I had applied the baseline by hand earlier. That is why I made a deliberate one-line change afterwards, so that the apply step would do real work through the pipeline.

## Trade-offs and what I would do with another sprint

- **Deploy role permissions.** The apply role uses service-level wildcards (for example `ec2:*`), limited by region and by a deny list around the vault. Listing every action would be brittle. With more time I would generate a minimal policy from CloudTrail activity with IAM Access Analyzer and replace the wildcards.
- **Static checks only see configuration.** The gate checks what Terraform intends, not what is running. Someone could change a resource in the console after the apply. I would add a scheduled drift run (plan on a timer, same gate and signing) and AWS Config rules for the same controls.
- **Spurious plan changes.** Because I moved policies to `aws_iam_policy_document`, a plan that changes a key shows the IAM policy as "known after apply". The apply found no real difference. It is harmless, but it makes plans noisier.
- **Partial fit for MP.L2-3.8.9** (explained above). A real backup solution with its own encryption would close it properly.
- **Manual approval and COMPLIANCE lock** for production, and the separate vault account.
- **The state bucket uses SSE-S3**, not a customer-managed key. I would move it to a key for consistency.
- **Public repository.** The Actions logs show resource names and the AWS account number. There are no secrets in this stack, but a real PHI system would keep logs private.
- **Pinned tool versions** (Terraform 1.16.0, Conftest 0.56.0, Cosign 2.2.4) keep runs reproducible, and they need deliberate upgrades.

## Scanner results

Before submitting I ran the scanners that the rubric names. gitleaks found no secrets in the full git history. `terraform fmt -check` passes for both `terraform/` and `bootstrap/`, and `terraform validate` passes on the main stack. semgrep reports no error-level findings. The one it did find, shell injection in the run-metadata step of the workflow, I fixed by passing the GitHub context values through `env:` instead of writing them into the script. What semgrep still reports are warnings about mutable action tags (`@v3`, `@v4`). I did not pin those to commit SHAs because a wrong SHA would break the pipeline and I could not verify them here, so pinning is on my list.

checkov reports 124 passed and 29 failed on the Terraform. The free version does not assign severities, so none of the failures is labeled HIGH or CRITICAL. I fixed the three that were cheap and safe: a public access block on the uploads bucket, an empty default security group, and no public IPs on the unused public subnets. I left the rest failing on purpose, in four groups:

- **Gaps already listed in this write-up:** the Lambda dead-letter queue, reserved concurrency, X-Ray, and API access logging (GAP-06 and GAP-08).
- **The CloudTrail log bucket:** my policies exempt it from the PHI storage controls by design (versioning and KMS), and CloudTrail's CloudWatch, SNS and CMK integrations are not built.
- **Sandbox best practices I did not add for a throwaway environment:** S3 replication, lifecycle rules, access logging and event notifications, DynamoDB point-in-time recovery, and VPC flow logs.
- **The API has no authorizer** (`CKV_AWS_309`). That is how the starter workload ships, it is not one of the eight listed gaps, and adding one would break the smoke test, so I treated it as out of scope. A real PHI system would need it.

I did not hide any of these with skip comments, because a scanner finding I have explained is more useful to a reviewer than one I have silenced.

## What I didn't get to

- **GAP-06** (SI.L2-3.14.6): no reserved concurrency, dead-letter queue, or X-Ray tracing on the Lambda. I would close it with `reserved_concurrent_executions`, a `dead_letter_config`, and `tracing_config`, plus a Rego policy for each, following the same pattern as the other six.
- **GAP-08** (AU.L2-3.3.1): no API Gateway access logging, throttling, or WAF. CloudTrail is deployed and records account-level activity, but I did not claim AU.L2-3.3.1 in the OSCAL because request-level logging for the API is still missing. I would add access logs to a CloudWatch log group on the stage, throttling settings, and a WAF web ACL.
- **A system security plan** and any assessment results in OSCAL; the component definition and profile are what I built.

## How this was built

I built this Capstone with assistance from Claude for drafting code and expediting document drafting. I was solely responsible for running every command, testing the results, and all design decisions. I can explain each choice that was made in this write-up.