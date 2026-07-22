# Write-up

**Primary framework: SOC 2 Type II.** Acme's near-term motivation is an enterprise customer asking
for it, and it's the framework whose control language (logical access, transmission security,
least privilege, monitoring, availability) maps most directly onto the concrete gaps this starter
ships with. HIPAA would be the more obvious fit given the PHI at stake, and CMMC L2 the more obvious
fit given the federal pilot, but SOC 2 was chosen and every layer below is built around it.

## Design decisions

- **OSCAL catalog mapping.** AICPA publishes no official OSCAL catalog for the Trust Services
  Criteria. Per the starter's `FRAMEWORKS.md`, each SOC 2 criterion used here is mapped to its
  closest NIST SP 800-53 Rev 5 control, and that catalog is cited as
  `control-implementation.source`. To keep the two layers legible against each other, every
  `implemented-requirement.description` in `oscal/components/acme-health-intake.json` opens by
  naming the SOC 2 CC ID explicitly, before the 800-53 mechanics -- so the same control reads as
  (for example) CC6.1 in a Rego deny message and as "CC6.1, implemented via sc-28" in the OSCAL.
- **Terraform override files, not hand-edited `main.tf`.** GAP-02 (DynamoDB encryption), GAP-05
  (Lambda `vpc_config`), GAP-07 (IAM policy), and GAP-08 (access logging/throttling) are all
  arguments of resources the starter already declares -- Terraform has
  no way to add those as new, separate resource blocks the way GAP-01/03/04 (new S3 sub-resources)
  work. `terraform/starter_override.tf` uses Terraform's native override-file mechanism
  (`*_override.tf`) instead, so `terraform/main.tf` stays byte-for-byte identical to the upstream
  fork and every gap-closing change is visible in one place.
- **Object Lock mode: GOVERNANCE, not COMPLIANCE**, for the 30-day project window -- reversible if
  a fixture needs correcting during grading. COMPLIANCE would be the production-intent choice once
  the pipeline has proven stable over more than one grading cycle.
- **CloudTrail's dedicated log bucket uses SSE-S3 (AES256), not the CMK.** A CloudTrail trail
  encrypted with a customer CMK requires additional key-policy statements explicitly granting
  `cloudtrail.amazonaws.com` `kms:GenerateDataKey*`/`kms:DescribeKey`. Given the brief's actual
  requirement is that the *evidence vault and PHI stores* sit under the CMK (which they do), adding
  that extra key-policy surface for the trail bucket specifically wasn't worth the risk of a
  misconfigured policy silently breaking log delivery.
- **Single AWS account**, not a separate evidence-vault account. Cleaner separation would use two;
  for a 30-day solo project the brief calls single-account "acceptable," and the vault's own bucket
  policy (deny `s3:DeleteBucket` from anyone but the account root) is the compensating control.
- **Pipeline applies automatically on merge to `main`**, no manual post-merge approval gate. Simplest
  defensible choice for this scope -- the Conftest policy gate is the actual control that matters,
  and it runs pre-merge on every PR regardless.
- **Remote Terraform state, bootstrapped by hand in `oidc/`.** CI can't manage infrastructure it has
  no record of: without shared state, a GitHub Actions checkout would have no way to know the
  workload's 42 resources already exist, and would plan to create a second, parallel copy of
  everything. `oidc/main.tf` (applied once by hand, kept in its own root module and local state,
  since it's what makes `terraform/`'s backend and CI's ability to authenticate possible in the
  first place) provisions an S3 state bucket alongside the GitHub OIDC trust + IAM role.
  `terraform/backend.tf` points at it and uses `use_lockfile` (native S3 state locking, Terraform
  >= 1.10) rather than a separate DynamoDB lock table -- one fewer resource for the same guarantee.
- **The CI role's IAM policy is scoped by service and resource-name pattern, not full per-resource
  least privilege.** CGE-P Lab 4.3's reference OIDC module attaches AWS-managed `ReadOnlyAccess`,
  because its pipeline only ever plans, never applies. This pipeline has a real Apply step, so the
  role needs real write permissions; `oidc/main.tf`'s policy grants broad access within each AWS
  service this workload touches (S3, DynamoDB, Lambda, the specific Lambda execution role, KMS,
  CloudTrail, API Gateway, CloudWatch Logs), scoped by ARN pattern to the `acme-health-intake-*`
  naming convention where the API supports resource-level permissions at all. EC2 networking
  (VPC/subnet/route table/security group/endpoint create+delete) is the one statement that's
  unavoidably `Resource: "*"` -- most of those actions don't support resource-level ARNs in IAM.
  Tightening this to true least privilege is listed under "what we'd do with another sprint."

## Control coverage

| Gap | SOC 2 control | 800-53 mapping | Layer(s) |
|---|---|---|---|
| GAP-01 uploads bucket SSE-S3 -> CMK | CC6.1 | sc-28 | Terraform + Rego + OSCAL |
| GAP-02 DynamoDB default key -> CMK | CC6.1 | sc-28 | Terraform + Rego + OSCAL |
| GAP-03 no TLS-only bucket policy | CC6.7 | sc-8 | Terraform + Rego + OSCAL |
| GAP-04 no versioning | A1.2 | cp-9 | Terraform + Rego + OSCAL |
| GAP-05 Lambda outside VPC | CC6.6 | sc-7 | Terraform + Rego + OSCAL |
| GAP-07 IAM `dynamodb:*`/`s3:*` | CC6.3 | ac-6 | Terraform + Rego + OSCAL |
| GAP-06 no concurrency/DLQ/X-Ray | CC7.2 | si-4 | Terraform (partial) + OSCAL |
| GAP-08 no access log/throttle/WAF | CC7.2 | si-4 | Terraform (partial) + OSCAL |

Six of eight gaps are closed across all three layers (Terraform, Rego, OSCAL). Two (GAP-06,
GAP-08) are closed partially in Terraform and documented, not silently dropped -- see below.

## Trade-offs

- **GAP-06: no dead-letter queue, and no reserved concurrency either.** The intake Lambda's only
  trigger is the synchronous API Gateway proxy integration. Lambda DLQs only capture failures from
  *asynchronous* invocations, so a DLQ here would never receive anything -- adding one would be
  compliance theater, not a control. `reserved_concurrent_executions` was the planned alternative
  lever, but deploying it against the real sandbox account surfaced a hard constraint: this
  account's total Lambda concurrency limit is 10 (`aws lambda get-account-settings`), and AWS
  enforces a floor of 10 unreserved executions account-wide -- reserving *any* amount for a single
  function drops the account below that floor and `PutFunctionConcurrency` fails outright. The
  account-wide limit is itself already a (coarser, shared) ceiling on this single-function
  workload, so nothing was silently left uncontrolled -- but a per-function reservation isn't
  achievable in this account without first requesting a service-quota increase.
- **GAP-01/GAP-04 Rego policies are scoped to `aws_s3_bucket.uploads` by name**, not every bucket in
  the config. An earlier draft checked all `aws_s3_bucket` resources generically and false-flagged
  the CloudTrail log bucket (which deliberately uses AES256, see above) as a GAP-01 violation.
  GAPS.md's own gap definitions are specific to the uploads bucket; the policies now match that
  scope rather than imposing a fleet-wide rule the architecture doesn't actually need.
- **Two Rego policies (`cc6_7_s3_tls_only`, `cc6_3_iam_least_privilege`) read `resource_changes`
  instead of `configuration`.** Both gaps live inside a `jsonencode(...)` call (a bucket policy
  document, an IAM policy document), and Terraform's static `configuration` representation doesn't
  expose literal values from inside a function call's arguments -- only `resource_changes[].
  change.after` has the fully-rendered string, and only once every reference inside it is already
  known (i.e., once the referenced resources already exist in state). On a from-scratch plan
  (nothing applied yet), that value is unresolvable and both policies **fail closed** rather than
  passing silently -- confirmed by generating a real plan against the as-yet-unapplied Terraform
  and running Conftest against it directly, not just the `opa test` fixtures.

## What we'd do with another sprint

- Move the evidence vault into a separate AWS account from the workload, with cross-account
  replication, closing the "single account" trade-off above.
- Add X-Ray tracing and a WAF in front of API Gateway (GAP-06/GAP-08's remaining pieces). Request a
  Lambda concurrency service-quota increase for the sandbox account so
  `reserved_concurrent_executions` becomes usable at all.
- Grant CloudTrail its own KMS key-policy statements and move its log bucket onto the CMK too, once
  that policy has been tested against a real trail rather than assumed.
- A manual approval gate between Conftest passing and `terraform apply`, for defense in depth beyond
  the policy gate alone.
- Tighten the CI role's IAM policy (`oidc/main.tf`) from service-and-name-pattern scoping to true
  per-resource least privilege, and move the EC2-networking statement off `Resource: "*"` wherever
  the specific action actually supports resource-level ARNs.

## What we didn't get to

- WAF in front of API Gateway (GAP-08).
- X-Ray tracing on the Lambda (GAP-06).
- A community or self-authored SOC 2-native OSCAL catalog (we mapped to NIST 800-53 instead, per
  `FRAMEWORKS.md` -- see "Design decisions" above for the reasoning and the mitigation).

*(Sections below are filled in as later weeks complete -- see the execution plan for sequencing.)*

- [ ] Real evidence bundle verification results (`scripts/verify-evidence.sh` output) once the
      pipeline has run against `main`.
- [ ] Links to the green (merged) and red (blocked) PRs once they exist.
- [ ] `trestle validate` output once a working `trestle` install is set up in this repo.
