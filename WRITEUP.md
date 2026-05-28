# Acme Health - Capstone Project Write-up

## 1. Design Decisions & Framework Selection
For the governance and security hardening of the Acme Health "Patient Intake API," **SOC 2 Type II (Trust Services Criteria - Security & Availability)** has been selected as the primary compliance framework.

As a fast-growing telehealth startup with 50 employees, Acme Health faces immediate commercial pressure from enterprise customers demanding a defensible security posture. SOC 2 provides the ideal balance between the rigorous engineering controls required to protect Protected Health Information (PHI) and the operational agility needed to maintain software delivery velocity. Achieving SOC 2 compliance directly addresses commercial procurement blockers while establishing a baseline that simplifies future HIPAA or CMMC alignments.

## 2. Control Coverage & Gap Remediation
Five critical material security gaps identified in the starter code (`GAPS.md`) have been mapped directly to SOC 2 criteria. These are technically remediated via baseline configuration overrides (Layer 1) and proactively enforced via automated policy gates (Layer 2):

* **GAP-01 (S3 Uploads Bucket Encryption) - SOC 2 CC6.1 (Data Protection):** Remediated by provisioning a Customer-Managed Key (CMK) via AWS KMS with 365-day automatic rotation. The `aws_s3_bucket_server_side_encryption_configuration` for the starter's uploads bucket is overridden to use this CMK, ensuring cryptographic custody of PHI.
* **GAP-02 (DynamoDB Table Encryption) - SOC 2 CC6.1 (Data Protection):** Remediated by overriding the `server_side_encryption` configuration of the `aws_dynamodb_table.intake` resource. This moves the database away from AWS-owned keys and brings it under the perimeter of our custom KMS CMK.
* **GAP-03 (S3 Non-TLS Deny Policy) - SOC 2 CC6.7 (Transmission Security):** Remediated by attaching an explicit `aws_s3_bucket_policy` to the uploads bucket. The policy enforces an explicit `Deny` on any API requests where `aws:SecureTransport` evaluates to false, mitigating data-in-transit interception risks.
* **GAP-04 (S3 Bucket Versioning) - SOC 2 A1.2 (Availability / Data Integrity):** Remediated by implementing an `aws_s3_bucket_versioning` resource on the workload bucket. This ensures an immutable audit trail of file modifications and provides instant recovery points against accidental or malicious overwrites.
* **GAP-07 (Over-privileged Lambda IAM Role) - SOC 2 CC6.3 (Access Modification):** Remediated by refactoring the `aws_iam_role_policy.lambda_inline` resource. The over-broad wildcard actions (`dynamodb:*` and `s3:*`) are destroyed and replaced with granular, least-privilege permissions (`dynamodb:PutItem` and `s3:PutObject`).
