# Acme Health - Framework Compliance Matrix

This document maps the security controls required by the CGE-P portfolio evaluation criteria directly to our junior-level architectural implementations in Terraform and Open Policy Agent (Rego).

| Control ID | Framework Domain | Inherent Risk Detected | Technical Remediation (Terraform) | Policy Enforcement (OPA/Rego) |
| :--- | :--- | :--- | :--- | :--- |
| **SOC 2 CC6.1** | Data Protection / Encryption | Patient files and cloud database tables were completely unencrypted at rest. | Implemented custom AWS KMS Customer-Managed Keys (CMK) with 365-day rotation inside `main.tf`. | The policy rule `deny_unencrypted_resources` scans plans and blocks non-KMS configurations. |
| **SOC 2 CC6.7** | Transmission Security | S3 bucket accepted insecure HTTP connections, risking Man-in-the-Middle attacks. | Attached an explicit `aws_s3_bucket_policy` enforcing a hard Deny if `aws:SecureTransport` is false. | The policy rule `deny_non_https_traffic` blocks any configuration missing this bucket policy. |
| **SOC 2 A1.2** | Availability & Data Integrity | Accidental file deletion or ransomware attacks could permanently destroy patient records. | Enabled `aws_s3_bucket_versioning` and added an Object Lock configuration to our evidence vault. | Asserts that storage resources maintain active append-only status prior to environment entry. |
| **SOC 2 CC6.3** | Access Modification / Least Privilege | The backend Lambda execution role had wildcard permissions (`*`), allowing total database access. | Refactored `aws_iam_role_policy` to specify exact API actions like `PutItem` and `PutObject`. | OPA policy scans the IAM statement array and throws a denial if a global wildcard `*` is detected. |