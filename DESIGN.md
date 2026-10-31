\# Acme Health — GRC Engineering Capstone Design



\## 1. System Overview



Acme Health is a fictional 50-person telehealth company operating a Patient Intake API on AWS.



The application uses Amazon API Gateway, AWS Lambda, Amazon DynamoDB, Amazon S3, and an existing VPC.



The starter application has eight intentional security and compliance gaps. The objective of this project is to remediate selected gaps, prevent their reintroduction through automated policy checks, and produce verifiable compliance evidence.



\## 2. Primary Compliance Framework



\*\*Selected framework: CMMC Level 2, based on NIST SP 800-171 Rev. 2.\*\*



CMMC Level 2 is selected because Acme Health is pursuing a federal pilot that may involve Controlled Unclassified Information (CUI). Its access control, auditing, and system protection requirements provide a relevant basis for governing the application.



The HIPAA Security Rule will be considered a secondary framework because the application handles patient information. SOC 2 will also be considered for future enterprise customer assurance.



Framework selection does not establish that the application is compliant or certified.



\## 3. Security Gap Remediation Strategy



| Gap | Security weakness | Planned remediation |

|---|---|---|

| GAP-01 | S3 lacks customer-managed KMS encryption | Configure SSE-KMS with a customer-managed key |

| GAP-02 | DynamoDB lacks customer-managed KMS encryption | Configure table encryption with a customer-managed key |

| GAP-03 | S3 lacks explicit TLS enforcement | Add a bucket policy denying insecure transport |

| GAP-04 | S3 versioning is disabled | Enable bucket versioning |

| GAP-05 | Lambda is not configured inside the existing VPC | Configure Lambda VPC integration |

| GAP-06 | Lambda lacks concurrency limits, DLQ, and tracing | Add relevant reliability and monitoring controls |

| GAP-07 | Lambda IAM permissions are excessively broad | Restrict IAM permissions to required actions and resources |

| GAP-08 | API Gateway lacks access logging, throttling, and WAF | Add API logging and appropriate request protections |



At least five material gaps will be covered by automated Rego policies with passing and failing tests.



\## 4. Architecture and Design Decisions



\- \*\*AWS region:\*\* us-east-1, consistent with the deployed starter.

\- \*\*AWS environment:\*\* Single sandbox account for the capstone.

\- \*\*Infrastructure:\*\* Terraform, reusing existing starter resources.

\- \*\*Encryption:\*\* Customer-managed AWS KMS keys with rotation.

\- \*\*Evidence vault:\*\* Versioned S3 bucket with Object Lock in GOVERNANCE mode.

\- \*\*Audit logging:\*\* Multi-region AWS CloudTrail with log-file validation.

\- \*\*Policy enforcement:\*\* OPA/Rego and Conftest against Terraform plans.

\- \*\*CI/CD:\*\* GitHub Actions, with deployment after successful checks and merge to main.

\- \*\*Evidence signing:\*\* Cosign keyless signing with GitHub OIDC.

\- \*\*Compliance documentation:\*\* OSCAL component definition and control profile.



\## 5. Evidence Management Strategy



The pipeline will produce an evidence bundle after successful deployment.



Evidence will be digitally signed, timestamped, and uploaded to the S3 evidence vault with Object Lock retention.



Evidence verification will include signature verification, SHA-256 integrity validation, and confirmation of active Object Lock retention.



\## 6. Design Trade-offs



A single AWS account is selected to reduce implementation complexity. A separate evidence account would provide stronger isolation in production.



GOVERNANCE Object Lock mode is selected for sandbox flexibility, with recognition that authorized privileged users may bypass retention.



Automated deployment after merge is selected to demonstrate continuous compliance enforcement. Production environments may require additional approval gates.



The project prioritizes verifiable control implementation and integrated evidence collection over unnecessary infrastructure expansion.



\## 7. Planned Validation



The capstone will demonstrate:



1\. Successful deployment and testing of the Patient Intake API.

2\. Terraform remediation of selected security gaps.

3\. Five or more Rego policies with positive and negative tests.

4\. One successful, merged pull request.

5\. One intentionally noncompliant pull request blocked by the policy gate.

6\. Signed evidence stored with Object Lock retention.

7\. A validated OSCAL component describing actual implemented controls.

8\. A final `WRITEUP.md` documenting design decisions, control coverage, limitations, and trade-offs.



\## 8. Current Progress



The original starter application has been successfully deployed in AWS, and a synthetic API submission returned `"status": "received"`.



Infrastructure hardening, automated policy validation, evidence integration, and OSCAL implementation remain in progress.

