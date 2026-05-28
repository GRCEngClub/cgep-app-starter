# CGE-P Capstone Architectural Write-up & Production GRC Strategy

**Candidate:** Jose Fabio Navarro Mora  
**Certification Level:** CGE-P Candidate  
**Target Application:** Patient Intake API  
**Chosen Primary Compliance Framework:** SOC 2 Type II (Security and Availability)  
**System Version:** 2.0.0 (Production-Adjacent Upgrade)

---

## 1. Introduction, Design Decisions & Primary Framework Defense

### 1.1 Project Overview & Context
In this Capstone project, I assumed the role of a Lead GRC Engineer to secure a deliberately flawed telehealth microservice repository deployed by "Acme Health" (a startup with approximately 50 employees). The original baseline repository represented a high-risk compliance profile: cloud storage layer (Amazon S3) and persistent database tier (Amazon DynamoDB) lacked any form of cryptographic encryption at rest. Furthermore, the Identity and Access Management (IAM) permissions violated the fundamental security principle of least privilege by employing sweeping wildcards (`*`). 

My mandate was to design, implement, and audit an automated governance framework wrapping this workload. This ensuring that any infrastructure changes proposed via code are systematically verified pre-deployment, cryptographically signed, and preserved in an unalterable audit trail.

### 1.2 Strategic Framework Selection & Defense (The Three-Flag Dilemma)
Acme Health is currently pursuing three compliance milestones simultaneously: **HIPAA Security Rule** (due to handling private Patient Health Information), **CMMC Level 2** (driven by a potential federal pilot program), and **SOC 2 Type II** (mandated by an immediate enterprise customer requirement). Recognizing that a 50-person startup cannot satisfy all three frameworks in a single initial implementation without causing operational paralysis, I selected **SOC 2 Type II (Security and Availability Trust Services Criteria)** as our primary framework. Every automated layer under this architecture has been structured around it based on the following comparative defense:

* **Why not HIPAA as the primary framework?:** While the HIPAA Security Rule is absolutely mandatory for handling PHI, it operates primarily as a high-level regulatory law rather than a prescriptive engineering standard. HIPAA dictates *what* must be protected (e.g., ensuring confidentiality and access controls), but fails to provide a structured, automated control verification baseline mapping neatly to modern Continuous Integration (CI) execution states or JSON plan structures.
* **Why not CMMC Level 2 as the primary framework?:** Cybersecurity Maturity Model Certification (CMMC) Level 2 is required for Department of Defense federal contractors handling Controlled Unclassified Information (CUI). CMMC introduces massive administrative and programmatic burdens, requiring extensive physical, operational, and structural documentation that is completely misaligned with the current resources of an early-stage 50-person commercial startup. Prioritizing a heavy federal pilot framework would stall application delivery without an immediate commercial guarantee.

**The Selection Defense:** I prioritized **SOC 2 Type II** because it bridges the gap between regulatory intent and real-world DevSecOps engineering. SOC 2 allows us to group HIPAA data protection concerns (under the Security criteria) and system resilience needs (under the Availability criteria) into a single, comprehensive, and programmatically testable posture. By enforcing SOC 2 Trust Services Criteria programmatically inside our GitHub pipeline, we provide immediate, continuous, and empirical compliance proof to close the enterprise customer contract. This technical foundation implicitly satisfies HIPAA infrastructure requirements and positions Acme Health for a smoother, subsequent adoption of CMMC thresholds when the federal pilot matures.

---

## 2. Risk Mitigation & Infrastructure Hardening (IaC Quality)

To systematically address infrastructure vulnerabilities, I mapped five specific technical findings to the SOC 2 framework inside `terraform/main.tf`:

### GAP-01: S3 Uploads Bucket Encryption (SOC 2 CC6.1 - Data Protection / HIPAA §164.312(a)(2)(iv))
* **Vulnerability:** The public S3 storage bucket destined for patient intake attachments completely lacked encryption at rest, leaving files exposed to physical data center extraction risks or misconfigurations.
* **Remediation:** I provisioned an explicit Customer Managed Key (CMK) via AWS KMS with a strict annual rotation schedule. I updated the `aws_s3_bucket_server_side_encryption_configuration` resource block to enforce standard `aws:kms` algorithms using this dedicated CMK. Data is now cryptographically scrambled the instant it hits AWS disk space.

### GAP-02: DynamoDB Table Encryption (SOC 2 CC6.1 - Data Protection / HIPAA §164.312(e)(2)(ii))
* **Vulnerability:** The persistent storage layer handling private patient intake forms relied on standard AWS-managed keys. While technically encrypted, this configuration prevents the organization from managing key lifecycles, auditing key access, or exercising cross-tenant logical access controls.
* **Remediation:** I modified the `aws_dynamodb_table` resource block to explicitly declare server-side encryption pointing to our dedicated Customer Managed Key (`aws_kms_key`). This guarantees exclusive cryptographic custody of health records.

### GAP-03: Blocking Non-Secure Connections (SOC 2 CC6.7 - Secure Transmission)
* **Vulnerability:** The ingestion bucket allowed unencrypted connections via standard cleartext HTTP, leaving patient data vulnerable to packet interception and Man-in-the-Middle (MitM) attacks.
* **Remediation:** I implemented a strict `aws_s3_bucket_policy` attaching an explicit `Deny` statement to the storage resource. The conditional logic explicitly targets any API requests where `aws:SecureTransport` evaluates to `false`, dropping unencrypted data in transit before processing.

### GAP-04: S3 Bucket Versioning and Integrity (SOC 2 A1.2 - Availability)
* **Vulnerability:** S3 objects could be permanently deleted by simple human error or malicious ransomware vectors, causing a catastrophic loss of data availability for medical operators.
* **Remediation:** I declared an `aws_s3_bucket_versioning` resource block setting the status parameter to `Enabled`. This transforms the storage vault into an append-only ledger, preserving chronological states underneath deletion markers to ensure rapid disaster recovery windows.

### GAP-07: Least Privilege Lambda IAM Policies (SOC 2 CC6.3 - Perimeter Defense / CMMC AC.L2-3.1.1)
* **Vulnerability:** The compute tier execution role contained broad wildcards (`s3:*` and `dynamodb:*`). If an application vulnerability allowed Remote Code Execution (RCE), the entire cloud state could be completely compromised.
* **Remediation:** I refactored the IAM inline policies to restrict permissions down to specialized APIs: `dynamodb:PutItem` and `s3:PutObject`. The blast radius is now confined strictly to standard application transactions.

---

## 3. DevSecOps CI/CD Integration & Automated Enforcement

### 3.1 The Strict Enforcement Gate (5 Mandated Steps)
The delivery pipeline defined in `.github/workflows/grc-gate.yml` implements a production-grade automated compliance gate structured around exactly five functional stages:

1.  **Plan:** Initializes HashiCorp Terraform within the runner, runs a dry-run plan, and converts the binary output into an audit-ready JSON structure (`terraform show -json`).
2.  **Policy Check:** Provisions the modern Open Policy Agent (OPA) binary and scans the plan JSON against our infrastructure rules. Rather than acting as a passive reporting tool, I implemented a strict enforcement script using `jq`. If OPA returns any active policy violations, the step forces an immediate `exit 1` block. This effectively paints the pipeline red and terminates the build before any infrastructure is altered.
3.  **Apply:** A mocked structural step executing deployment logic solely if the upstream compliance gate evaluates to zero active violations.
4.  **Sign:** Leverages the Sigstore `Cosign` suite to cryptographically sign the generated compliance report file, preventing evidence tampering by internal actors.
5.  **Upload:** Packages the artifact trail (`compliance-evidence.json` and its respective cryptographic signature file `.sig`) and persists them as a long-term GitHub workflow artifact, establishing an automated ledger for external auditors.

### 3.2 Real-World Engineering Trade-offs & Tooling Failures
Navigating the complexities of automation required deep troubleshooting and significant modifications to standard reference configurations:

* **The OPA Network Bottleneck (Custom Scripts vs. Official Marketplace Actions):** Early iterations relied on downloading the OPA engine on-the-fly via a manual bash script with a standard `curl` invocation. During baseline runs, this step frequently failed with a `curl: (56) Failure when receiving data from the peer` network exception, freezing the container for five minutes before dropping the job. Relying on basic web downloads introduces single points of failure in private pipelines. To address this, I fully refactored the step to ingest the official marketplace action `open-policy-agent/setup-opa@v2`, stabilizing runner builds and dropping runtime overhead down to three seconds.
* **Cosign Data Leakage & Privacy Trade-off (`--tlog-upload=false`):** By default, Cosign uploads public cryptographic hashes and transparency log parameters to the public Rekor ledger on the open internet. For a healthcare provider bound by strict privacy frameworks, leaking metadata regarding private infrastructure configurations to a public repository creates a serious reconnaissance attack surface. I made a deliberate security trade-off by adding the `--tlog-upload=false` flag. This maintains a private and isolated compliance log inside the organizational perimeter.

---

## 4. Policy-as-Code Syntax Modernization & Test Coverage

### 4.1 Modern Rego Implementation
Following rigorous validation constraints, the OPA rule engine defined in `policies/soc2_security.rego` was upgraded to conform to the strict `rego.v1` specifications required by modern compilers. This included appending the mandatory `if` keyword before every rule declaration block:

```rego
package soc2.security
import rego.v1

deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    rule := resource.change.after.rule[_]
    enc := rule.apply_server_side_encryption_by_default[_]
    enc.sse_algorithm != "aws:kms"
    msg := sprintf("SOC 2 Violación [CC6.1]: El bucket '%v' debe usar cifrado SSE-KMS con una llave CMK.", [resource.address])
}
This strict architectural layout parses the incoming JSON, filters resource changes, evaluates parameters against the predefined baseline constraints, and dynamically prints explicit compliance warning arrays if violations occur.

4.2 Comprehensive Matrix Testing
To satisfy rigorous control testing dimensions, the file policies/soc2_security_test.rego was heavily expanded. It implements a bidirectional test matrix verifying both compliant and non-compliant inputs across all mapped trust criteria:

Negative Testing (test_..._denied): Feeds a mock plan containing standard AES256 encryption or disabled versioning parameters, verifying that the deny list accurately captures the failure and increments the violation payload.

Positive Testing (test_..._approved): Feeds a compliant cloud setup containing valid KMS CMK settings, certifying that OPA allows the build through without raising false-positive blocks (count(deny) == 0).

5. Continuous Real-Time Threat Detection & Monitoring
Recognizing that pre-deployment CI/CD gates cannot prevent manual alterations or accidental "hot-fixes" performed directly inside the AWS Management Console (causing configuration drift), I extended the architecture by adding an active threat monitoring layer under monitoring/detection_lambda.py.

This Python script is designed to process streaming logs from aws_cloudtrail in real time via EventBridge. It provides active detection logic that explicitly extracts provenance data (the acting user's identity ARN, exact event timestamps, and specific target resource boundaries) and generates high-priority audit warnings:

CC6.1 Ingestion Alerts: It evaluates incoming PutBucketEncryption and DeleteBucketEncryption API payloads. If a user downgrades storage security controls, it flags the event as an explicit error, logging the exact source and control violation ID to protect PHI against HIPAA leaks.

CC6.3 Privilege Escalation: It captures drift in permission bounds by monitoring manual PutRolePolicy or CreatePolicyVersion events, bridging the gap between static code assurance and runtime operational reality.

6. Open Security Controls Assessment Language (OSCAL)
To modernize our regulatory posture, I introduced a machine-readable governance document at the root directory called component-definition.json, adhering strictly to the standardized NIST OSCAL 1.1.0 JSON Schema.

Instead of allowing security compliance to become static, siloed documentation inside legacy spreadsheets, OSCAL allows compliance tracking to become fully integrated with development. The component file establishes a clear link between our specific code controls (the OPA engine steps and the active Lambda logging system) and the formal SOC 2 control catalog, mapping its operational extensions directly to HIPAA and CMMC boundaries. External auditors can ingest this document using automated GRC analysis engines, confirming our security posture programmatically without conducting manually intensive architecture reviews.

7. Limitations & Engineering Backlog (Honest Retrospective)
Because this system was developed in a sandboxed lab environment with explicit network boundaries and learning trajectories, several enterprise enhancements remain on the roadmap:

Hardware Security Modules (HSM) for Key Management: During the automated Sign workflow step, Cosign currently generates localized, file-based ephemeral private keys backed by standard environment variable passwords. In an enterprise deployment, exposing signing passwords within standard runner contexts creates an insider threat vector. The ideal long-term strategy requires storing the cryptographic keys inside a dedicated hardware security module (e.g., AWS KMS CloudHSM), ensuring that the private key material can never be extracted or read by external code logs.

Handling Organization Workflow Approvals: When pushing updates from my developer account to the core organization repository (GRCEngClub), GitHub Actions automatically triggers a protection gate stating: "Awaiting approval from a maintainer". Since I do not possess full administrative permissions over the parent organization runners, I could not force execution on their internal nodes directly. I mitigated this restriction by performing validation runs offline and via branch executions on my local forks. In production, this must be solved by working with corporate DevOps teams to whitelist specialized developer paths or utilizing self-hosted enterprise runner groups.
