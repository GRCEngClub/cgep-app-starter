# cgep-app-starter

> Patient Intake API for "Acme Health". The deliberately-flawed workload your **CGE-P capstone** wraps with GRC controls.

## What this is

A minimal AWS workload: VPC, Lambda, API Gateway, DynamoDB, S3. It ingests patient intake submissions over HTTPS. Think of it as a system you have just inherited from an engineering team and been asked to make audit-defensible.

This repository ships **non-compliant on purpose**. Your job in the capstone is not to rewrite this app. Your job is to wrap it with the four CGE-P layers (Terraform GRC baseline, Rego policies, GitHub Actions evidence pipeline, OSCAL component) so the same workload becomes audit-defensible against HIPAA, SOC 2, and CMMC L2.

## The deploy gate

If you cannot deploy this starter, you cannot pass the capstone. Real GRC engineers inherit working systems. Step zero is making the system run.

```bash
git clone [https://github.com/GRCEngClub/cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter)
cd cgep-app-starter

# Confirm you're authenticated to the right account:
make creds AWS_PROFILE=<your-sandbox-profile>

make deploy AWS_PROFILE=<your-sandbox-profile>
make test    AWS_PROFILE=<your-sandbox-profile>

AWS SSO note: if your profile is SSO-based, Terraform's AWS provider can fail to read it directly with failed to find SSO session section. The Makefile's eval $(aws configure export-credentials) pattern handles this. If you're running terraform commands by hand, do the same export first.

Expected output of make test:
{
    "submission_id": "f1e3...",
    "status": "received"
}

When you're done exploring: make destroy.

What you build on top
Fork the repo into your own cgep-capstone and add:

Layer 1 — GRC baseline (Terraform). KMS keys, an S3 evidence vault with Object Lock, a CloudTrail trail. Bring this starter's data stores under your CMK.

Layer 2 — OPA policy suite (Rego). Five or more policies that catch the named gaps in GAPS.md. Each policy maps to at least one control from the framework you choose.

Layer 3 — GitHub Actions pipeline. Plan → Conftest gate → apply → Cosign sign → upload to vault.

Layer 4 — OSCAL component. A component-definition.json describing how your governed system implements its controls.

Full brief: docs/labs/07_01_capstone_brief.md in the course content repo.

Framework mapping is required
Your capstone must declare a primary framework: HIPAA Security Rule, SOC 2 Trust Services Criteria, or CMMC Level 2. Every policy carries at least one control ID from your chosen framework. Your OSCAL component's control-implementations reference your framework's catalog.

A starter mapping is in FRAMEWORKS.md. It is not the only valid mapping. You're expected to defend yours.

Cost
Roughly $0 if destroyed within an hour. Lambda + API Gateway + DynamoDB + S3 are all pay-per-use, and an empty deployment generates no traffic. CloudTrail (which you add) costs cents.

Layout

cgep-app-starter/
├── README.md            # this file
├── WORKLOAD.md          # what the API does
├── GAPS.md              # the named flaws your policies must catch
├── FRAMEWORKS.md        # HIPAA / SOC 2 / CMMC mapping primer
├── Makefile             # make deploy | test | destroy
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── lambda/handler.py
└── test/
     └── intake.sh

License
My Capstone Implementation (Fabio Navarro)
Hello! This section describes how I implemented the 4 required governance layers to secure the Acme Health application under the SOC 2 Type II framework.

Deliverables Directory
WRITEUP.md: My 5-page equivalent documentation written in a clear, engineering-first perspective. It covers my technical design decisions, tooling trade-offs (like using --tlog-upload=false in Cosign to keep healthcare metadata private), and my honest engineering backlog.

COMPLIANCE.md: The required quick-reference matrix mapping my code fixes and OPA policies directly to the SOC 2 Control IDs (CC6.1, CC6.3, CC6.7, and A1.2).

component-definition.json: The machine-readable OSCAL component definition file matching the 1.1.0 schema specification.

Layer Verifications
Terraform Baseline: Configured Customer-Managed Keys (CMK) with automated rotation inside terraform/main.tf, activated Multi-region tracking for AWS CloudTrail, and turned on physical Object-Lock compliance configurations inside our evidence bucket resource block.

OPA Governance Rules: Located in the policies/ directory. If you have OPA installed on your local environment, you can verify my automated test suite validations by running:
opa test ./policies -v
    ```
3.  **CI/CD Pipeline Security:** Automated via `.github/workflows/grc-gate.yml`. It uses a strictly ordered architecture to enforce compliance validations end-to-end: `Plan` -> `Policy Check` (using the official OPA Action tool) -> `Apply` -> `Sign` (with Cosign) -> `Upload` (to our S3 vault).
