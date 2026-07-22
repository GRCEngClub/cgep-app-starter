# Acme Health Patient Intake API — CGE-P Capstone (SOC 2 Type II)

Fork of [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter) wrapped with
a Terraform GRC baseline, an OPA/Rego policy suite, a signing GitHub Actions pipeline, and an OSCAL
component. Declared primary framework: **SOC 2 Type II** (see `WRITEUP.md` for the defense).

## For the grader

```bash
git clone https://github.com/samruss824/cgep-app-starter
cd cgep-app-starter

# Layer 1 -- deploy gate (same as upstream)
make deploy AWS_PROFILE=<your-sandbox-profile>
make test   AWS_PROFILE=<your-sandbox-profile>   # expect {"status": "received"}

# Layer 2 -- policy suite
opa test ./policies                              # expect PASS on every test

# Layer 3 -- pipeline
# See .github/workflows/grc-gate.yml and the repo's PR history for one
# green (merged) PR and one red (blocked) PR.

# Verify a signed evidence bundle end-to-end (SHA-256, Cosign/Rekor,
# Object Lock retention):
./scripts/verify-evidence.sh <run_id> --vault <evidence-vault-bucket> --profile <your-sandbox-profile>

# Layer 4 -- OSCAL
trestle validate -f oscal/components/acme-health-intake.json
```

When you're done: `make destroy`.

## Layout

```
cgep-app-starter/
├── README.md                       # this file
├── WRITEUP.md                      # design decisions, control coverage, trade-offs
├── WORKLOAD.md, GAPS.md, FRAMEWORKS.md   # upstream starter docs, unchanged
├── Makefile
├── terraform/
│   ├── main.tf, variables.tf, outputs.tf, lambda/  # upstream starter, unchanged
│   ├── kms.tf                      # customer-managed key
│   ├── evidence_vault.tf           # Object Lock evidence bucket, KMS-encrypted
│   ├── cloudtrail.tf               # multi-region trail + dedicated log bucket
│   ├── s3_hardening.tf             # GAP-01, GAP-03, GAP-04 (new S3 sub-resources)
│   ├── networking_lambda.tf        # GAP-05 support (SG, gateway VPC endpoints)
│   ├── monitoring.tf                # GAP-08 support (CloudWatch log group)
│   ├── starter_override.tf         # GAP-02, GAP-05, GAP-07, GAP-08 (Terraform
│   │                                # override file -- merges into the starter's own
│   │                                # resource blocks without editing main.tf)
│   ├── outputs_grc.tf
│   └── backend.tf                  # remote state -- see oidc/ for the bucket this points at
├── oidc/                           # bootstrap: GitHub OIDC trust + CI's IAM role + the
│                                    # state bucket above. Applied once by hand, not by CI.
├── policies/                       # 6 Rego policies + _test.rego, SOC 2 CC-mapped
├── scripts/
│   ├── policy-gate.sh              # conftest runner (used locally; CI inlines the loop)
│   └── verify-evidence.sh          # the 3 checks the grader runs on a signed bundle
├── .github/workflows/grc-gate.yml  # Plan -> Policy check -> Apply -> Sign -> Upload
└── oscal/
    ├── components/acme-health-intake.json
    └── profiles/soc2-minimum.json
```

## License

MIT. Fork freely. Submissions remain learners' own work.
