# compliant-s3

This primitive enforces five NIST 800-53 controls on a single AWS S3 bucket:

- **SC-28** — AES-256 server-side encryption at rest
- **AU-3 / AU-6** — Server access logging to a dedicated log bucket
- **CM-6** — Versioning enabled; four required compliance tags enforced via provider default_tags
- **AC-3** — All four public access block flags set to true

SOC 2 mapping: CC6.1 (encryption), CC7.2 (logging), CC6.8 (config), CC6.6 (access control).