######################################################################
# Layer 1 — Evidence vault (immutable storage for pipeline evidence)
#
# Purpose : Every pipeline run uploads its signed evidence bundle here.
#           Once written, a bundle can't be overwritten or deleted for
#           365 days, which gives the evidence chain of custody.
# Control : Supports AU.L2-3.3.1 (audit records retained and protected)
#           and the integrity of every control's evidence.
#
# Design (locked decisions)
#   - Object Lock GOVERNANCE mode, 365-day default retention. Tamper-
#     resistant now, while leaving a narrow, audited path to fix a
#     mistake: only a principal with s3:BypassGovernanceRetention, sending
#     the bypass header, can remove a lock. No role in this repo is
#     granted that permission. COMPLIANCE (no bypass, not even root) is
#     deferred until the program stabilizes.
#   - Same secure-bucket floor as the uploads bucket (SSE-KMS, versioning,
#     TLS-only policy, public access block), but with the EVIDENCE key, so
#     the workload role can never decrypt or alter evidence.
#   - Single account for now; a separate vault account is
#     deferred to scale.
######################################################################

# --------------------------------------------------------------------
# Bucket
# --------------------------------------------------------------------

resource "aws_s3_bucket" "evidence" {
  bucket = "${local.name_prefix}-evidence-${local.suffix}"

  # Object Lock can only be switched on when the bucket is created in
  # this configuration ("Forces new resource"), so it is set here, not
  # added later.
  object_lock_enabled = true

  # Never let Terraform empty the vault on destroy. Locked versions can't
  # be deleted before retention ends anyway; this makes the intent explicit.
  force_destroy = false

  tags = {
    Name      = "${local.name_prefix}-evidence"
    DataClass = "evidence" # overrides default "phi": this bucket holds audit data
  }
}

# --------------------------------------------------------------------
# Security floor: SSE-KMS (evidence key), versioning, TLS-only, no public
# --------------------------------------------------------------------

# Object Lock works only on versioned buckets; the module enables
# versioning along with the rest of the floor.

module "evidence_bucket" {
  source = "./modules/secure-bucket"

  bucket_id   = aws_s3_bucket.evidence.id
  bucket_arn  = aws_s3_bucket.evidence.arn
  kms_key_arn = aws_kms_key.evidence.arn
}

# --------------------------------------------------------------------
# Object Lock default retention
# --------------------------------------------------------------------

# Applies to every new object automatically: S3 sets each version's
# "retain until" date to its creation time plus the retention period.
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "GOVERNANCE" # locked decision; see banner
      days = var.evidence_retention_days
    }
  }
}
