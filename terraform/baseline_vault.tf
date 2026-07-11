# baseline_vault.tf
# Object-Locked evidence vault — chain-of-custody storage (AU-9)
# Signed CI bundles land here; Object Lock prevents overwrite/deletion.

resource "aws_s3_bucket" "evidence_vault" {
  bucket              = "${local.name_prefix}-evidence-vault-${local.suffix}"
  object_lock_enabled = true
  force_destroy       = true # lab setting; production would never set this
}

resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1 # lab retention; production: COMPLIANCE mode, years
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket                  = aws_s3_bucket.evidence_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "evidence_vault_tls_only" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.evidence_vault.arn,
      "${aws_s3_bucket.evidence_vault.arn}/*",
    ]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence_vault_tls_only" {
  bucket = aws_s3_bucket.evidence_vault.id
  policy = data.aws_iam_policy_document.evidence_vault_tls_only.json
}

