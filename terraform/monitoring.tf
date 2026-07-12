# monitoring.tf
# Real-time drift detection + auto-remediation (HIPAA 164.312(b); SI-4, CM-3)
# Closes the continuous-monitoring gap: CloudTrail records, EventBridge detects,
# Lambda remediates — finding to fix in seconds, not audit cycles.

# --- Detect: EventBridge rule fires on S3 public-access-block changes ---
resource "aws_cloudwatch_event_rule" "s3_pab_change" {
  name        = "${local.name_prefix}-s3-pab-drift-${local.suffix}"
  description = "Detects deletion or modification of S3 public access blocks (drift from baseline)"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["DeletePublicAccessBlock", "PutPublicAccessBlock"]
    }
  })
}

# --- Respond: Lambda re-applies the compliant configuration ---
resource "aws_lambda_function" "pab_remediate" {
  function_name    = "${local.name_prefix}-pab-remediate-${local.suffix}"
  role             = aws_iam_role.remediation.arn
  handler          = "remediate.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.remediate.output_path
  source_code_hash = data.archive_file.remediate.output_base64sha256
  timeout          = 30
}

data "archive_file" "remediate" {
  type        = "zip"
  source_file = "${path.module}/lambda/remediate.py"
  output_path = "${path.module}/lambda/remediate.zip"
}

resource "aws_cloudwatch_event_target" "pab_to_lambda" {
  rule = aws_cloudwatch_event_rule.s3_pab_change.name
  arn  = aws_lambda_function.pab_remediate.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pab_remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_pab_change.arn
}

# --- Least-privilege role for the remediation Lambda (GAP-07 discipline applies) ---
resource "aws_iam_role" "remediation" {
  name = "${local.name_prefix}-remediation-${local.suffix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "remediation" {
  name = "pab-remediation"
  role = aws_iam_role.remediation.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReapplyPublicAccessBlock"
      Effect   = "Allow"
      Action   = ["s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock"]
      Resource = aws_s3_bucket.uploads.arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "remediation_logs" {
  role       = aws_iam_role.remediation.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}