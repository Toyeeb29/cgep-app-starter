# apigw_logging.tf
# GAP-08: API Gateway access logging — HIPAA 164.312(b)
# Every request touching PHI gets an audit record.

resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigateway/${local.name_prefix}-access-${local.suffix}"
  retention_in_days = 90
}