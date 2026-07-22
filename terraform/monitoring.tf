# terraform/monitoring.tf
#
# GAP-08 (SOC 2 CC7.2), partial: API Gateway access logging + throttling.
# The access_log_settings and default_route_settings arguments themselves
# are added via the override mechanism (starter_override.tf) since they
# belong to the starter's existing aws_apigatewayv2_stage.default resource;
# this file just provides the new CloudWatch log group they point at.
#
# WAF is explicitly deferred — see WRITEUP.md "what you didn't get to".

resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 90
}
