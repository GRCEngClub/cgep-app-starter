package compliance.hipaa.audit_logging_test

import rego.v1
import data.compliance.hipaa.audit_logging

compliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_apigatewayv2_stage.default",
    "type": "aws_apigatewayv2_stage",
    "values": {"access_log_settings": [{"destination_arn": "arn:aws:logs:us-east-1:123:log-group:/aws/apigateway/acme"}]}
  }
]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_apigatewayv2_stage.default",
    "type": "aws_apigatewayv2_stage",
    "values": {"access_log_settings": []}
  }
]}}}

test_compliant_passes if { count(audit_logging.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in audit_logging.deny with input as noncompliant_input
  contains(msg, "164.312(b)")
}
