package soc2.security

import rego.v1

# --- CONTROL: SOC 2 CC6.1 (Cifrado S3 mediante CMK) ---
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    rule := resource.change.after.rule[_]
    enc := rule.apply_server_side_encryption_by_default[_]
    enc.sse_algorithm != "aws:kms"
    msg := sprintf("SOC 2 Violación [CC6.1]: El bucket '%v' debe usar cifrado SSE-KMS con una llave CMK controlada por el cliente.", [resource.address])
}

# --- CONTROL: SOC 2 CC6.3 (Mesa de Control - DynamoDB KMS) ---
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    sse := resource.change.after.server_side_encryption[_]
    sse.enabled != true
    msg := sprintf("SOC 2 Violación [CC6.3]: La tabla DynamoDB '%v' debe tener habilitado el cifrado en reposo.", [resource.address])
}

# --- CONTROL: SOC 2 CC6.7 (Tránsito Seguro - S3 Versioning) ---
deny[msg] if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_versioning"
    versioning := resource.change.after.versioning_configuration[_]
    versioning.status != "Enabled"
    msg := sprintf("SOC 2 Violación [CC6.7]: El bucket '%v' debe tener el versionamiento activado.", [resource.address])
}
