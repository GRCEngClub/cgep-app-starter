package soc2.security

# === PRUEBAS CONTROL CC6.1 (Cifrado S3) ===
test_s3_encryption_denied if {
    mock_input := {"resource_changes": [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.bad",
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}}
    }]}
    count(deny) > 0 with input as mock_input
}

test_s3_encryption_approved if {
    mock_input := {"resource_changes": [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.good",
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}}
    }]}
    count(deny) == 0 with input as mock_input
}

# === PRUEBAS CONTROL CC6.3 (Mesa de Control - DynamoDB KMS) ===
test_dynamodb_no_kms_denied if {
    mock_input := {"resource_changes": [{
        "address": "aws_dynamodb_table.bad",
        "type": "aws_dynamodb_table",
        "change": {"after": {"server_side_encryption": [{"enabled": false}]}}
    }]}
    count(deny) > 0 with input as mock_input
}

test_dynamodb_kms_approved if {
    mock_input := {"resource_changes": [{
        "address": "aws_dynamodb_table.good",
        "type": "aws_dynamodb_table",
        "change": {"after": {"server_side_encryption": [{"enabled": true}]}}
    }]}
    count(deny) == 0 with input as mock_input
}

# === PRUEBAS CONTROL CC6.7 (Tránsito Seguro - S3 HTTPS) ===
test_s3_versioning_disabled if {
    mock_input := {"resource_changes": [{
        "address": "aws_s3_bucket_versioning.bad",
        "type": "aws_s3_bucket_versioning",
        "change": {"after": {"versioning_configuration": [{"status": "Disabled"}]}}
    }]}
    count(deny) > 0 with input as mock_input
}

test_s3_versioning_approved if {
    mock_input := {"resource_changes": [{
        "address": "aws_s3_bucket_versioning.good",
        "type": "aws_s3_bucket_versioning",
        "change": {"after": {"versioning_configuration": [{"status": "Enabled"}]}}
    }]}
    count(deny) == 0 with input as mock_input
}
