package soc2.security

test_s3_encryption_denied {
    mock_input := {"resource_changes": [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.bad",
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}}
    }]}
    deny["SOC 2 Violación [CC6.1]: El bucket 'aws_s3_bucket_server_side_encryption_configuration.bad' debe usar cifrado SSE-KMS con una llave CMK controlada por el cliente."] with input as mock_input
}

test_dynamodb_no_kms_denied {
    mock_input := {"resource_changes": [{
        "address": "aws_dynamodb_table.bad",
        "type": "aws_dynamodb_table",
        "change": {"after": {"server_side_encryption": [{"enabled": true}]}}
    }]}
    count(deny) == 0 with input as mock_input
}

test_s3_versioning_disabled {
    mock_input := {"resource_changes": [{
        "address": "aws_s3_bucket_versioning.bad",
        "type": "aws_s3_bucket_versioning",
        "change": {"after": {"versioning_configuration": [{"status": "Suspended"}]}}
    }]}
    count(deny) > 0 with input as mock_input
}
