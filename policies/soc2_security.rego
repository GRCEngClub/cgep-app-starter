# metadata.package
# title: Suite de Seguridad y Gobernanza GRC para SOC 2
# description: Reglas de validación estricta para asegurar la conformidad con los criterios de servicios de confianza (TSC) de SOC 2.
# custom:
#   primary_framework: SOC2-TSC
package soc2.security

import future.keywords.in

# Por defecto, el plan es válido a menos que una regla de denegación se active
default allow = true

allow = false {
    count(deny) > 0
}

# metadata.rule
# title: Cifrado Seguro de S3 mediante CMK
# description: Bloquea si los buckets S3 no utilizan una llave de cifrado administrada por el cliente (KMS CMK).
# custom:
#   control_id: CC6.1
#   gap_id: GAP-01
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    
    rule := resource.change.after.rule[_]
    enc := rule.apply_server_side_encryption_by_default[_]
    enc.sse_algorithm != "aws:kms"
    
    msg := sprintf("SOC 2 Violación [CC6.1]: El bucket '%v' debe usar cifrado SSE-KMS con una llave CMK controlada por el cliente.", [resource.address])
}

# metadata.rule
# title: Cifrado en Reposo Obligatorio de DynamoDB
# description: Bloquea si la tabla de DynamoDB deshabilita explícitamente el cifrado perimetral.
# custom:
#   control_id: CC6.1
#   gap_id: GAP-02
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    
    sse := resource.change.after.server_side_encryption[_]
    sse.enabled == false
    
    msg := sprintf("SOC 2 Violación [CC6.1]: La tabla DynamoDB '%v' debe tener el cifrado en reposo habilitado explícitamente.", [resource.address])
}

# metadata.rule
# title: Cifrado Personalizado de DynamoDB mediante CMK
# description: Bloquea si DynamoDB utiliza las llaves por defecto de AWS (AWS Managed Keys) en lugar de una CMK propia.
# custom:
#   control_id: CC6.1
#   gap_id: GAP-02-B
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    
    sse := resource.change.after.server_side_encryption[_]
    not sse.kms_key_arn
    
    msg := sprintf("SOC 2 Violación [CC6.1]: La tabla DynamoDB '%v' debe usar un KMS CMK personalizado, no la llave por defecto de AWS.", [resource.address])
}

# metadata.rule
# title: Encriptación en Tránsito Forzada con TLS
# description: Exige que los buckets S3 tengan una política de bucket (S3 Bucket Policy) adjunta para obligar conexiones TLS seguras.
# custom:
#   control_id: CC6.7
#   gap_id: GAP-03
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    bucket_name := resource.name
    policies := [p | p := input.resource_changes[_]; p.type == "aws_s3_bucket_policy"]
    count(policies) == 0
    
    msg := sprintf("SOC 2 Violación [CC6.7]: El bucket '%v' requiere una política S3BucketPolicy adjunta para forzar conexiones TLS seguro.", [bucket_name])
}

# metadata.rule
# title: Versionado de Buckets S3 para Disponibilidad
# description: Bloquea buckets si no cuentan con el versionado activo para salvaguardar la inmutabilidad y auditoría ante fallas.
# custom:
#   control_id: A1.2
#   gap_id: GAP-04
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_versioning"
    
    versioning := resource.change.after.versioning_configuration[_]
    versioning.status != "Enabled"
    
    msg := sprintf("SOC 2 Violación [A1.2]: El versionado de S3 debe estar explícitamente 'Enabled' para garantizar disponibilidad y auditoría.", [resource.address])
}

# metadata.rule
# title: Principio de Menor Privilegio en IAM
# description: Detecta y bloquea roles o políticas de IAM que utilicen comodines peligrosos (*) sobre servicios sensibles.
# custom:
#   control_id: CC6.3
#   gap_id: GAP-07
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    
    policy_str := resource.change.after.policy
    policy := json.unmarshal(policy_str)
    statement := policy.Statement[_]
    
    statement.Effect == "Allow"
    actions := statement.Action
    
    dangerous_actions := ["*", "dynamodb:*", "s3:*"]
    some act in actions
    act in dangerous_actions
    
    msg := sprintf("SOC 2 Violación [CC6.3]: Privilegios excesivos detectados en '%v'. El uso de acciones comodín como s3:* o dynamodb:* está prohibido.", [resource.address])
}