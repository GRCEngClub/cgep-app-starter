# terraform/networking_lambda.tf
#
# Support resources for GAP-05: moving the Lambda into the starter's private
# subnets (the vpc_config override lives in starter_override.tf). Gateway VPC
# endpoints are required here — without them, DynamoDB/S3 calls from inside
# the private subnets have no route out and the intake handler starts
# timing out.

######################################################################
# Security group for the Lambda ENI. Gateway endpoints (S3, DynamoDB) route
# via the VPC's prefix lists, not through the SG, so default egress-all is
# sufficient. No ingress: Lambda ENIs don't accept inbound connections.
######################################################################

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Lambda intake handler ENI, private subnets"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "All outbound (gateway endpoints route via prefix list, not SG)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

######################################################################
# Any Lambda with a vpc_config needs ec2:CreateNetworkInterface (and
# friends) to attach an ENI in the target subnets -- a separate grant from
# AWSLambdaBasicExecutionRole, which only covers CloudWatch Logs. Without
# this, CreateFunction fails with "execution role does not have
# permissions to call CreateNetworkInterface on EC2."
######################################################################

resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

######################################################################
# GAP-05 (SOC 2 CC6.6): gateway endpoints so the now-VPC-bound Lambda can
# still reach DynamoDB and S3 without traversing the public internet or
# needing a NAT gateway. Gateway endpoints attach to route tables; the
# starter's private subnets have no explicit route table association, so
# they use the VPC's default route table.
######################################################################

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.main.default_route_table_id]
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.main.default_route_table_id]
}
