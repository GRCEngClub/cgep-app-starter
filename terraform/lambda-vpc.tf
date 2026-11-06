######################################################################
# Lambda-in-VPC support (GAP-05, CMMC SC.L2-3.13.1).
#
# The starter's private subnets have no internet route. The Lambda only
# talks to DynamoDB and S3, so we give it free gateway endpoints for
# those two services and a security group that allows outbound HTTPS to
# nothing else. No NAT gateway, no second VPC.
######################################################################

# Dedicated route table for the private subnets (the starter has none).
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Gateway endpoints: private path to S3 and DynamoDB, no internet needed.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-dynamodb-endpoint" }
}

# Hardened security group: no inbound at all, outbound HTTPS only to the
# S3 and DynamoDB endpoints.
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Intake Lambda: no inbound, HTTPS out to S3 and DynamoDB endpoints only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to S3 and DynamoDB gateway endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    prefix_list_ids = [
      aws_vpc_endpoint.s3.prefix_list_id,
      aws_vpc_endpoint.dynamodb.prefix_list_id,
    ]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

# Lets Lambda create and manage its network interfaces inside the VPC.
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
