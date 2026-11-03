# GAP-06 — Lambda dead-letter queue

resource "aws_sqs_queue" "intake_dlq" {
  name = "${local.name_prefix}-dlq-${local.suffix}"

  message_retention_seconds = 1209600
}
