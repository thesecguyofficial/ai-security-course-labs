output "guardrail_id" {
  value = aws_bedrock_guardrail.helpdesk.guardrail_id
}

output "guardrail_arn" {
  value = aws_bedrock_guardrail.helpdesk.guardrail_arn
}

output "guardrail_version" {
  value = aws_bedrock_guardrail_version.v1.version
}
