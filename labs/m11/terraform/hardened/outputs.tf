output "function_name" {
  value = aws_lambda_function.helpdesk.function_name
}

output "bedrock_runtime_endpoint_id" {
  value = aws_vpc_endpoint.bedrock_runtime.id
}

output "prompt_log_group" {
  value = aws_cloudwatch_log_group.prompts.name
}

output "prompt_log_bucket" {
  value = aws_s3_bucket.prompts.bucket
}

output "trail_name" {
  value = aws_cloudtrail.ai_data_events.name
}
