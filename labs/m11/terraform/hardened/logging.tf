# 11.4 Model invocation logging: prompts, answers and token counts for every bedrock-runtime call.
# It is off by default and covers bedrock-runtime only, not bedrock-mantle (AWS docs). Prompt logs are
# sensitive data: encrypted with the prompts key, readable by investigators, deleted after a fixed time.

resource "aws_cloudwatch_log_group" "prompts" {
  name              = local.prompt_log_group_name
  kms_key_id        = aws_kms_key.prompts.arn
  retention_in_days = var.prompt_log_retention_days
}

# --- S3 bucket for bodies over 100 KB and binary data (CloudWatch Logs only takes up to 100 KB per body)
resource "aws_s3_bucket" "prompts" {
  bucket        = local.prompt_bucket
  force_destroy = true # lab only, so `make down` can delete it with logs inside
}

resource "aws_s3_bucket_public_access_block" "prompts" {
  bucket                  = aws_s3_bucket.prompts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "prompts" {
  bucket = aws_s3_bucket.prompts.id
  rule {
    object_ownership = "BucketOwnerEnforced" # ACLs disabled: AWS says the bucket policy only works without ACLs
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prompts" {
  bucket = aws_s3_bucket.prompts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.prompts.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "prompts" {
  bucket = aws_s3_bucket.prompts.id
  rule {
    id     = "expire-prompt-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.prompt_log_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "prompts" {
  bucket     = aws_s3_bucket.prompts.id
  depends_on = [aws_s3_bucket_public_access_block.prompts, aws_s3_bucket_ownership_controls.prompts]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AmazonBedrockLogsWrite"
        Effect    = "Allow"
        Principal = { Service = "bedrock.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${local.prompt_bucket}/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:${var.region}:${var.account_id}:*" }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["arn:aws:s3:::${local.prompt_bucket}", "arn:aws:s3:::${local.prompt_bucket}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# --- The role Bedrock assumes to write to CloudWatch Logs. The conditions stop another account's Bedrock
# configuration from using it (the "confused deputy" problem).
resource "aws_iam_role" "bedrock_logging" {
  name = "${local.name}-bedrock-logging"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:${var.region}:${var.account_id}:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_logging" {
  name = "write-invocation-logs"
  role = aws_iam_role.bedrock_logging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${local.prompt_log_group_arn}:log-stream:aws/bedrock/modelinvocations"
    }]
  })
}

# One configuration per account and Region. If your sandbox already has one, this REPLACES it,
# and `make down` deletes it.
resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  depends_on = [aws_s3_bucket_policy.prompts, aws_iam_role_policy.bedrock_logging, aws_cloudwatch_log_group.prompts]
  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = false # the Helpdesk is text-only: don't collect what you don't need
    embedding_data_delivery_enabled = false
    video_data_delivery_enabled     = false
    cloudwatch_config {
      log_group_name = local.prompt_log_group_name
      role_arn       = local.logging_role_arn
      large_data_delivery_s3_config {
        bucket_name = local.prompt_bucket
        key_prefix  = "large-data"
      }
    }
  }
}
