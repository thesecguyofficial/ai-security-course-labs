# 11.4 CloudTrail. Bedrock runtime calls (InvokeModel, Converse...) are management events: already in the free
# 90-day event history. What is NOT recorded unless you ask: data events, including EVERY inference call on the
# bedrock-mantle endpoint (OpenAI-compatible and Anthropic Messages APIs), which invocation logging also misses.
# This trail records only Bedrock data events and network activity events (calls through our VPC endpoint,
# including ones the endpoint policy refused), so it doesn't pay for a second copy of management events.
# Both are billed at $0.10 per 100,000 events delivered (CloudTrail pricing).

resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket
  force_destroy = true # lab only
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket     = aws_s3_bucket.trail.id
  depends_on = [aws_s3_bucket_public_access_block.trail, aws_s3_bucket_ownership_controls.trail]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck20150319"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = "arn:aws:s3:::${local.trail_bucket}"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AWSCloudTrailWrite20150319"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${local.trail_bucket}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["arn:aws:s3:::${local.trail_bucket}", "arn:aws:s3:::${local.trail_bucket}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_cloudtrail" "ai_data_events" {
  name                       = local.trail_name
  s3_bucket_name             = local.trail_bucket
  kms_key_id                 = aws_kms_key.audit.arn
  enable_log_file_validation = true
  is_multi_region_trail      = true # someone can call bedrock-mantle in any Region
  depends_on                 = [aws_s3_bucket_policy.trail]

  advanced_event_selector {
    name = "Bedrock mantle: CreateInference and other inference/file calls"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::BedrockMantle::Project"]
    }
  }

  advanced_event_selector {
    name = "Network activity through our VPC endpoints for Amazon Bedrock, including VpceAccessDenied"
    field_selector {
      field  = "eventCategory"
      equals = ["NetworkActivity"]
    }
    field_selector {
      field  = "eventSource"
      equals = ["bedrock.amazonaws.com"]
    }
  }

  advanced_event_selector {
    name = "Bedrock guardrails: ApplyGuardrail, including evaluations during model calls"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::Bedrock::Guardrail"]
    }
  }
}
