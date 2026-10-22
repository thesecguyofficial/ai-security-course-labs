# M13 optional cloud step: the PORTED Helpdesk knowledge base (Bedrock Managed Knowledge Base, ACL-aware S3 data
# source, customer managed KMS key) and, optionally, the AgentCore harness with two inline function tools.
# Deploy ONLY in your own sandbox account (lesson 0.7). Cost and teardown: README Step 9 and GUIDED-BUILD.md.
# Not applied by the course authors: checked with `tofu fmt`, `tofu validate` and an offline mock-credential plan.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.70" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "users" {
  description = "Stand-ins for your identity provider's users. They are ONLY strings in the ACL file: nothing is emailed."
  type        = map(string)
  default = {
    alice = "alice@example.com" # IT staff
    bob   = "bob@example.com"   # sales
    priya = "priya@example.com" # HR
  }
}

variable "create_harness" {
  description = "Also create the AgentCore harness (GUIDED-BUILD Part B, path C). The knowledge base alone costs almost nothing."
  type        = bool
  default     = false
}

variable "model_id" {
  description = "The M11 inference profile."
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

data "aws_caller_identity" "me" {}

locals {
  account  = data.aws_caller_identity.me.account_id
  bucket   = "tsg-m13-kb-${local.account}"
  docs     = fileset("${path.module}/../../data/docs", "**/*.md")
  everyone = [for u in values(var.users) : { Name = u, Type = "USER", Access = "ALLOW" }]
  global_acl = [
    { keyPrefix = "s3://${local.bucket}/public/", aclEntries = local.everyone },
    { keyPrefix = "s3://${local.bucket}/inbox/", aclEntries = local.everyone },
    { keyPrefix = "s3://${local.bucket}/hr/", aclEntries = [{ Name = var.users["priya"], Type = "USER", Access = "ALLOW" }] },
    { keyPrefix = "s3://${local.bucket}/it-admin/", aclEntries = [{ Name = var.users["alice"], Type = "USER", Access = "ALLOW" }] },
  ]
}

# ---------------------------------------------------------------- encryption: one customer managed key for the KB
resource "aws_kms_key" "kb" {
  description             = "TSG Helpdesk M13 knowledge base"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# ---------------------------------------------------------------- the documents and the ACL file (same bucket)
resource "aws_s3_bucket" "kb" {
  bucket        = local.bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "kb" {
  bucket                  = aws_s3_bucket.kb.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kb" {
  bucket = aws_s3_bucket.kb.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_policy" "kb" {
  bucket = aws_s3_bucket.kb.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.kb.arn, "${aws_s3_bucket.kb.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_object" "doc" {
  for_each     = local.docs
  bucket       = aws_s3_bucket.kb.id
  key          = each.value
  source       = "${path.module}/../../data/docs/${each.value}"
  etag         = filemd5("${path.module}/../../data/docs/${each.value}")
  content_type = "text/markdown"
}

resource "aws_s3_object" "global_acl" {
  bucket       = aws_s3_bucket.kb.id
  key          = "acl/global-acl.json"
  content      = jsonencode(local.global_acl)
  content_type = "application/json"
}

# ---------------------------------------------------------------- the knowledge base service role (AWS's documented shape)
resource "aws_iam_role" "kb" {
  name = "tsg-m13-kb-service-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account }
        ArnLike      = { "AWS:SourceArn" = "arn:aws:bedrock:${var.region}:${local.account}:knowledge-base/*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "kb" {
  role = aws_iam_role.kb.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "S3ListBucketStatement", Effect = "Allow", Action = ["s3:ListBucket"], Resource = [aws_s3_bucket.kb.arn],
      Condition = { StringEquals = { "aws:ResourceAccount" = local.account } } },
      { Sid = "S3GetObjectStatement", Effect = "Allow", Action = ["s3:GetObject"], Resource = ["${aws_s3_bucket.kb.arn}/*"],
      Condition = { StringEquals = { "aws:ResourceAccount" = local.account } } },
      { Sid = "KbMetrics", Effect = "Allow", Action = "cloudwatch:PutMetricData", Resource = "*",
      Condition = { StringEquals = { "cloudwatch:namespace" = "AWS/Bedrock/KnowledgeBases" } } },
    ]
  })
}

# ---------------------------------------------------------------- the managed knowledge base + ACL-aware S3 data source
resource "aws_bedrockagent_knowledge_base" "kb" {
  name        = "tsg-m13-helpdesk-kb"
  description = "TSG Helpdesk M13: managed knowledge base, ACL-aware S3 source"
  role_arn    = aws_iam_role.kb.arn
  knowledge_base_configuration {
    type = "MANAGED"
    managed_knowledge_base_configuration {
      embedding_model_type = "MANAGED"
      server_side_encryption_configuration {
        kms_key_arn = aws_kms_key.kb.arn
      }
    }
  }
  depends_on = [aws_iam_role_policy.kb]
}

resource "aws_bedrockagent_data_source" "s3" {
  name                 = "tsg-m13-kb-s3"
  knowledge_base_id    = aws_bedrockagent_knowledge_base.kb.id
  data_deletion_policy = "DELETE"
  data_source_configuration {
    type = "MANAGED_KNOWLEDGE_BASE_CONNECTOR"
    managed_knowledge_base_connector_configuration {
      connector_parameters = jsonencode({
        type                    = "S3"
        version                 = "1"
        aclEnabled              = true
        connectionConfiguration = { bucketName = aws_s3_bucket.kb.id, bucketOwnerAccountId = local.account }
        aclConfiguration        = { globalAccessControlListS3Uri = "s3://${aws_s3_bucket.kb.id}/acl/global-acl.json" }
      })
    }
  }
  depends_on = [aws_s3_object.doc, aws_s3_object.global_acl]
}

# ---------------------------------------------------------------- optional: the AgentCore harness (inline functions only)
resource "aws_iam_role" "harness" {
  count = var.create_harness ? 1 : 0
  name  = "tsg-m13-harness-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "bedrock-agentcore.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# AWS's sample execution policy (harness-security), cut down: no Browser, no Code Interpreter, no Memory (all unused
# here), and model access limited to Claude Haiku 4.5 through the US inference profile.
resource "aws_iam_role_policy" "harness" {
  count = var.create_harness ? 1 : 0
  role  = aws_iam_role.harness[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "BedrockModelInvocation", Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        Resource = ["arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
      "arn:aws:bedrock:${var.region}:${local.account}:inference-profile/${var.model_id}"] },
      { Sid = "EcrPublicTokenAccess", Effect = "Allow", Action = ["ecr-public:GetAuthorizationToken"], Resource = "*" },
      { Sid = "StsForEcrPublicPull", Effect = "Allow", Action = ["sts:GetServiceBearerToken"], Resource = "*" },
      { Sid = "XRayTracingAccess", Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"], Resource = "*" },
      { Sid = "CloudWatchLogsGroup", Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:DescribeLogStreams"],
      Resource = "arn:aws:logs:${var.region}:${local.account}:log-group:/aws/bedrock-agentcore/runtimes/*" },
      { Sid = "CloudWatchLogsDescribeGroups", Effect = "Allow", Action = ["logs:DescribeLogGroups"], Resource = "arn:aws:logs:${var.region}:${local.account}:log-group:*" },
      { Sid = "CloudWatchLogsStream", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = "arn:aws:logs:${var.region}:${local.account}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*" },
      { Sid = "CloudWatchMetricsPublish", Effect = "Allow", Action = "cloudwatch:PutMetricData", Resource = "*",
      Condition = { StringEquals = { "cloudwatch:namespace" = "bedrock-agentcore" } } },
      { Sid = "AgentCoreWorkloadIdentity", Effect = "Allow", Action = ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT"],
        Resource = ["arn:aws:bedrock-agentcore:${var.region}:${local.account}:workload-identity-directory/default",
      "arn:aws:bedrock-agentcore:${var.region}:${local.account}:workload-identity-directory/default/workload-identity/harness_tsg_m13_helpdesk-*"] },
    ]
  })
}

resource "aws_bedrockagentcore_harness" "helpdesk" {
  count              = var.create_harness ? 1 : 0
  harness_name       = "tsg_m13_helpdesk"
  execution_role_arn = aws_iam_role.harness[0].arn
  allowed_tools      = ["search_kb", "reset_mfa"]
  max_iterations     = 6
  timeout_seconds    = 120
  model {
    bedrock_model_config { model_id = var.model_id }
  }
  system_prompt {
    text = "You are TSG Helpdesk, the IT helpdesk assistant for AnyCompany staff. Use search_kb to answer from the knowledge base. Use reset_mfa only when the user asks for an MFA reset."
  }
  tool {
    name = "search_kb"
    type = "inline_function"
    config {
      inline_function {
        description  = "Search the IT knowledge base for articles that answer the user's question."
        input_schema = jsonencode({ type = "object", properties = { query = { type = "string" } }, required = ["query"] })
      }
    }
  }
  tool {
    name = "reset_mfa"
    type = "inline_function"
    config {
      inline_function {
        description  = "Reset multi-factor authentication for a user so they can enrol a new device."
        input_schema = jsonencode({ type = "object", properties = { target_email = { type = "string" } }, required = ["target_email"] })
      }
    }
  }
  memory {
    disabled {}
  }
  depends_on = [aws_iam_role_policy.harness]
}

output "knowledge_base_id" { value = aws_bedrockagent_knowledge_base.kb.id }
output "data_source_id" { value = aws_bedrockagent_data_source.s3.data_source_id }
output "bucket" { value = aws_s3_bucket.kb.id }
output "harness_arn" { value = var.create_harness ? aws_bedrockagentcore_harness.helpdesk[0].arn : "" }
