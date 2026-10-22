# 11.3 Encryption. Two customer managed keys, because two different groups should read two different things:
#   prompts key: model invocation logs (prompts and answers) in CloudWatch Logs and S3
#   audit key:   CloudTrail log files
# Each key costs $1/month, prorated hourly (AWS KMS pricing).

resource "aws_iam_role" "investigator" {
  name = "${local.name}-log-investigator"
  # Who may read prompt logs during an investigation: people in this account who assume this role with MFA.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.account_root_arn }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
}

resource "aws_kms_key" "prompts" {
  description             = "${local.name}: Bedrock model invocation logs (prompts and answers)"
  enable_key_rotation     = true
  deletion_window_in_days = 7 # the minimum; fine for a lab, use 30 in production
  depends_on              = [aws_iam_role.investigator, aws_iam_role.bedrock_logging]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministrationByTheAccount" # the AWS default statement; IAM policies decide who else
        Effect    = "Allow"
        Principal = { AWS = local.account_root_arn }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsForThePromptLogGroupOnly"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = { ArnEquals = { "kms:EncryptionContext:aws:logs:arn" = local.prompt_log_group_arn } }
      },
      {
        Sid       = "BedrockLogDeliveryFromThisAccountOnly"
        Effect    = "Allow"
        Principal = { Service = "bedrock.amazonaws.com" }
        Action    = "kms:GenerateDataKey"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:${var.region}:${var.account_id}:*" }
        }
      },
      {
        # CloudWatch Logs: a principal calling PutLogEvents on a log group with a customer managed key "needs
        # additional AWS KMS permissions". Bedrock writes as the logging role, so that role gets them, only via Logs.
        Sid       = "BedrockLoggingRoleWritesThroughCloudWatchLogsOnly"
        Effect    = "Allow"
        Principal = { AWS = local.logging_role_arn }
        Action    = ["kms:Encrypt", "kms:ReEncrypt*", "kms:Decrypt", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = { StringEquals = { "kms:ViaService" = "logs.${var.region}.amazonaws.com" } }
      },
      {
        Sid       = "InvestigatorsMayDecryptPromptLogs"
        Effect    = "Allow"
        Principal = { AWS = local.investigator_role_arn }
        Action    = "kms:Decrypt"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "prompts" {
  name          = "alias/${local.name}-prompt-logs"
  target_key_id = aws_kms_key.prompts.key_id
}

resource "aws_kms_key" "audit" {
  description             = "${local.name}: CloudTrail log files"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  depends_on              = [aws_iam_role.investigator]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministrationByTheAccount"
        Effect    = "Allow"
        Principal = { AWS = local.account_root_arn }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncryptLogs"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${var.account_id}:trail/*" }
        }
      },
      {
        Sid       = "AllowCloudTrailAccess"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "EnableCloudTrailLogDecryptPermissions"
        Effect    = "Allow"
        Principal = { AWS = local.investigator_role_arn }
        Action    = "kms:Decrypt"
        Resource  = "*"
        Condition = { Null = { "kms:EncryptionContext:aws:cloudtrail:arn" = "false" } }
      }
    ]
  })
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${local.name}-trail"
  target_key_id = aws_kms_key.audit.key_id
}
