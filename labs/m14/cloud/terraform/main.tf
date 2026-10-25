# M14 guided build, Terraform path (optional). YOUR sandbox account only. Read GUIDED-BUILD.md first.
#
# Creates: a Cognito user pool with two app clients (the Helpdesk web app and a "partner portal"), the tools Lambda,
# its role, the gateway role, an AgentCore Gateway (CUSTOM_JWT, allowedClients = the web app only), the Lambda
# target with three tools, a policy engine attached in ENFORCE mode with the six Cedar policies from
# ../policies, and an AgentCore Memory with a per-user namespace template.
# NOT created here: the agent runtime (AgentCore CLI, GUIDED-BUILD Part C), Cognito users (AWS CLI, Part A),
# CloudTrail data event selectors (Part D).
#
# Checked offline with OpenTofu 1.x and the AWS provider 6.70.0 schema (fmt, validate). Not applied by the authors.
# Cost while it exists: a few US cents for the guide's requests (GUIDED-BUILD "Cost"). Destroy it the same day.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.70.0" }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "policy_mode" {
  description = "ENFORCE (default) or LOG_ONLY: GUIDED-BUILD A4 flips it to see the difference, then back"
  type        = string
  default     = "ENFORCE"
  validation {
    condition     = contains(["ENFORCE", "LOG_ONLY"], var.policy_mode)
    error_message = "policy_mode must be ENFORCE or LOG_ONLY."
  }
}

variable "name" {
  type    = string
  default = "tsg-m14"
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "me" {}

locals {
  account   = data.aws_caller_identity.me.account_id
  discovery = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.pool.id}/.well-known/openid-configuration"
  tools = {
    search_kb  = { description = "Search the IT knowledge base.", props = { query = true } }
    reset_mfa  = { description = "Reset a user's MFA device. caller_username is the signed-in user.", props = { target_username = true, caller_username = true } }
    send_email = { description = "Send an email for the signed-in user.", props = { to = true, subject = true, body = true, caller_username = true } }
  }
}

# ---------------------------------------------------------------- identity provider (inbound)
resource "aws_cognito_user_pool" "pool" {
  name = "${var.name}-users"
  password_policy {
    minimum_length = 12
  }
}

resource "aws_cognito_user_pool_client" "web" {
  name                = "${var.name}-helpdesk-web"
  user_pool_id        = aws_cognito_user_pool.pool.id
  generate_secret     = false
  explicit_auth_flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
}

resource "aws_cognito_user_pool_client" "partner" {
  name                = "${var.name}-partner-portal"
  user_pool_id        = aws_cognito_user_pool.pool.id
  generate_secret     = false
  explicit_auth_flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
}

# ---------------------------------------------------------------- the tools Lambda
resource "aws_iam_role" "tools" {
  name = "${var.name}-tools-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "tools_logs" {
  role       = aws_iam_role.tools.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "tools" {
  function_name    = "${var.name}-helpdesk-tools"
  role             = aws_iam_role.tools.arn
  runtime          = "python3.13"
  handler          = "helpdesk_tools.lambda_handler"
  filename         = "${path.module}/tools.zip" # made by `make cloud-up`
  source_code_hash = filebase64sha256("${path.module}/tools.zip")
  timeout          = 10
}

# ---------------------------------------------------------------- gateway role: invoke ONE function and ask the policy engine, assumable only by this account's gateways
resource "aws_iam_role" "gateway" {
  name = "${var.name}-gateway"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock-agentcore:${var.region}:${local.account}:gateway/*" }
      }
    }]
  })
}

# A gateway with a policy engine also needs GetPolicyEngine, AuthorizeAction and PartiallyAuthorizeActions. Without
# them AWS says "all tool invocations will be denied by default even if you have permit policies configured", and
# attaching the engine fails with InternalServerException. Resources as on AWS's page: the engine for all three, plus
# the gateway for the two authorize actions (gateway/* in this account and Region: the gateway's own ARN would be a
# dependency cycle). https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-permissions.md
resource "aws_iam_role_policy" "gateway" {
  name = "invoke-tools-and-authorize"
  role = aws_iam_role.gateway.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_function.tools.arn },
      { Effect = "Allow", Action = "bedrock-agentcore:GetPolicyEngine", Resource = aws_bedrockagentcore_policy_engine.pe.policy_engine_arn },
      { Effect   = "Allow", Action = ["bedrock-agentcore:AuthorizeAction", "bedrock-agentcore:PartiallyAuthorizeActions"],
        Resource = [aws_bedrockagentcore_policy_engine.pe.policy_engine_arn,
      "arn:aws:bedrock-agentcore:${var.region}:${local.account}:gateway/*"] },
    ]
  })
}

# ---------------------------------------------------------------- policy engine, gateway, target, policies
resource "aws_bedrockagentcore_policy_engine" "pe" {
  name        = "tsg_m14_pe"
  description = "TSG Helpdesk tool rules"
}

resource "aws_bedrockagentcore_gateway" "gw" {
  name            = "${var.name}-gw"
  role_arn        = aws_iam_role.gateway.arn
  protocol_type   = "MCP"
  authorizer_type = "CUSTOM_JWT"
  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url   = local.discovery
      allowed_clients = [aws_cognito_user_pool_client.web.id]
    }
  }
  policy_engine_configuration {
    arn  = aws_bedrockagentcore_policy_engine.pe.policy_engine_arn
    mode = var.policy_mode
  }
  depends_on = [aws_iam_role_policy.gateway] # the role must be able to reach the engine before it is attached
}

resource "aws_bedrockagentcore_gateway_target" "tools" {
  gateway_identifier = aws_bedrockagentcore_gateway.gw.gateway_id
  name               = "HelpdeskTools"
  description        = "TSG Helpdesk tools in one Lambda function"
  credential_provider_configuration {
    gateway_iam_role {}
  }
  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.tools.arn
        tool_schema {
          dynamic "inline_payload" {
            for_each = local.tools
            content {
              name        = inline_payload.key
              description = inline_payload.value.description
              input_schema {
                type = "object"
                dynamic "property" {
                  for_each = inline_payload.value.props
                  content {
                    name     = property.key
                    type     = "string"
                    required = property.value
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

resource "aws_bedrockagentcore_policy" "rules" {
  for_each         = fileset("${path.module}/../policies", "*.cedar")
  name             = trimsuffix(each.value, ".cedar")
  policy_engine_id = aws_bedrockagentcore_policy_engine.pe.policy_engine_id
  definition {
    cedar {
      statement = replace(replace(file("${path.module}/../policies/${each.value}"),
      "GATEWAY_ARN", aws_bedrockagentcore_gateway.gw.gateway_arn), "WEB_CLIENT_ID", aws_cognito_user_pool_client.web.id)
    }
  }
  depends_on = [aws_bedrockagentcore_gateway_target.tools] # the engine validates policies against the gateway's tool schema
}

# ---------------------------------------------------------------- memory: one namespace per actor
resource "aws_bedrockagentcore_memory" "mem" {
  name                  = "tsg_m14_mem"
  event_expiry_duration = 7
}

resource "aws_bedrockagentcore_memory_strategy" "facts" {
  memory_id           = aws_bedrockagentcore_memory.mem.id
  name                = "helpdesk_facts"
  type                = "SEMANTIC"
  namespace_templates = ["/users/{actorId}/facts/"]
}

# ---------------------------------------------------------------- outputs for the guide
output "user_pool_id" { value = aws_cognito_user_pool.pool.id }
output "web_client_id" { value = aws_cognito_user_pool_client.web.id }
output "partner_client_id" { value = aws_cognito_user_pool_client.partner.id }
output "discovery_url" { value = local.discovery }
output "gateway_id" { value = aws_bedrockagentcore_gateway.gw.gateway_id }
output "gateway_arn" { value = aws_bedrockagentcore_gateway.gw.gateway_arn }
output "gateway_url" { value = aws_bedrockagentcore_gateway.gw.gateway_url }
output "policy_engine_id" { value = aws_bedrockagentcore_policy_engine.pe.policy_engine_id }
output "memory_id" { value = aws_bedrockagentcore_memory.mem.id }
output "tools_lambda_arn" { value = aws_lambda_function.tools.arn }
