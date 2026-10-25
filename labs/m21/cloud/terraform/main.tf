# M21 guided build, Terraform path (optional). YOUR sandbox account only. Read GUIDED-BUILD.md first.
#
# Creates: a Cognito user pool and the Helpdesk web app client, the refund tools Lambda and its role, the gateway
# role, an AgentCore Gateway (CUSTOM_JWT, allowedClients = the web app), the Lambda target with three tools
# (amount_cents is an INTEGER, so Cedar sees a Long and Dogwood can count and compare it), and a policy engine in
# ENFORCE mode with the four Cedar policies from ../policies.
# NOT created here: the Dogwood temporal policy (AWS CLI, GUIDED-BUILD Part B: it goes under definition.policy, not
# definition.cedar) and the Cognito users (AWS CLI, Part A).
#
# Adapted from the M14 guided build's main.tf, which was checked offline with OpenTofu and the AWS provider 6.70.0
# schema. The resources and attribute names are the same; THIS file was not separately validated or applied by the
# authors (no Terraform in the build environment). Run `terraform validate` first and report anything that fails.
# Cost while it exists: a few US cents (GUIDED-BUILD "Cost"). Destroy it the same day.

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
  default = "tsg-m21"
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "me" {}

locals {
  account   = data.aws_caller_identity.me.account_id
  discovery = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.pool.id}/.well-known/openid-configuration"
  tools = {
    lookup_order = { description = "Look up an order by ID.", props = { order_id = ["string", true] } }
    issue_refund = { description = "Refund part or all of an order. amount_cents is an integer number of US cents. caller_username is the signed-in user.",
    props = { order_id = ["string", true], amount_cents = ["integer", true], currency = ["string", true], caller_username = ["string", true] } }
    request_refund_approval = { description = "Ask a supervisor to approve a refund over $100. Moves no money.",
    props = { order_id = ["string", true], amount_cents = ["integer", true], caller_username = ["string", true] } }
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
  function_name    = "${var.name}-refund-tools"
  role             = aws_iam_role.tools.arn
  runtime          = "python3.13"
  handler          = "refund_tools.lambda_handler"
  filename         = "${path.module}/tools.zip" # made by `make cloud-up`
  source_code_hash = filebase64sha256("${path.module}/tools.zip")
  timeout          = 10
}

# ---------------------------------------------------------------- gateway role: invoke ONE function, assumable only by this account's gateways
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

resource "aws_iam_role_policy" "gateway" {
  name = "invoke-tools-and-policy"
  role = aws_iam_role.gateway.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_function.tools.arn },
      # Policy in AgentCore needs these three on the gateway role, or every tool call is denied by default
      # (AWS "AgentCore Gateway and Policy in AgentCore IAM Permissions"). Account-wide wildcards because the
      # gateway's ID doesn't exist yet when this role is made; narrow them after the first apply if you like.
      { Effect = "Allow", Action = "bedrock-agentcore:GetPolicyEngine",
      Resource = "arn:aws:bedrock-agentcore:${var.region}:${local.account}:policy-engine/*" },
      { Effect   = "Allow", Action = ["bedrock-agentcore:AuthorizeAction", "bedrock-agentcore:PartiallyAuthorizeActions"],
        Resource = ["arn:aws:bedrock-agentcore:${var.region}:${local.account}:policy-engine/*",
      "arn:aws:bedrock-agentcore:${var.region}:${local.account}:gateway/*"] },
      # Temporal (Dogwood) policies: the gateway mints a Workload Access Token per policy session.
      { Effect   = "Allow", Action = "bedrock-agentcore:GetWorkloadAccessToken",
        Resource = ["arn:aws:bedrock-agentcore:${var.region}:${local.account}:workload-identity-directory/default",
      "arn:aws:bedrock-agentcore:${var.region}:${local.account}:workload-identity-directory/default/workload-identity/*"] },
    ]
  })
}

# ---------------------------------------------------------------- policy engine, gateway, target, policies
resource "aws_bedrockagentcore_policy_engine" "pe" {
  name        = "tsg_m21_pe"
  description = "TSG Helpdesk refund rules"
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
}

resource "aws_bedrockagentcore_gateway_target" "tools" {
  gateway_identifier = aws_bedrockagentcore_gateway.gw.gateway_id
  name               = "RefundTools"
  description        = "TSG Helpdesk refund tools in one Lambda function"
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
                    type     = property.value[0]
                    required = property.value[1]
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

# ---------------------------------------------------------------- outputs for the guide
output "user_pool_id" { value = aws_cognito_user_pool.pool.id }
output "web_client_id" { value = aws_cognito_user_pool_client.web.id }
output "discovery_url" { value = local.discovery }
output "gateway_id" { value = aws_bedrockagentcore_gateway.gw.gateway_id }
output "gateway_arn" { value = aws_bedrockagentcore_gateway.gw.gateway_arn }
output "gateway_url" { value = aws_bedrockagentcore_gateway.gw.gateway_url }
output "policy_engine_id" { value = aws_bedrockagentcore_policy_engine.pe.policy_engine_id }
output "tools_lambda_arn" { value = aws_lambda_function.tools.arn }
