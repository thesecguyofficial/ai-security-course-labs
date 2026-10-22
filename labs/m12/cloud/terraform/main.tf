# The reviewed guardrail from guardrails/tuned.json, in Terraform. Lesson 12.1 explains every block.
locals {
  guardrail_profile_arns = [for r in ["us-east-1", "us-east-2", "us-west-2"] :
  "arn:aws:bedrock:${r}:${var.account_id}:guardrail-profile/${var.guardrail_profile_id}"]
}

resource "aws_bedrock_guardrail" "helpdesk" {
  name                      = "tsg-helpdesk"
  description               = "TSG Helpdesk guardrail, tuned on the M12 suite"
  blocked_input_messaging   = "Sorry, I can't help with that request. If you think this is a mistake, raise a ticket."
  blocked_outputs_messaging = "Sorry, I can't share that answer. Please raise a ticket and a person will help."

  # Standard tier needs a guardrail profile (cross-Region inference). US profile = US Regions only.
  cross_region_config {
    guardrail_profile_identifier = "arn:aws:bedrock:${var.region}:${var.account_id}:guardrail-profile/${var.guardrail_profile_id}"
  }

  content_policy_config {
    tier_config {
      tier_name = "STANDARD"
    }
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "MEDIUM"
      output_strength = "NONE"
      input_action    = "BLOCK"
    }
    filters_config {
      type            = "MISCONDUCT"
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
    }
    filters_config {
      type            = "VIOLENCE"
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
    }
    filters_config {
      type            = "INSULTS"
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
    }
    filters_config {
      type            = "HATE"
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
    }
    filters_config {
      type            = "SEXUAL"
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
    }
  }

  topic_policy_config {
    tier_config {
      tier_name = "STANDARD"
    }
    topics_config {
      name       = "Pay of other people"
      type       = "DENY"
      definition = "Questions or statements about how much a named person or job role is paid, such as salary, bonus or pay band."
      examples = [
        "How much does the IT director earn?",
        "What is the salary of the finance manager?",
        "Which pay band is the CTO on?",
      ]
    }
  }

  sensitive_information_policy_config {
    pii_entities_config {
      type          = "EMAIL"
      action        = "ANONYMIZE"
      input_action  = "NONE"
      output_action = "ANONYMIZE"
    }
    pii_entities_config {
      type          = "PHONE"
      action        = "ANONYMIZE"
      input_action  = "NONE"
      output_action = "ANONYMIZE"
    }
    pii_entities_config {
      type          = "AWS_ACCESS_KEY"
      action        = "BLOCK"
      input_action  = "BLOCK"
      output_action = "BLOCK"
    }
    pii_entities_config {
      type          = "AWS_SECRET_KEY"
      action        = "BLOCK"
      input_action  = "BLOCK"
      output_action = "BLOCK"
    }
    regexes_config {
      name          = "SYSTEM_PROMPT_CANARY"
      description   = "The leak marker in TSG Helpdesk's system prompt. Regex filters are free."
      pattern       = "CANARY-M12-[A-Z0-9]{3}"
      action        = "BLOCK"
      input_enabled = false
      output_action = "BLOCK"
    }
  }

  contextual_grounding_policy_config {
    filters_config {
      type      = "GROUNDING"
      threshold = 0.6
    }
    filters_config {
      type      = "RELEVANCE"
      threshold = 0.1
    }
  }
}

# A numbered version: an immutable snapshot. Apps and IAM pin THIS, never the DRAFT (lesson 12.3).
resource "aws_bedrock_guardrail_version" "v1" {
  guardrail_arn = aws_bedrock_guardrail.helpdesk.guardrail_arn
  description   = "Reviewed in the M12 lab"
}

# OPTIONAL (lesson 12.3): the M11 Helpdesk role may call the model only with guardrail version 1.
resource "aws_iam_role_policy" "helpdesk_guardrail_required" {
  count = var.helpdesk_role_name == "" ? 0 : 1
  name  = "m12-guardrail-required"
  role  = var.helpdesk_role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "UseTheHelpdeskGuardrail"
        Effect   = "Allow"
        Action   = "bedrock:ApplyGuardrail"
        Resource = concat([aws_bedrock_guardrail.helpdesk.guardrail_arn], local.guardrail_profile_arns)
      },
      {
        Sid      = "NoModelCallWithoutGuardrailVersion"
        Effect   = "Deny"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "bedrock:GuardrailIdentifier" = "${aws_bedrock_guardrail.helpdesk.guardrail_arn}:${aws_bedrock_guardrail_version.v1.version}"
          }
        }
      }
    ]
  })
}

# OPTIONAL (lesson 12.3): account-level enforcement in this Region. Every model call in the account gets the guardrail.
resource "aws_bedrock_enforced_guardrail_configuration" "account" {
  count             = var.enforce_account_wide ? 1 : 0
  guardrail_arn     = aws_bedrock_guardrail.helpdesk.guardrail_arn
  guardrail_version = aws_bedrock_guardrail_version.v1.version

  selective_content_guarding {
    system   = "COMPREHENSIVE"
    messages = "COMPREHENSIVE"
  }
}
