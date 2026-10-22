locals {
  name = "tsg-helpdesk"

  # ARNs are built from variables, not from resource attributes, so that every policy is known at plan time
  # and the offline checker (checker.py) can read it from `terraform show -json`.
  app_role_arn          = "arn:aws:iam::${var.account_id}:role/${local.name}-app"
  investigator_role_arn = "arn:aws:iam::${var.account_id}:role/${local.name}-log-investigator"
  logging_role_arn      = "arn:aws:iam::${var.account_id}:role/${local.name}-bedrock-logging"
  account_root_arn      = "arn:aws:iam::${var.account_id}:root"

  profile_arn = "arn:aws:bedrock:${var.region}:${var.account_id}:inference-profile/${var.inference_profile_id}"
  model_arns  = [for r in var.destination_regions : "arn:aws:bedrock:${r}::foundation-model/${var.foundation_model_id}"]

  prompt_log_group_name = "/${local.name}/bedrock/model-invocations"
  prompt_log_group_arn  = "arn:aws:logs:${var.region}:${var.account_id}:log-group:${local.prompt_log_group_name}"
  prompt_bucket         = "${local.name}-prompt-logs-${var.account_id}-${var.region}"
  trail_bucket          = "${local.name}-trail-${var.account_id}-${var.region}"
  trail_name            = "${local.name}-ai-data-events"
  trail_arn             = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${local.trail_name}"
}
