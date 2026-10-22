# 11.1 Least privilege per app and per model. The Helpdesk role can run ONE model, through ONE geographic
# inference profile, and nothing else in Bedrock: no other model, no logging changes, no capacity purchases,
# no Marketplace subscriptions. Pattern from AWS's geographic cross-Region inference example policy.

resource "aws_iam_role" "app" {
  name = "${local.name}-app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "app_invoke" {
  name = "invoke-approved-model-only"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "TheApprovedGeographicProfile"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = local.profile_arn
      },
      {
        Sid      = "TheModelOnlyThroughThatProfile"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = local.model_arns
        Condition = {
          StringEquals = { "bedrock:InferenceProfileArn" = local.profile_arn }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_vpc" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" # network interfaces + its own logs
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 14 # the function never logs prompts; its own logs still don't need to live forever
}

resource "aws_lambda_function" "helpdesk" {
  function_name    = local.name
  role             = aws_iam_role.app.arn
  runtime          = "python3.13"
  handler          = "handler.handler"
  filename         = "${path.module}/build/helpdesk.zip" # made by `make package` from lambda/handler.py
  source_code_hash = filebase64sha256("${path.module}/build/helpdesk.zip")
  timeout          = 30
  memory_size      = 256

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.app.id]
  }

  environment {
    variables = {
      MODEL_ID   = var.inference_profile_id
      MAX_TOKENS = tostring(var.max_tokens)
    }
  }

  depends_on = [aws_cloudwatch_log_group.app, aws_iam_role_policy_attachment.app_vpc]
}
