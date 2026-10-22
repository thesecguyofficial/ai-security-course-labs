locals {
  name                  = "tsg-helpdesk"
  prompt_log_group_name = "/${local.name}/bedrock/model-invocations"
  logging_role_arn      = "arn:aws:iam::${var.account_id}:role/${local.name}-bedrock-logging"
}

# --- Network: private subnets for the function, plus a NAT gateway "so pip install works"
resource "aws_vpc" "helpdesk" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.helpdesk.id
  availability_zone = var.availability_zones[count.index]
  cidr_block        = cidrsubnet("10.20.0.0/16", 8, count.index + 1)
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.helpdesk.id
  availability_zone = var.availability_zones[0]
  cidr_block        = "10.20.100.0/24"
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.helpdesk.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.helpdesk.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "app" {
  name   = "${local.name}-app"
  vpc_id = aws_vpc.helpdesk.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "endpoint" {
  name   = "${local.name}-bedrock-endpoint"
  vpc_id = aws_vpc.helpdesk.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

# "We added PrivateLink, so it's private." No policy argument: the default endpoint policy applies.
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = aws_vpc.helpdesk.id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoint.id]
}

# --- App role: copied from the old Helpdesk role
resource "aws_iam_role" "app" {
  name = "${local.name}-app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "app_invoke" {
  name = "bedrock"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "LetTheAppUseBedrock"
      Effect   = "Allow"
      Action   = ["bedrock:*", "bedrock-mantle:*"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app_vpc" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_lambda_function" "helpdesk" {
  function_name    = local.name
  role             = aws_iam_role.app.arn
  runtime          = "python3.13"
  handler          = "handler.handler"
  filename         = "${path.module}/build/helpdesk.zip"
  source_code_hash = filebase64sha256("${path.module}/build/helpdesk.zip")
  timeout          = 30
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.app.id]
  }
  environment {
    variables = {
      MODEL_ID   = var.inference_profile_id
      MAX_TOKENS = "4096"
    }
  }
}

# --- Logging: "turned on", to CloudWatch only. No key, no retention, no large-data bucket.
resource "aws_cloudwatch_log_group" "prompts" {
  name = local.prompt_log_group_name
}

resource "aws_iam_role" "bedrock_logging" {
  name = "${local.name}-bedrock-logging"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
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
      Action   = ["logs:*"]
      Resource = "*"
    }]
  })
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  depends_on = [aws_iam_role_policy.bedrock_logging, aws_cloudwatch_log_group.prompts]
  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = true
    embedding_data_delivery_enabled = true
    video_data_delivery_enabled     = true
    cloudwatch_config {
      log_group_name = local.prompt_log_group_name
      role_arn       = local.logging_role_arn
    }
  }
}
