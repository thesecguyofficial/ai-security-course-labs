# 11.2 Private networking. The app's subnets have NO route to the internet: no internet gateway, no NAT.
# The only way out is the bedrock-runtime interface endpoint, and its policy says who may use it, for what.

resource "aws_vpc" "helpdesk" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true # both are required for private DNS on an interface endpoint
  enable_dns_hostnames = true
  tags                 = { Name = "${local.name}-vpc" }
}

resource "aws_subnet" "private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.helpdesk.id
  availability_zone = var.availability_zones[count.index]
  cidr_block        = cidrsubnet("10.20.0.0/16", 8, count.index + 1)
  tags              = { Name = "${local.name}-private-${count.index + 1}" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.helpdesk.id
  tags   = { Name = "${local.name}-private" } # only the implicit local route: nothing leaves the VPC
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "app" {
  name        = "${local.name}-app"
  description = "Helpdesk function: HTTPS to the Bedrock endpoint only"
  vpc_id      = aws_vpc.helpdesk.id
}

resource "aws_security_group" "endpoint" {
  name        = "${local.name}-bedrock-endpoint"
  description = "bedrock-runtime endpoint: HTTPS from the Helpdesk function only"
  vpc_id      = aws_vpc.helpdesk.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_endpoint" {
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.endpoint.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "endpoint_from_app" {
  security_group_id            = aws_security_group.endpoint.id
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = aws_vpc.helpdesk.id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoint.id]

  # The default endpoint policy "allows full access" (AWS docs): any principal, any action, any resource,
  # including credentials from someone else's AWS account. This one lets only the Helpdesk role run models.
  # The model allow-list lives in the role (app.tf) and in the org SCPs; the endpoint is the identity perimeter.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OnlyTheHelpdeskRoleMayInvokeModels"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      Resource  = "*"
      Condition = {
        StringEquals = { "aws:PrincipalAccount" = var.account_id }
        ArnEquals    = { "aws:PrincipalArn" = local.app_role_arn }
      }
    }]
  })

  tags = { Name = "${local.name}-bedrock-runtime" }
}
