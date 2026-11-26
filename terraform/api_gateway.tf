# API Gateway HTTP API (v2)
resource "aws_apigatewayv2_api" "http_api" {
  name          = "${var.project_prefix}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["content-type", "authorization"]
    max_age       = 300
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_prefix}-api"
    }
  )
}

# Integração HTTP API com a AWS Lambda via AWS_PROXY (payload format 2.0)
resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id                 = aws_apigatewayv2_api.http_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.engine.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# Rota POST /audit conectada à integração da Lambda
resource "aws_apigatewayv2_route" "audit_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /audit"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

# Stage $default com auto_deploy habilitado
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true

  tags = local.common_tags
}
