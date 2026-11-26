# Import blocks for existing AWS resources (Terraform 1.5+)
import {
  to = aws_iam_role.lambda_role
  id = "onion-auditor-lambda-execution-role"
}

import {
  to = aws_iam_policy.lambda_execution_policy
  id = "arn:aws:iam::654341980060:policy/onion-auditor-lambda-execution-policy"
}

import {
  to = aws_iam_role_policy_attachment.lambda_execution_attachment
  id = "onion-auditor-lambda-execution-role/arn:aws:iam::654341980060:policy/onion-auditor-lambda-execution-policy"
}

import {
  to = aws_cloudwatch_log_group.lambda_log_group
  id = "/aws/lambda/onion-auditor-engine"
}

import {
  to = aws_s3_bucket.frontend
  id = "onion-auditor-frontend-654341980060-us-east-2"
}

import {
  to = aws_s3_bucket_public_access_block.frontend
  id = "onion-auditor-frontend-654341980060-us-east-2"
}

import {
  to = aws_s3_bucket_website_configuration.frontend
  id = "onion-auditor-frontend-654341980060-us-east-2"
}

import {
  to = aws_s3_bucket_ownership_controls.frontend
  id = "onion-auditor-frontend-654341980060-us-east-2"
}

import {
  to = aws_s3_bucket_policy.frontend_public_read
  id = "onion-auditor-frontend-654341980060-us-east-2"
}

import {
  to = aws_apigatewayv2_api.http_api
  id = "p73sp8ai87"
}

import {
  to = aws_apigatewayv2_stage.default
  id = "p73sp8ai87/$default"
}

import {
  to = aws_lambda_function.engine
  id = "onion-auditor-engine"
}

import {
  to = aws_lambda_permission.api_gateway
  id = "onion-auditor-engine/AllowAPIGatewayInvoke"
}

import {
  to = aws_apigatewayv2_integration.lambda_integration
  id = "p73sp8ai87/sd876sj"
}

import {
  to = aws_apigatewayv2_route.audit_route
  id = "p73sp8ai87/t3hvz9i"
}
