# Role de execução IAM para a AWS Lambda do motor de auditoria
resource "aws_iam_role" "lambda_role" {
  name        = "${var.project_prefix}-lambda-execution-role"
  description = "Role IAM com menor privilegio para execucao da funcao AWS Lambda ${var.project_prefix}-engine"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaAssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_prefix}-lambda-execution-role"
    }
  )
}

# Politica gerenciada com menor privilegio anexando iam/execution-policy.json
resource "aws_iam_policy" "lambda_execution_policy" {
  name        = "${var.project_prefix}-lambda-execution-policy"
  description = "Politica de menor privilegio para escrita de logs no CloudWatch pela Lambda ${var.project_prefix}-engine"
  policy      = file("${path.module}/../iam/execution-policy.json")

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_prefix}-lambda-execution-policy"
    }
  )
}

# Anexo da politica de execucao a role da Lambda
resource "aws_iam_role_policy_attachment" "lambda_execution_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_execution_policy.arn
}
