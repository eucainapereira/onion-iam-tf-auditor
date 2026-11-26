variable "aws_region" {
  description = "Região da AWS para provisionamento dos recursos"
  type        = string
  default     = "us-east-2"
}

variable "project_prefix" {
  description = "Prefixo padrão único para todos os recursos na AWS"
  type        = string
  default     = "onion-auditor"
}

variable "environment" {
  description = "Ambiente de deploy (ex: prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "lambda_handler" {
  description = "Handler da função AWS Lambda (handler.lambda_handler conforme especificação da etapa ou app.lambda_handler)"
  type        = string
  default     = "handler.lambda_handler"
}
