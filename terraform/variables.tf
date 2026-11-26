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

variable "cors_allow_origins" {
  description = "Lista de origens permitidas para requisições CORS na HTTP API"
  type        = list(string)
  default     = ["*"]
}

variable "api_throttling_burst_limit" {
  description = "Limite máximo de requisições simultâneas em rajada (burst) para o estágio padrão do API Gateway v2"
  type        = number
  default     = 100
}

variable "api_throttling_rate_limit" {
  description = "Taxa contínua máxima de requisições em regime estacionário por segundo para o API Gateway v2"
  type        = number
  default     = 50
}
