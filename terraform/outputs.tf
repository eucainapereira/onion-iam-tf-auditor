# ==============================================================================
# Onion Auditor — Saídas Oficiais e Contratuais da Infraestrutura
# Camada 3: Infraestrutura (Terraform) & CI/CD
# ==============================================================================

output "api_url" {
  description = "URL base da HTTP API com o caminho /audit"
  value       = "${trimsuffix(aws_apigatewayv2_stage.default.invoke_url, "/")}/audit"
}

output "frontend_url" {
  description = "URL do website estático público hospedado no S3"
  value       = "http://${aws_s3_bucket_website_configuration.frontend.website_endpoint}"
}

output "s3_bucket_name" {
  description = "Nome físico do bucket S3 criado para o frontend"
  value       = aws_s3_bucket.frontend.id
}
