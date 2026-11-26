# ==============================================================================
# Onion Auditor — Provedores e Versões Mínimas (Terraform & AWS)
# Camada 3: Infraestrutura (Terraform) & CI/CD
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}
