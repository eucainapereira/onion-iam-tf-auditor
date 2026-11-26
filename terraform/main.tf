# ==============================================================================
# Onion Auditor — Configuração do Provedor AWS e Tags Globais
# Camada 3: Infraestrutura (Terraform) & CI/CD
# ==============================================================================

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  common_tags = {
    Project     = var.project_prefix
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
