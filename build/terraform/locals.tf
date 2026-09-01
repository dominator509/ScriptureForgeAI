locals {
  name_prefix = "scriptureforge-${var.environment}"

  tags = {
    Project     = "ScriptureForgeAI"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
