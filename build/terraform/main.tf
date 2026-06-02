provider "aws" {
  region = "us-east-1"
}

variable "database_root_security_passphrase" {
  description = "Root password for the PostgreSQL cluster"
  type        = string
  sensitive   = true
}

resource "aws_eks_cluster" "platform_kubernetes_core" {
  name     = "scriptureforge-production-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"

  vpc_config {
    subnet_ids              = ["subnet-12345678", "subnet-87654321"]
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}

resource "aws_rds_cluster" "storage_backend_postgres" {
  cluster_identifier      = "scriptureforge-core-postgres-cluster"
  engine                  = "postgres"
  engine_version          = "17.2"
  database_name           = "scriptureforge_prod"
  master_username         = "forge_admin_root"
  master_password         = var.database_root_security_passphrase
  storage_encrypted       = true
  deletion_protection     = true
  skip_final_snapshot     = true
}
