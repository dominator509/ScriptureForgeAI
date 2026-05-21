# Terraform Configuration for RDS and Read Replica

provider "aws" {
  region = "us-east-1"
}

variable "database_root_security_passphrase" {
  type        = string
  description = "Root password for the core database"
  sensitive   = true
}

resource "aws_db_instance" "primary" {
  identifier           = "scriptureforge-core-postgres-cluster"
  engine               = "postgres"
  engine_version       = "17"
  instance_class       = "db.t3.medium"
  allocated_storage    = 20
  db_name              = "scriptureforge_prod"
  username             = "forge_admin_root"
  password             = var.database_root_security_passphrase
  storage_encrypted    = true
  deletion_protection  = true
  skip_final_snapshot  = true
}

resource "aws_db_instance" "read_replica" {
  identifier             = "scriptureforge-read-replica"
  replicate_source_db    = aws_db_instance.primary.identifier
  instance_class         = "db.t3.medium"
  storage_encrypted      = true
  skip_final_snapshot    = true
}
