terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region for the validated infrastructure skeleton."
  type        = string
  default     = "us-east-1"
}

variable "cluster_role_arn" {
  description = "Existing IAM role ARN for the EKS control plane."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+", var.cluster_role_arn))
    error_message = "cluster_role_arn must be a valid IAM role ARN."
  }
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for EKS, RDS, and cache placement."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least two private subnets are required."
  }
}

variable "database_root_security_passphrase" {
  description = "Root password for the PostgreSQL cluster."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.database_root_security_passphrase) >= 16
    error_message = "The database root password must be at least 16 characters."
  }
}

resource "aws_eks_cluster" "platform_kubernetes_core" {
  name     = "scriptureforge-production-cluster"
  role_arn = var.cluster_role_arn

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}

resource "aws_db_subnet_group" "storage" {
  name       = "scriptureforge-storage"
  subnet_ids = var.private_subnet_ids
}

resource "aws_rds_cluster" "storage_backend_postgres" {
  cluster_identifier   = "scriptureforge-core-postgres-cluster"
  engine               = "postgres"
  engine_version       = "17.2"
  database_name        = "scriptureforge_prod"
  master_username      = "forge_admin_root"
  master_password      = var.database_root_security_passphrase
  db_subnet_group_name = aws_db_subnet_group.storage.name
  storage_encrypted    = true
  deletion_protection  = true
  skip_final_snapshot  = false
}

resource "aws_elasticache_subnet_group" "cache" {
  name       = "scriptureforge-cache"
  subnet_ids = var.private_subnet_ids
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "scriptureforge-redis"
  description                = "Redis-compatible cache for room state and rate limits."
  engine                     = "redis"
  node_type                  = "cache.t4g.micro"
  num_cache_clusters         = 1
  automatic_failover_enabled = false
  subnet_group_name          = aws_elasticache_subnet_group.cache.name
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}
