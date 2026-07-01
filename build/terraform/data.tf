resource "aws_db_subnet_group" "storage" {
  name       = "${local.name_prefix}-storage"
  subnet_ids = var.private_subnet_ids
}

resource "aws_rds_cluster" "postgres" {
  cluster_identifier     = "${local.name_prefix}-postgres"
  engine                 = "aurora-postgresql"
  engine_version         = "16.4"
  database_name          = "scriptureforge"
  master_username        = "forge_admin_root"
  master_password        = var.database_root_security_passphrase
  db_subnet_group_name   = aws_db_subnet_group.storage.name
  vpc_security_group_ids = [aws_security_group.data.id]
  storage_encrypted      = true
  kms_key_id             = var.database_kms_key_arn

  backup_retention_period      = var.database_backup_retention_days
  preferred_backup_window      = var.database_preferred_backup_window
  preferred_maintenance_window = var.database_preferred_maintenance_window
  copy_tags_to_snapshot        = true
  enabled_cloudwatch_logs_exports = [
    "postgresql"
  ]

  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name_prefix}-postgres-final"
  apply_immediately         = false
}

resource "aws_rds_cluster_instance" "postgres" {
  count              = 2
  identifier         = "${local.name_prefix}-postgres-${count.index + 1}"
  cluster_identifier = aws_rds_cluster.postgres.id
  instance_class     = var.database_instance_class
  engine             = aws_rds_cluster.postgres.engine
  engine_version     = aws_rds_cluster.postgres.engine_version
}

resource "aws_elasticache_subnet_group" "cache" {
  name       = "${local.name_prefix}-cache"
  subnet_ids = var.private_subnet_ids
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${local.name_prefix}-redis"
  description                = "Redis-compatible cache for room state, rate limits, and realtime coordination."
  engine                     = "redis"
  node_type                  = "cache.t4g.micro"
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  subnet_group_name          = aws_elasticache_subnet_group.cache.name
  security_group_ids         = [aws_security_group.data.id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = var.redis_kms_key_arn
}

data "aws_secretsmanager_secret" "jwt_secret_key" {
  arn = var.app_secret_arns.jwt_secret_key
}

data "aws_secretsmanager_secret" "database_url" {
  arn = var.app_secret_arns.database_url
}

data "aws_secretsmanager_secret" "openai_api_key" {
  arn = var.app_secret_arns.openai_api_key
}

data "aws_secretsmanager_secret" "zoom_credentials" {
  arn = var.app_secret_arns.zoom_credentials
}
