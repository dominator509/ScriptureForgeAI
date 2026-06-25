output "cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.platform.name
}

output "postgres_endpoint" {
  description = "Aurora PostgreSQL writer endpoint."
  value       = aws_rds_cluster.postgres.endpoint
}

output "redis_primary_endpoint" {
  description = "Redis primary endpoint."
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "api_repository_url" {
  description = "ECR repository URL for the Go API image."
  value       = aws_ecr_repository.api.repository_url
}

output "web_repository_url" {
  description = "ECR repository URL for the web image."
  value       = aws_ecr_repository.web.repository_url
}

output "rust_engine_repository_url" {
  description = "ECR repository URL for the Rust engine image."
  value       = aws_ecr_repository.rust_engine.repository_url
}

output "api_hostname" {
  description = "Configured API ingress hostname."
  value       = var.api_hostname
}

output "web_hostname" {
  description = "Configured web ingress hostname."
  value       = var.web_hostname
}

output "ingress_ssl_policy" {
  description = "ALB SSL policy configured for public ingresses."
  value       = var.ingress_ssl_policy
}

output "otel_export_enabled" {
  description = "Whether the API deployment is configured with an OTLP collector endpoint."
  value       = var.otel_exporter_otlp_endpoint != ""
}
