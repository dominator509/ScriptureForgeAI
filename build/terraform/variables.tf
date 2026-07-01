variable "aws_region" {
  description = "AWS region for the deployment skeleton."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name, such as staging or production."
  type        = string
  default     = "staging"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.environment))
    error_message = "environment must be lowercase alphanumeric with optional hyphens."
  }
}

variable "vpc_id" {
  description = "Existing VPC ID for EKS, RDS, Redis, and ingress."
  type        = string

  validation {
    condition     = can(regex("^vpc-[a-f0-9]+$", var.vpc_id))
    error_message = "vpc_id must look like an AWS VPC ID."
  }
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for EKS nodes, RDS, and Redis placement."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least two private subnet IDs are required."
  }
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for external ingress load balancers."
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "At least two public subnet IDs are required for ingress."
  }
}

variable "allowed_ingress_cidrs" {
  description = "CIDR ranges allowed to reach public ingress."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "database_root_security_passphrase" {
  description = "Root password for the PostgreSQL cluster. Prefer injecting this from a secure CI variable or secret manager at apply time."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.database_root_security_passphrase) >= 16
    error_message = "The database root password must be at least 16 characters."
  }
}

variable "database_instance_class" {
  description = "Aurora PostgreSQL instance class."
  type        = string
  default     = "db.r6g.large"
}

variable "database_kms_key_arn" {
  description = "Customer-managed AWS KMS key ARN used to encrypt the Aurora PostgreSQL cluster and snapshots."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]+$", var.database_kms_key_arn)) || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:alias/[A-Za-z0-9/_-]+$", var.database_kms_key_arn))
    error_message = "database_kms_key_arn must be a customer-managed AWS KMS key or alias ARN."
  }
}

variable "redis_kms_key_arn" {
  description = "Customer-managed AWS KMS key ARN used to encrypt the Redis replication group."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]+$", var.redis_kms_key_arn)) || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:alias/[A-Za-z0-9/_-]+$", var.redis_kms_key_arn))
    error_message = "redis_kms_key_arn must be a customer-managed AWS KMS key or alias ARN."
  }
}

variable "database_backup_retention_days" {
  description = "Aurora PostgreSQL automated backup retention period in days."
  type        = number
  default     = 14

  validation {
    condition     = var.database_backup_retention_days >= 7 && var.database_backup_retention_days <= 35
    error_message = "database_backup_retention_days must be between 7 and 35 days."
  }
}

variable "database_preferred_backup_window" {
  description = "UTC backup window for Aurora PostgreSQL automated backups."
  type        = string
  default     = "07:00-09:00"
}

variable "database_preferred_maintenance_window" {
  description = "UTC maintenance window for Aurora PostgreSQL."
  type        = string
  default     = "sun:09:00-sun:10:00"
}

variable "api_image" {
  description = "Immutable container image digest for the Go API service."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.api_image))
    error_message = "api_image must be pinned to an immutable sha256 digest, for example repository/scriptureforge-api@sha256:<64 lowercase hex chars>."
  }
}

variable "web_image" {
  description = "Immutable container image digest for the Next.js web service."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.web_image))
    error_message = "web_image must be pinned to an immutable sha256 digest, for example repository/scriptureforge-web@sha256:<64 lowercase hex chars>."
  }
}

variable "rust_engine_image" {
  description = "Immutable container image digest for the Rust gRPC scripture engine."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.rust_engine_image))
    error_message = "rust_engine_image must be pinned to an immutable sha256 digest, for example repository/scriptureforge-rust-engine@sha256:<64 lowercase hex chars>."
  }
}

variable "api_resources" {
  description = "Kubernetes CPU and memory requests/limits for the Go API container."
  type = object({
    requests = object({
      cpu    = string
      memory = string
    })
    limits = object({
      cpu    = string
      memory = string
    })
  })
  default = {
    requests = {
      cpu    = "250m"
      memory = "256Mi"
    }
    limits = {
      cpu    = "1000m"
      memory = "768Mi"
    }
  }
}

variable "rust_engine_resources" {
  description = "Kubernetes CPU and memory requests/limits for the Rust gRPC scripture engine container."
  type = object({
    requests = object({
      cpu    = string
      memory = string
    })
    limits = object({
      cpu    = string
      memory = string
    })
  })
  default = {
    requests = {
      cpu    = "250m"
      memory = "256Mi"
    }
    limits = {
      cpu    = "1000m"
      memory = "768Mi"
    }
  }
}

variable "web_resources" {
  description = "Kubernetes CPU and memory requests/limits for the Next.js web container."
  type = object({
    requests = object({
      cpu    = string
      memory = string
    })
    limits = object({
      cpu    = string
      memory = string
    })
  })
  default = {
    requests = {
      cpu    = "150m"
      memory = "192Mi"
    }
    limits = {
      cpu    = "500m"
      memory = "512Mi"
    }
  }
}

variable "api_autoscaling" {
  description = "Horizontal Pod Autoscaler settings for the Go API deployment."
  type = object({
    min_replicas                         = number
    max_replicas                         = number
    target_cpu_utilization_percentage    = number
    target_memory_utilization_percentage = number
  })
  default = {
    min_replicas                         = 2
    max_replicas                         = 10
    target_cpu_utilization_percentage    = 65
    target_memory_utilization_percentage = 75
  }

  validation {
    condition     = var.api_autoscaling.min_replicas >= 2 && var.api_autoscaling.max_replicas >= var.api_autoscaling.min_replicas
    error_message = "api_autoscaling must keep at least two replicas and max_replicas must be >= min_replicas."
  }
}

variable "rust_engine_autoscaling" {
  description = "Horizontal Pod Autoscaler settings for the Rust scripture engine deployment."
  type = object({
    min_replicas                         = number
    max_replicas                         = number
    target_cpu_utilization_percentage    = number
    target_memory_utilization_percentage = number
  })
  default = {
    min_replicas                         = 2
    max_replicas                         = 8
    target_cpu_utilization_percentage    = 65
    target_memory_utilization_percentage = 75
  }

  validation {
    condition     = var.rust_engine_autoscaling.min_replicas >= 2 && var.rust_engine_autoscaling.max_replicas >= var.rust_engine_autoscaling.min_replicas
    error_message = "rust_engine_autoscaling must keep at least two replicas and max_replicas must be >= min_replicas."
  }
}

variable "web_autoscaling" {
  description = "Horizontal Pod Autoscaler settings for the Next.js web deployment."
  type = object({
    min_replicas                         = number
    max_replicas                         = number
    target_cpu_utilization_percentage    = number
    target_memory_utilization_percentage = number
  })
  default = {
    min_replicas                         = 2
    max_replicas                         = 6
    target_cpu_utilization_percentage    = 70
    target_memory_utilization_percentage = 80
  }

  validation {
    condition     = var.web_autoscaling.min_replicas >= 2 && var.web_autoscaling.max_replicas >= var.web_autoscaling.min_replicas
    error_message = "web_autoscaling must keep at least two replicas and max_replicas must be >= min_replicas."
  }
}

variable "app_secret_arns" {
  description = "Existing AWS Secrets Manager ARNs used by workloads. database_url, jwt_secret_key, openai_api_key, and zoom_credentials must all be Secrets Manager ARNs; zoom_credentials secret value must be JSON with account_id, client_id, client_secret, and webhook_secret_token keys."
  type = object({
    database_url     = string
    jwt_secret_key   = string
    openai_api_key   = string
    zoom_credentials = string
  })

  validation {
    condition = alltrue([
      can(regex("^arn:aws:secretsmanager:", var.app_secret_arns.database_url)),
      can(regex("^arn:aws:secretsmanager:", var.app_secret_arns.jwt_secret_key)),
      can(regex("^arn:aws:secretsmanager:", var.app_secret_arns.openai_api_key)),
      can(regex("^arn:aws:secretsmanager:", var.app_secret_arns.zoom_credentials))
    ])
    error_message = "app_secret_arns values must be AWS Secrets Manager ARNs."
  }
}

variable "eks_oidc_thumbprint_list" {
  description = "OIDC root CA thumbprints for the EKS issuer used by IRSA. Confirm in staging before apply."
  type        = list(string)
  default     = ["9e99a48a9960b14926bb7f3b02e22da0afd10efd"]

  validation {
    condition     = length(var.eks_oidc_thumbprint_list) > 0
    error_message = "At least one OIDC thumbprint is required for the EKS IAM OIDC provider."
  }
}

variable "allowed_ws_origins" {
  description = "Comma-separated browser origins allowed for WebSocket upgrades."
  type        = string

  validation {
    condition = (
      length(trimspace(var.allowed_ws_origins)) > 0 &&
      alltrue([
        for origin in split(",", var.allowed_ws_origins) :
        startswith(trimspace(origin), "https://") &&
        !strcontains(lower(trimspace(origin)), "localhost") &&
        !strcontains(lower(trimspace(origin)), "example.com") &&
        !strcontains(lower(trimspace(origin)), ".example") &&
        !strcontains(lower(trimspace(origin)), ".test") &&
        !strcontains(lower(trimspace(origin)), ".invalid") &&
        !strcontains(trimspace(origin), "*")
      ])
    )
    error_message = "allowed_ws_origins must be comma-separated HTTPS origins for real staging/production hosts; localhost, wildcard, example, test, and invalid origins are not allowed."
  }
}

variable "trust_proxy_headers" {
  description = "Whether the API should trust X-Forwarded-For/X-Real-IP from the managed ingress for abuse-rate-limit client identity."
  type        = bool
  default     = true
}

variable "service_version" {
  description = "Release or image version label attached to application telemetry."
  type        = string

  validation {
    condition = (
      length(trimspace(var.service_version)) > 0 &&
      !contains(["unversioned", "latest"], lower(trimspace(var.service_version))) &&
      !strcontains(lower(trimspace(var.service_version)), "replace-with")
    )
    error_message = "service_version must be an explicit release value, not unversioned, latest, or a replace-with placeholder."
  }
}

variable "otel_exporter_otlp_endpoint" {
  description = "Optional OTLP/HTTP collector endpoint for Go API traces. Leave empty to keep tracing export disabled."
  type        = string
  default     = ""

  validation {
    condition = (
      var.otel_exporter_otlp_endpoint == "" ||
      can(regex("^(https?://)?[A-Za-z0-9._-]+(:[0-9]{2,5})?(/.*)?$", var.otel_exporter_otlp_endpoint))
    )
    error_message = "otel_exporter_otlp_endpoint must be empty or an OTLP HTTP collector endpoint."
  }
}

variable "otel_exporter_otlp_insecure" {
  description = "Set true only for plaintext in-cluster OTLP collector traffic."
  type        = bool
  default     = false
}

variable "api_hostname" {
  description = "Hostname for the Go API ingress."
  type        = string

  validation {
    condition = (
      can(regex("^[A-Za-z0-9][A-Za-z0-9.-]+[.][A-Za-z]{2,}$", var.api_hostname)) &&
      lower(trimspace(var.api_hostname)) != "localhost" &&
      !strcontains(lower(trimspace(var.api_hostname)), "example.com") &&
      !strcontains(lower(trimspace(var.api_hostname)), ".example") &&
      !strcontains(lower(trimspace(var.api_hostname)), ".test") &&
      !strcontains(lower(trimspace(var.api_hostname)), ".invalid")
    )
    error_message = "api_hostname must be a real DNS hostname; localhost, example, test, and invalid hosts are not allowed for staging/production."
  }
}

variable "web_hostname" {
  description = "Hostname for the web ingress."
  type        = string

  validation {
    condition = (
      can(regex("^[A-Za-z0-9][A-Za-z0-9.-]+[.][A-Za-z]{2,}$", var.web_hostname)) &&
      lower(trimspace(var.web_hostname)) != "localhost" &&
      !strcontains(lower(trimspace(var.web_hostname)), "example.com") &&
      !strcontains(lower(trimspace(var.web_hostname)), ".example") &&
      !strcontains(lower(trimspace(var.web_hostname)), ".test") &&
      !strcontains(lower(trimspace(var.web_hostname)), ".invalid")
    )
    error_message = "web_hostname must be a real DNS hostname; localhost, example, test, and invalid hosts are not allowed for staging/production."
  }
}

variable "ingress_certificate_arn" {
  description = "ACM certificate ARN used by the ALB ingresses for api_hostname and web_hostname."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-fA-F-]+$", var.ingress_certificate_arn))
    error_message = "ingress_certificate_arn must be an ACM certificate ARN."
  }
}

variable "ingress_ssl_policy" {
  description = "AWS ALB SSL negotiation policy for public HTTPS ingresses."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  validation {
    condition     = startswith(var.ingress_ssl_policy, "ELBSecurityPolicy-")
    error_message = "ingress_ssl_policy must be an AWS ELB security policy name."
  }
}
