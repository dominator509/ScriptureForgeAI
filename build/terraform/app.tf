resource "aws_ecr_repository" "api" {
  name                 = "${local.name_prefix}/api"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "web" {
  name                 = "${local.name_prefix}/web"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "rust_engine" {
  name                 = "${local.name_prefix}/rust-engine"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "kubernetes_namespace" "app" {
  metadata {
    name = "scriptureforge-${var.environment}"
  }

  depends_on = [aws_eks_node_group.system]
}

resource "kubernetes_secret" "external_secret_refs" {
  metadata {
    name      = "scriptureforge-external-secret-refs"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  data = {
    database_url_arn                = data.aws_secretsmanager_secret.database_url.arn
    jwt_secret_key_arn              = data.aws_secretsmanager_secret.jwt_secret_key.arn
    journal_salt_secret_arn         = data.aws_secretsmanager_secret.journal_salt_secret.arn
    openai_api_key_arn              = data.aws_secretsmanager_secret.openai_api_key.arn
    zoom_credentials_arn            = data.aws_secretsmanager_secret.zoom_credentials.arn
    grpc_engine_shared_secret_arn   = data.aws_secretsmanager_secret.grpc_engine_shared_secret.arn
    grpc_engine_tls_credentials_arn = data.aws_secretsmanager_secret.grpc_engine_tls_credentials.arn
  }

  type = "Opaque"
}

resource "kubernetes_service_account" "workload" {
  metadata {
    name      = "scriptureforge-workload"
    namespace = kubernetes_namespace.app.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.app_secrets.arn
    }
  }
}

resource "kubernetes_manifest" "app_secret_provider" {
  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "scriptureforge-app-secrets"
      namespace = kubernetes_namespace.app.metadata[0].name
    }
    spec = {
      provider = "aws"
      parameters = {
        objects = yamlencode([
          {
            objectName  = data.aws_secretsmanager_secret.database_url.arn
            objectType  = "secretsmanager"
            objectAlias = "database_url"
          },
          {
            objectName  = data.aws_secretsmanager_secret.jwt_secret_key.arn
            objectType  = "secretsmanager"
            objectAlias = "jwt_secret_key"
          },
          {
            objectName  = data.aws_secretsmanager_secret.journal_salt_secret.arn
            objectType  = "secretsmanager"
            objectAlias = "journal_salt_secret"
          },
          {
            objectName  = data.aws_secretsmanager_secret.openai_api_key.arn
            objectType  = "secretsmanager"
            objectAlias = "openai_api_key"
          },
          {
            objectName  = data.aws_secretsmanager_secret.grpc_engine_shared_secret.arn
            objectType  = "secretsmanager"
            objectAlias = "grpc_engine_shared_secret"
          },
          {
            objectName = data.aws_secretsmanager_secret.grpc_engine_tls_credentials.arn
            objectType = "secretsmanager"
            jmesPath = [
              {
                path        = "ca_pem"
                objectAlias = "grpc_engine_tls_ca_pem"
              },
              {
                path        = "server_cert_pem"
                objectAlias = "grpc_engine_tls_server_cert_pem"
              },
              {
                path        = "server_key_pem"
                objectAlias = "grpc_engine_tls_server_key_pem"
              },
              {
                path        = "client_cert_pem"
                objectAlias = "grpc_engine_tls_client_cert_pem"
              },
              {
                path        = "client_key_pem"
                objectAlias = "grpc_engine_tls_client_key_pem"
              }
            ]
          },
          {
            objectName = data.aws_secretsmanager_secret.zoom_credentials.arn
            objectType = "secretsmanager"
            jmesPath = [
              {
                path        = "account_id"
                objectAlias = "zoom_account_id"
              },
              {
                path        = "client_id"
                objectAlias = "zoom_client_id"
              },
              {
                path        = "client_secret"
                objectAlias = "zoom_client_secret"
              },
              {
                path        = "webhook_secret_token"
                objectAlias = "zoom_webhook_secret_token"
              }
            ]
          }
        ])
      }
      secretObjects = [
        {
          secretName = "scriptureforge-runtime-secrets"
          type       = "Opaque"
          data = [
            {
              objectName = "database_url"
              key        = "DATABASE_URL"
            },
            {
              objectName = "jwt_secret_key"
              key        = "JWT_SECRET_KEY"
            },
            {
              objectName = "journal_salt_secret"
              key        = "JOURNAL_SALT_SECRET"
            },
            {
              objectName = "openai_api_key"
              key        = "OPENAI_API_KEY"
            },
            {
              objectName = "grpc_engine_shared_secret"
              key        = "GRPC_ENGINE_SHARED_SECRET"
            },
            {
              objectName = "grpc_engine_tls_ca_pem"
              key        = "GRPC_ENGINE_TLS_CA_PEM"
            },
            {
              objectName = "grpc_engine_tls_server_cert_pem"
              key        = "GRPC_ENGINE_TLS_CERT_PEM"
            },
            {
              objectName = "grpc_engine_tls_server_key_pem"
              key        = "GRPC_ENGINE_TLS_KEY_PEM"
            },
            {
              objectName = "grpc_engine_tls_client_cert_pem"
              key        = "GRPC_ENGINE_TLS_CLIENT_CERT_PEM"
            },
            {
              objectName = "grpc_engine_tls_client_key_pem"
              key        = "GRPC_ENGINE_TLS_CLIENT_KEY_PEM"
            },
            {
              objectName = "zoom_account_id"
              key        = "ZOOM_ACCOUNT_ID"
            },
            {
              objectName = "zoom_client_id"
              key        = "ZOOM_CLIENT_ID"
            },
            {
              objectName = "zoom_client_secret"
              key        = "ZOOM_CLIENT_SECRET"
            },
            {
              objectName = "zoom_webhook_secret_token"
              key        = "ZOOM_WEBHOOK_SECRET_TOKEN"
            }
          ]
        }
      ]
    }
  }

  depends_on = [
    kubernetes_service_account.workload,
    aws_iam_role_policy_attachment.app_secrets_read
  ]
}

resource "kubernetes_deployment" "api" {
  metadata {
    name      = "scriptureforge-api"
    namespace = kubernetes_namespace.app.metadata[0].name
    labels = {
      app = "scriptureforge-api"
    }
  }

  spec {
    replicas                  = 2
    revision_history_limit    = 10
    progress_deadline_seconds = 600
    min_ready_seconds         = 5

    strategy {
      type = "RollingUpdate"

      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
    }

    selector {
      match_labels = {
        app = "scriptureforge-api"
      }
    }

    template {
      metadata {
        labels = {
          app = "scriptureforge-api"
        }
      }

      spec {
        service_account_name = kubernetes_service_account.workload.metadata[0].name

        topology_spread_constraint {
          max_skew           = 1
          topology_key       = "topology.kubernetes.io/zone"
          when_unsatisfiable = "ScheduleAnyway"

          label_selector {
            match_labels = {
              app = "scriptureforge-api"
            }
          }
        }

        container {
          name  = "api"
          image = var.api_image

          port {
            container_port = 8080
          }

          env {
            name  = "API_REQUEST_TIMEOUT_MS"
            value = tostring(var.api_request_timeout_ms)
          }

          env {
            name  = "SHUTDOWN_TIMEOUT_MS"
            value = tostring(var.api_shutdown_timeout_ms)
          }

          env {
            name  = "ZOOM_HTTP_TIMEOUT_MS"
            value = tostring(var.zoom_http_timeout_ms)
          }

          env {
            name  = "ZOOM_MAX_RETRIES"
            value = tostring(var.zoom_max_retries)
          }

          env {
            name  = "HTTP_READ_HEADER_TIMEOUT_MS"
            value = tostring(var.api_http_read_header_timeout_ms)
          }

          env {
            name  = "HTTP_READ_TIMEOUT_MS"
            value = tostring(var.api_http_read_timeout_ms)
          }

          env {
            name  = "HTTP_WRITE_TIMEOUT_MS"
            value = tostring(var.api_http_write_timeout_ms)
          }

          env {
            name  = "HTTP_IDLE_TIMEOUT_MS"
            value = tostring(var.api_http_idle_timeout_ms)
          }

          env {
            name  = "HTTP_MAX_HEADER_BYTES"
            value = tostring(var.api_http_max_header_bytes)
          }

          env {
            name  = "STARTUP_DEPENDENCY_TIMEOUT_MS"
            value = tostring(var.api_startup_dependency_timeout_ms)
          }

          env {
            name  = "DB_POOL_MAX_CONNS"
            value = tostring(var.api_db_pool_max_conns)
          }

          env {
            name  = "DB_POOL_MIN_CONNS"
            value = tostring(var.api_db_pool_min_conns)
          }

          env {
            name  = "DB_POOL_MAX_CONN_LIFETIME_MS"
            value = tostring(var.api_db_pool_max_conn_lifetime_ms)
          }

          env {
            name  = "DB_POOL_MAX_CONN_IDLE_TIME_MS"
            value = tostring(var.api_db_pool_max_conn_idle_time_ms)
          }

          env {
            name  = "REDIS_POOL_SIZE"
            value = tostring(var.api_redis_pool_size)
          }

          env {
            name  = "REDIS_MAX_ACTIVE_CONNS"
            value = tostring(var.api_redis_max_active_conns)
          }

          env {
            name  = "REDIS_POOL_TIMEOUT_MS"
            value = tostring(var.api_redis_pool_timeout_ms)
          }

          env {
            name  = "REDIS_DIAL_TIMEOUT_MS"
            value = tostring(var.api_redis_dial_timeout_ms)
          }

          env {
            name  = "REDIS_READ_TIMEOUT_MS"
            value = tostring(var.api_redis_read_timeout_ms)
          }

          env {
            name  = "REDIS_WRITE_TIMEOUT_MS"
            value = tostring(var.api_redis_write_timeout_ms)
          }

          resources {
            requests = var.api_resources.requests
            limits   = var.api_resources.limits
          }

          liveness_probe {
            http_get {
              path = "/live"
              port = 8080
            }

            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 2
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/ready"
              port = 8080
            }

            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 2
            failure_threshold     = 3
          }

          env {
            name = "DATABASE_URL"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "DATABASE_URL"
              }
            }
          }

          env {
            name  = "REDIS_URL"
            value = "rediss://${aws_elasticache_replication_group.redis.primary_endpoint_address}:6379"
          }

          env {
            name  = "GRPC_ENGINE_ADDRESS"
            value = "scriptureforge-rust-engine:50051"
          }

          env {
            name = "GRPC_ENGINE_SHARED_SECRET"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "GRPC_ENGINE_SHARED_SECRET"
              }
            }
          }

          env {
            name = "GRPC_ENGINE_TLS_CA_PEM"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "GRPC_ENGINE_TLS_CA_PEM"
              }
            }
          }

          env {
            name = "GRPC_ENGINE_TLS_CLIENT_CERT_PEM"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "GRPC_ENGINE_TLS_CLIENT_CERT_PEM"
              }
            }
          }

          env {
            name = "GRPC_ENGINE_TLS_CLIENT_KEY_PEM"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "GRPC_ENGINE_TLS_CLIENT_KEY_PEM"
              }
            }
          }

          env {
            name  = "GRPC_ENGINE_TLS_SERVER_NAME"
            value = var.grpc_engine_tls_server_name
          }

          env {
            name  = "ALLOWED_WS_ORIGINS"
            value = var.allowed_ws_origins
          }

          env {
            name  = "TRUST_PROXY_HEADERS"
            value = tostring(var.trust_proxy_headers)
          }

          env {
            name  = "OTEL_SERVICE_NAME"
            value = "scriptureforge-api"
          }

          env {
            name  = "SERVICE_VERSION"
            value = var.service_version
          }

          env {
            name  = "DEPLOYMENT_ENVIRONMENT"
            value = var.environment
          }

          env {
            name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
            value = var.otel_exporter_otlp_endpoint
          }

          env {
            name  = "OTEL_EXPORTER_OTLP_INSECURE"
            value = tostring(var.otel_exporter_otlp_insecure)
          }

          env {
            name = "JWT_SECRET_KEY"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "JWT_SECRET_KEY"
              }
            }
          }

          env {
            name = "JOURNAL_SALT_SECRET"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "JOURNAL_SALT_SECRET"
              }
            }
          }

          env {
            name = "OPENAI_API_KEY"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "OPENAI_API_KEY"
              }
            }
          }

          env {
            name = "ZOOM_ACCOUNT_ID"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "ZOOM_ACCOUNT_ID"
              }
            }
          }

          env {
            name = "ZOOM_CLIENT_ID"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "ZOOM_CLIENT_ID"
              }
            }
          }

          env {
            name = "ZOOM_CLIENT_SECRET"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "ZOOM_CLIENT_SECRET"
              }
            }
          }

          env {
            name = "ZOOM_WEBHOOK_SECRET_TOKEN"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "ZOOM_WEBHOOK_SECRET_TOKEN"
              }
            }
          }

          volume_mount {
            name       = "app-secrets-store"
            mount_path = "/mnt/secrets-store"
            read_only  = true
          }
        }

        volume {
          name = "app-secrets-store"

          csi {
            driver    = "secrets-store.csi.k8s.io"
            read_only = true

            volume_attributes = {
              secretProviderClass = kubernetes_manifest.app_secret_provider.manifest.metadata.name
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "api" {
  metadata {
    name      = "scriptureforge-api"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    min_available = 1

    selector {
      match_labels = {
        app = "scriptureforge-api"
      }
    }
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "api" {
  metadata {
    name      = "scriptureforge-api"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    min_replicas = var.api_autoscaling.min_replicas
    max_replicas = var.api_autoscaling.max_replicas

    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.api.metadata[0].name
    }

    metric {
      type = "Resource"

      resource {
        name = "cpu"

        target {
          type                = "Utilization"
          average_utilization = var.api_autoscaling.target_cpu_utilization_percentage
        }
      }
    }

    metric {
      type = "Resource"

      resource {
        name = "memory"

        target {
          type                = "Utilization"
          average_utilization = var.api_autoscaling.target_memory_utilization_percentage
        }
      }
    }
  }
}

resource "kubernetes_deployment" "rust_engine" {
  metadata {
    name      = "scriptureforge-rust-engine"
    namespace = kubernetes_namespace.app.metadata[0].name
    labels = {
      app = "scriptureforge-rust-engine"
    }
  }

  spec {
    replicas                  = 2
    revision_history_limit    = 10
    progress_deadline_seconds = 600
    min_ready_seconds         = 5

    strategy {
      type = "RollingUpdate"

      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
    }

    selector {
      match_labels = {
        app = "scriptureforge-rust-engine"
      }
    }

    template {
      metadata {
        labels = {
          app = "scriptureforge-rust-engine"
        }
      }

      spec {
        service_account_name = kubernetes_service_account.workload.metadata[0].name

        topology_spread_constraint {
          max_skew           = 1
          topology_key       = "topology.kubernetes.io/zone"
          when_unsatisfiable = "ScheduleAnyway"

          label_selector {
            match_labels = {
              app = "scriptureforge-rust-engine"
            }
          }
        }

        container {
          name  = "rust-engine"
          image = var.rust_engine_image

          port {
            container_port = 50051
          }

          port {
            container_port = 9102
          }

          resources {
            requests = var.rust_engine_resources.requests
            limits   = var.rust_engine_resources.limits
          }

          liveness_probe {
            http_get {
              path = "/healthz"
              port = 9102
            }

            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 2
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/healthz"
              port = 9102
            }

            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 2
            failure_threshold     = 3
          }

          env {
            name  = "RUST_ENGINE_BIND_ADDRESS"
            value = "0.0.0.0:50051"
          }

          env {
            name  = "RUST_ENGINE_METRICS_ADDRESS"
            value = "0.0.0.0:9102"
          }

          env {
            name = "GRPC_ENGINE_SHARED_SECRET"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "GRPC_ENGINE_SHARED_SECRET"
              }
            }
          }

          env {
            name = "GRPC_ENGINE_TLS_CERT_PEM"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "GRPC_ENGINE_TLS_CERT_PEM"
              }
            }
          }

          env {
            name = "GRPC_ENGINE_TLS_KEY_PEM"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "GRPC_ENGINE_TLS_KEY_PEM"
              }
            }
          }

          env {
            name = "GRPC_ENGINE_TLS_CA_PEM"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "GRPC_ENGINE_TLS_CA_PEM"
              }
            }
          }

          env {
            name  = "OTEL_SERVICE_NAME"
            value = "scriptureforge-rust-engine"
          }

          env {
            name  = "SERVICE_VERSION"
            value = var.service_version
          }

          env {
            name  = "DEPLOYMENT_ENVIRONMENT"
            value = var.environment
          }

          env {
            name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
            value = var.otel_exporter_otlp_endpoint
          }

          env {
            name = "DATABASE_URL"
            value_from {
              secret_key_ref {
                name = "scriptureforge-runtime-secrets"
                key  = "DATABASE_URL"
              }
            }
          }

          volume_mount {
            name       = "app-secrets-store"
            mount_path = "/mnt/secrets-store"
            read_only  = true
          }
        }

        volume {
          name = "app-secrets-store"

          csi {
            driver    = "secrets-store.csi.k8s.io"
            read_only = true

            volume_attributes = {
              secretProviderClass = kubernetes_manifest.app_secret_provider.manifest.metadata.name
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "rust_engine" {
  metadata {
    name      = "scriptureforge-rust-engine"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    min_available = 1

    selector {
      match_labels = {
        app = "scriptureforge-rust-engine"
      }
    }
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "rust_engine" {
  metadata {
    name      = "scriptureforge-rust-engine"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    min_replicas = var.rust_engine_autoscaling.min_replicas
    max_replicas = var.rust_engine_autoscaling.max_replicas

    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.rust_engine.metadata[0].name
    }

    metric {
      type = "Resource"

      resource {
        name = "cpu"

        target {
          type                = "Utilization"
          average_utilization = var.rust_engine_autoscaling.target_cpu_utilization_percentage
        }
      }
    }

    metric {
      type = "Resource"

      resource {
        name = "memory"

        target {
          type                = "Utilization"
          average_utilization = var.rust_engine_autoscaling.target_memory_utilization_percentage
        }
      }
    }
  }
}

resource "kubernetes_deployment" "web" {
  metadata {
    name      = "scriptureforge-web"
    namespace = kubernetes_namespace.app.metadata[0].name
    labels = {
      app = "scriptureforge-web"
    }
  }

  spec {
    replicas                  = 2
    revision_history_limit    = 10
    progress_deadline_seconds = 600
    min_ready_seconds         = 5

    strategy {
      type = "RollingUpdate"

      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
    }

    selector {
      match_labels = {
        app = "scriptureforge-web"
      }
    }

    template {
      metadata {
        labels = {
          app = "scriptureforge-web"
        }
      }

      spec {
        topology_spread_constraint {
          max_skew           = 1
          topology_key       = "topology.kubernetes.io/zone"
          when_unsatisfiable = "ScheduleAnyway"

          label_selector {
            match_labels = {
              app = "scriptureforge-web"
            }
          }
        }

        container {
          name  = "web"
          image = var.web_image

          port {
            container_port = 3000
          }

          resources {
            requests = var.web_resources.requests
            limits   = var.web_resources.limits
          }

          env {
            name  = "NEXT_PUBLIC_API_BASE_URL"
            value = "https://${var.api_hostname}"
          }
        }
      }
    }
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "web" {
  metadata {
    name      = "scriptureforge-web"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    min_replicas = var.web_autoscaling.min_replicas
    max_replicas = var.web_autoscaling.max_replicas

    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.web.metadata[0].name
    }

    metric {
      type = "Resource"

      resource {
        name = "cpu"

        target {
          type                = "Utilization"
          average_utilization = var.web_autoscaling.target_cpu_utilization_percentage
        }
      }
    }

    metric {
      type = "Resource"

      resource {
        name = "memory"

        target {
          type                = "Utilization"
          average_utilization = var.web_autoscaling.target_memory_utilization_percentage
        }
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "web" {
  metadata {
    name      = "scriptureforge-web"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    min_available = 1

    selector {
      match_labels = {
        app = "scriptureforge-web"
      }
    }
  }
}
