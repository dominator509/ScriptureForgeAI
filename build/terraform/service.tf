resource "kubernetes_service" "api" {
  metadata {
    name      = "scriptureforge-api"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    selector = {
      app = "scriptureforge-api"
    }

    port {
      port        = 8080
      target_port = 8080
    }
  }
}

resource "kubernetes_service" "rust_engine" {
  metadata {
    name      = "scriptureforge-rust-engine"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    selector = {
      app = "scriptureforge-rust-engine"
    }

    port {
      name        = "grpc"
      port        = 50051
      target_port = 50051
    }

    port {
      name        = "metrics"
      port        = 9102
      target_port = 9102
    }
  }
}

resource "kubernetes_service" "web" {
  metadata {
    name      = "scriptureforge-web"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    selector = {
      app = "scriptureforge-web"
    }

    port {
      port        = 3000
      target_port = 3000
    }
  }
}

resource "kubernetes_ingress_v1" "api" {
  metadata {
    name      = "scriptureforge-api"
    namespace = kubernetes_namespace.app.metadata[0].name
    annotations = {
      "kubernetes.io/ingress.class"                        = "alb"
      "alb.ingress.kubernetes.io/scheme"                   = "internet-facing"
      "alb.ingress.kubernetes.io/listen-ports"             = "[{\"HTTP\":80},{\"HTTPS\":443}]"
      "alb.ingress.kubernetes.io/certificate-arn"          = var.ingress_certificate_arn
      "alb.ingress.kubernetes.io/ssl-policy"               = var.ingress_ssl_policy
      "alb.ingress.kubernetes.io/ssl-redirect"             = "443"
      "alb.ingress.kubernetes.io/subnets"                  = join(",", var.public_subnet_ids)
      "alb.ingress.kubernetes.io/security-groups"          = aws_security_group.ingress.id
      "alb.ingress.kubernetes.io/target-type"              = "ip"
      "alb.ingress.kubernetes.io/healthcheck-path"         = "/ready"
      "alb.ingress.kubernetes.io/load-balancer-attributes" = "routing.http2.enabled=true"
    }
  }

  spec {
    rule {
      host = var.api_hostname

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service.api.metadata[0].name

              port {
                number = 8080
              }
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_ingress_v1" "web" {
  metadata {
    name      = "scriptureforge-web"
    namespace = kubernetes_namespace.app.metadata[0].name
    annotations = {
      "kubernetes.io/ingress.class"                        = "alb"
      "alb.ingress.kubernetes.io/scheme"                   = "internet-facing"
      "alb.ingress.kubernetes.io/listen-ports"             = "[{\"HTTP\":80},{\"HTTPS\":443}]"
      "alb.ingress.kubernetes.io/certificate-arn"          = var.ingress_certificate_arn
      "alb.ingress.kubernetes.io/ssl-policy"               = var.ingress_ssl_policy
      "alb.ingress.kubernetes.io/ssl-redirect"             = "443"
      "alb.ingress.kubernetes.io/subnets"                  = join(",", var.public_subnet_ids)
      "alb.ingress.kubernetes.io/security-groups"          = aws_security_group.ingress.id
      "alb.ingress.kubernetes.io/target-type"              = "ip"
      "alb.ingress.kubernetes.io/load-balancer-attributes" = "routing.http2.enabled=true"
    }
  }

  spec {
    rule {
      host = var.web_hostname

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service.web.metadata[0].name

              port {
                number = 3000
              }
            }
          }
        }
      }
    }
  }
}
