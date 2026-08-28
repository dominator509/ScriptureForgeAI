resource "kubernetes_network_policy" "app_default_deny" {
  metadata {
    name      = "scriptureforge-default-deny"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy" "api" {
  metadata {
    name      = "scriptureforge-api"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "scriptureforge-api"
      }
    }

    policy_types = ["Ingress", "Egress"]

    dynamic "ingress" {
      for_each = var.allowed_ingress_cidrs

      content {
        from {
          ip_block {
            cidr = ingress.value
          }
        }

        ports {
          port     = 8080
          protocol = "TCP"
        }
      }
    }

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = kubernetes_namespace.app.metadata[0].name
          }
        }

        pod_selector {
          match_labels = {
            app = "scriptureforge-web"
          }
        }
      }

      from {
        namespace_selector {}

        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "prometheus"
          }
        }
      }

      ports {
        port     = 8080
        protocol = "TCP"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = kubernetes_namespace.app.metadata[0].name
          }
        }

        pod_selector {
          match_labels = {
            app = "scriptureforge-rust-engine"
          }
        }
      }

      ports {
        port     = 50051
        protocol = "TCP"
      }
    }

    dynamic "egress" {
      for_each = var.data_tier_cidrs

      content {
        to {
          ip_block {
            cidr = egress.value
          }
        }

        ports {
          port     = 5432
          protocol = "TCP"
        }

        ports {
          port     = 6379
          protocol = "TCP"
        }
      }
    }

    egress {
      ports {
        port     = 443
        protocol = "TCP"
      }

      ports {
        port     = 4317
        protocol = "TCP"
      }

      ports {
        port     = 4318
        protocol = "TCP"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }

        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }

      ports {
        port     = 53
        protocol = "UDP"
      }

      ports {
        port     = 53
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy" "rust_engine" {
  metadata {
    name      = "scriptureforge-rust-engine"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "scriptureforge-rust-engine"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = kubernetes_namespace.app.metadata[0].name
          }
        }

        pod_selector {
          match_labels = {
            app = "scriptureforge-api"
          }
        }
      }

      ports {
        port     = 50051
        protocol = "TCP"
      }
    }

    ingress {
      from {
        namespace_selector {}

        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "prometheus"
          }
        }
      }

      ports {
        port     = 9102
        protocol = "TCP"
      }
    }

    dynamic "egress" {
      for_each = var.data_tier_cidrs

      content {
        to {
          ip_block {
            cidr = egress.value
          }
        }

        ports {
          port     = 5432
          protocol = "TCP"
        }
      }
    }

    egress {
      ports {
        port     = 443
        protocol = "TCP"
      }

      ports {
        port     = 4317
        protocol = "TCP"
      }

      ports {
        port     = 4318
        protocol = "TCP"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }

        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }

      ports {
        port     = 53
        protocol = "UDP"
      }

      ports {
        port     = 53
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy" "web" {
  metadata {
    name      = "scriptureforge-web"
    namespace = kubernetes_namespace.app.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "scriptureforge-web"
      }
    }

    policy_types = ["Ingress", "Egress"]

    dynamic "ingress" {
      for_each = var.allowed_ingress_cidrs

      content {
        from {
          ip_block {
            cidr = ingress.value
          }
        }

        ports {
          port     = 3000
          protocol = "TCP"
        }
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = kubernetes_namespace.app.metadata[0].name
          }
        }

        pod_selector {
          match_labels = {
            app = "scriptureforge-api"
          }
        }
      }

      ports {
        port     = 8080
        protocol = "TCP"
      }
    }

    egress {
      ports {
        port     = 443
        protocol = "TCP"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }

        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }

      ports {
        port     = 53
        protocol = "UDP"
      }

      ports {
        port     = 53
        protocol = "TCP"
      }
    }
  }
}
