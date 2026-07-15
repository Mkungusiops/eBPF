resource "kubernetes_namespace" "cp" {
  metadata {
    name = var.namespace
  }
}

locals {
  ns = kubernetes_namespace.cp.metadata[0].name
}

# --- Secrets (values injected via TF_VAR_ / a secrets manager) --------------
resource "kubernetes_secret" "db" {
  metadata {
    name      = "cp-db"
    namespace = local.ns
  }
  data = {
    "password"          = var.db_password
    "postgres-password" = var.db_password
  }
}

resource "kubernetes_secret" "keycloak" {
  metadata {
    name      = "cp-keycloak"
    namespace = local.ns
  }
  data = {
    "admin-password" = var.keycloak_admin_password
  }
}

# --- Postgres: control state + Row-Level-Security central store -------------
resource "helm_release" "postgres" {
  name       = "postgres"
  namespace  = local.ns
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "postgresql"
  version    = var.postgres_chart_version

  set {
    name  = "auth.username"
    value = var.db_user
  }
  set {
    name  = "auth.database"
    value = var.db_name
  }
  set {
    name  = "auth.existingSecret"
    value = kubernetes_secret.db.metadata[0].name
  }
  set {
    name  = "primary.persistence.size"
    value = var.postgres_storage
  }
}

# --- NATS JetStream: message bus (per-tenant subjects) ----------------------
resource "helm_release" "nats" {
  name       = "nats"
  namespace  = local.ns
  repository = "https://nats-io.github.io/k8s/helm/charts"
  chart      = "nats"
  version    = var.nats_chart_version

  set {
    name  = "config.jetstream.enabled"
    value = "true"
  }
}

# --- Keycloak: identity / OIDC broker (humans only) -------------------------
resource "helm_release" "keycloak" {
  name       = "keycloak"
  namespace  = local.ns
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "keycloak"
  version    = var.keycloak_chart_version

  set {
    name  = "auth.adminUser"
    value = "admin"
  }
  set {
    name  = "auth.existingSecret"
    value = kubernetes_secret.keycloak.metadata[0].name
  }
}

# --- The control plane itself ----------------------------------------------
# ClickHouse + SeaweedFS are added with the same helm_release pattern when the
# firehose / cold storage are needed (ADR §5 sequencing).
resource "kubernetes_deployment" "controlplane" {
  metadata {
    name      = "controlplane"
    namespace = local.ns
    labels    = { app = "controlplane" }
  }

  spec {
    replicas = var.controlplane_replicas
    selector {
      match_labels = { app = "controlplane" }
    }
    template {
      metadata {
        labels = { app = "controlplane" }
      }
      spec {
        container {
          name  = "controlplane"
          image = var.controlplane_image
          args = [
            "-store", "postgres",
            "-pg-dsn", "postgres://${var.db_user}@postgres-postgresql:5432/${var.db_name}?sslmode=disable",
            "-grpc", ":9443",
            "-http", ":9090",
            "-oidc-issuer", var.oidc_issuer,
            "-state-dir", "/var/lib/controlplane",
          ]
          port {
            name           = "grpc"
            container_port = 9443
          }
          port {
            name           = "http"
            container_port = 9090
          }
          env {
            name = "PGPASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.db.metadata[0].name
                key  = "password"
              }
            }
          }
          volume_mount {
            name       = "state"
            mount_path = "/var/lib/controlplane"
          }
        }
        volume {
          name = "state"
          empty_dir {} # replace with a PVC for restart-stable CA/fleet key
        }
      }
    }
  }
}

resource "kubernetes_service" "controlplane_grpc" {
  metadata {
    name      = "controlplane-grpc"
    namespace = local.ns
  }
  spec {
    selector = { app = "controlplane" }
    port {
      name        = "grpc"
      port        = 9443
      target_port = 9443
    }
  }
}

resource "kubernetes_service" "controlplane_http" {
  metadata {
    name      = "controlplane-http"
    namespace = local.ns
  }
  spec {
    selector = { app = "controlplane" }
    port {
      name        = "http"
      port        = 80
      target_port = 9090
    }
  }
}
