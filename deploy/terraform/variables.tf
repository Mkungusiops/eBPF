variable "kubeconfig" {
  description = "Path to the kubeconfig for the target cluster."
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "kubeconfig context to use (empty = current)."
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Namespace for the control plane and its dependencies."
  type        = string
  default     = "ebpf-soc"
}

variable "controlplane_image" {
  description = "Control-plane container image (the signed image CI publishes)."
  type        = string
  default     = "ghcr.io/jeffmk/ebpf-soc/controlplane:latest"
}

variable "controlplane_replicas" {
  description = "Control-plane replica count."
  type        = number
  default     = 1
}

# --- Postgres (control state + RLS) ----------------------------------------
variable "postgres_chart_version" {
  type    = string
  default = "15.5.20"
}
variable "db_user" {
  type    = string
  default = "soc"
}
variable "db_name" {
  type    = string
  default = "ebpf_soc"
}
variable "db_password" {
  description = "Postgres password. Supply via TF_VAR_db_password / a secrets manager — never commit."
  type        = string
  sensitive   = true
}
variable "postgres_storage" {
  type    = string
  default = "20Gi"
}

# --- NATS JetStream (bus) --------------------------------------------------
variable "nats_chart_version" {
  type    = string
  default = "1.2.2"
}

# --- Keycloak (identity/OIDC) ----------------------------------------------
variable "keycloak_chart_version" {
  type    = string
  default = "22.1.4"
}
variable "keycloak_admin_password" {
  description = "Keycloak bootstrap admin password. Supply via TF_VAR_ / secrets manager."
  type        = string
  sensitive   = true
}
variable "oidc_issuer" {
  description = "OIDC issuer URL the control plane trusts (a Keycloak realm)."
  type        = string
  default     = ""
}
