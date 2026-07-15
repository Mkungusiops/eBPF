# Control-plane IaC baseline (roadmap Phase 0 "IaC baseline"). Deliberately
# cloud-AGNOSTIC: it deploys the strictly-permissive-OSS control-plane stack
# (docs/plan/d4c-tech-decisions.md) onto ANY Kubernetes cluster — managed (EKS/
# GKE/AKS) for SaaS, or on-prem for data-residency tenants — from one config.
# "Nothing production yet, just the substrate."

terraform {
  required_version = ">= 1.5"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
  }
}

provider "kubernetes" {
  config_path    = var.kubeconfig
  config_context = var.kube_context
}

provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig
    config_context = var.kube_context
  }
}
