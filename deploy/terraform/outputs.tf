output "namespace" {
  value = local.ns
}

output "controlplane_grpc_service" {
  description = "In-cluster address agents connect to (front with a LoadBalancer/Ingress for external fleets)."
  value       = "${kubernetes_service.controlplane_grpc.metadata[0].name}.${local.ns}.svc:9443"
}

output "controlplane_http_service" {
  description = "In-cluster operator HTTP address (front with an Ingress + TLS)."
  value       = "${kubernetes_service.controlplane_http.metadata[0].name}.${local.ns}.svc"
}
