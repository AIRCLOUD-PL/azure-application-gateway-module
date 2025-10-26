# Application Gateway Module Outputs

output "application_gateway_id" {
  description = "Application Gateway resource ID"
  value       = azurerm_application_gateway.main.id
}

output "application_gateway_name" {
  description = "Application Gateway name"
  value       = azurerm_application_gateway.main.name
}

output "frontend_ip_configurations" {
  description = "Frontend IP configurations"
  value       = azurerm_application_gateway.main.frontend_ip_configuration
}

output "frontend_ports" {
  description = "Frontend ports"
  value       = azurerm_application_gateway.main.frontend_port
}

output "backend_address_pools" {
  description = "Backend address pools"
  value       = azurerm_application_gateway.main.backend_address_pool
}

output "backend_http_settings" {
  description = "Backend HTTP settings"
  value       = azurerm_application_gateway.main.backend_http_settings
}

output "http_listeners" {
  description = "HTTP listeners"
  value       = azurerm_application_gateway.main.http_listener
}

output "request_routing_rules" {
  description = "Request routing rules"
  value       = azurerm_application_gateway.main.request_routing_rule
}

output "probes" {
  description = "Health probes"
  value       = azurerm_application_gateway.main.probe
}

output "ssl_certificates" {
  description = "SSL certificates"
  value       = azurerm_application_gateway.main.ssl_certificate
}

output "url_path_maps" {
  description = "URL path maps"
  value       = azurerm_application_gateway.main.url_path_map
}

output "redirect_configurations" {
  description = "Redirect configurations"
  value       = azurerm_application_gateway.main.redirect_configuration
}

output "rewrite_rule_sets" {
  description = "Rewrite rule sets"
  value       = azurerm_application_gateway.main.rewrite_rule_set
}

output "public_ip_addresses" {
  description = "Public IP addresses associated with the Application Gateway"
  value = [
    for config in azurerm_application_gateway.main.frontend_ip_configuration :
    config.public_ip_address_id if config.public_ip_address_id != null
  ]
}

output "private_ip_addresses" {
  description = "Private IP addresses of the Application Gateway"
  value = [
    for config in azurerm_application_gateway.main.frontend_ip_configuration :
    config.private_ip_address if config.private_ip_address != null
  ]
}

output "resource_group_name" {
  description = "Resource group name"
  value       = var.resource_group_name
}

output "location" {
  description = "Azure region"
  value       = var.location
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "sku" {
  description = "Application Gateway SKU"
  value       = var.sku
}

output "waf_configuration" {
  description = "WAF configuration"
  value       = var.waf_configuration
}

output "identity" {
  description = "Managed identity"
  value       = azurerm_application_gateway.main.identity
}

output "tags" {
  description = "Resource tags"
  value       = local.tags
}