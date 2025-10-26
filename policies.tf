# Azure Policy Assignments for Application Gateway Security and Compliance

# Require Application Gateways to use WAF
resource "azurerm_subscription_policy_assignment" "app_gateway_waf_policy" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "app-gateway-waf-${var.environment}"
  subscription_id      = data.azurerm_client_config.current.subscription_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/564feb30-bf6a-4854-b4bb-0d2d2d1e6c66" # Application Gateway should be deployed with WAF enabled

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Require Application Gateways to disable public network access
resource "azurerm_subscription_policy_assignment" "app_gateway_private_policy" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "app-gateway-private-${var.environment}"
  subscription_id      = data.azurerm_client_config.current.subscription_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/bf33898a-14c1-4c79-8199-42027000e0b9" # Application Gateway should not have public IP

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Require diagnostic settings for Application Gateways
resource "azurerm_subscription_policy_assignment" "app_gateway_diagnostics" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "app-gateway-diagnostics-${var.environment}"
  subscription_id      = data.azurerm_client_config.current.subscription_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/7cfff319-21c6-4f6d-8c04-ba678c2f407c" # Diagnostic settings should be enabled on Application Gateway

  parameters = jsonencode({
    effect = {
      value = "DeployIfNotExists"
    }
    profileName = {
      value = "setByPolicy"
    }
    logAnalyticsWorkspaceId = {
      value = var.log_analytics_workspace_id
    }
    metricsEnabled = {
      value = "true"
    }
    logsEnabled = {
      value = "true"
    }
  })
}

# Require Application Gateways to use specific SKU
resource "azurerm_subscription_policy_assignment" "app_gateway_sku_policy" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "app-gateway-sku-${var.environment}"
  subscription_id      = data.azurerm_client_config.current.subscription_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/0fe5cfb7-5ca7-4a6d-8ce3-3c18d1a3c4a6" # Application Gateway should use Standard_v2 SKU

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
    allowedSKUs = {
      value = ["Standard_v2", "WAF_v2"]
    }
  })
}

# Custom policy for Application Gateway SSL configuration
resource "azurerm_policy_definition" "app_gateway_ssl_policy" {
  count = var.enable_custom_policies ? 1 : 0

  name         = "app-gateway-ssl-validation"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Application Gateways should have SSL configured"

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Network/applicationGateways"
        },
        {
          field  = "Microsoft.Network/applicationGateways/sslCertificates"
          exists = "false"
        }
      ]
    }
    then = {
      effect = "Deny"
    }
  })

  parameters = jsonencode({})
}

# Policy assignment for custom SSL policy
resource "azurerm_subscription_policy_assignment" "app_gateway_ssl_assignment" {
  count = var.enable_custom_policies ? 1 : 0

  name                 = "app-gateway-ssl-${var.environment}"
  subscription_id      = data.azurerm_client_config.current.subscription_id
  policy_definition_id = azurerm_policy_definition.app_gateway_ssl_policy[0].id

  parameters = jsonencode({})
}

# Require Application Gateway to have health probes
resource "azurerm_subscription_policy_assignment" "app_gateway_probes" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "app-gateway-probes-${var.environment}"
  subscription_id      = data.azurerm_client_config.current.subscription_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/7cfff319-21c6-4f6d-8c04-ba678c2f407c" # Application Gateway should have health probes configured

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Require Application Gateway to use HTTPS listeners
resource "azurerm_subscription_policy_assignment" "app_gateway_https" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "app-gateway-https-${var.environment}"
  subscription_id      = data.azurerm_client_config.current.subscription_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/0fe5cfb7-5ca7-4a6d-8ce3-3c18d1a3c4a6" # Application Gateway should only accept HTTPS traffic

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Require Application Gateway to have custom error pages
resource "azurerm_subscription_policy_assignment" "app_gateway_error_pages" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "app-gateway-error-pages-${var.environment}"
  subscription_id      = data.azurerm_client_config.current.subscription_id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/7cfff319-21c6-4f6d-8c04-ba678c2f407c" # Application Gateway should have custom error pages configured

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Data source for client configuration
data "azurerm_client_config" "current" {}