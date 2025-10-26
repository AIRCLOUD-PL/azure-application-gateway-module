# Application Gateway Enterprise Example

This example demonstrates how to deploy an Azure Application Gateway with enterprise-grade features including WAF, SSL/TLS termination, path-based routing, health probes, and comprehensive monitoring.

## Architecture

The example creates:
- Application Gateway with WAF v2 SKU
- Public IP address for frontend access
- SSL certificates for HTTPS termination
- Multiple backend pools for different services
- Path-based routing rules
- Health probes for backend monitoring
- Diagnostic settings for logging and monitoring
- Azure Policy assignments for security compliance

## Usage

```hcl
module "application_gateway" {
  source = "../../"

  # Resource Group
  resource_group_name = "rg-agw-enterprise-prod"
  location           = "East US 2"
  environment       = "prod"

  # Application Gateway Configuration
  application_gateway_name = "agw-enterprise-prod"

  # SKU Configuration
  sku = {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }

  # Gateway IP Configuration
  gateway_ip_configurations = {
    gateway = {
      name      = "gateway-ip-config"
      subnet_id = azurerm_subnet.agw_subnet.id
    }
  }

  # Frontend IP Configuration
  frontend_ip_configurations = {
    public = {
      name                 = "public-ip-config"
      public_ip_address_id = azurerm_public_ip.agw_pip.id
    }
  }

  # Frontend Ports
  frontend_ports = {
    http = {
      name = "http"
      port = 80
    }
    https = {
      name = "https"
      port = 443
    }
  }

  # SSL Certificates
  ssl_certificates = {
    wildcard-cert = {
      name     = "wildcard-cert"
      data     = filebase64("certificates/wildcard.pfx")
      password = var.ssl_certificate_password
    }
  }

  # Backend Address Pools
  backend_address_pools = {
    web-pool = {
      name         = "web-pool"
      ip_addresses = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
    }
    api-pool = {
      name         = "api-pool"
      ip_addresses = ["10.0.2.10", "10.0.2.11"]
    }
    admin-pool = {
      name         = "admin-pool"
      ip_addresses = ["10.0.3.10"]
    }
  }

  # Backend HTTP Settings
  backend_http_settings = {
    http-setting = {
      name                           = "http-setting"
      port                           = 80
      protocol                       = "Http"
      cookie_based_affinity          = "Disabled"
      request_timeout                = 30
      pick_host_name_from_backend_address = false
      probe_name                     = "health-probe"
    }
    https-setting = {
      name                           = "https-setting"
      port                           = 443
      protocol                       = "Https"
      cookie_based_affinity          = "Disabled"
      request_timeout                = 30
      pick_host_name_from_backend_address = false
      probe_name                     = "health-probe-https"
    }
  }

  # Health Probes
  probes = {
    health-probe = {
      name                = "health-probe"
      protocol            = "Http"
      path                = "/health"
      interval            = 30
      timeout             = 30
      unhealthy_threshold = 3
      pick_host_name_from_backend_http_settings = false
      minimum_servers     = 0
    }
    health-probe-https = {
      name                = "health-probe-https"
      protocol            = "Https"
      path                = "/health"
      interval            = 30
      timeout             = 30
      unhealthy_threshold = 3
      pick_host_name_from_backend_http_settings = false
      minimum_servers     = 0
    }
  }

  # HTTP Listeners
  http_listeners = {
    http-listener = {
      name                           = "http-listener"
      frontend_ip_configuration_name = "public-ip-config"
      frontend_port_name             = "http"
      protocol                       = "Http"
    }
    https-listener = {
      name                           = "https-listener"
      frontend_ip_configuration_name = "public-ip-config"
      frontend_port_name             = "https"
      protocol                       = "Https"
      ssl_certificate_name           = "wildcard-cert"
    }
  }

  # URL Path Maps for Path-based Routing
  url_path_maps = {
    path-map = {
      name                               = "path-map"
      default_backend_address_pool_name  = "web-pool"
      default_backend_http_settings_name = "http-setting"
      path_rules = [
        {
          name                       = "api-rule"
          paths                      = ["/api/*", "/swagger/*"]
          backend_address_pool_name  = "api-pool"
          backend_http_settings_name = "https-setting"
        },
        {
          name                       = "admin-rule"
          paths                      = ["/admin/*"]
          backend_address_pool_name  = "admin-pool"
          backend_http_settings_name = "https-setting"
        }
      ]
    }
  }

  # Request Routing Rules
  request_routing_rules = {
    http-redirect-rule = {
      name                        = "http-redirect-rule"
      http_listener_name          = "http-listener"
      redirect_configuration_name = "http-to-https"
    }
    path-routing-rule = {
      name              = "path-routing-rule"
      http_listener_name = "https-listener"
      url_path_map_name = "path-map"
    }
  }

  # Redirect Configurations
  redirect_configurations = {
    http-to-https = {
      name                 = "http-to-https"
      redirect_type        = "Permanent"
      target_listener_name = "https-listener"
      include_path         = true
      include_query_string = true
    }
  }

  # WAF Configuration
  waf_configuration = {
    enabled                  = true
    firewall_mode           = "Prevention"
    rule_set_type           = "OWASP"
    rule_set_version        = "3.2"
    file_upload_limit_mb    = 100
    request_body_check      = true
    max_request_body_size_kb = 128
    disabled_rule_groups    = []
    exclusions = [
      {
        match_variable          = "RequestArgNames"
        selector_match_operator = "Equals"
        selector                = "password"
      }
    ]
  }

  # Rewrite Rule Sets
  rewrite_rule_sets = {
    security-headers = {
      name = "security-headers"
      rewrite_rules = [
        {
          name          = "add-security-headers"
          rule_sequence = 100
          conditions    = []
          request_header_configurations = [
            {
              header_name  = "X-Frame-Options"
              header_value = "DENY"
            },
            {
              header_name  = "X-Content-Type-Options"
              header_value = "nosniff"
            },
            {
              header_name  = "Referrer-Policy"
              header_value = "strict-origin-when-cross-origin"
            }
          ]
          response_header_configurations = []
        }
      ]
    }
  }

  # Autoscale Configuration
  autoscale_configuration = {
    min_capacity = 2
    max_capacity = 10
  }

  # Identity
  identity = {
    type = "SystemAssigned"
  }

  # Diagnostic Settings
  diagnostic_settings = {
    logs = [
      {
        category = "ApplicationGatewayAccessLog"
        enabled  = true
        retention_policy = {
          enabled = true
          days    = 30
        }
      },
      {
        category = "ApplicationGatewayPerformanceLog"
        enabled  = true
        retention_policy = {
          enabled = true
          days    = 30
        }
      },
      {
        category = "ApplicationGatewayFirewallLog"
        enabled  = true
        retention_policy = {
          enabled = true
          days    = 30
        }
      }
    ]
    metrics = [
      {
        category = "AllMetrics"
        enabled  = true
        retention_policy = {
          enabled = true
          days    = 30
        }
      }
    ]
  }

  # Tags
  tags = {
    Environment         = "prod"
    Project            = "enterprise-app"
    Owner              = "platform-team"
    CostCenter         = "IT-001"
    DataClassification = "internal"
    Backup             = "daily"
    Monitoring         = "enabled"
  }

  # Azure Policy Assignments
  enable_policy_assignments = true
  policy_assignments = {
    waf_enabled = {
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/564feb30-bf6a-4854-b4bb-0d2d2d1e6c66"
      display_name         = "Application Gateway should have WAF enabled"
    }
    ssl_policy = {
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/60d4b3bc-61d4-4c4e-89e7-0dbb3c52e1d6"
      display_name         = "Application Gateway should use SSL policy with minimum TLS version"
    }
    diagnostic_logs = {
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/34f95f76-764f-4379-a43a-6a181c10cc51"
      display_name         = "Application Gateway should have diagnostic logs enabled"
    }
  }
}

# Supporting Resources
resource "azurerm_resource_group" "example" {
  name     = "rg-agw-enterprise-prod"
  location = "East US 2"

  tags = {
    Environment = "prod"
  }
}

resource "azurerm_virtual_network" "example" {
  name                = "vnet-agw-prod"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  address_space       = ["10.0.0.0/16"]

  tags = {
    Environment = "prod"
  }
}

resource "azurerm_subnet" "agw_subnet" {
  name                 = "snet-agw-prod"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.0.0/24"]
}

resource "azurerm_public_ip" "agw_pip" {
  name                = "pip-agw-prod"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Environment = "prod"
  }
}

# Outputs
output "application_gateway_id" {
  description = "The ID of the Application Gateway"
  value       = module.application_gateway.application_gateway_id
}

output "application_gateway_public_ip" {
  description = "The public IP address of the Application Gateway"
  value       = azurerm_public_ip.agw_pip.ip_address
}

output "application_gateway_fqdn" {
  description = "The FQDN of the Application Gateway"
  value       = module.application_gateway.application_gateway_fqdn
}
```

## Requirements

- Terraform >= 1.5.0
- AzureRM provider >= 3.80.0
- Go 1.21 (for testing)

## Testing

Run the tests:

```bash
cd test
go test -v
```

## Security Features

- **WAF Protection**: OWASP 3.2 rule set with prevention mode
- **SSL/TLS Termination**: HTTPS-only with strong cipher suites
- **Security Headers**: Automatic injection of security headers
- **Path-based Routing**: Secure routing to different backend services
- **Health Monitoring**: Comprehensive health probes for backend services
- **Diagnostic Logging**: Full logging and monitoring integration

## Monitoring

The Application Gateway is configured with:
- Access logs
- Performance logs
- Firewall logs
- All metrics collection
- 30-day retention policy

## Compliance

Azure Policy assignments ensure:
- WAF is always enabled
- Minimum TLS 1.2 policy
- Diagnostic logs are enabled
- Security best practices are enforced