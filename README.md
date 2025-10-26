# Azure Application Gateway Terraform Module

This Terraform module creates an Azure Application Gateway with enterprise-grade features including Web Application Firewall (WAF), SSL/TLS termination, load balancing, path-based routing, health probes, and comprehensive monitoring.

## Features

- **Load Balancing**: Advanced load balancing with multiple backend pools and routing rules
- **Web Application Firewall (WAF)**: OWASP rule sets with customizable exclusions
- **SSL/TLS Termination**: HTTPS support with custom SSL certificates and policies
- **Path-based Routing**: Route traffic based on URL paths to different backend services
- **Health Monitoring**: Configurable health probes for backend service monitoring
- **Security Headers**: Automatic injection of security headers via rewrite rules
- **Auto-scaling**: Automatic scaling based on traffic patterns
- **Monitoring & Logging**: Comprehensive diagnostic settings and log integration
- **Azure Policy**: Built-in policy assignments for security compliance
- **Multi-region Support**: Zone redundancy and regional failover capabilities

## Architecture

```
Internet
    ↓
[Azure Application Gateway]
    ↓ (WAF Protection)
[SSL/TLS Termination]
    ↓ (Load Balancing)
[Backend Pools]
    ↓ (Health Monitoring)
[Backend Services]
```

## Usage

### Basic Example

```hcl
module "application_gateway" {
  source = "./modules/network/application-gateway"

  # Resource Configuration
  resource_group_name = "rg-app-gateway"
  location           = "East US"
  environment       = "prod"

  # Application Gateway
  application_gateway_name = "agw-example"

  # SKU
  sku = {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }

  # Network Configuration
  gateway_ip_configurations = {
    gateway = {
      name      = "gateway-ip-config"
      subnet_id = azurerm_subnet.agw_subnet.id
    }
  }

  frontend_ip_configurations = {
    public = {
      name                 = "public-ip-config"
      public_ip_address_id = azurerm_public_ip.agw_pip.id
    }
  }

  # Backend Configuration
  backend_address_pools = {
    web-pool = {
      name         = "web-pool"
      ip_addresses = ["10.0.1.10", "10.0.1.11"]
    }
  }

  backend_http_settings = {
    http-setting = {
      name     = "http-setting"
      port     = 80
      protocol = "Http"
    }
  }

  # Frontend Configuration
  http_listeners = {
    http-listener = {
      name                           = "http-listener"
      frontend_ip_configuration_name = "public-ip-config"
      frontend_port_name             = "http"
      protocol                       = "Http"
    }
  }

  # Routing
  request_routing_rules = {
    routing-rule = {
      name                       = "routing-rule"
      http_listener_name         = "http-listener"
      backend_address_pool_name  = "web-pool"
      backend_http_settings_name = "http-setting"
    }
  }

  # Tags
  tags = {
    Environment = "prod"
    Project     = "web-app"
  }
}
```

### Enterprise Example with WAF

```hcl
module "application_gateway_waf" {
  source = "./modules/network/application-gateway"

  # Resource Configuration
  resource_group_name = "rg-app-gateway-prod"
  location           = "East US 2"
  environment       = "prod"

  # Application Gateway
  application_gateway_name = "agw-enterprise-prod"

  # WAF SKU
  sku = {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }

  # Network Configuration
  gateway_ip_configurations = {
    gateway = {
      name      = "gateway-ip-config"
      subnet_id = azurerm_subnet.agw_subnet.id
    }
  }

  frontend_ip_configurations = {
    public = {
      name                 = "public-ip-config"
      public_ip_address_id = azurerm_public_ip.agw_pip.id
    }
  }

  # SSL Configuration
  ssl_certificates = {
    wildcard-cert = {
      name     = "wildcard-cert"
      data     = filebase64("certificates/wildcard.pfx")
      password = var.ssl_certificate_password
    }
  }

  # Backend Configuration
  backend_address_pools = {
    web-pool = {
      name         = "web-pool"
      ip_addresses = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
    }
    api-pool = {
      name         = "api-pool"
      ip_addresses = ["10.0.2.10", "10.0.2.11"]
    }
  }

  backend_http_settings = {
    https-setting = {
      name     = "https-setting"
      port     = 443
      protocol = "Https"
    }
  }

  # Health Probes
  probes = {
    health-probe = {
      name     = "health-probe"
      protocol = "Https"
      path     = "/health"
      interval = 30
      timeout  = 30
    }
  }

  # Frontend Configuration
  http_listeners = {
    https-listener = {
      name                           = "https-listener"
      frontend_ip_configuration_name = "public-ip-config"
      frontend_port_name             = "https"
      protocol                       = "Https"
      ssl_certificate_name           = "wildcard-cert"
    }
  }

  # Path-based Routing
  url_path_maps = {
    path-map = {
      name                               = "path-map"
      default_backend_address_pool_name  = "web-pool"
      default_backend_http_settings_name = "https-setting"
      path_rules = [
        {
          name                       = "api-rule"
          paths                      = ["/api/*"]
          backend_address_pool_name  = "api-pool"
          backend_http_settings_name = "https-setting"
        }
      ]
    }
  }

  # Routing Rules
  request_routing_rules = {
    path-routing-rule = {
      name              = "path-routing-rule"
      http_listener_name = "https-listener"
      url_path_map_name = "path-map"
    }
  }

  # WAF Configuration
  waf_configuration = {
    enabled            = true
    firewall_mode      = "Prevention"
    rule_set_type      = "OWASP"
    rule_set_version   = "3.2"
    file_upload_limit_mb = 100
    request_body_check = true
  }

  # Auto-scaling
  autoscale_configuration = {
    min_capacity = 2
    max_capacity = 10
  }

  # Monitoring
  diagnostic_settings = {
    logs = [
      {
        category = "ApplicationGatewayAccessLog"
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
      }
    ]
  }

  # Security Policies
  enable_policy_assignments = true
  policy_assignments = {
    waf_enabled = {
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/564feb30-bf6a-4854-b4bb-0d2d2d1e6c66"
      display_name         = "Application Gateway should have WAF enabled"
    }
  }

  # Tags
  tags = {
    Environment = "prod"
    Project     = "enterprise-app"
    Security    = "high"
  }
}
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.0 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | >= 3.80.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | >= 3.80.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_application_gateway.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway) | resource |
| [azurerm_policy_assignment.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/policy_assignment) | resource |
| [azurerm_monitor_diagnostic_setting.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name) | Name of the resource group | `string` | n/a | yes |
| <a name="input_location"></a> [location](#input\_location) | Azure region for resources | `string` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | Environment name (dev, test, prod) | `string` | n/a | yes |
| <a name="input_application_gateway_name"></a> [application\_gateway\_name](#input\_application\_gateway\_name) | Name of the Application Gateway | `string` | n/a | yes |
| <a name="input_sku"></a> [sku](#input\_sku) | SKU configuration for the Application Gateway | <pre>object({<br>    name     = string<br>    tier     = string<br>    capacity = optional(number)<br>  })</pre> | n/a | yes |
| <a name="input_gateway_ip_configurations"></a> [gateway\_ip\_configurations](#input\_gateway\_ip\_configurations) | Gateway IP configurations | <pre>map(object({<br>    name      = string<br>    subnet_id = string<br>  }))</pre> | n/a | yes |
| <a name="input_frontend_ip_configurations"></a> [frontend\_ip\_configurations](#input\_frontend\_ip\_configurations) | Frontend IP configurations | <pre>map(object({<br>    name                            = string<br>    public_ip_address_id            = optional(string)<br>    private_ip_address              = optional(string)<br>    private_ip_address_allocation   = optional(string)<br>    subnet_id                       = optional(string)<br>  }))</pre> | n/a | yes |
| <a name="input_backend_address_pools"></a> [backend\_address\_pools](#input\_backend\_address\_pools) | Backend address pools configuration | <pre>map(object({<br>    name         = string<br>    ip_addresses = optional(list(string))<br>    fqdns        = optional(list(string))<br>  }))</pre> | `{}` | no |
| <a name="input_backend_http_settings"></a> [backend\_http\_settings](#input\_backend\_http\_settings) | Backend HTTP settings configuration | <pre>map(object({<br>    name                                = string<br>    port                                = number<br>    protocol                            = string<br>    cookie_based_affinity               = optional(string)<br>    affinity_cookie_name                = optional(string)<br>    path                                = optional(string)<br>    request_timeout                     = optional(number)<br>    host_name                           = optional(string)<br>    pick_host_name_from_backend_address = optional(bool)<br>    probe_name                          = optional(string)<br>    trusted_root_certificate_names      = optional(list(string))<br>  }))</pre> | `{}` | no |
| <a name="input_http_listeners"></a> [http\_listeners](#input\_http\_listeners) | HTTP listeners configuration | <pre>map(object({<br>    name                           = string<br>    frontend_ip_configuration_name = string<br>    frontend_port_name             = string<br>    protocol                       = string<br>    host_name                      = optional(string)<br>    host_names                     = optional(list(string))<br>    require_sni                    = optional(bool)<br>    ssl_certificate_name           = optional(string)<br>    ssl_profile_name               = optional(string)<br>    firewall_policy_id             = optional(string)<br>  }))</pre> | `{}` | no |
| <a name="input_request_routing_rules"></a> [request\_routing\_rules](#input\_request\_routing\_rules) | Request routing rules configuration | <pre>map(object({<br>    name                        = string<br>    http_listener_name          = string<br>    backend_address_pool_name   = optional(string)<br>    backend_http_settings_name  = optional(string)<br>    url_path_map_name           = optional(string)<br>    redirect_configuration_name = optional(string)<br>    rewrite_rule_set_name       = optional(string)<br>    priority                    = optional(number)<br>  }))</pre> | `{}` | no |
| <a name="input_frontend_ports"></a> [frontend\_ports](#input\_frontend\_ports) | Frontend ports configuration | <pre>map(object({<br>    name = string<br>    port = number<br>  }))</pre> | `{}` | no |
| <a name="input_ssl_certificates"></a> [ssl\_certificates](#input\_ssl\_certificates) | SSL certificates configuration | <pre>map(object({<br>    name              = string<br>    data              = string<br>    password          = optional(string)<br>    key_vault_secret_id = optional(string)<br>  }))</pre> | `{}` | no |
| <a name="input_probes"></a> [probes](#input\_probes) | Health probes configuration | <pre>map(object({<br>    name                                    = string<br>    protocol                                = string<br>    path                                    = string<br>    interval                                = number<br>    timeout                                 = number<br>    unhealthy_threshold                     = number<br>    pick_host_name_from_backend_http_settings = optional(bool)<br>    minimum_servers                          = optional(number)<br>    match                                   = optional(object({<br>      body        = optional(string)<br>      status_code = optional(list(string))<br>    }))<br>  }))</pre> | `{}` | no |
| <a name="input_url_path_maps"></a> [url\_path\_maps](#input\_url\_path\_maps) | URL path maps for path-based routing | <pre>map(object({<br>    name                               = string<br>    default_backend_address_pool_name  = string<br>    default_backend_http_settings_name = string<br>    default_rewrite_rule_set_name      = optional(string)<br>    path_rules                         = list(object({<br>      name                       = string<br>      paths                      = list(string)<br>      backend_address_pool_name  = string<br>      backend_http_settings_name = string<br>      rewrite_rule_set_name      = optional(string)<br>      redirect_configuration_name = optional(string)<br>    }))<br>  }))</pre> | `{}` | no |
| <a name="input_redirect_configurations"></a> [redirect\_configurations](#input\_redirect\_configurations) | Redirect configurations | <pre>map(object({<br>    name                 = string<br>    redirect_type        = string<br>    target_listener_name = optional(string)<br>    target_url           = optional(string)<br>    include_path         = optional(bool)<br>    include_query_string = optional(bool)<br>  }))</pre> | `{}` | no |
| <a name="input_rewrite_rule_sets"></a> [rewrite\_rule\_sets](#input\_rewrite\_rule\_sets) | Rewrite rule sets | <pre>map(object({<br>    name = string<br>    rewrite_rules = list(object({<br>      name          = string<br>      rule_sequence = number<br>      conditions    = optional(list(object({<br>        variable    = string<br>        pattern     = string<br>        ignore_case = optional(bool)<br>        negate      = optional(bool)<br>      })))<br>      request_header_configurations = optional(list(object({<br>        header_name  = string<br>        header_value = string<br>      })))<br>      response_header_configurations = optional(list(object({<br>        header_name  = string<br>        header_value = string<br>      })))<br>    }))<br>  }))</pre> | `{}` | no |
| <a name="input_waf_configuration"></a> [waf\_configuration](#input\_waf\_configuration) | WAF configuration | <pre>object({<br>    enabled                  = bool<br>    firewall_mode           = string<br>    rule_set_type           = string<br>    rule_set_version        = string<br>    file_upload_limit_mb    = optional(number)<br>    request_body_check      = optional(bool)<br>    max_request_body_size_kb = optional(number)<br>    disabled_rule_groups    = optional(list(object({<br>      rule_group_name = string<br>      rules           = optional(list(number))<br>    })))<br>    exclusions = optional(list(object({<br>      match_variable          = string<br>      selector_match_operator = string<br>      selector                = string<br>    })))<br>  })</pre> | `null` | no |
| <a name="input_ssl_policy"></a> [ssl\_policy](#input\_ssl\_policy) | SSL policy configuration | <pre>object({<br>    disabled_protocols   = optional(list(string))<br>    policy_type          = optional(string)<br>    policy_name          = optional(string)<br>    cipher_suites        = optional(list(string))<br>    min_protocol_version = optional(string)<br>  })</pre> | `null` | no |
| <a name="input_autoscale_configuration"></a> [autoscale\_configuration](#input\_autoscale\_configuration) | Autoscale configuration | <pre>object({<br>    min_capacity = number<br>    max_capacity = number<br>  })</pre> | `null` | no |
| <a name="input_identity"></a> [identity](#input\_identity) | Managed identity configuration | <pre>object({<br>    type         = string<br>    identity_ids = optional(list(string))<br>  })</pre> | `null` | no |
| <a name="input_zones"></a> [zones](#input\_zones) | Availability zones | `list(string)` | `[]` | no |
| <a name="input_enable_http2"></a> [enable\_http2](#input\_enable\_http2) | Enable HTTP/2 support | `bool` | `true` | no |
| <a name="input_force_firewall_policy_association"></a> [force\_firewall\_policy\_association](#input\_force\_firewall\_policy\_association) | Force firewall policy association | `bool` | `false` | no |
| <a name="input_diagnostic_settings"></a> [diagnostic\_settings](#input\_diagnostic\_settings) | Diagnostic settings configuration | <pre>object({<br>    name                           = optional(string)<br>    log_analytics_workspace_id     = optional(string)<br>    storage_account_id             = optional(string)<br>    eventhub_name                  = optional(string)<br>    eventhub_authorization_rule_id = optional(string)<br>    logs = optional(list(object({<br>      category        = string<br>      enabled         = bool<br>      retention_policy = optional(object({<br>        enabled = bool<br>        days    = number<br>      }))<br>    })))<br>    metrics = optional(list(object({<br>      category        = string<br>      enabled         = bool<br>      retention_policy = optional(object({<br>        enabled = bool<br>        days    = number<br>      }))<br>    })))<br>  })</pre> | `null` | no |
| <a name="input_enable_policy_assignments"></a> [enable\_policy\_assignments](#input\_enable\_policy\_assignments) | Enable Azure Policy assignments | `bool` | `false` | no |
| <a name="input_policy_assignments"></a> [policy\_assignments](#input\_policy\_assignments) | Azure Policy assignments | <pre>map(object({<br>    policy_definition_id = string<br>    display_name         = string<br>    description          = optional(string)<br>    parameters           = optional(string)<br>  }))</pre> | `{}` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags to apply to resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_application_gateway_id"></a> [application\_gateway\_id](#output\_application\_gateway\_id) | The ID of the Application Gateway |
| <a name="output_application_gateway_name"></a> [application\_gateway\_name](#output\_application\_gateway\_name) | The name of the Application Gateway |
| <a name="output_frontend_ip_configurations"></a> [frontend\_ip\_configurations](#output\_frontend\_ip\_configurations) | Frontend IP configurations |
| <a name="output_backend_address_pools"></a> [backend\_address\_pools](#output\_backend\_address\_pools) | Backend address pools |
| <a name="output_http_listeners"></a> [http\_listeners](#output\_http\_listeners) | HTTP listeners |
| <a name="output_request_routing_rules"></a> [request\_routing\_rules](#output\_request\_routing\_rules) | Request routing rules |
| <a name="output_resource_group_name"></a> [resource\_group\_name](#output\_resource\_group\_name) | Resource group name |
| <a name="output_location"></a> [location](#output\_location) | Azure region |

## Testing

Run the tests using Terratest:

```bash
cd modules/network/application-gateway/test
go test -v
```

## Security Features

- **Web Application Firewall (WAF)**: Protection against common web vulnerabilities
- **SSL/TLS Encryption**: Secure communication with backend services
- **Security Headers**: Automatic injection of security headers
- **Azure Policy**: Compliance with security best practices
- **Diagnostic Logging**: Comprehensive audit and monitoring capabilities

## Monitoring

The module configures:
- Application Gateway access logs
- Performance logs
- Firewall logs (when WAF is enabled)
- All available metrics
- Configurable retention policies

## Contributing

1. Follow the established patterns for enterprise modules
2. Include comprehensive tests for all features
3. Update documentation for any new features
4. Ensure backward compatibility

## License

This module is licensed under the MIT License.