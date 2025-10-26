# Azure Application Gateway Module
# Enterprise-grade Application Gateway with WAF, SSL termination, and advanced load balancing

locals {
  application_gateway_name = var.application_gateway_name != null ? var.application_gateway_name : "${var.naming_prefix}-${var.environment}-${random_string.suffix.result}"

  # Default tags
  default_tags = {
    Environment       = var.environment
    Module            = "application-gateway"
    ManagedBy         = "terraform"
    Owner             = "platform-team"
    CostCenter        = "networking"
    Confidentiality   = "internal"
    Compliance        = "sox-pci"
    Backup            = "daily"
    MaintenanceWindow = "sunday-02:00"
  }

  tags = merge(local.default_tags, var.tags)
}

# Random suffix for unique naming
resource "random_string" "suffix" {
  length  = 6
  lower   = true
  upper   = false
  numeric = true
  special = false
}

# Application Gateway
resource "azurerm_application_gateway" "main" {
  name                = local.application_gateway_name
  location            = var.location
  resource_group_name = var.resource_group_name

  # SKU Configuration
  sku {
    name     = var.sku.name
    tier     = var.sku.tier
    capacity = var.sku.capacity
  }

  # Autoscale Configuration
  dynamic "autoscale_configuration" {
    for_each = var.autoscale_configuration != null ? [1] : []
    content {
      min_capacity = var.autoscale_configuration.min_capacity
      max_capacity = var.autoscale_configuration.max_capacity
    }
  }

  # Zones
  zones = var.zones

  # Enable HTTP2
  enable_http2 = var.enable_http2

  # Gateway IP Configurations
  dynamic "gateway_ip_configuration" {
    for_each = var.gateway_ip_configurations
    content {
      name      = gateway_ip_configuration.value.name
      subnet_id = gateway_ip_configuration.value.subnet_id
    }
  }

  # Frontend IP Configurations
  dynamic "frontend_ip_configuration" {
    for_each = var.frontend_ip_configurations
    content {
      name                          = frontend_ip_configuration.value.name
      public_ip_address_id          = frontend_ip_configuration.value.public_ip_address_id
      private_ip_address            = frontend_ip_configuration.value.private_ip_address
      private_ip_address_allocation = frontend_ip_configuration.value.private_ip_address_allocation
      subnet_id                     = frontend_ip_configuration.value.subnet_id
    }
  }

  # Frontend Ports
  dynamic "frontend_port" {
    for_each = var.frontend_ports
    content {
      name = frontend_port.value.name
      port = frontend_port.value.port
    }
  }

  # SSL Certificates
  dynamic "ssl_certificate" {
    for_each = var.ssl_certificates
    content {
      name                = ssl_certificate.value.name
      key_vault_secret_id = ssl_certificate.value.key_vault_secret_id
      data                = ssl_certificate.value.data
      password            = ssl_certificate.value.password
    }
  }

  # Trusted Root Certificates
  dynamic "trusted_root_certificate" {
    for_each = var.trusted_root_certificates
    content {
      name = trusted_root_certificate.value.name
      data = trusted_root_certificate.value.data
    }
  }

  # SSL Profiles
  dynamic "ssl_profile" {
    for_each = var.ssl_profiles
    content {
      name                             = ssl_profile.value.name
      trusted_client_certificate_names = ssl_profile.value.trusted_client_certificate_names
      verify_client_cert_issuer_dn     = ssl_profile.value.verify_client_cert_issuer_dn

      dynamic "ssl_policy" {
        for_each = ssl_profile.value.ssl_policy != null ? [1] : []
        content {
          disabled_protocols   = ssl_profile.value.ssl_policy.disabled_protocols
          policy_type          = ssl_profile.value.ssl_policy.policy_type
          policy_name          = ssl_profile.value.ssl_policy.policy_name
          cipher_suites        = ssl_profile.value.ssl_policy.cipher_suites
          min_protocol_version = ssl_profile.value.ssl_policy.min_protocol_version
        }
      }


    }
  }

  # Backend Address Pools
  dynamic "backend_address_pool" {
    for_each = var.backend_address_pools
    content {
      name         = backend_address_pool.value.name
      fqdns        = backend_address_pool.value.fqdns
      ip_addresses = backend_address_pool.value.ip_addresses
    }
  }

  # Backend HTTP Settings
  dynamic "backend_http_settings" {
    for_each = var.backend_http_settings
    content {
      name                                = backend_http_settings.value.name
      cookie_based_affinity               = backend_http_settings.value.cookie_based_affinity
      affinity_cookie_name                = backend_http_settings.value.affinity_cookie_name
      path                                = backend_http_settings.value.path
      port                                = backend_http_settings.value.port
      protocol                            = backend_http_settings.value.protocol
      request_timeout                     = backend_http_settings.value.request_timeout
      host_name                           = backend_http_settings.value.host_name
      pick_host_name_from_backend_address = backend_http_settings.value.pick_host_name_from_backend_address
      probe_name                          = backend_http_settings.value.probe_name
      trusted_root_certificate_names      = backend_http_settings.value.trusted_root_certificate_names

      dynamic "connection_draining" {
        for_each = backend_http_settings.value.connection_draining != null ? [1] : []
        content {
          enabled           = backend_http_settings.value.connection_draining.enabled
          drain_timeout_sec = backend_http_settings.value.connection_draining.drain_timeout_sec
        }
      }
    }
  }

  # HTTP Listeners
  dynamic "http_listener" {
    for_each = var.http_listeners
    content {
      name                           = http_listener.value.name
      frontend_ip_configuration_name = http_listener.value.frontend_ip_configuration_name
      frontend_port_name             = http_listener.value.frontend_port_name
      protocol                       = http_listener.value.protocol
      host_name                      = http_listener.value.host_name
      host_names                     = http_listener.value.host_names
      require_sni                    = http_listener.value.require_sni
      ssl_certificate_name           = http_listener.value.ssl_certificate_name
      ssl_profile_name               = http_listener.value.ssl_profile_name
      firewall_policy_id             = http_listener.value.firewall_policy_id

      dynamic "custom_error_configuration" {
        for_each = http_listener.value.custom_error_configuration
        content {
          status_code           = custom_error_configuration.value.status_code
          custom_error_page_url = custom_error_configuration.value.custom_error_page_url
        }
      }
    }
  }

  # Request Routing Rules
  dynamic "request_routing_rule" {
    for_each = var.request_routing_rules
    content {
      name                        = request_routing_rule.value.name
      rule_type                   = request_routing_rule.value.rule_type
      http_listener_name          = request_routing_rule.value.http_listener_name
      backend_address_pool_name   = request_routing_rule.value.backend_address_pool_name
      backend_http_settings_name  = request_routing_rule.value.backend_http_settings_name
      redirect_configuration_name = request_routing_rule.value.redirect_configuration_name
      rewrite_rule_set_name       = request_routing_rule.value.rewrite_rule_set_name
      url_path_map_name           = request_routing_rule.value.url_path_map_name
      priority                    = request_routing_rule.value.priority
    }
  }

  # Probes
  dynamic "probe" {
    for_each = var.probes
    content {
      name                                      = probe.value.name
      host                                      = probe.value.host
      interval                                  = probe.value.interval
      path                                      = probe.value.path
      port                                      = probe.value.port
      protocol                                  = probe.value.protocol
      timeout                                   = probe.value.timeout
      unhealthy_threshold                       = probe.value.unhealthy_threshold
      pick_host_name_from_backend_http_settings = probe.value.pick_host_name_from_backend_http_settings
      minimum_servers                           = probe.value.minimum_servers

      dynamic "match" {
        for_each = probe.value.match != null ? [1] : []
        content {
          body        = probe.value.match.body
          status_code = probe.value.match.status_code
        }
      }
    }
  }

  # URL Path Maps
  dynamic "url_path_map" {
    for_each = var.url_path_maps
    content {
      name                                = url_path_map.value.name
      default_backend_address_pool_name   = url_path_map.value.default_backend_address_pool_name
      default_backend_http_settings_name  = url_path_map.value.default_backend_http_settings_name
      default_redirect_configuration_name = url_path_map.value.default_redirect_configuration_name
      default_rewrite_rule_set_name       = url_path_map.value.default_rewrite_rule_set_name

      dynamic "path_rule" {
        for_each = url_path_map.value.path_rules
        content {
          name                        = path_rule.value.name
          paths                       = path_rule.value.paths
          backend_address_pool_name   = path_rule.value.backend_address_pool_name
          backend_http_settings_name  = path_rule.value.backend_http_settings_name
          redirect_configuration_name = path_rule.value.redirect_configuration_name
          rewrite_rule_set_name       = path_rule.value.rewrite_rule_set_name
          firewall_policy_id          = path_rule.value.firewall_policy_id
        }
      }
    }
  }

  # Redirect Configurations
  dynamic "redirect_configuration" {
    for_each = var.redirect_configurations
    content {
      name                 = redirect_configuration.value.name
      redirect_type        = redirect_configuration.value.redirect_type
      target_listener_name = redirect_configuration.value.target_listener_name
      target_url           = redirect_configuration.value.target_url
      include_path         = redirect_configuration.value.include_path
      include_query_string = redirect_configuration.value.include_query_string
    }
  }

  # Rewrite Rule Sets
  dynamic "rewrite_rule_set" {
    for_each = var.rewrite_rule_sets
    content {
      name = rewrite_rule_set.value.name

      dynamic "rewrite_rule" {
        for_each = rewrite_rule_set.value.rewrite_rules
        content {
          name          = rewrite_rule.value.name
          rule_sequence = rewrite_rule.value.rule_sequence

          dynamic "condition" {
            for_each = rewrite_rule.value.conditions
            content {
              variable    = condition.value.variable
              pattern     = condition.value.pattern
              ignore_case = condition.value.ignore_case
              negate      = condition.value.negate
            }
          }

          dynamic "request_header_configuration" {
            for_each = rewrite_rule.value.request_header_configurations
            content {
              header_name  = request_header_configuration.value.header_name
              header_value = request_header_configuration.value.header_value
            }
          }

          dynamic "response_header_configuration" {
            for_each = rewrite_rule.value.response_header_configurations
            content {
              header_name  = response_header_configuration.value.header_name
              header_value = response_header_configuration.value.header_value
            }
          }

          dynamic "url" {
            for_each = rewrite_rule.value.url != null ? [1] : []
            content {
              path         = rewrite_rule.value.url.path
              query_string = rewrite_rule.value.url.query_string
              components   = rewrite_rule.value.url.components
              reroute      = rewrite_rule.value.url.reroute
            }
          }
        }
      }
    }
  }

  # WAF Configuration
  dynamic "waf_configuration" {
    for_each = var.waf_configuration != null ? [1] : []
    content {
      enabled                  = var.waf_configuration.enabled
      firewall_mode            = var.waf_configuration.firewall_mode
      rule_set_type            = var.waf_configuration.rule_set_type
      rule_set_version         = var.waf_configuration.rule_set_version
      file_upload_limit_mb     = var.waf_configuration.file_upload_limit_mb
      request_body_check       = var.waf_configuration.request_body_check
      max_request_body_size_kb = var.waf_configuration.max_request_body_size_kb

      dynamic "disabled_rule_group" {
        for_each = var.waf_configuration.disabled_rule_groups
        content {
          rule_group_name = disabled_rule_group.value.rule_group_name
          rules           = disabled_rule_group.value.rules
        }
      }

      dynamic "exclusion" {
        for_each = var.waf_configuration.exclusions
        content {
          match_variable          = exclusion.value.match_variable
          selector_match_operator = exclusion.value.selector_match_operator
          selector                = exclusion.value.selector
        }
      }
    }
  }

  # Firewall Policy
  firewall_policy_id = var.firewall_policy_id

  # Managed Identity
  dynamic "identity" {
    for_each = var.identity != null ? [1] : []
    content {
      type         = var.identity.type
      identity_ids = var.identity.identity_ids
    }
  }

  tags = local.tags
}

# Diagnostic Settings
resource "azurerm_monitor_diagnostic_setting" "diagnostic_settings" {
  for_each = var.diagnostic_settings

  name                       = each.value.name
  target_resource_id         = azurerm_application_gateway.main.id
  log_analytics_workspace_id = each.value.log_analytics_workspace_id

  dynamic "enabled_log" {
    for_each = each.value.logs
    content {
      category = enabled_log.value.category
    }
  }

  dynamic "metric" {
    for_each = each.value.metrics
    content {
      category = metric.value.category
      enabled  = metric.value.enabled
    }
  }
}