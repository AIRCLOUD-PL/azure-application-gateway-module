variable "application_gateway_name" {
  description = "Name of the Application Gateway. If null, will be auto-generated."
  type        = string
  default     = null
}

variable "naming_prefix" {
  description = "Prefix for Application Gateway naming"
  type        = string
  default     = "agw"
}

variable "environment" {
  description = "Environment name (e.g., prod, dev, test)"
  type        = string
}

variable "location" {
  description = "Azure region where resources will be created"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "sku" {
  description = "SKU configuration for the Application Gateway"
  type = object({
    name     = string
    tier     = string
    capacity = optional(number, 2)
  })
  default = {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }
}

variable "zones" {
  description = "Availability zones for the Application Gateway"
  type        = list(string)
  default     = []
}

variable "enable_http2" {
  description = "Enable HTTP/2 protocol"
  type        = bool
  default     = true
}

variable "autoscale_configuration" {
  description = "Autoscale configuration for the Application Gateway"
  type = object({
    min_capacity = number
    max_capacity = number
  })
  default = null
}

variable "gateway_ip_configurations" {
  description = "IP configurations for the Application Gateway"
  type = map(object({
    name      = string
    subnet_id = string
    primary   = optional(bool, false)
  }))
}

variable "frontend_ip_configurations" {
  description = "Frontend IP configurations"
  type = map(object({
    name                          = string
    public_ip_address_id          = optional(string)
    private_ip_address            = optional(string)
    subnet_id                     = optional(string)
    private_ip_address_allocation = optional(string, "Dynamic")
  }))
}

variable "frontend_ports" {
  description = "Frontend ports configuration"
  type = map(object({
    name = string
    port = number
  }))
  default = {
    "http" = {
      name = "http"
      port = 80
    }
    "https" = {
      name = "https"
      port = 443
    }
  }
}

variable "ssl_certificates" {
  description = "SSL certificates configuration"
  type = map(object({
    name                = string
    key_vault_secret_id = optional(string)
    data                = optional(string)
    password            = optional(string)
  }))
  default = {}
}

variable "trusted_root_certificates" {
  description = "Trusted root certificates for backend authentication"
  type = map(object({
    name = string
    data = string
  }))
  default = {}
}

variable "ssl_profiles" {
  description = "SSL profiles for custom SSL/TLS policies"
  type = map(object({
    name                             = string
    trusted_client_certificate_names = optional(list(string), [])
    verify_client_cert_issuer_dn     = optional(bool, false)
    ssl_policy = optional(object({
      disabled_protocols   = optional(list(string), [])
      policy_type          = optional(string, "Predefined")
      policy_name          = optional(string, "AppGwSslPolicy20170401S")
      cipher_suites        = optional(list(string), [])
      min_protocol_version = optional(string, "TLSv1_2")
    }))
    client_auth_configuration = optional(object({
      verify_client_cert_issuer_dn         = bool
      verify_client_certificate_revocation = string
    }))
  }))
  default = {}
}

variable "backend_address_pools" {
  description = "Backend address pools configuration"
  type = map(object({
    name         = string
    fqdns        = optional(list(string), [])
    ip_addresses = optional(list(string), [])
  }))
}

variable "backend_http_settings" {
  description = "Backend HTTP settings configuration"
  type = map(object({
    name                                = string
    cookie_based_affinity               = optional(string, "Disabled")
    affinity_cookie_name                = optional(string)
    path                                = optional(string)
    port                                = number
    protocol                            = string
    request_timeout                     = optional(number, 30)
    host_name                           = optional(string)
    pick_host_name_from_backend_address = optional(bool, false)
    probe_name                          = optional(string)
    trusted_root_certificate_names      = optional(list(string), [])
    connection_draining = optional(object({
      enabled           = bool
      drain_timeout_sec = number
    }))
  }))
}

variable "http_listeners" {
  description = "HTTP listeners configuration"
  type = map(object({
    name                           = string
    frontend_ip_configuration_name = string
    frontend_port_name             = string
    protocol                       = string
    host_name                      = optional(string)
    host_names                     = optional(list(string), [])
    require_sni                    = optional(bool, false)
    ssl_certificate_name           = optional(string)
    ssl_profile_name               = optional(string)
    firewall_policy_id             = optional(string)
    custom_error_configuration = optional(list(object({
      status_code           = string
      custom_error_page_url = string
    })), [])
  }))
}

variable "request_routing_rules" {
  description = "Request routing rules configuration"
  type = map(object({
    name                        = string
    rule_type                   = optional(string, "Basic")
    http_listener_name          = string
    backend_address_pool_name   = optional(string)
    backend_http_settings_name  = optional(string)
    redirect_configuration_name = optional(string)
    rewrite_rule_set_name       = optional(string)
    url_path_map_name           = optional(string)
    priority                    = optional(number)
  }))
}

variable "probes" {
  description = "Health probes configuration"
  type = map(object({
    name                                      = string
    host                                      = optional(string)
    interval                                  = optional(number, 30)
    path                                      = string
    port                                      = optional(number)
    protocol                                  = string
    timeout                                   = optional(number, 30)
    unhealthy_threshold                       = optional(number, 3)
    pick_host_name_from_backend_http_settings = optional(bool, false)
    minimum_servers                           = optional(number, 0)
    match = optional(object({
      body        = optional(string)
      status_code = optional(list(string), ["200-399"])
    }))
  }))
  default = {}
}

variable "url_path_maps" {
  description = "URL path maps for advanced routing"
  type = map(object({
    name                                = string
    default_backend_address_pool_name   = optional(string)
    default_backend_http_settings_name  = optional(string)
    default_redirect_configuration_name = optional(string)
    default_rewrite_rule_set_name       = optional(string)
    path_rules = optional(list(object({
      name                        = string
      paths                       = list(string)
      backend_address_pool_name   = optional(string)
      backend_http_settings_name  = optional(string)
      redirect_configuration_name = optional(string)
      rewrite_rule_set_name       = optional(string)
      firewall_policy_id          = optional(string)
    })), [])
  }))
  default = {}
}

variable "redirect_configurations" {
  description = "Redirect configurations"
  type = map(object({
    name                 = string
    redirect_type        = string
    target_listener_name = optional(string)
    target_url           = optional(string)
    include_path         = optional(bool, true)
    include_query_string = optional(bool, true)
  }))
  default = {}
}

variable "rewrite_rule_sets" {
  description = "Rewrite rule sets"
  type = map(object({
    name = string
    rewrite_rules = optional(list(object({
      name          = string
      rule_sequence = number
      conditions = optional(list(object({
        variable    = string
        pattern     = string
        ignore_case = optional(bool, false)
        negate      = optional(bool, false)
      })), [])
      request_header_configurations = optional(list(object({
        header_name  = string
        header_value = string
      })), [])
      response_header_configurations = optional(list(object({
        header_name  = string
        header_value = string
      })), [])
      url = optional(object({
        path         = optional(string)
        query_string = optional(string)
        components   = optional(string)
        reroute      = optional(bool, false)
      }))
    })), [])
  }))
  default = {}
}

variable "waf_configuration" {
  description = "Web Application Firewall configuration"
  type = object({
    enabled          = bool
    firewall_mode    = string
    rule_set_type    = optional(string, "OWASP")
    rule_set_version = optional(string, "3.2")
    disabled_rule_groups = optional(list(object({
      rule_group_name = string
      rules           = optional(list(string), [])
    })), [])
    exclusions = optional(list(object({
      match_variable          = string
      selector_match_operator = optional(string)
      selector                = optional(string)
    })), [])
    file_upload_limit_mb     = optional(number, 100)
    request_body_check       = optional(bool, true)
    max_request_body_size_kb = optional(number, 128)
  })
  default = null
}

variable "firewall_policy_id" {
  description = "ID of the Web Application Firewall policy"
  type        = string
  default     = null
}

variable "identity" {
  description = "Managed identity configuration"
  type = object({
    type         = string
    identity_ids = optional(list(string), [])
  })
  default = null
}

variable "diagnostic_settings" {
  description = "Diagnostic settings configurations"
  type = map(object({
    name                       = string
    log_analytics_workspace_id = string
    logs = list(object({
      category = string
    }))
    metrics = list(object({
      category = string
      enabled  = bool
    }))
  }))
  default = {}
}

variable "enable_policy_assignments" {
  description = "Enable Azure Policy assignments for Application Gateway security"
  type        = bool
  default     = false
}

variable "enable_custom_policies" {
  description = "Enable custom Azure Policy definitions"
  type        = bool
  default     = false
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics Workspace ID for diagnostic settings"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}