package test

import (
	"testing"
	"fmt"
	"strings"

	"github.com/gruntwork-io/terratest/modules/azure"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplicationGatewayModule(t *testing.T) {
	t.Parallel()

	// Generate unique names for resources
	uniqueId := random.UniqueId()
	resourceGroupName := fmt.Sprintf("rg-agw-test-%s", uniqueId)
	appGatewayName := fmt.Sprintf("agw-test-%s", uniqueId)
	location := "East US"

	// Configure Terraform options
	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resource_group_name": resourceGroupName,
			"location":           location,
			"environment":       "test",
			"application_gateway_name": appGatewayName,
			"sku": map[string]interface{}{
				"name":     "Standard_v2",
				"tier":     "Standard_v2",
				"capacity": 1,
			},
			"gateway_ip_configurations": map[string]interface{}{
				"gateway": map[string]interface{}{
					"name":      "gateway-ip-config",
					"subnet_id": "", // Will be set by dependency
				},
			},
			"frontend_ip_configurations": map[string]interface{}{
				"public": map[string]interface{}{
					"name":                 "public-ip-config",
					"public_ip_address_id": "", // Will be set by dependency
				},
			},
			"backend_address_pools": map[string]interface{}{
				"backend-pool": map[string]interface{}{
					"name":         "backend-pool",
					"ip_addresses": []string{"10.0.1.10", "10.0.1.11"},
				},
			},
			"backend_http_settings": map[string]interface{}{
				"http-setting": map[string]interface{}{
					"name":     "http-setting",
					"port":     80,
					"protocol": "Http",
				},
			},
			"http_listeners": map[string]interface{}{
				"http-listener": map[string]interface{}{
					"name":                           "http-listener",
					"frontend_ip_configuration_name": "public-ip-config",
					"frontend_port_name":             "http",
					"protocol":                       "Http",
				},
			},
			"request_routing_rules": map[string]interface{}{
				"routing-rule": map[string]interface{}{
					"name":                       "routing-rule",
					"http_listener_name":         "http-listener",
					"backend_address_pool_name":  "backend-pool",
					"backend_http_settings_name": "http-setting",
				},
			},
			"tags": map[string]string{
				"Environment": "test",
				"Module":      "application-gateway",
			},
		},
	}

	// Clean up resources after test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy resources
	terraform.InitAndApply(t, terraformOptions)

	// Validate Application Gateway
	validateApplicationGateway(t, terraformOptions, appGatewayName, resourceGroupName)

	// Validate outputs
	validateOutputs(t, terraformOptions)
}

func TestApplicationGatewayWithWAF(t *testing.T) {
	t.Parallel()

	uniqueId := random.UniqueId()
	resourceGroupName := fmt.Sprintf("rg-agw-waf-test-%s", uniqueId)
	appGatewayName := fmt.Sprintf("agw-waf-test-%s", uniqueId)
	location := "East US"

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resource_group_name": resourceGroupName,
			"location":           location,
			"environment":       "test",
			"application_gateway_name": appGatewayName,
			"sku": map[string]interface{}{
				"name":     "WAF_v2",
				"tier":     "WAF_v2",
				"capacity": 1,
			},
			"gateway_ip_configurations": map[string]interface{}{
				"gateway": map[string]interface{}{
					"name":      "gateway-ip-config",
					"subnet_id": "", // Will be set by dependency
				},
			},
			"frontend_ip_configurations": map[string]interface{}{
				"public": map[string]interface{}{
					"name":                 "public-ip-config",
					"public_ip_address_id": "", // Will be set by dependency
				},
			},
			"backend_address_pools": map[string]interface{}{
				"backend-pool": map[string]interface{}{
					"name":         "backend-pool",
					"ip_addresses": []string{"10.0.1.10"},
				},
			},
			"backend_http_settings": map[string]interface{}{
				"https-setting": map[string]interface{}{
					"name":     "https-setting",
					"port":     443,
					"protocol": "Https",
				},
			},
			"http_listeners": map[string]interface{}{
				"https-listener": map[string]interface{}{
					"name":                           "https-listener",
					"frontend_ip_configuration_name": "public-ip-config",
					"frontend_port_name":             "https",
					"protocol":                       "Https",
					"ssl_certificate_name":           "ssl-cert",
				},
			},
			"request_routing_rules": map[string]interface{}{
				"routing-rule": map[string]interface{}{
					"name":                       "routing-rule",
					"http_listener_name":         "https-listener",
					"backend_address_pool_name":  "backend-pool",
					"backend_http_settings_name": "https-setting",
				},
			},
			"ssl_certificates": map[string]interface{}{
				"ssl-cert": map[string]interface{}{
					"name":     "ssl-cert",
					"data":     "LS0tLS1CRUdJTi...", // Base64 encoded certificate
					"password": "password123",
				},
			},
			"waf_configuration": map[string]interface{}{
				"enabled":            true,
				"firewall_mode":      "Prevention",
				"rule_set_type":      "OWASP",
				"rule_set_version":   "3.2",
				"file_upload_limit_mb": 100,
				"request_body_check": true,
				"max_request_body_size_kb": 128,
			},
			"tags": map[string]string{
				"Environment": "test",
				"Module":      "application-gateway-waf",
			},
		},
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	validateApplicationGatewayWithWAF(t, terraformOptions, appGatewayName, resourceGroupName)
}

func TestApplicationGatewayWithPathBasedRouting(t *testing.T) {
	t.Parallel()

	uniqueId := random.UniqueId()
	resourceGroupName := fmt.Sprintf("rg-agw-path-test-%s", uniqueId)
	appGatewayName := fmt.Sprintf("agw-path-test-%s", uniqueId)
	location := "East US"

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resource_group_name": resourceGroupName,
			"location":           location,
			"environment":       "test",
			"application_gateway_name": appGatewayName,
			"sku": map[string]interface{}{
				"name":     "Standard_v2",
				"tier":     "Standard_v2",
				"capacity": 1,
			},
			"gateway_ip_configurations": map[string]interface{}{
				"gateway": map[string]interface{}{
					"name":      "gateway-ip-config",
					"subnet_id": "", // Will be set by dependency
				},
			},
			"frontend_ip_configurations": map[string]interface{}{
				"public": map[string]interface{}{
					"name":                 "public-ip-config",
					"public_ip_address_id": "", // Will be set by dependency
				},
			},
			"backend_address_pools": map[string]interface{}{
				"api-pool": map[string]interface{}{
					"name":         "api-pool",
					"ip_addresses": []string{"10.0.1.10"},
				},
				"web-pool": map[string]interface{}{
					"name":         "web-pool",
					"ip_addresses": []string{"10.0.1.11"},
				},
			},
			"backend_http_settings": map[string]interface{}{
				"http-setting": map[string]interface{}{
					"name":     "http-setting",
					"port":     80,
					"protocol": "Http",
				},
			},
			"http_listeners": map[string]interface{}{
				"http-listener": map[string]interface{}{
					"name":                           "http-listener",
					"frontend_ip_configuration_name": "public-ip-config",
					"frontend_port_name":             "http",
					"protocol":                       "Http",
				},
			},
			"url_path_maps": map[string]interface{}{
				"path-map": map[string]interface{}{
					"name":                               "path-map",
					"default_backend_address_pool_name":  "web-pool",
					"default_backend_http_settings_name": "http-setting",
					"path_rules": []map[string]interface{}{
						{
							"name":                       "api-rule",
							"paths":                      []string{"/api/*"},
							"backend_address_pool_name":  "api-pool",
							"backend_http_settings_name": "http-setting",
						},
					},
				},
			},
			"request_routing_rules": map[string]interface{}{
				"path-routing-rule": map[string]interface{}{
					"name":              "path-routing-rule",
					"http_listener_name": "http-listener",
					"url_path_map_name": "path-map",
				},
			},
			"tags": map[string]string{
				"Environment": "test",
				"Module":      "application-gateway-path",
			},
		},
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	validateApplicationGatewayWithPathRouting(t, terraformOptions, appGatewayName, resourceGroupName)
}

func validateApplicationGateway(t *testing.T, terraformOptions *terraform.Options, appGatewayName, resourceGroupName string) {
	// Get Application Gateway details
	appGateway := azure.GetApplicationGateway(t, appGatewayName, resourceGroupName, "")

	// Validate basic properties
	assert.Equal(t, appGatewayName, appGateway.Name)
	assert.Equal(t, "Standard_v2", appGateway.SKU.Name)
	assert.Equal(t, "Standard_v2", appGateway.SKU.Tier)
	assert.True(t, appGateway.EnableHTTP2)
}

func validateApplicationGatewayWithWAF(t *testing.T, terraformOptions *terraform.Options, appGatewayName, resourceGroupName string) {
	appGateway := azure.GetApplicationGateway(t, appGatewayName, resourceGroupName, "")

	assert.Equal(t, appGatewayName, appGateway.Name)
	assert.Equal(t, "WAF_v2", appGateway.SKU.Name)
	assert.Equal(t, "WAF_v2", appGateway.SKU.Tier)
	assert.NotNil(t, appGateway.WebApplicationFirewallConfiguration)
	assert.True(t, appGateway.WebApplicationFirewallConfiguration.Enabled)
	assert.Equal(t, "Prevention", appGateway.WebApplicationFirewallConfiguration.FirewallMode)
}

func validateApplicationGatewayWithPathRouting(t *testing.T, terraformOptions *terraform.Options, appGatewayName, resourceGroupName string) {
	appGateway := azure.GetApplicationGateway(t, appGatewayName, resourceGroupName, "")

	assert.Equal(t, appGatewayName, appGateway.Name)
	assert.NotEmpty(t, appGateway.URLPathMaps)
	assert.NotEmpty(t, appGateway.BackendAddressPools)
}

func validateOutputs(t *testing.T, terraformOptions *terraform.Options) {
	// Validate required outputs
	appGatewayId := terraform.Output(t, terraformOptions, "application_gateway_id")
	assert.NotEmpty(t, appGatewayId)
	assert.Contains(t, appGatewayId, "Microsoft.Network/applicationGateways")

	appGatewayName := terraform.Output(t, terraformOptions, "application_gateway_name")
	assert.NotEmpty(t, appGatewayName)

	frontendIPConfigs := terraform.Output(t, terraformOptions, "frontend_ip_configurations")
	assert.NotEmpty(t, frontendIPConfigs)

	backendPools := terraform.Output(t, terraformOptions, "backend_address_pools")
	assert.NotEmpty(t, backendPools)

	httpListeners := terraform.Output(t, terraformOptions, "http_listeners")
	assert.NotEmpty(t, httpListeners)

	resourceGroupName := terraform.Output(t, terraformOptions, "resource_group_name")
	assert.NotEmpty(t, resourceGroupName)

	location := terraform.Output(t, terraformOptions, "location")
	assert.NotEmpty(t, location)
}