# Application Gateway Module Automation Script
# This script provides automation for deploying and managing Application Gateway modules

param(
    [Parameter(Mandatory = $false)]
    [string]$Action = "deploy",

    [Parameter(Mandatory = $false)]
    [string]$Environment = "dev",

    [Parameter(Mandatory = $false)]
    [string]$ModulePath = "modules\network\application-gateway",

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [switch]$SkipTests,

    [Parameter(Mandatory = $false)]
    [switch]$Cleanup
)

#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.Network

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Configuration
$script:Config = @{
    TerraformVersion = "1.5.0"
    GoVersion = "1.21"
    AzureProviderVersion = ">= 3.80.0"
    ModuleName = "application-gateway"
    TestTimeout = "30m"
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }

    # Log to file
    $logFile = Join-Path $PSScriptRoot "logs\$($script:Config.ModuleName)-automation.log"
    $logDir = Split-Path $logFile -Parent
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Add-Content -Path $logFile -Value $logMessage
}

# Validate prerequisites
function Test-Prerequisites {
    Write-Log "Validating prerequisites..."

    # Check Terraform
    try {
        $terraformVersion = terraform version | Select-String -Pattern "Terraform v(\d+\.\d+\.\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }
        if ([version]$terraformVersion -lt [version]$script:Config.TerraformVersion) {
            throw "Terraform version $terraformVersion is below required version $($script:Config.TerraformVersion)"
        }
        Write-Log "Terraform version: $terraformVersion" -Level "SUCCESS"
    }
    catch {
        Write-Log "Terraform not found or version check failed: $_" -Level "ERROR"
        throw
    }

    # Check Go
    try {
        $goVersion = go version | Select-String -Pattern "go(\d+\.\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }
        if ([version]$goVersion -lt [version]$script:Config.GoVersion) {
            throw "Go version $goVersion is below required version $($script:Config.GoVersion)"
        }
        Write-Log "Go version: $goVersion" -Level "SUCCESS"
    }
    catch {
        Write-Log "Go not found or version check failed: $_" -Level "ERROR"
        throw
    }

    # Check Azure CLI
    try {
        $azVersion = az version --query '"azure-cli"' -o tsv
        Write-Log "Azure CLI version: $azVersion" -Level "SUCCESS"
    }
    catch {
        Write-Log "Azure CLI not found: $_" -Level "ERROR"
        throw
    }

    Write-Log "Prerequisites validation completed" -Level "SUCCESS"
}

# Initialize Azure connection
function Connect-AzureSubscription {
    param([string]$SubscriptionId)

    Write-Log "Connecting to Azure..."

    try {
        if ($SubscriptionId) {
            az account set --subscription $SubscriptionId
        }

        $account = az account show | ConvertFrom-Json
        Write-Log "Connected to subscription: $($account.name) ($($account.id))" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to connect to Azure: $_" -Level "ERROR"
        throw
    }
}

# Validate Terraform configuration
function Test-TerraformConfig {
    param([string]$ModulePath)

    Write-Log "Validating Terraform configuration..."

    Push-Location $ModulePath

    try {
        # Format check
        Write-Log "Running terraform fmt check..."
        terraform fmt -check -recursive
        Write-Log "Terraform formatting check passed" -Level "SUCCESS"

        # Initialize
        Write-Log "Running terraform init..."
        terraform init -backend=false -upgrade
        Write-Log "Terraform init completed" -Level "SUCCESS"

        # Validate
        Write-Log "Running terraform validate..."
        terraform validate
        Write-Log "Terraform validation completed" -Level "SUCCESS"
    }
    catch {
        Write-Log "Terraform validation failed: $_" -Level "ERROR"
        throw
    }
    finally {
        Pop-Location
    }
}

# Run tests
function Invoke-ModuleTests {
    param([string]$ModulePath)

    if ($SkipTests) {
        Write-Log "Skipping tests as requested"
        return
    }

    Write-Log "Running module tests..."

    $testPath = Join-Path $ModulePath "test"

    Push-Location $testPath

    try {
        # Install dependencies
        Write-Log "Installing test dependencies..."
        go mod download
        go mod tidy

        # Run tests
        Write-Log "Running Go tests..."
        $testResult = go test -v -timeout $script:Config.TestTimeout 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Log "All tests passed" -Level "SUCCESS"
        }
        else {
            Write-Log "Tests failed:`n$testResult" -Level "ERROR"
            throw "Test execution failed"
        }
    }
    catch {
        Write-Log "Test execution failed: $_" -Level "ERROR"
        throw
    }
    finally {
        Pop-Location
    }
}

# Deploy example configuration
function Deploy-Example {
    param([string]$ModulePath)

    Write-Log "Deploying example configuration..."

    $examplePath = Join-Path $ModulePath "examples"

    if (!(Test-Path $examplePath)) {
        Write-Log "No examples directory found" -Level "WARNING"
        return
    }

    # For demonstration, we'll use the enterprise example
    $exampleFile = Join-Path $examplePath "enterprise-example.tf"

    if (!(Test-Path $exampleFile)) {
        Write-Log "Enterprise example not found" -Level "WARNING"
        return
    }

    Write-Log "Example deployment would require manual configuration of variables and resources"
    Write-Log "Please refer to the README.md for complete deployment instructions" -Level "WARNING"
}

# Generate documentation
function Update-Documentation {
    param([string]$ModulePath)

    Write-Log "Updating documentation..."

    try {
        # Check if terraform-docs is available
        $terraformDocs = Get-Command terraform-docs -ErrorAction SilentlyContinue
        if (!$terraformDocs) {
            Write-Log "terraform-docs not found, skipping documentation update" -Level "WARNING"
            return
        }

        Push-Location $ModulePath

        # Generate docs
        terraform-docs markdown table --output-file README.md --output-mode inject .

        Write-Log "Documentation updated" -Level "SUCCESS"
    }
    catch {
        Write-Log "Documentation update failed: $_" -Level "ERROR"
    }
    finally {
        Pop-Location
    }
}

# Clean up resources
function Remove-TestResources {
    Write-Log "Cleaning up test resources..."

    try {
        # Find resources created by tests (this is a simplified example)
        $testResources = az network application-gateway list --query "[?contains(name, 'test')].{name:name, resourceGroup:resourceGroup}" -o json | ConvertFrom-Json

        foreach ($resource in $testResources) {
            Write-Log "Removing Application Gateway: $($resource.name) in resource group: $($resource.resourceGroup)"
            az network application-gateway delete --name $resource.name --resource-group $resource.resourceGroup --yes
        }

        # Clean up resource groups created by tests
        $testRGs = az group list --query "[?contains(name, 'rg-agw-test')].name" -o json | ConvertFrom-Json

        foreach ($rg in $testRGs) {
            Write-Log "Removing resource group: $rg"
            az group delete --name $rg --yes --no-wait
        }

        Write-Log "Cleanup completed" -Level "SUCCESS"
    }
    catch {
        Write-Log "Cleanup failed: $_" -Level "ERROR"
    }
}

# Main execution
function Invoke-Main {
    Write-Log "Starting Application Gateway module automation"
    Write-Log "Action: $Action, Environment: $Environment"

    try {
        # Validate prerequisites
        Test-Prerequisites

        # Connect to Azure if needed
        if ($Action -in @("deploy", "test", "cleanup")) {
            Connect-AzureSubscription -SubscriptionId $SubscriptionId
        }

        # Execute action
        switch ($Action) {
            "validate" {
                Test-TerraformConfig -ModulePath $ModulePath
            }
            "test" {
                Test-TerraformConfig -ModulePath $ModulePath
                Invoke-ModuleTests -ModulePath $ModulePath
            }
            "deploy" {
                Test-TerraformConfig -ModulePath $ModulePath
                Invoke-ModuleTests -ModulePath $ModulePath
                Deploy-Example -ModulePath $ModulePath
            }
            "docs" {
                Update-Documentation -ModulePath $ModulePath
            }
            "cleanup" {
                Remove-TestResources
            }
            default {
                Write-Log "Unknown action: $Action" -Level "ERROR"
                Write-Log "Available actions: validate, test, deploy, docs, cleanup" -Level "ERROR"
                throw "Invalid action specified"
            }
        }

        Write-Log "Application Gateway module automation completed successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log "Automation failed: $_" -Level "ERROR"
        exit 1
    }
}

# Execute main function
Invoke-Main