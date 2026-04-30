# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    DSC v3 resource script for managing Microsoft.PowerShell.SecretStore configuration.

.DESCRIPTION
    Implements Get, Set, and Test operations for the SecretStore vault configuration.
    Requires the Microsoft.PowerShell.SecretStore module to be installed.

.PARAMETER Operation
    The DSC operation to perform: Get, Set, or Test.

.PARAMETER jsonInput
    JSON string received via pipeline containing the desired state properties.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Get', 'Set', 'Test')]
    [string]$Operation,

    [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
    [string]$jsonInput
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-DscTrace {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Error', 'Warn', 'Info', 'Debug', 'Trace')]
        [string]$Level,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Message
    )

    $trace = @{ $Level.ToLower() = $Message } | ConvertTo-Json -Compress
    $host.ui.WriteErrorLine($trace)
}

function Assert-ModuleAvailable {
    param([string]$ModuleName)

    if (-not (Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue |
              Select-Object -First 1)) {
        Write-DscTrace -Level Error -Message (
            "Required module '$ModuleName' is not installed. " +
            "Install it with: Install-Module -Name $ModuleName -Repository PSGallery -Force"
        )
        exit 1
    }
}

function Get-CurrentState {
    <#
    .SYNOPSIS
        Returns a hashtable representing the current SecretStore configuration.
    #>
    try {
        $config = Get-SecretStoreConfiguration -ErrorAction Stop
        return [ordered]@{
            authentication  = $config.Authentication.ToString()
            passwordTimeout = [int]$config.PasswordTimeout
            interaction     = $config.Interaction.ToString()
            scope           = $config.Scope.ToString()
        }
    }
    catch {
        Write-DscTrace -Level Error -Message "Failed to retrieve SecretStore configuration: $_"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

Assert-ModuleAvailable -ModuleName 'Microsoft.PowerShell.SecretStore'

try {
    Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
}
catch {
    Write-DscTrace -Level Error -Message "Failed to import Microsoft.PowerShell.SecretStore: $_"
    exit 1
}

# ---------------------------------------------------------------------------
# Parse input
# ---------------------------------------------------------------------------

$desired = $null
try {
    $desired = $jsonInput | ConvertFrom-Json -AsHashtable -ErrorAction Stop
}
catch {
    Write-DscTrace -Level Error -Message "Failed to parse JSON input: $_"
    exit 1
}

if ($null -eq $desired) {
    $desired = @{}
}

# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

switch ($Operation) {
    'Get' {
        try {
            Get-CurrentState | ConvertTo-Json -Compress
        }
        catch {
            Write-DscTrace -Level Error -Message "Get operation failed: $_"
            exit 1
        }
    }

    'Set' {
        try {
            $setParams = @{ Confirm = $false }

            if ($desired.ContainsKey('authentication'))  { $setParams['Authentication']  = $desired['authentication'] }
            if ($desired.ContainsKey('passwordTimeout')) { $setParams['PasswordTimeout'] = [int]$desired['passwordTimeout'] }
            if ($desired.ContainsKey('interaction'))     { $setParams['Interaction']     = $desired['interaction'] }
            if ($desired.ContainsKey('scope'))           { $setParams['Scope']           = $desired['scope'] }

            if ($setParams.Count -eq 1) {
                # Only Confirm was in params - nothing to change
                Write-DscTrace -Level Info -Message 'No configurable properties specified; nothing to set.'
            }
            else {
                Set-SecretStoreConfiguration @setParams -ErrorAction Stop
                Write-DscTrace -Level Info -Message 'SecretStore configuration updated successfully.'
            }

            # Return the resulting state
            Get-CurrentState | ConvertTo-Json -Compress
        }
        catch {
            Write-DscTrace -Level Error -Message "Set operation failed: $_"
            exit 1
        }
    }

    'Test' {
        try {
            $current        = Get-CurrentState
            $inDesiredState = $true

            $propertyMap = @{
                authentication  = 'authentication'
                passwordTimeout = 'passwordTimeout'
                interaction     = 'interaction'
                scope           = 'scope'
            }

            foreach ($key in $propertyMap.Keys) {
                if ($desired.ContainsKey($key)) {
                    $desiredValue = $desired[$key]
                    $currentValue = $current[$key]

                    # Normalize integer comparison
                    if ($key -eq 'passwordTimeout') {
                        $desiredValue = [int]$desiredValue
                        $currentValue = [int]$currentValue
                    }

                    if ($currentValue -ne $desiredValue) {
                        Write-DscTrace -Level Info -Message (
                            "Property '$key' is not in desired state. " +
                            "Current: '$currentValue', Desired: '$desiredValue'."
                        )
                        $inDesiredState = $false
                    }
                }
            }

            $current['_inDesiredState'] = $inDesiredState
            $current | ConvertTo-Json -Compress
        }
        catch {
            Write-DscTrace -Level Error -Message "Test operation failed: $_"
            exit 1
        }
    }
}
