# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    DSC Resource for managing Windows certificates.

.DESCRIPTION
    This script implements Get, Set, Test, Delete, and Export operations
    for managing certificates in the Windows certificate store.

.PARAMETER Operation
    The DSC operation to perform: Get, Set, Test, Delete, or Export.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Get', 'Set', 'Test', 'Delete', 'Export')]
    [string]$Operation
)

$ErrorActionPreference = 'Stop'

function Write-DscTrace {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Error', 'Warn', 'Info', 'Debug', 'Trace')]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $trace = @{ $Level.ToLower() = $Message } | ConvertTo-Json -Compress
    $host.ui.WriteErrorLine($trace)
}

function Get-CertificateStorePath {
    param(
        [string]$StoreLocation = 'CurrentUser',
        [string]$StoreName = 'My'
    )
    return "Cert:\$StoreLocation\$StoreName"
}

function Get-CertificateInfo {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$StoreName,
        [string]$StoreLocation
    )

    $dnsNames = @()
    $ekuList = @()

    # Get DNS names from SAN extension
    $sanExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if ($sanExtension) {
        $sanString = $sanExtension.Format($false)
        if ($sanString -match 'DNS Name=([^,\r\n]+)') {
            $dnsNames = [regex]::Matches($sanString, 'DNS Name=([^,\r\n]+)') | ForEach-Object { $_.Groups[1].Value.Trim() }
        }
    }

    # Get Enhanced Key Usage
    $ekuExtension = $Certificate.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
    if ($ekuExtension) {
        $ekuList = $ekuExtension.EnhancedKeyUsages | ForEach-Object { $_.FriendlyName }
    }

    return @{
        thumbprint           = $Certificate.Thumbprint
        subject              = $Certificate.Subject
        issuer               = $Certificate.Issuer
        friendlyName         = $Certificate.FriendlyName
        notBefore            = $Certificate.NotBefore.ToString('o')
        notAfter             = $Certificate.NotAfter.ToString('o')
        hasPrivateKey        = $Certificate.HasPrivateKey
        dnsNameList          = @($dnsNames)
        enhancedKeyUsageList = @($ekuList)
        storeName            = $StoreName
        storeLocation        = $StoreLocation
    }
}

function Find-Certificate {
    param(
        [hashtable]$Input
    )

    $storePath = Get-CertificateStorePath -StoreLocation $Input.storeLocation -StoreName $Input.storeName

    if (-not (Test-Path $storePath)) {
        Write-DscTrace -Level Warn -Message "Certificate store '$storePath' not found"
        return $null
    }

    $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue

    if ($Input.thumbprint) {
        return $certs | Where-Object { $_.Thumbprint -eq $Input.thumbprint } | Select-Object -First 1
    }

    if ($Input.subject) {
        return $certs | Where-Object { $_.Subject -like "*$($Input.subject)*" } | Select-Object -First 1
    }

    return $null
}

function Invoke-GetOperation {
    param([hashtable]$InputObject)

    $cert = Find-Certificate -Input $InputObject

    if ($null -eq $cert) {
        Write-DscTrace -Level Info -Message "Certificate not found"
        return @{
            thumbprint    = $null
            storeName     = $InputObject.storeName
            storeLocation = $InputObject.storeLocation
            ensure        = 'Absent'
        }
    }

    $result = Get-CertificateInfo -Certificate $cert -StoreName $InputObject.storeName -StoreLocation $InputObject.storeLocation
    $result['ensure'] = 'Present'

    return $result
}

function Invoke-TestOperation {
    param([hashtable]$InputObject)

    $desiredEnsure = if ($InputObject.ensure) { $InputObject.ensure } else { 'Present' }
    $cert = Find-Certificate -Input $InputObject

    $currentEnsure = if ($null -eq $cert) { 'Absent' } else { 'Present' }

    $inDesiredState = $currentEnsure -eq $desiredEnsure

    if ($inDesiredState -and $currentEnsure -eq 'Present') {
        # Check additional properties if specified
        if ($InputObject.friendlyName -and $cert.FriendlyName -ne $InputObject.friendlyName) {
            $inDesiredState = $false
        }
    }

    $result = @{
        _inDesiredState = $inDesiredState
        storeName       = $InputObject.storeName
        storeLocation   = $InputObject.storeLocation
        ensure          = $currentEnsure
    }

    if ($cert) {
        $result['thumbprint'] = $cert.Thumbprint
        $result['subject'] = $cert.Subject
    }

    return $result
}

function Invoke-SetOperation {
    param([hashtable]$InputObject)

    $desiredEnsure = if ($InputObject.ensure) { $InputObject.ensure } else { 'Present' }
    $storePath = Get-CertificateStorePath -StoreLocation $InputObject.storeLocation -StoreName $InputObject.storeName

    if ($desiredEnsure -eq 'Absent') {
        $cert = Find-Certificate -Input $InputObject
        if ($cert) {
            Write-DscTrace -Level Info -Message "Removing certificate with thumbprint: $($cert.Thumbprint)"
            $cert | Remove-Item -Force
        }
        return @{
            _inDesiredState = $true
            ensure          = 'Absent'
            storeName       = $InputObject.storeName
            storeLocation   = $InputObject.storeLocation
        }
    }

    # Import certificate if PFX path is provided
    if ($InputObject.pfxPath) {
        if (-not (Test-Path $InputObject.pfxPath)) {
            Write-DscTrace -Level Error -Message "PFX file not found: $($InputObject.pfxPath)"
            exit 3
        }

        $importParams = @{
            FilePath          = $InputObject.pfxPath
            CertStoreLocation = $storePath
        }

        if ($InputObject.pfxPassword) {
            $securePassword = ConvertTo-SecureString -String $InputObject.pfxPassword -AsPlainText -Force
            $importParams['Password'] = $securePassword
        }

        Write-DscTrace -Level Info -Message "Importing certificate from: $($InputObject.pfxPath)"
        $importedCert = Import-PfxCertificate @importParams

        # Set friendly name if specified
        if ($InputObject.friendlyName) {
            $importedCert.FriendlyName = $InputObject.friendlyName
        }

        $result = Get-CertificateInfo -Certificate $importedCert -StoreName $InputObject.storeName -StoreLocation $InputObject.storeLocation
        $result['_inDesiredState'] = $true
        $result['ensure'] = 'Present'

        return $result
    }

    # If no PFX path, check if certificate already exists
    $cert = Find-Certificate -Input $InputObject
    if ($null -eq $cert) {
        Write-DscTrace -Level Error -Message "Certificate not found and no PFX file specified for import"
        exit 2
    }

    # Update friendly name if needed
    if ($InputObject.friendlyName -and $cert.FriendlyName -ne $InputObject.friendlyName) {
        $cert.FriendlyName = $InputObject.friendlyName
        Write-DscTrace -Level Info -Message "Updated friendly name to: $($InputObject.friendlyName)"
    }

    $result = Get-CertificateInfo -Certificate $cert -StoreName $InputObject.storeName -StoreLocation $InputObject.storeLocation
    $result['_inDesiredState'] = $true
    $result['ensure'] = 'Present'

    return $result
}

function Invoke-DeleteOperation {
    param([hashtable]$InputObject)

    $cert = Find-Certificate -Input $InputObject

    if ($null -eq $cert) {
        Write-DscTrace -Level Info -Message "Certificate not found, nothing to delete"
        return @{
            thumbprint    = $null
            storeName     = $InputObject.storeName
            storeLocation = $InputObject.storeLocation
            ensure        = 'Absent'
        }
    }

    $thumbprint = $cert.Thumbprint
    Write-DscTrace -Level Info -Message "Deleting certificate with thumbprint: $thumbprint"
    $cert | Remove-Item -Force

    return @{
        thumbprint    = $thumbprint
        storeName     = $InputObject.storeName
        storeLocation = $InputObject.storeLocation
        ensure        = 'Absent'
    }
}

function Invoke-ExportOperation {
    # Export all certificates from common stores
    $stores = @(
        @{ Location = 'CurrentUser'; Name = 'My' },
        @{ Location = 'LocalMachine'; Name = 'My' },
        @{ Location = 'LocalMachine'; Name = 'Root' }
    )

    $results = @()

    foreach ($store in $stores) {
        $storePath = Get-CertificateStorePath -StoreLocation $store.Location -StoreName $store.Name

        if (Test-Path $storePath) {
            $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue

            foreach ($cert in $certs) {
                $certInfo = Get-CertificateInfo -Certificate $cert -StoreName $store.Name -StoreLocation $store.Location
                $certInfo['ensure'] = 'Present'
                $results += $certInfo
            }
        }
    }

    return $results
}

# Main execution
try {
    if ($Operation -eq 'Export') {
        $results = Invoke-ExportOperation
        $results | ConvertTo-Json -Depth 10 -Compress
        exit 0
    }

    # Read input from stdin
    $jsonInput = $input | Out-String

    if ([string]::IsNullOrWhiteSpace($jsonInput)) {
        Write-DscTrace -Level Error -Message "No input provided"
        exit 3
    }

    $inputObject = $jsonInput | ConvertFrom-Json -AsHashtable

    # Set defaults
    if (-not $inputObject.storeName) { $inputObject.storeName = 'My' }
    if (-not $inputObject.storeLocation) { $inputObject.storeLocation = 'CurrentUser' }

    $result = switch ($Operation) {
        'Get' { Invoke-GetOperation -InputObject $inputObject }
        'Set' { Invoke-SetOperation -InputObject $inputObject }
        'Test' { Invoke-TestOperation -InputObject $inputObject }
        'Delete' { Invoke-DeleteOperation -InputObject $inputObject }
    }

    $result | ConvertTo-Json -Depth 10 -Compress
    exit 0
}
catch [System.Security.Cryptography.CryptographicException] {
    Write-DscTrace -Level Error -Message "Cryptographic error: $_"
    exit 4
}
catch [System.UnauthorizedAccessException] {
    Write-DscTrace -Level Error -Message "Access denied: $_"
    exit 4
}
catch {
    Write-DscTrace -Level Error -Message "Error: $_"
    exit 1
}
