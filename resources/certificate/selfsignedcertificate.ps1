# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    DSC Resource for generating and managing self-signed certificates.

.DESCRIPTION
    This script implements Get, Set, Test, and Delete operations
    for creating and managing self-signed certificates in Windows.

.PARAMETER Operation
    The DSC operation to perform: Get, Set, Test, or Delete.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Get', 'Set', 'Test', 'Delete')]
    [string]$Operation
)

$ErrorActionPreference = 'Stop'
$DebugPreference = 'Continue'

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
        if ($sanString -match 'DNS Name=') {
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
        friendlyName         = $Certificate.FriendlyName
        notBefore            = $Certificate.NotBefore.ToString('o')
        notAfter             = $Certificate.NotAfter.ToString('o')
        hasPrivateKey        = $Certificate.HasPrivateKey
        dnsNames             = @($dnsNames)
        enhancedKeyUsage     = @($ekuList)
        storeName            = $StoreName
        storeLocation        = $StoreLocation
    }
}

function Find-CertificateBySubject {
    param(
        [hashtable]$Input
    )

    $storePath = Get-CertificateStorePath -StoreLocation $Input.storeLocation -StoreName $Input.storeName

    if (-not (Test-Path $storePath)) {
        return $null
    }

    $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue

    # Find by subject
    $subject = $Input.subject
    if (-not $subject.StartsWith('CN=')) {
        $subject = "CN=$subject"
    }

    return $certs | Where-Object { $_.Subject -eq $subject -or $_.Subject -like "*$($Input.subject)*" } | Select-Object -First 1
}

function Get-EnhancedKeyUsageOid {
    param([string]$Name)

    $oidMap = @{
        'ServerAuthentication' = '1.3.6.1.5.5.7.3.1'
        'ClientAuthentication' = '1.3.6.1.5.5.7.3.2'
        'CodeSigning'          = '1.3.6.1.5.5.7.3.3'
        'EmailProtection'      = '1.3.6.1.5.5.7.3.4'
        'DocumentEncryption'   = '1.3.6.1.4.1.311.80.1'
    }

    if ($oidMap.ContainsKey($Name)) {
        return $oidMap[$Name]
    }

    return $Name
}

function Invoke-GetOperation {
    param([hashtable]$InputObject)

    $cert = Find-CertificateBySubject -Input $InputObject

    if ($null -eq $cert) {
        Write-Debug "Self-signed certificate not found for subject: $($InputObject.subject)"
        return @{
            subject       = $InputObject.subject
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
    $cert = Find-CertificateBySubject -Input $InputObject

    $currentEnsure = if ($null -eq $cert) { 'Absent' } else { 'Present' }

    $inDesiredState = $currentEnsure -eq $desiredEnsure

    # Additional checks for Present state
    if ($inDesiredState -and $currentEnsure -eq 'Present') {
        # Check if certificate is expired or about to expire
        if ($cert.NotAfter -lt (Get-Date)) {
            Write-Debug "Certificate is expired"
            if (-not $InputObject.force) {
                $inDesiredState = $false
            }
        }

        # Check DNS names if specified
        if ($InputObject.dnsNames -and $InputObject.dnsNames.Count -gt 0) {
            $sanExtension = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
            if ($sanExtension) {
                $sanString = $sanExtension.Format($false)
                foreach ($dns in $InputObject.dnsNames) {
                    if ($sanString -notmatch [regex]::Escape($dns)) {
                        Write-Debug "DNS name '$dns' not found in certificate SAN"
                        $inDesiredState = $false
                        break
                    }
                }
            }
            else {
                $inDesiredState = $false
            }
        }
    }

    $result = @{
        _inDesiredState = $inDesiredState
        subject         = $InputObject.subject
        storeName       = $InputObject.storeName
        storeLocation   = $InputObject.storeLocation
        ensure          = $currentEnsure
    }

    if ($cert) {
        $result['thumbprint'] = $cert.Thumbprint
        $result['notAfter'] = $cert.NotAfter.ToString('o')
        $result['notBefore'] = $cert.NotBefore.ToString('o')
    }

    return $result
}

function Invoke-SetOperation {
    param([hashtable]$InputObject)

    $desiredEnsure = if ($InputObject.ensure) { $InputObject.ensure } else { 'Present' }
    $storePath = Get-CertificateStorePath -StoreLocation $InputObject.storeLocation -StoreName $InputObject.storeName

    # Handle Absent state
    if ($desiredEnsure -eq 'Absent') {
        $cert = Find-CertificateBySubject -Input $InputObject
        if ($cert) {
            Write-Debug "Removing certificate with subject: $($cert.Subject)"
            $cert | Remove-Item -Force
        }
        return @{
            _inDesiredState = $true
            subject         = $InputObject.subject
            ensure          = 'Absent'
            storeName       = $InputObject.storeName
            storeLocation   = $InputObject.storeLocation
        }
    }

    # Check if certificate exists and if we should regenerate
    $existingCert = Find-CertificateBySubject -Input $InputObject
    if ($existingCert) {
        if ($InputObject.force) {
            Write-Debug "Force flag set - removing existing certificate"
            $existingCert | Remove-Item -Force
        }
        else {
            # Certificate exists and force is not set - check if it's still valid
            if ($existingCert.NotAfter -gt (Get-Date)) {
                Write-Debug "Certificate already exists and is valid"
                $result = Get-CertificateInfo -Certificate $existingCert -StoreName $InputObject.storeName -StoreLocation $InputObject.storeLocation
                $result['_inDesiredState'] = $true
                $result['ensure'] = 'Present'
                return $result
            }
            else {
                Write-Debug "Certificate is expired - regenerating"
                $existingCert | Remove-Item -Force
            }
        }
    }

    # Build New-SelfSignedCertificate parameters
    $subject = $InputObject.subject
    if (-not $subject.StartsWith('CN=')) {
        $subject = "CN=$subject"
    }

    $certParams = @{
        Subject           = $subject
        CertStoreLocation = $storePath
    }

    # DNS names (Subject Alternative Names)
    if ($InputObject.dnsNames -and $InputObject.dnsNames.Count -gt 0) {
        $certParams['DnsName'] = $InputObject.dnsNames
    }

    # Friendly name
    if ($InputObject.friendlyName) {
        $certParams['FriendlyName'] = $InputObject.friendlyName
    }

    # Validity period
    $validityDays = if ($InputObject.validityInDays) { $InputObject.validityInDays } else { 365 }
    $notBefore = if ($InputObject.notBefore) { [DateTime]::Parse($InputObject.notBefore) } else { Get-Date }
    $notAfter = $notBefore.AddDays($validityDays)
    $certParams['NotBefore'] = $notBefore
    $certParams['NotAfter'] = $notAfter

    # Key algorithm and length
    $keyAlgorithm = if ($InputObject.keyAlgorithm) { $InputObject.keyAlgorithm } else { 'RSA' }
    if ($keyAlgorithm -eq 'RSA') {
        $keyLength = if ($InputObject.keyLength) { $InputObject.keyLength } else { 2048 }
        $certParams['KeyLength'] = $keyLength
        $certParams['KeyAlgorithm'] = 'RSA'
    }
    else {
        # ECDSA algorithms
        $certParams['KeyAlgorithm'] = $keyAlgorithm
    }

    # Hash algorithm
    $hashAlgorithm = if ($InputObject.hashAlgorithm) { $InputObject.hashAlgorithm } else { 'SHA256' }
    $certParams['HashAlgorithm'] = $hashAlgorithm

    # Key exportability
    $exportable = if ($null -ne $InputObject.exportable) { $InputObject.exportable } else { $true }
    if ($exportable) {
        $certParams['KeyExportPolicy'] = 'Exportable'
    }
    else {
        $certParams['KeyExportPolicy'] = 'NonExportable'
    }

    # Key usage
    if ($InputObject.keyUsage -and $InputObject.keyUsage.Count -gt 0) {
        $certParams['KeyUsage'] = $InputObject.keyUsage
    }
    else {
        $certParams['KeyUsage'] = @('DigitalSignature', 'KeyEncipherment')
    }

    # Key spec
    $keySpec = if ($InputObject.keySpec) { $InputObject.keySpec } else { 'KeyExchange' }
    $certParams['KeySpec'] = $keySpec

    # Certificate type (predefined templates)
    $certType = if ($InputObject.certificateType) { $InputObject.certificateType } else { 'SSLServerAuthentication' }
    if ($certType -ne 'Custom') {
        $certParams['Type'] = $certType
    }

    # Enhanced key usage
    if ($InputObject.enhancedKeyUsage -and $InputObject.enhancedKeyUsage.Count -gt 0) {
        $ekuOids = $InputObject.enhancedKeyUsage | ForEach-Object { Get-EnhancedKeyUsageOid -Name $_ }
        $certParams['TextExtension'] = @("2.5.29.37={text}$($ekuOids -join ',')")
    }

    # Provider
    if ($InputObject.provider) {
        $certParams['Provider'] = $InputObject.provider
    }

    Write-Debug "Creating self-signed certificate with subject: $subject"
    Write-Debug "Certificate parameters: $($certParams | ConvertTo-Json -Compress)"

    try {
        $newCert = New-SelfSignedCertificate @certParams
        Write-Debug "Certificate created with thumbprint: $($newCert.Thumbprint)"

        $result = Get-CertificateInfo -Certificate $newCert -StoreName $InputObject.storeName -StoreLocation $InputObject.storeLocation
        $result['_inDesiredState'] = $true
        $result['ensure'] = 'Present'

        return $result
    }
    catch {
        Write-Debug "Failed to create certificate: $_"
        exit 2
    }
}

function Invoke-DeleteOperation {
    param([hashtable]$InputObject)

    $cert = Find-CertificateBySubject -Input $InputObject

    if ($null -eq $cert) {
        Write-Debug "Certificate not found, nothing to delete"
        return @{
            subject       = $InputObject.subject
            thumbprint    = $null
            storeName     = $InputObject.storeName
            storeLocation = $InputObject.storeLocation
            ensure        = 'Absent'
        }
    }

    $thumbprint = $cert.Thumbprint
    $subject = $cert.Subject
    Write-Debug "Deleting certificate: $subject (Thumbprint: $thumbprint)"
    $cert | Remove-Item -Force

    return @{
        subject       = $subject
        thumbprint    = $thumbprint
        storeName     = $InputObject.storeName
        storeLocation = $InputObject.storeLocation
        ensure        = 'Absent'
    }
}

# Main execution
try {
    # Read input from stdin
    $jsonInput = $input | Out-String

    if ([string]::IsNullOrWhiteSpace($jsonInput)) {
        Write-Debug "No input provided"
        exit 3
    }

    $inputObject = $jsonInput | ConvertFrom-Json -AsHashtable

    # Validate required fields
    if (-not $inputObject.subject) {
        Write-Debug "Subject is required"
        exit 3
    }

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
    Write-Debug "Cryptographic error: $_"
    exit 2
}
catch [System.UnauthorizedAccessException] {
    Write-Debug "Access denied: $_"
    exit 4
}
catch {
    Write-Debug "Error: $_"
    exit 1
}
