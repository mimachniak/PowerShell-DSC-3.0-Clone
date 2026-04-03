# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Tests for Certificate DSC resources.

.DESCRIPTION
    Pester tests to verify Certificate and SelfSignedCertificate DSC resources.
#>

Describe 'Certificate DSC Resource Tests' {
    BeforeAll {
        $script:resourcePath = $PSScriptRoot
    }

    Context 'Certificate Resource - certificate.ps1' {
        It 'Should return empty result for non-existent certificate' {
            $input = @{
                thumbprint    = 'NONEXISTENT000000000000000000000000000000'
                storeName     = 'My'
                storeLocation = 'CurrentUser'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\certificate.ps1" Get | ConvertFrom-Json

            $result.ensure | Should -Be 'Absent'
            $result.thumbprint | Should -BeNullOrEmpty
        }

        It 'Should test non-existent certificate as not in desired state for Present' {
            $input = @{
                subject       = 'CN=NonExistent-DSC-Test-Cert'
                storeName     = 'My'
                storeLocation = 'CurrentUser'
                ensure        = 'Present'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\certificate.ps1" Test | ConvertFrom-Json

            $result._inDesiredState | Should -BeFalse
        }

        It 'Should test non-existent certificate as in desired state for Absent' {
            $input = @{
                subject       = 'CN=NonExistent-DSC-Test-Cert'
                storeName     = 'My'
                storeLocation = 'CurrentUser'
                ensure        = 'Absent'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\certificate.ps1" Test | ConvertFrom-Json

            $result._inDesiredState | Should -BeTrue
        }

        It 'Should export certificates from store' {
            $result = & "$script:resourcePath\certificate.ps1" Export | ConvertFrom-Json

            # Export should return an array (might be empty)
            $result | Should -Not -BeNullOrEmpty -Because 'Export should return results array'
        }
    }

    Context 'SelfSignedCertificate Resource - selfsignedcertificate.ps1' {
        BeforeAll {
            $script:testSubject = "CN=DSC-Test-SelfSigned-$(Get-Random)"
        }

        AfterAll {
            # Cleanup: Remove test certificate if it exists
            $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq $script:testSubject }
            if ($cert) {
                $cert | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Should return Absent for non-existent self-signed certificate' {
            $input = @{
                subject       = $script:testSubject
                storeName     = 'My'
                storeLocation = 'CurrentUser'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\selfsignedcertificate.ps1" Get | ConvertFrom-Json

            $result.ensure | Should -Be 'Absent'
        }

        It 'Should create self-signed certificate' {
            $input = @{
                subject        = $script:testSubject
                friendlyName   = 'DSC Test Certificate'
                validityInDays = 30
                storeName      = 'My'
                storeLocation  = 'CurrentUser'
                ensure         = 'Present'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\selfsignedcertificate.ps1" Set | ConvertFrom-Json

            $result.ensure | Should -Be 'Present'
            $result.thumbprint | Should -Not -BeNullOrEmpty
            $result._inDesiredState | Should -BeTrue
        }

        It 'Should find created certificate' {
            $input = @{
                subject       = $script:testSubject
                storeName     = 'My'
                storeLocation = 'CurrentUser'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\selfsignedcertificate.ps1" Get | ConvertFrom-Json

            $result.ensure | Should -Be 'Present'
            $result.thumbprint | Should -Not -BeNullOrEmpty
        }

        It 'Should test existing certificate as in desired state' {
            $input = @{
                subject       = $script:testSubject
                storeName     = 'My'
                storeLocation = 'CurrentUser'
                ensure        = 'Present'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\selfsignedcertificate.ps1" Test | ConvertFrom-Json

            $result._inDesiredState | Should -BeTrue
        }

        It 'Should delete the test certificate' {
            $input = @{
                subject       = $script:testSubject
                storeName     = 'My'
                storeLocation = 'CurrentUser'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\selfsignedcertificate.ps1" Delete | ConvertFrom-Json

            $result.ensure | Should -Be 'Absent'
        }

        It 'Should verify certificate is deleted' {
            $input = @{
                subject       = $script:testSubject
                storeName     = 'My'
                storeLocation = 'CurrentUser'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\selfsignedcertificate.ps1" Get | ConvertFrom-Json

            $result.ensure | Should -Be 'Absent'
        }
    }

    Context 'SelfSignedCertificate with DNS Names' {
        BeforeAll {
            $script:testSubjectSAN = "CN=DSC-Test-SAN-$(Get-Random)"
        }

        AfterAll {
            $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq $script:testSubjectSAN }
            if ($cert) {
                $cert | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Should create certificate with DNS SANs' {
            $input = @{
                subject        = $script:testSubjectSAN
                dnsNames       = @('www.example.local', 'api.example.local')
                validityInDays = 30
                storeName      = 'My'
                storeLocation  = 'CurrentUser'
            } | ConvertTo-Json

            $result = $input | & "$script:resourcePath\selfsignedcertificate.ps1" Set | ConvertFrom-Json

            $result.ensure | Should -Be 'Present'
            $result.dnsNames | Should -Contain 'www.example.local'
        }

        It 'Should cleanup SAN test certificate' {
            $input = @{
                subject       = $script:testSubjectSAN
                storeName     = 'My'
                storeLocation = 'CurrentUser'
            } | ConvertTo-Json

            $null = $input | & "$script:resourcePath\selfsignedcertificate.ps1" Delete
        }
    }
}
