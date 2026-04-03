# Certificate DSC Resources

This folder contains DSC resources for managing Windows certificates.

## Resources

### Microsoft.Windows/Certificate

Manages existing certificates in the Windows certificate store - get, set, test, delete, and export operations.

### Microsoft.Windows/SelfSignedCertificate

Generates and manages self-signed certificates with configurable options.

## Requirements

- Windows operating system
- PowerShell 7.x or later
- Administrator privileges may be required for `LocalMachine` store operations

## Usage Examples

### Certificate Resource

#### Get a certificate by thumbprint

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
  - name: Get Certificate
    type: Microsoft.Windows/Certificate
    properties:
      thumbprint: "ABC123..."
      storeName: My
      storeLocation: CurrentUser
```

#### Import a PFX certificate

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
  - name: Import Certificate
    type: Microsoft.Windows/Certificate
    properties:
      pfxPath: "C:\\certs\\mycert.pfx"
      pfxPassword: "SecurePassword123"
      storeName: My
      storeLocation: LocalMachine
      friendlyName: "My Application Certificate"
      ensure: Present
```

#### Remove a certificate

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
  - name: Remove Certificate
    type: Microsoft.Windows/Certificate
    properties:
      subject: "CN=OldCert"
      storeName: My
      storeLocation: CurrentUser
      ensure: Absent
```

### SelfSignedCertificate Resource

#### Create a simple self-signed certificate

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
  - name: Create Self-Signed Cert
    type: Microsoft.Windows/SelfSignedCertificate
    properties:
      subject: "CN=MyApp.local"
      storeName: My
      storeLocation: CurrentUser
      validityInDays: 365
```

#### Create an SSL server certificate with SANs

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
  - name: SSL Certificate
    type: Microsoft.Windows/SelfSignedCertificate
    properties:
      subject: "CN=www.example.com"
      dnsNames:
        - "www.example.com"
        - "example.com"
        - "api.example.com"
      friendlyName: "Example SSL Certificate"
      certificateType: SSLServerAuthentication
      keyLength: 4096
      hashAlgorithm: SHA256
      validityInDays: 730
      storeName: My
      storeLocation: LocalMachine
      exportable: true
```

#### Create a code signing certificate

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
  - name: Code Signing Cert
    type: Microsoft.Windows/SelfSignedCertificate
    properties:
      subject: "CN=MyCompany Code Signing"
      friendlyName: "Code Signing Certificate"
      certificateType: CodeSigningCert
      keyLength: 4096
      hashAlgorithm: SHA384
      validityInDays: 365
      storeName: My
      storeLocation: CurrentUser
```

#### Create certificate with custom enhanced key usage

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
  - name: Client Auth Cert
    type: Microsoft.Windows/SelfSignedCertificate
    properties:
      subject: "CN=ClientAuth"
      certificateType: Custom
      enhancedKeyUsage:
        - ClientAuthentication
        - ServerAuthentication
      keyUsage:
        - DigitalSignature
        - KeyEncipherment
      validityInDays: 365
      storeName: My
      storeLocation: CurrentUser
```

#### Force regenerate an expired certificate

```yaml
$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
resources:
  - name: Regenerate Cert
    type: Microsoft.Windows/SelfSignedCertificate
    properties:
      subject: "CN=MyExpiredCert"
      validityInDays: 365
      force: true
      storeName: My
      storeLocation: CurrentUser
```

## Properties Reference

### Certificate Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `thumbprint` | string | No* | Certificate thumbprint (SHA1 hash) |
| `subject` | string | No* | Certificate subject name |
| `storeName` | string | Yes | Store: My, Root, CA, TrustedPublisher, TrustedPeople, AuthRoot, Disallowed |
| `storeLocation` | string | No | Location: CurrentUser (default), LocalMachine |
| `friendlyName` | string | No | Friendly display name |
| `ensure` | string | No | Desired state: Present (default), Absent |
| `pfxPath` | string | No | Path to PFX file for import |
| `pfxPassword` | string | No | Password for PFX file |
| `exportPath` | string | No | Path for certificate export |
| `exportType` | string | No | Export format: Cert (default), Pfx |

*Either `thumbprint` or `subject` is required for identifying a certificate.

### SelfSignedCertificate Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `subject` | string | Yes | Certificate subject (e.g., CN=MyApp) |
| `dnsNames` | string[] | No | Subject Alternative Names (SANs) |
| `friendlyName` | string | No | Friendly display name |
| `keyLength` | integer | No | RSA key length: 2048 (default), 4096 |
| `keyAlgorithm` | string | No | Algorithm: RSA (default), ECDSA_nistP256/384/521 |
| `hashAlgorithm` | string | No | Hash: SHA256 (default), SHA384, SHA512 |
| `validityInDays` | integer | No | Validity period in days (default: 365) |
| `certificateType` | string | No | Type: SSLServerAuthentication, CodeSigningCert, DocumentEncryptionCert, Custom |
| `enhancedKeyUsage` | string[] | No | EKU: ServerAuthentication, ClientAuthentication, CodeSigning, EmailProtection, DocumentEncryption |
| `keyUsage` | string[] | No | Key usage flags |
| `storeName` | string | No | Store name (default: My) |
| `storeLocation` | string | No | Store location (default: CurrentUser) |
| `exportable` | boolean | No | Allow private key export (default: true) |
| `force` | boolean | No | Replace existing certificate (default: false) |
| `ensure` | string | No | Desired state: Present (default), Absent |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error - operation failed |
| 2 | Certificate not found / generation failed |
| 3 | Invalid input |
| 4 | Access denied |
| 5 | Store not found |

## Security Considerations

- Avoid storing `pfxPassword` in plain text in configuration files. Use secure methods like environment variables or Azure Key Vault.
- Use `LocalMachine` store location for server certificates that need to be accessible to services running under different accounts.
- Set `exportable: false` for certificates that should never leave the machine.
- Consider using strong key lengths (4096-bit RSA or ECDSA) for production certificates.
- Self-signed certificates should only be used for development/testing. Use CA-issued certificates in production.

## Troubleshooting

### Access Denied (Exit Code 4)

- LocalMachine store requires administrator privileges
- Run PowerShell as Administrator

### Certificate Not Found (Exit Code 2)

- Verify the thumbprint or subject is correct
- Check the correct store name and location

### Invalid Input (Exit Code 3)

- Ensure required properties are provided
- Verify property values match the expected enums
