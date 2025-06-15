# Certificate Authority Management Scripts

A comprehensive set of bash scripts for creating and managing Certificate Authorities (CAs) and issuing certificates in various formats. These scripts provide an enterprise-grade solution for PKI management with extensive validation, logging, and format support.

## 🚀 Quick Start

```bash
# 1. Create CA hierarchy
./create_ca.sh

# 2. Issue a certificate
./issue_certificates.sh IssuingCA1 server.example.com www.server.example.com 192.168.1.10

# 3. Test existing CA hierarchy
./create_ca.sh --test-only
```

## 📁 Project Structure

```
scripts/
├── create_ca.sh              # Main CA creation script
├── issue_certificates.sh     # Certificate issuance script
├── common_functions.sh       # Shared utility functions
├── ca_config.conf            # CA creation configuration
├── cert_config.conf          # Certificate issuance configuration
├── logs/                     # Generated log files
└── README.md                 # This file

Generated directories:
├── CertificateAuthority/     # CA hierarchy
│   ├── RootCA/              # Root Certificate Authority
│   ├── IntermediateCA1/     # Intermediate CA (3-tier chain)
│   ├── IssuingCA1/          # Issuing CA (3-tier: Root→Intermediate→Issuing)
│   └── IssuingCA2/          # Issuing CA (2-tier: Root→Issuing)
└── certificate/             # Generated certificates by CN
    └── server.example.com/  # Certificate files for specific CN
```

## 🏗️ CA Hierarchy

The scripts create a flexible PKI hierarchy:

### 3-Tier Chain (IssuingCA1)
```
RootCA → IntermediateCA1 → IssuingCA1 → End Certificates
```

### 2-Tier Chain (IssuingCA2)
```
RootCA → IssuingCA2 → End Certificates
```

**Why multiple chains?**
- **3-tier**: Maximum security, offline root CA, operational flexibility
- **2-tier**: Simplified management, faster certificate operations

## 🔧 Installation & Requirements

### Prerequisites
```bash
# Required
openssl >= 1.1.1

# Optional (for Java keystores)
java >= 8
keytool (included with Java)

# Optional (for BKS keystores)
Bouncy Castle provider JAR
```

### Installation
```bash
# Clone or download the scripts
git clone <repository-url>
cd certificate-scripts

# Make scripts executable
chmod +x *.sh

# Verify prerequisites
./create_ca.sh --help
```

## 📖 Detailed Usage

### Creating Certificate Authorities

#### Basic CA Creation
```bash
./create_ca.sh
```

#### Advanced Options
```bash
# Clean existing CAs and recreate
./create_ca.sh --clean

# Verbose logging
./create_ca.sh --verbose

# Custom configuration
./create_ca.sh --config my_ca.conf

# Skip backups
./create_ca.sh --no-backup

# Test existing hierarchy only
./create_ca.sh --test-only
```

### Issuing Certificates

#### Basic Certificate Issuance
```bash
./issue_certificates.sh <CA_NAME> <COMMON_NAME> [SANs...]
```

#### Examples
```bash
# Single domain certificate
./issue_certificates.sh IssuingCA1 server.local

# Multi-domain certificate with SANs
./issue_certificates.sh IssuingCA1 web.example.com www.example.com api.example.com

# Certificate with IP addresses
./issue_certificates.sh IssuingCA2 server.local 192.168.1.100 10.0.0.50

# Certificate with mixed SANs
./issue_certificates.sh IssuingCA1 app.local app.local.dev 127.0.0.1 ::1
```

#### Advanced Certificate Options
```bash
# Custom key size
./issue_certificates.sh --key-size 4096 IssuingCA1 secure.example.com

# Custom validity period
./issue_certificates.sh --validity-days 365 IssuingCA2 temp.example.com

# Custom configuration
./issue_certificates.sh --config my_cert.conf IssuingCA1 test.local

# Environment variable overrides
DEBUG=1 ./issue_certificates.sh IssuingCA1 debug.local
DEFAULT_PASSWORD=mypass123 ./issue_certificates.sh IssuingCA1 secure.local
```

## ⚙️ Configuration

### CA Configuration (`ca_config.conf`)

Key settings for CA creation:

```bash
# Key sizes (bits)
ROOT_KEY_SIZE=4096           # Root CA (highest security)
INTERMEDIATE_KEY_SIZE=3072   # Intermediate CA
ISSUING_KEY_SIZE=3072        # Issuing CA

# Validity periods (days)
ROOT_VALIDITY_DAYS=3650      # 10 years
INTERMEDIATE_VALIDITY_DAYS=1825  # 5 years
ISSUING_VALIDITY_DAYS=825    # ~2.25 years

# Organization details
DEFAULT_COUNTRY=CH
DEFAULT_STATE=BE
DEFAULT_ORG=DanielF
DEFAULT_OU="IT Infrastructure"

# Directories
BASE_DIR=./CertificateAuthority

# Security options
BACKUP_ON_OVERWRITE=true
VALIDATE_AFTER_CREATION=true
RUN_COMPREHENSIVE_TESTS=true
```

### Certificate Configuration (`cert_config.conf`)

Key settings for certificate issuance:

```bash
# Default certificate settings
DEFAULT_KEY_SIZE=3072
DEFAULT_VALIDITY_DAYS=825
DEFAULT_PASSWORD=changeme123

# Output directories
BASE_CA_DIR=./CertificateAuthority
CERT_OUTPUT_DIR=./certificate

# Format generation
CREATE_ALL_FORMATS=true
CREATE_PEM_FORMATS=true
CREATE_DER_FORMATS=true
CREATE_PKCS_FORMATS=true
CREATE_JAVA_FORMATS=true

# Security settings
BACKUP_EXISTING_CERTS=true
VALIDATE_AFTER_CREATION=true
SECURE_FILE_PERMISSIONS=true
```

## 📄 Generated Certificate Formats

Each certificate generation creates multiple formats for maximum compatibility:

### Private Keys
- `server.key.pem` - Unencrypted PEM private key
- `server.key.der` - Unencrypted DER private key
- `server.pwd.key.pem` - Encrypted PEM private key
- `server.pwd.key.der` - Encrypted DER private key

### Certificates
- `server.cert.pem` - Certificate (PEM format)
- `server.cert.der` - Certificate (DER format)
- `server.chain.cert.pem` - Full certificate chain (PEM)
- `server.chain.cert.der` - Full certificate chain (DER)

### Certificate Bundles
- `server.pkcs7.pem` - PKCS#7 bundle (PEM)
- `server.pkcs7.p7b` - PKCS#7 bundle (DER/P7B)
- `server.pkcs12.p12` - PKCS#12 bundle (with password)
- `server.nopass.pkcs12.p12` - PKCS#12 bundle (no password)
- `server.pfx` - PFX bundle (Windows format)

### Java Keystores (if Java available)
- `server.keystore.jks` - Java KeyStore
- `server.keystore.bks` - BKS KeyStore (with password)
- `server.nopass.keystore.bks` - BKS KeyStore (no password)

### Other Files
- `server.csr.pem` - Certificate Signing Request

## 🎯 Use Cases by Format

| Use Case | Recommended Files |
|----------|-------------------|
| **Apache/Nginx Web Server** | `*.chain.cert.pem` + `*.key.pem` |
| **Windows IIS** | `*.pfx` or `*.pkcs12.p12` |
| **Java Applications** | `*.keystore.jks` or `*.pkcs12.p12` |
| **Android Apps** | `*.keystore.bks` |
| **Email/S-MIME** | `*.pkcs12.p12` or `*.pfx` |
| **Legacy/Binary Systems** | `*.cert.der` + `*.key.der` |
| **Load Balancers** | `*.chain.cert.pem` + `*.key.pem` |
| **Docker/Containers** | `*.cert.pem` + `*.key.pem` |

## 🔍 Features

### Security Features
- **Secure key sizes**: 2048/3072/4096-bit RSA keys
- **Modern algorithms**: SHA-256 hashing, AES-256 encryption
- **Proper permissions**: Restrictive file permissions (400 for keys, 644 for certs)
- **Input validation**: Comprehensive validation of all inputs
- **Atomic operations**: Safe file operations with rollback capability

### Operational Features
- **Progress tracking**: Real-time progress bars and status updates
- **Comprehensive logging**: Detailed logs with configurable levels
- **Backup system**: Automatic backups before overwriting
- **Error handling**: Graceful error handling with recovery options
- **Testing suite**: Built-in validation and testing capabilities

### Certificate Features
- **Multiple formats**: 15+ certificate and key formats
- **SAN support**: Subject Alternative Names for multi-domain certificates
- **Chain building**: Automatic certificate chain construction
- **Validation**: Post-generation certificate validation
- **Flexibility**: Support for both 2-tier and 3-tier PKI hierarchies

## 🧪 Testing & Validation

### Built-in Tests
```bash
# Test existing CA hierarchy
./create_ca.sh --test-only

# Comprehensive CA testing includes:
# - Certificate format validation
# - Private key validation
# - Certificate-key pair matching
# - Certificate chain validation
# - Certificate extension validation
# - CA functionality testing
# - Hierarchy integrity testing
```

### Manual Validation
```bash
# Verify certificate
openssl x509 -in certificate/server.local/server.local.cert.pem -text -noout

# Verify certificate chain
openssl verify -CAfile CertificateAuthority/RootCA/certs/ca.cert.pem \
  -untrusted CertificateAuthority/IntermediateCA1/certs/ca.cert.pem \
  certificate/server.local/server.local.cert.pem

# Test certificate and key matching
openssl x509 -in certificate/server.local/server.local.cert.pem -noout -modulus | openssl md5
openssl rsa -in certificate/server.local/server.local.key.pem -noout -modulus | openssl md5
```

## 🚨 Troubleshooting

### Common Issues

#### "OpenSSL not found"
```bash
# Install OpenSSL
# Ubuntu/Debian: apt-get install openssl
# CentOS/RHEL: yum install openssl
# macOS: brew install openssl
```

#### "Java keytool not available"
```bash
# Install Java JDK
# Ubuntu/Debian: apt-get install openjdk-11-jdk
# CentOS/RHEL: yum install java-11-openjdk-devel
# macOS: brew install openjdk@11
```

#### "BKS KeyStore creation failed"
```bash
# Install Bouncy Castle provider
wget https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.70/bcprov-jdk15on-1.70.jar
sudo mv bcprov-jdk15on-1.70.jar /usr/share/java/bcprov.jar

# Update cert_config.conf
BOUNCY_CASTLE_JAR="/usr/share/java/bcprov.jar"
```

#### "Permission denied"
```bash
# Make scripts executable
chmod +x *.sh

# Check directory permissions
ls -la
```

#### "Configuration validation failed"
```bash
# Check configuration syntax
bash -n ca_config.conf
bash -n cert_config.conf

# Verify configuration values
cat ca_config.conf | grep -E "KEY_SIZE|VALIDITY|COUNTRY"
```

### Debug Mode
```bash
# Enable debug logging
DEBUG=1 ./create_ca.sh
DEBUG=1 ./issue_certificates.sh IssuingCA1 test.local

# Or set log level
LOG_LEVEL=DEBUG ./create_ca.sh
```

### Log Analysis
```bash
# View recent logs
tail -f scripts/logs/ca_creation_*.log
tail -f scripts/logs/cert_issuance_*.log

# Search for errors
grep -i error scripts/logs/*.log
grep -i warning scripts/logs/*.log
```

## 🔒 Security Considerations

### Production Deployment
1. **Secure the Root CA**: Keep root CA offline and in secure storage
2. **Regular backups**: Backup CA hierarchy and configurations
3. **Access control**: Restrict access to CA private keys
4. **Monitor usage**: Log and monitor certificate issuance
5. **Certificate lifecycle**: Implement certificate renewal and revocation

### Key Management
- Root CA keys should be stored offline
- Intermediate CA keys should be in HSMs when possible
- Regular key rotation for issuing CAs
- Secure key backup and recovery procedures

### Certificate Policies
- Implement certificate policies and practices statements
- Regular security audits of PKI infrastructure
- Certificate transparency logging for public certificates
- Proper certificate validation in applications

## 📚 Additional Resources

### OpenSSL Documentation
- [OpenSSL Manual](https://www.openssl.org/docs/)
- [OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/)

### PKI Best Practices
- [RFC 5280 - Internet X.509 PKI Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
- [NIST SP 800-57 - Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

### Certificate Formats
- [PKCS Standards](https://en.wikipedia.org/wiki/PKCS)
- [X.509 Certificate Format](https://en.wikipedia.org/wiki/X.509)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files in `scripts/logs/`
3. Enable debug mode for detailed output
4. Open an issue with relevant log excerpts