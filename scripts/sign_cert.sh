#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# Certificate Signing Script
# =============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/ca_config.conf"
readonly CA_BASE_DIR="./CertificateAuthority"
readonly CERT_BASE_DIR="./Certificates"

# Global variables
VERBOSE_MODE=false
DEBUG_MODE=false
CN=""
SANS=()
PASSWORD=""
KEY_SIZE=3072
VALIDITY_DAYS=365

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log_info() { echo -e "${BLUE}ℹ️  INFO:${NC} $1"; }
log_success() { echo -e "${GREEN}✅ SUCCESS:${NC} $1"; }
log_error() { echo -e "${RED}❌ ERROR:${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠️  WARNING:${NC} $1"; }

show_usage() {
    cat << EOF
Certificate Signing Script

Usage: $0 [OPTIONS] --cn COMMON_NAME [--san SAN1] [--san SAN2] ...

Required Arguments:
  --cn COMMON_NAME     Common Name for the certificate

Optional Arguments:
  --san SAN            Subject Alternative Name (IP or FQDN, can be used multiple times)
  --password PASSWORD  Private key password (if not provided, will prompt)
  --key-size SIZE      RSA key size in bits (default: 3072)
  --validity DAYS      Certificate validity in days (default: 365)
  -v, --verbose        Enable verbose output
  -d, --debug          Enable debug output
  -h, --help           Show this help message

Examples:
  $0 --cn "web.example.com" --san "192.168.1.100" --san "www.example.com"
  $0 --cn "api.company.com" --san "10.0.0.50" --san "api-internal.company.com" --password "mypass123"
  $0 --cn "mail.domain.org" --validity 730 --key-size 4096
EOF
}

# =============================================================================
# CONFIGURATION LOADING
# =============================================================================

load_ca_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "CA configuration file not found: $CONFIG_FILE"
        log_error "Please run the CA creation script first"
        exit 1
    fi
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Loading CA configuration from: $CONFIG_FILE"
    fi
    
    source "$CONFIG_FILE"
    log_success "CA configuration loaded"
}

# =============================================================================
# INPUT VALIDATION
# =============================================================================

validate_inputs() {
    if [[ -z "$CN" ]]; then
        log_error "Common Name (--cn) is required"
        exit 1
    fi
    
    # Validate SANs
    for san in "${SANS[@]}"; do
        if [[ ! "$san" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && [[ ! "$san" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$ ]]; then
            log_error "Invalid SAN format: $san"
            exit 1
        fi
    done
    
    # Prompt for password if not provided
    if [[ -z "$PASSWORD" ]]; then
        echo -n "Enter private key password (or press Enter for no password): "
        read -s PASSWORD
        echo
    fi
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} CN: $CN"
        echo -e "${YELLOW}🐛 DEBUG:${NC} SANs: ${SANS[*]}"
        echo -e "${YELLOW}🐛 DEBUG:${NC} Key size: $KEY_SIZE"
        echo -e "${YELLOW}🐛 DEBUG:${NC} Validity: $VALIDITY_DAYS days"
    fi
}

# =============================================================================
# DIRECTORY SETUP
# =============================================================================

setup_certificate_directory() {
    local cert_dir="$CERT_BASE_DIR/$CN"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Certificate directory: $cert_dir" >&2
    fi
    
    mkdir -p "$cert_dir"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Created directory: $cert_dir" >&2
    fi
    
    echo "$cert_dir"
}

# =============================================================================
# OPENSSL CONFIG GENERATION
# =============================================================================

generate_openssl_config() {
    local config_file="$1"
    local cn="$2"
    local sans=("${@:3}")
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Generating OpenSSL config: $config_file" >&2
        echo -e "${YELLOW}🐛 DEBUG:${NC} CN: $cn" >&2
        echo -e "${YELLOW}🐛 DEBUG:${NC} SANs: ${sans[*]}" >&2
    fi
    
    local san_section=""
    local san_counter=1
    
    # Add CN as first SAN
    san_section="DNS.${san_counter} = $cn"
    ((san_counter++))
    
    # Add additional SANs
    for san in "${sans[@]}"; do
        if [[ "$san" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # IP address
            san_section="${san_section}\nIP.${san_counter} = $san"
        else
            # DNS name
            san_section="${san_section}\nDNS.${san_counter} = $san"
        fi
        ((san_counter++))
    done
    
    cat > "$config_file" << EOF
[ req ]
default_bits = $KEY_SIZE
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[ dn ]
C = ${DEFAULT_COUNTRY:-CH}
ST = ${DEFAULT_STATE:-BE}
L = ${DEFAULT_LOCALITY:-Bern}
O = ${DEFAULT_ORG:-DanielF}
OU = ${DEFAULT_OU:-IT Infrastructure}
CN = $cn

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
$(echo -e "$san_section")
EOF
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Generated OpenSSL config with $(echo -e "$san_section" | wc -l) SANs" >&2
    fi
}

# =============================================================================
# PRIVATE KEY GENERATION
# =============================================================================

generate_private_key() {
    local cert_dir="$1"
    local cn="$2"
    local issuing_ca="$3"
    
    local key_file_pem="$cert_dir/${cn}_${issuing_ca}.key.pem"
    local key_file_p8="$cert_dir/${cn}_${issuing_ca}.key.p8"
    local key_file_pem_nopass="$cert_dir/${cn}_${issuing_ca}.key.nopass.pem"
    local key_file_der_nopass="$cert_dir/${cn}_${issuing_ca}.key.nopass.der"
    local key_file_p8_nopass="$cert_dir/${cn}_${issuing_ca}.key.nopass.p8"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Key size: $KEY_SIZE bits" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Encrypted PEM: $key_file_pem" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Encrypted PKCS#8: $key_file_p8" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Unencrypted PEM: $key_file_pem_nopass" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Unencrypted DER: $key_file_der_nopass" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Unencrypted PKCS#8: $key_file_p8_nopass" >&2
    fi
    
    # Generate private key (always encrypted if password provided)
    if [[ -n "$PASSWORD" ]]; then
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Generating encrypted private key" >&2
        fi
        openssl genrsa -aes256 -passout pass:"$PASSWORD" -out "$key_file_pem" "$KEY_SIZE"
        
        # Create unencrypted PEM version
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Creating unencrypted PEM version" >&2
        fi
        openssl rsa -in "$key_file_pem" -passin pass:"$PASSWORD" -out "$key_file_pem_nopass"
        
        # Convert to encrypted PKCS#8 format
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Converting to encrypted PKCS#8 format" >&2
        fi
        openssl pkcs8 -topk8 -inform PEM -outform DER -in "$key_file_pem_nopass" -out "$key_file_p8" -passout pass:"$PASSWORD"
        
        # Convert to unencrypted DER format (traditional)
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Converting to unencrypted DER format (traditional)" >&2
        fi
        openssl rsa -in "$key_file_pem_nopass" -outform DER -out "$key_file_der_nopass"
        
        # Convert to unencrypted PKCS#8 format
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Converting to unencrypted PKCS#8 format" >&2
        fi
        openssl pkcs8 -topk8 -inform PEM -outform DER -in "$key_file_pem_nopass" -out "$key_file_p8_nopass" -nocrypt
        
        # Set secure permissions
        chmod 600 "$key_file_pem" "$key_file_p8" "$key_file_pem_nopass" "$key_file_der_nopass" "$key_file_p8_nopass"
        
        # Return the encrypted PEM for CSR generation
        echo "$key_file_pem"
    else
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Generating unencrypted private key" >&2
        fi
        openssl genrsa -out "$key_file_pem_nopass" "$KEY_SIZE"
        
        # Create encrypted PEM version with default password
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Creating encrypted PEM version with password 'default'" >&2
        fi
        openssl rsa -in "$key_file_pem_nopass" -aes256 -passout pass:"default" -out "$key_file_pem"
        
        # Convert to encrypted PKCS#8 format
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Converting to encrypted PKCS#8 format" >&2
        fi
        openssl pkcs8 -topk8 -inform PEM -outform DER -in "$key_file_pem_nopass" -out "$key_file_p8" -passout pass:"default"
        
        # Convert to unencrypted DER format (traditional)
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Converting to unencrypted DER format (traditional)" >&2
        fi
        openssl rsa -in "$key_file_pem_nopass" -outform DER -out "$key_file_der_nopass"
        
        # Convert to unencrypted PKCS#8 format
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Converting to unencrypted PKCS#8 format" >&2
        fi
        openssl pkcs8 -topk8 -inform PEM -outform DER -in "$key_file_pem_nopass" -out "$key_file_p8_nopass" -nocrypt
        
        # Set secure permissions
        chmod 600 "$key_file_pem" "$key_file_p8" "$key_file_pem_nopass" "$key_file_der_nopass" "$key_file_p8_nopass"
        
        # Return the unencrypted PEM for CSR generation
        echo "$key_file_pem_nopass"
    fi
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Set permissions to 600 on all key files" >&2
    fi
}

# =============================================================================
# CSR GENERATION
# =============================================================================

generate_csr() {
    local cert_dir="$1"
    local cn="$2"
    local issuing_ca="$3"
    local key_file="$4"
    
    local csr_file_pem="$cert_dir/${cn}_${issuing_ca}.csr.pem"
    local csr_file_der="$cert_dir/${cn}_${issuing_ca}.csr.der"
    local config_file="$cert_dir/${cn}_${issuing_ca}.conf"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} PEM file: $csr_file_pem" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} DER file: $csr_file_der" >&2
    fi
    
    # Generate OpenSSL config
    generate_openssl_config "$config_file" "$cn" "${SANS[@]}"
    
    # Generate CSR
    if [[ -n "$PASSWORD" ]]; then
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Creating CSR with encrypted key" >&2
        fi
        openssl req -new -key "$key_file" -passin pass:"$PASSWORD" -out "$csr_file_pem" -config "$config_file"
    else
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Creating CSR with unencrypted key" >&2
        fi
        openssl req -new -key "$key_file" -out "$csr_file_pem" -config "$config_file"
    fi
    
    # Convert to DER format
    openssl req -in "$csr_file_pem" -outform DER -out "$csr_file_der"
    
    # Clean up config file
    rm -f "$config_file"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Removed temporary config file" >&2
    fi
    
    echo "$csr_file_pem"
}

# =============================================================================
# CERTIFICATE SIGNING
# =============================================================================

sign_certificate() {
    local cert_dir="$1"
    local cn="$2"
    local issuing_ca="$3"
    local csr_file="$4"
    
    local cert_file_pem="$cert_dir/${cn}_${issuing_ca}.crt.pem"
    local cert_file_der="$cert_dir/${cn}_${issuing_ca}.crt.der"
    local ca_dir="$CA_BASE_DIR/$issuing_ca"
    local ca_config="$ca_dir/openssl.cnf"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Validity: $VALIDITY_DAYS days" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} PEM file: $cert_file_pem" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} DER file: $cert_file_der" >&2
    fi
    
    if [[ ! -f "$ca_config" ]]; then
        log_error "CA configuration not found: $ca_config"
        return 1
    fi
    
    # Create a temporary extension file for end-entity certificates
    local ext_file="$cert_dir/temp_extensions.ext"
    cat > "$ext_file" << EOF
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $cn
EOF
    
    # Add SANs to extension file
    local san_counter=2
    for san in "${SANS[@]}"; do
        if [[ "$san" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "IP.${san_counter} = $san" >> "$ext_file"
        else
            echo "DNS.${san_counter} = $san" >> "$ext_file"
        fi
        ((san_counter++))
    done
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Signing with CA: $issuing_ca" >&2
        echo -e "${YELLOW}🐛 DEBUG:${NC} Using extensions file: $ext_file" >&2
    fi
    
    # Sign the certificate
    openssl ca -config "$ca_config" -in "$csr_file" -out "$cert_file_pem" \
        -days "$VALIDITY_DAYS" -notext -md sha256 -extensions v3_req \
        -extfile "$ext_file" -batch
    
    # Convert to DER format
    openssl x509 -in "$cert_file_pem" -outform DER -out "$cert_file_der"
    
    # Clean up extension file
    rm -f "$ext_file"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local serial=$(openssl x509 -in "$cert_file_pem" -noout -serial | cut -d'=' -f2)
        echo -e "${YELLOW}🐛 DEBUG:${NC} Certificate serial: $serial" >&2
        echo -e "${YELLOW}🐛 DEBUG:${NC} Removed temporary extension file" >&2
    fi
}

# =============================================================================
# PKCS#7 CERTIFICATE CHAIN CREATION
# =============================================================================

create_pkcs7_bundle() {
    local cert_dir="$1"
    local cn="$2"
    local issuing_ca="$3"
    local cert_file="$4"
    
    local p7b_file="$cert_dir/${cn}_${issuing_ca}.p7b"
    local p7c_file="$cert_dir/${cn}_${issuing_ca}.p7c"
    local ca_dir="$CA_BASE_DIR/$issuing_ca"
    local ca_cert="$ca_dir/${CERTS_DIR:-certs}/ca.cert.pem"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} PKCS#7 PEM: $p7b_file" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} PKCS#7 DER: $p7c_file" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Building certificate chain from: $ca_cert" >&2
    fi
    
    # Build the certificate chain
    local chain_file="$cert_dir/temp_p7_chain.pem"
    local chain_certs=()
    
    # Build the full CA chain (same logic as PKCS#12)
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Building certificate chain for PKCS#7" >&2
    fi
    
    # Start with the end-entity certificate
    chain_certs+=("$cert_file")
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Added end-entity certificate to chain" >&2
    fi
    
    # Get the parent chain by walking up the CA hierarchy
    local current_ca="$issuing_ca"
    
    # Add the issuing CA certificate
    if [[ -f "$ca_cert" ]]; then
        chain_certs+=("$ca_cert")
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Added to chain: $issuing_ca" >&2
        fi
    fi
    
    # Find parent CAs by looking at the CA configuration
    for ca_def in "${ISSUING_CAS[@]}" "${INTERMEDIATE_CAS[@]}"; do
        IFS=':' read -r ca_name ca_cn parent_ca description <<< "$ca_def"
        if [[ "$ca_name" == "$current_ca" && "$parent_ca" != "none" ]]; then
            local parent_cert="$CA_BASE_DIR/$parent_ca/${CERTS_DIR:-certs}/ca.cert.pem"
            if [[ -f "$parent_cert" ]]; then
                chain_certs+=("$parent_cert")
                current_ca="$parent_ca"
                if [[ "$DEBUG_MODE" == "true" ]]; then
                    echo -e "${YELLOW}🐛 DEBUG:${NC} Added to chain: $parent_ca" >&2
                fi
                # Continue walking up the chain
                for parent_def in "${INTERMEDIATE_CAS[@]}"; do
                    IFS=':' read -r p_name p_cn p_parent p_desc <<< "$parent_def"
                    if [[ "$p_name" == "$current_ca" && "$p_parent" != "none" ]]; then
                        local grandparent_cert="$CA_BASE_DIR/$p_parent/${CERTS_DIR:-certs}/ca.cert.pem"
                        if [[ -f "$grandparent_cert" ]]; then
                            chain_certs+=("$grandparent_cert")
                            if [[ "$DEBUG_MODE" == "true" ]]; then
                                echo -e "${YELLOW}🐛 DEBUG:${NC} Added to chain: $p_parent" >&2
                            fi
                        fi
                        break
                    fi
                done
            fi
            break
        fi
    done
    
    # Create the complete chain file
    cat "${chain_certs[@]}" > "$chain_file"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Created certificate chain with ${#chain_certs[@]} certificates" >&2
    fi
    
    # Create PKCS#7 bundle in PEM format (.p7b)
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Creating PKCS#7 PEM format (.p7b)" >&2
    fi
    openssl crl2pkcs7 -nocrl -certfile "$chain_file" -out "$p7b_file"
    
    # Create PKCS#7 bundle in DER format (.p7c)
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Creating PKCS#7 DER format (.p7c)" >&2
    fi
    openssl crl2pkcs7 -nocrl -certfile "$chain_file" -outform DER -out "$p7c_file"
    
    # Clean up temporary chain file
    rm -f "$chain_file"
    
    # Set appropriate permissions
    chmod 644 "$p7b_file" "$p7c_file"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} PKCS#7 bundles created in PEM and DER formats" >&2
        echo -e "${YELLOW}🐛 DEBUG:${NC} Set permissions to 644 (certificates are public)" >&2
    fi
}

# =============================================================================
# PKCS#12 BUNDLE CREATION
# =============================================================================

create_pkcs12_bundle() {
    local cert_dir="$1"
    local cn="$2"
    local issuing_ca="$3"
    local key_file="$4"
    local cert_file="$5"
    
    local p12_file="$cert_dir/${cn}_${issuing_ca}.p12"
    local p12_file_nopass="$cert_dir/${cn}_${issuing_ca}.nopass.p12"
    local ca_dir="$CA_BASE_DIR/$issuing_ca"
    local ca_cert="$ca_dir/${CERTS_DIR:-certs}/ca.cert.pem"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} PKCS#12 encrypted: $p12_file" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} PKCS#12 unencrypted: $p12_file_nopass" >&2
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Including CA chain from: $ca_cert" >&2
    fi
    
    # Build the certificate chain
    local chain_file="$cert_dir/temp_chain.pem"
    local chain_certs=()
    
    # Build the full CA chain
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Building certificate chain for PKCS#12" >&2
    fi
    
    # Get the parent chain by walking up the CA hierarchy
    local current_ca="$issuing_ca"
    
    # Add the issuing CA certificate
    if [[ -f "$ca_cert" ]]; then
        chain_certs+=("$ca_cert")
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Added to chain: $issuing_ca" >&2
        fi
    fi
    
    # Find parent CAs by looking at the CA configuration
    for ca_def in "${ISSUING_CAS[@]}" "${INTERMEDIATE_CAS[@]}"; do
        IFS=':' read -r ca_name ca_cn parent_ca description <<< "$ca_def"
        if [[ "$ca_name" == "$current_ca" && "$parent_ca" != "none" ]]; then
            local parent_cert="$CA_BASE_DIR/$parent_ca/${CERTS_DIR:-certs}/ca.cert.pem"
            if [[ -f "$parent_cert" ]]; then
                chain_certs+=("$parent_cert")
                current_ca="$parent_ca"
                if [[ "$DEBUG_MODE" == "true" ]]; then
                    echo -e "${YELLOW}🐛 DEBUG:${NC} Added to chain: $parent_ca" >&2
                fi
                # Continue walking up the chain
                for parent_def in "${INTERMEDIATE_CAS[@]}"; do
                    IFS=':' read -r p_name p_cn p_parent p_desc <<< "$parent_def"
                    if [[ "$p_name" == "$current_ca" && "$p_parent" != "none" ]]; then
                        local grandparent_cert="$CA_BASE_DIR/$p_parent/${CERTS_DIR:-certs}/ca.cert.pem"
                        if [[ -f "$grandparent_cert" ]]; then
                            chain_certs+=("$grandparent_cert")
                            if [[ "$DEBUG_MODE" == "true" ]]; then
                                echo -e "${YELLOW}🐛 DEBUG:${NC} Added to chain: $p_parent" >&2
                            fi
                        fi
                        break
                    fi
                done
            fi
            break
        fi
    done
    
    # Create the chain file
    cat "${chain_certs[@]}" > "$chain_file"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Created certificate chain with ${#chain_certs[@]} certificates" >&2
    fi
    
    # Determine which key file to use for each bundle
    local key_file_for_encrypted="$key_file"
    local key_file_for_unencrypted
    
    if [[ -n "$PASSWORD" ]]; then
        # Use unencrypted key for the unencrypted bundle
        key_file_for_unencrypted="${key_file%.*}.nopass.pem"
    else
        # Both use the same unencrypted key
        key_file_for_unencrypted="$key_file"
    fi
    
    # Create encrypted PKCS#12 bundle
    if [[ -n "$PASSWORD" ]]; then
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Creating encrypted PKCS#12 with user password" >&2
        fi
        openssl pkcs12 -export -in "$cert_file" -inkey "$key_file_for_encrypted" -passin pass:"$PASSWORD" \
            -certfile "$chain_file" -out "$p12_file" -passout pass:"$PASSWORD" \
            -name "${cn}_${issuing_ca}"
    else
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Creating encrypted PKCS#12 with password 'default'" >&2
        fi
        openssl pkcs12 -export -in "$cert_file" -inkey "$key_file_for_encrypted" \
            -certfile "$chain_file" -out "$p12_file" -passout pass:"default" \
            -name "${cn}_${issuing_ca}"
    fi
    
    # Create unencrypted PKCS#12 bundle
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Creating unencrypted PKCS#12 bundle" >&2
    fi
    openssl pkcs12 -export -in "$cert_file" -inkey "$key_file_for_unencrypted" \
        -certfile "$chain_file" -out "$p12_file_nopass" -passout pass: \
        -name "${cn}_${issuing_ca}_nopass"
    
    # Clean up temporary chain file
    rm -f "$chain_file"
    
    # Set secure permissions
    chmod 600 "$p12_file" "$p12_file_nopass"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} PKCS#12 bundles created: encrypted & unencrypted" >&2
        echo -e "${YELLOW}🐛 DEBUG:${NC} Set permissions to 600 on both files" >&2
    fi
}

# =============================================================================
# CERTIFICATE CREATION ORCHESTRATION
# =============================================================================

create_certificate_for_ca() {
    local cert_dir="$1"
    local cn="$2"
    local issuing_ca="$3"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Creating certificate for $cn signed by $issuing_ca" >&2
    fi
    
    # Generate private key
    log_info "Generating private key for $cn (signed by $issuing_ca)"
    local key_file
    key_file=$(generate_private_key "$cert_dir" "$cn" "$issuing_ca")
    log_success "Private key generated: ${cn}_${issuing_ca}.key.{pem,p8,nopass.pem,nopass.der,nopass.p8}"
    
    # Generate CSR
    log_info "Generating certificate signing request for $cn"
    local csr_file
    csr_file=$(generate_csr "$cert_dir" "$cn" "$issuing_ca" "$key_file")
    log_success "CSR generated: ${cn}_${issuing_ca}.csr.{pem,der}"
    
    # Sign certificate
    sign_certificate "$cert_dir" "$cn" "$issuing_ca" "$csr_file"
    log_success "Certificate signed: ${cn}_${issuing_ca}.crt.{pem,der}"
    
    # Define cert_file for the bundle functions
    local cert_file="$cert_dir/${cn}_${issuing_ca}.crt.pem"
    
    # Create PKCS#7 bundle
    log_info "Creating PKCS#7 certificate chain for $cn"
    create_pkcs7_bundle "$cert_dir" "$cn" "$issuing_ca" "$cert_file"
    log_success "PKCS#7 bundles created: ${cn}_${issuing_ca}.p7b (PEM) & ${cn}_${issuing_ca}.p7c (DER)"
    
    # Create PKCS#12 bundle
    log_info "Creating PKCS#12 bundle for $cn"
    create_pkcs12_bundle "$cert_dir" "$cn" "$issuing_ca" "$key_file" "$cert_file"
    log_success "PKCS#12 bundles created: ${cn}_${issuing_ca}.p12 (encrypted) & ${cn}_${issuing_ca}.nopass.p12 (unencrypted)"
    
    log_success "Certificate set created for $issuing_ca: ${cn}_${issuing_ca}.{key,csr,crt,p7b,p7c,p12}"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cn)
                CN="$2"
                shift 2
                ;;
            --san)
                SANS+=("$2")
                shift 2
                ;;
            --password)
                PASSWORD="$2"
                shift 2
                ;;
            --key-size)
                KEY_SIZE="$2"
                shift 2
                ;;
            --validity)
                VALIDITY_DAYS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE_MODE=true
                shift
                ;;
            -d|--debug)
                DEBUG_MODE=true
                VERBOSE_MODE=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    echo "🔐 Certificate Signing Script"
    echo "============================="
    
    # Validate inputs
    validate_inputs
    
    # Load CA configuration
    load_ca_config
    
    # Discover issuing CAs
    local issuing_cas=()
    
    if [[ ! -d "$CA_BASE_DIR" ]]; then
        log_error "CA directory not found: $CA_BASE_DIR"
        log_error "Please run the CA creation script first"
        exit 1
    fi
    
    log_info "Discovering available issuing CAs"
    
    # Parse issuing CAs from config
    for ca_def in "${ISSUING_CAS[@]}"; do
        IFS=':' read -r ca_name cn parent_ca description <<< "$ca_def"
        
        local ca_dir="$CA_BASE_DIR/$ca_name"
        local ca_cert="$ca_dir/${CERTS_DIR:-certs}/ca.cert.pem"
        local ca_key="$ca_dir/${PRIVATE_DIR:-private}/ca.key.pem"
        
        if [[ -f "$ca_cert" && -f "$ca_key" ]]; then
            issuing_cas+=("$ca_name")
            if [[ "$VERBOSE_MODE" == "true" ]]; then
                echo -e "${PURPLE}🔍 VERBOSE:${NC} Found issuing CA: $ca_name"
            fi
        else
            log_warning "Issuing CA $ca_name not found or incomplete"
        fi
    done
    
    if [[ ${#issuing_cas[@]} -eq 0 ]]; then
        log_error "No valid issuing CAs found"
        exit 1
    fi
    
    log_success "Discovered ${#issuing_cas[@]} issuing CAs: ${issuing_cas[*]}"
    
    # Setup certificate directory
    log_info "Setting up certificate directory"
    local cert_dir
    cert_dir=$(setup_certificate_directory)
    log_success "Certificate directory created: $cert_dir"
    
    # Create certificates for each issuing CA
    log_info "Creating certificates signed by ${#issuing_cas[@]} issuing CAs"
    
    local overall_start
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        overall_start=$(date +%s)
    fi
    
    for issuing_ca in "${issuing_cas[@]}"; do
        create_certificate_for_ca "$cert_dir" "$CN" "$issuing_ca"
    done
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        local overall_end=$(date +%s)
        local total_time=$((overall_end - overall_start))
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Total generation time: ${total_time}s"
    fi
    
    echo ""
    log_success "All certificates created successfully!"
    
    # Display summary
    echo ""
    echo "📁 Generated Certificates:"
    echo "=========================="
    echo "  📂 Location: $cert_dir"
    echo "  🔑 Common Name: $CN"
    if [[ ${#SANS[@]} -gt 0 ]]; then
        echo "  🌐 Subject Alternative Names: ${SANS[*]}"
    fi
    echo "  📋 Issuing CAs: ${issuing_cas[*]}"
    echo ""
    echo "📄 Files generated for each CA:"
    echo "  • CN_CA.key.pem (Encrypted private key - PEM format)"
    echo "  • CN_CA.key.p8 (Encrypted private key - PKCS#8 format)"
    echo "  • CN_CA.key.nopass.pem (Unencrypted private key - PEM format)"
    echo "  • CN_CA.key.nopass.der (Unencrypted private key - DER format)"
    echo "  • CN_CA.key.nopass.p8 (Unencrypted private key - PKCS#8 format)"
    echo "  • CN_CA.csr.pem/der (Certificate signing request)"
    echo "  • CN_CA.crt.pem/der (Signed certificate)"
    echo "  • CN_CA.p7b (PKCS#7 certificate chain - PEM format)"
    echo "  • CN_CA.p7c (PKCS#7 certificate chain - DER format)"
    echo "  • CN_CA.p12 (PKCS#12 bundle - encrypted with password)"
    echo "  • CN_CA.nopass.p12 (PKCS#12 bundle - unencrypted, no password)"
    echo ""
    echo "🎯 Next steps:"
    echo "  Use the certificates for your applications"
    echo "  Location: $cert_dir"
}

main "$@"
