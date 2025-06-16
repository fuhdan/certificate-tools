#!/bin/bash

set -euo pipefail

# =============================================================================
# Enhanced Certificate Issuance Script
# =============================================================================

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/cert_config.conf"
readonly DEFAULT_CONFIG="# Certificate Issuance Configuration
DEFAULT_KEY_SIZE=3072
DEFAULT_VALIDITY_DAYS=825
DEFAULT_PASSWORD=changeme123
DEFAULT_COUNTRY=CH
DEFAULT_STATE=BE
DEFAULT_ORG=DanielF
DEFAULT_OU=IT Infrastructure
BASE_CA_DIR=./CertificateAuthority
CERT_OUTPUT_DIR=./certificate
LOG_LEVEL=INFO
VALIDATE_AFTER_CREATION=true
CREATE_ALL_FORMATS=true
BACKUP_EXISTING_CERTS=true"

# Load shared common functions
readonly COMMON_FUNCTIONS="${SCRIPT_DIR}/common_functions.sh"
if [[ -f "$COMMON_FUNCTIONS" ]]; then
    source "$COMMON_FUNCTIONS"
else
    echo "❌ ERROR: Required common functions library not found: $COMMON_FUNCTIONS"
    echo "Please ensure common_functions.sh is in the same directory as this script."
    exit 1
fi

# Global variables
if [[ ${BASH_VERSION%%.*} -ge 4 ]]; then
    declare -g OPERATION_START_TIME
    declare -g CONFIG_LOADED=false
    declare -g STATS_TOTAL_FILES=0
    declare -g STATS_SUCCESS_FILES=0
    declare -g STATS_FAILED_FILES=0
    declare -g STATS_WARNINGS=0
    declare -g FAILED_OPERATIONS=()
    declare -g WARNING_MESSAGES=()
else
    declare OPERATION_START_TIME
    declare CONFIG_LOADED=false
    declare STATS_TOTAL_FILES=0
    declare STATS_SUCCESS_FILES=0
    declare STATS_FAILED_FILES=0
    declare STATS_WARNINGS=0
    declare FAILED_OPERATIONS
    declare WARNING_MESSAGES
    FAILED_OPERATIONS=()
    WARNING_MESSAGES=()
fi

# Progress tracking variables (also declared in common_functions.sh)
if [[ ${BASH_VERSION%%.*} -ge 4 ]]; then
    declare -g CURRENT_STEP=0
    declare -g TOTAL_STEPS=0
else
    declare CURRENT_STEP
    declare TOTAL_STEPS
    CURRENT_STEP=0
    TOTAL_STEPS=0
fi

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

load_configuration() {
    load_config_file "$CONFIG_FILE" "$DEFAULT_CONFIG" || return 1
    validate_cert_configuration || return 1
    CONFIG_LOADED=true
    log_debug "Certificate configuration loaded successfully"
}

validate_cert_configuration() {
    local errors=()
    
    # Validate key size
    validate_config_value "DEFAULT_KEY_SIZE" "$DEFAULT_KEY_SIZE" "^(2048|3072|4096)$" "must be 2048, 3072, or 4096" || errors+=("DEFAULT_KEY_SIZE")
    
    # Validate validity days
    validate_config_value "DEFAULT_VALIDITY_DAYS" "$DEFAULT_VALIDITY_DAYS" "^[0-9]+$" "must be a positive number" || errors+=("DEFAULT_VALIDITY_DAYS")
    [[ "$DEFAULT_VALIDITY_DAYS" -gt 0 ]] || errors+=("DEFAULT_VALIDITY_DAYS must be greater than 0")
    
    # Validate directories
    [[ -n "$BASE_CA_DIR" ]] || errors+=("BASE_CA_DIR cannot be empty")
    [[ -n "$CERT_OUTPUT_DIR" ]] || errors+=("CERT_OUTPUT_DIR cannot be empty")
    
    # Validate log level
    validate_config_value "LOG_LEVEL" "$LOG_LEVEL" "^(DEBUG|INFO|WARNING|ERROR)$" "must be DEBUG, INFO, WARNING, or ERROR" || errors+=("LOG_LEVEL")
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        log_error "Certificate configuration validation failed for: ${errors[*]}"
        return 1
    fi
    
    return 0
}

# =============================================================================
# CLEANUP AND ERROR HANDLING
# =============================================================================

cleanup_on_exit() {
    local exit_code=$?
    
    log_debug "Cleanup started (exit code: $exit_code)"
    cleanup_temp_files
    
    if [[ $exit_code -ne 0 ]]; then
        [[ -n "${LOG_FILE:-}" ]] && log_error "Script exited with error. Check log: $LOG_FILE"
    else
        log_success "Script completed successfully"
    fi
    
    exit $exit_code
}

trap cleanup_on_exit EXIT

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

validate_prerequisites() {
    log_info "Validating prerequisites"
    
    validate_openssl || return 1
    
    # Check Java tools (optional) - FIXED to avoid duplicates
    while IFS= read -r warning; do
        if [[ -n "$warning" ]]; then
            WARNING_MESSAGES+=("$warning")
            ((STATS_WARNINGS++))
        fi
    done < <(check_java_tools)
    
    log_success "Prerequisites validation completed"
    return 0
}

validate_ca_structure() {
    local ca_name="$1"
    local ca_dir="$BASE_CA_DIR/$ca_name"
    
    log_info "Validating CA structure for '$ca_name'"
    log_debug "CA directory: $ca_dir"
    
    if [[ ! -d "$ca_dir" ]]; then
        log_error "CA directory '$ca_dir' does not exist"
        return 1
    fi
    
    # Check required files
    local required_files=(
        "$ca_dir/openssl.cnf"
        "$ca_dir/private/ca.key.pem"
        "$ca_dir/certs/ca.cert.pem"
        "$ca_dir/index.txt"
        "$ca_dir/serial"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "Required CA file missing: $file"
            return 1
        fi
        log_debug "Found required file: $file"
    done
    
    # Validate CA certificate and key
    log_debug "Validating CA certificate format"
    if ! validate_certificate_format "$ca_dir/certs/ca.cert.pem"; then
        log_error "CA certificate validation failed"
        return 1
    fi
    
    log_debug "Validating CA private key format"
    if ! validate_private_key_format "$ca_dir/private/ca.key.pem"; then
        log_error "CA private key validation failed"
        return 1
    fi
    
    log_success "CA structure validation passed for '$ca_name'"
    return 0
}

validate_input_parameters() {
    local ca_name="$1"
    local cn="$2"
    
    validate_ca_name "$ca_name" || return 1
    validate_common_name "$cn" || return 1
    
    log_success "Input parameters validation passed"
    return 0
}

validate_sans() {
    local sans=("$@")
    
    for san in "${sans[@]}"; do
        # Enhanced SAN validation with IPv6 support
        if [[ $san =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # IPv4 address validation
            IFS='.' read -ra ADDR <<< "$san"
            for i in "${ADDR[@]}"; do
                if [[ $i -lt 0 || $i -gt 255 ]]; then
                    log_error "Invalid IPv4 address in SANs: $san"
                    return 1
                fi
            done
        elif [[ $san =~ ^[0-9a-fA-F:]+$ ]] && [[ $san == *":"* ]]; then
            # Basic IPv6 validation (simplified)
            if [[ ${#san} -gt 39 ]]; then
                log_error "Invalid IPv6 address in SANs: $san (too long)"
                return 1
            fi
        else
            # DNS name validation
            if [[ ! "$san" =~ ^[a-zA-Z0-9._-]+$ ]] || [[ ${#san} -gt 253 ]]; then
                log_error "Invalid DNS name in SANs: $san"
                return 1
            fi
            
            # Check for valid DNS format (no consecutive dots, etc.)
            if [[ "$san" == *".." ]] || [[ "$san" == .* ]] || [[ "$san" == *. ]]; then
                log_error "Invalid DNS name format in SANs: $san"
                return 1
            fi
        fi
    done
    
    log_success "SANs validation passed"
    return 0
}

# =============================================================================
# CERTIFICATE GENERATION FUNCTIONS
# =============================================================================

generate_private_keys() {
    local cn="$1"
    local cert_dir="$2"
    local key_size="$3"
    local password="$4"
    
    local key_file="$cert_dir/$cn.key.pem"
    local key_der_file="$cert_dir/$cn.key.der"
    local pwd_key_file="$cert_dir/$cn.pwd.key.pem"
    local pwd_key_der_file="$cert_dir/$cn.pwd.key.der"
    
    # Generate unencrypted private key (PEM)
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "Unencrypted private key (PEM)" \
        "openssl genrsa -out '$key_file' $key_size" \
        "$key_file"; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("Unencrypted private key (PEM)")
        return 1
    fi
    
    # Generate unencrypted private key (DER)
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "Unencrypted private key (DER)" \
        "openssl rsa -in '$key_file' -outform DER -out '$key_der_file'" \
        "$key_der_file"; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("Unencrypted private key (DER)")
    fi
    
    # Generate encrypted private key (PEM)
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "Encrypted private key (PEM)" \
        "openssl rsa -in '$key_file' -aes256 -out '$pwd_key_file' -passout pass:'$password'" \
        "$pwd_key_file"; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("Encrypted private key (PEM)")
    fi
    
    # Generate encrypted private key (DER)
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "Encrypted private key (DER)" \
        "openssl rsa -in '$pwd_key_file' -aes256 -outform DER -out '$pwd_key_der_file' -passin pass:'$password' -passout pass:'$password'" \
        "$pwd_key_der_file"; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("Encrypted private key (DER)")
    fi
    
    return 0
}

generate_csr_with_sans() {
    local cn="$1"
    local cert_dir="$2"
    shift 2
    local sans=("$@")
    
    local key_file="$cert_dir/$cn.key.pem"
    local csr_file="$cert_dir/$cn.csr.pem"
    local config_file="$cert_dir/openssl_san.cnf"
    
    log_info "Creating certificate signing request configuration"
    
    # Generate CSR config with SANs - LibreSSL compatible format
    cat > "$config_file" <<EOF
[ req ]
default_bits        = $DEFAULT_KEY_SIZE
prompt              = no
default_md          = sha256
distinguished_name  = dn
req_extensions      = req_ext

[ dn ]
C  = $DEFAULT_COUNTRY
ST = $DEFAULT_STATE
O  = $DEFAULT_ORG
OU = $DEFAULT_OU
CN = $cn

[ req_ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
EOF

    # Add SANs to config - ensure CN is always first DNS entry
    local index=1
    echo "DNS.$index = $cn" >> "$config_file"
    
    for san in "${sans[@]}"; do
        # Skip if SAN is same as CN to avoid duplicates
        if [[ "$san" == "$cn" ]]; then
            continue
        fi
        
        ((index++))
        if [[ $san =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # IPv4 address
            echo "IP.$((index - 1)) = $san" >> "$config_file"
        elif [[ $san =~ ^[0-9a-fA-F:]+$ ]] && [[ $san == *":"* ]]; then
            # IPv6 address
            echo "IP.$((index - 1)) = $san" >> "$config_file"
        else
            # DNS name
            echo "DNS.$index = $san" >> "$config_file"
        fi
    done
    
    add_temp_file "$config_file"
    
    # Generate CSR
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "Certificate signing request" \
        "openssl req -new -key '$key_file' -out '$csr_file' -config '$config_file'" \
        "$csr_file"; then
        ((STATS_SUCCESS_FILES++))
        update_progress
        return 0
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("Certificate signing request")
        return 1
    fi
}

sign_certificate() {
    local ca_name="$1"
    local cn="$2"
    local cert_dir="$3"
    shift 3
    local sans=("$@")
    
    local ca_dir="$BASE_CA_DIR/$ca_name"
    local csr_file="$cert_dir/$cn.csr.pem"
    local cert_file="$cert_dir/$cn.cert.pem"
    
    # Create extensions file for LibreSSL compatibility
    local ext_file="$cert_dir/v3_usr.ext"
    cat > "$ext_file" << EOF
[ v3_usr ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[ alt_names ]
EOF

    # Add alt_names to extensions file
    local index=1
    echo "DNS.$index = $cn" >> "$ext_file"
    
    for san in "${sans[@]}"; do
        ((index++))
        if [[ $san =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "IP.$((index - 1)) = $san" >> "$ext_file"
        else
            echo "DNS.$index = $san" >> "$ext_file"
        fi
    done
    
    add_temp_file "$ext_file"
    
    # LibreSSL compatible signing - use x509 instead of ca command for better compatibility
    if [[ "$SSL_TYPE" == "libressl" ]]; then
        log_info "Using LibreSSL-compatible certificate signing"
        
        # Sign using x509 command with extensions file
        ((STATS_TOTAL_FILES++))
        if atomic_file_operation \
            "Signed certificate" \
            "openssl x509 -req -in '$csr_file' -CA '$ca_dir/certs/ca.cert.pem' -CAkey '$ca_dir/private/ca.key.pem' -CAcreateserial -out '$cert_file' -days $DEFAULT_VALIDITY_DAYS -sha256 -extensions v3_usr -extfile '$ext_file'" \
            "$cert_file"; then
            ((STATS_SUCCESS_FILES++))
            update_progress
            return 0
        else
            ((STATS_FAILED_FILES++))
            FAILED_OPERATIONS+=("Signed certificate")
            return 1
        fi
    else
        # Standard OpenSSL approach using ca command
        log_info "Using OpenSSL ca command for certificate signing"
        
        # Create temporary CA config with SANs
        local temp_ca_config="$ca_dir/temp_openssl.cnf"
        cp "$ca_dir/openssl.cnf" "$temp_ca_config"
        add_temp_file "$temp_ca_config"
        
        cat >> "$temp_ca_config" <<EOF

[ v3_usr ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[ alt_names ]
EOF

        # Add alt_names to CA config
        local index=1
        echo "DNS.$index = $cn" >> "$temp_ca_config"
        
        for san in "${sans[@]}"; do
            ((index++))
            if [[ $san =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "IP.$((index - 1)) = $san" >> "$temp_ca_config"
            else
                echo "DNS.$index = $san" >> "$temp_ca_config"
            fi
        done
        
        # Sign certificate using ca command
        ((STATS_TOTAL_FILES++))
        if atomic_file_operation \
            "Signed certificate" \
            "openssl ca -batch -config '$temp_ca_config' -extensions v3_usr -days $DEFAULT_VALIDITY_DAYS -notext -md sha256 -in '$csr_file' -out '$cert_file'" \
            "$cert_file"; then
            ((STATS_SUCCESS_FILES++))
            update_progress
            return 0
        else
            ((STATS_FAILED_FILES++))
            FAILED_OPERATIONS+=("Signed certificate")
            return 1
        fi
    fi
}

build_certificate_chain() {
    local ca_name="$1"
    local cn="$2"
    local cert_dir="$3"
    
    local cert_file="$cert_dir/$cn.cert.pem"
    local chain_file="$cert_dir/$cn.chain.cert.pem"
    local ca_dir="$BASE_CA_DIR/$ca_name"
    
    log_info "Building certificate chain (PEM)"
    
    # Build chain based on CA hierarchy
    if [[ -f "$ca_dir/certs/ca.cert.pem" ]]; then
        if [[ -f "$BASE_CA_DIR/IntermediateCA1/certs/ca.cert.pem" && "$ca_name" == "IssuingCA1" ]]; then
            # 3-tier chain: IssuingCA1 -> IntermediateCA1 -> RootCA
            cat "$cert_file" \
                "$ca_dir/certs/ca.cert.pem" \
                "$BASE_CA_DIR/IntermediateCA1/certs/ca.cert.pem" \
                "$BASE_CA_DIR/RootCA/certs/ca.cert.pem" > "$chain_file"
        elif [[ -f "$BASE_CA_DIR/RootCA/certs/ca.cert.pem" && "$ca_name" == "IssuingCA2" ]]; then
            # 2-tier chain: IssuingCA2 -> RootCA
            cat "$cert_file" \
                "$ca_dir/certs/ca.cert.pem" \
                "$BASE_CA_DIR/RootCA/certs/ca.cert.pem" > "$chain_file"
        else
            # Default: certificate + immediate parent
            cat "$cert_file" "$ca_dir/certs/ca.cert.pem" > "$chain_file"
        fi
        
        if [[ -f "$chain_file" && -s "$chain_file" ]]; then
            log_success "Certificate chain (PEM) created successfully"
            ((STATS_SUCCESS_FILES++))
            update_progress
        else
            log_error "Certificate chain (PEM) creation failed"
            FAILED_OPERATIONS+=("Certificate chain (PEM)")
            ((STATS_FAILED_FILES++))
        fi
        ((STATS_TOTAL_FILES++))
    fi
    
    return 0
}

generate_certificate_formats() {
    local cn="$1"
    local cert_dir="$2"
    local password="$3"
    
    local cert_file="$cert_dir/$cn.cert.pem"
    local chain_file="$cert_dir/$cn.chain.cert.pem"
    local key_file="$cert_dir/$cn.key.pem"
    
    # DER formats
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "Certificate (DER)" \
        "openssl x509 -in '$cert_file' -outform DER -out '$cert_dir/$cn.cert.der'" \
        "$cert_dir/$cn.cert.der" \
        false; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("Certificate (DER)")
    fi
    
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "Certificate chain (DER)" \
        "openssl x509 -in '$chain_file' -outform DER -out '$cert_dir/$cn.chain.cert.der'" \
        "$cert_dir/$cn.chain.cert.der" \
        false; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("Certificate chain (DER)")
    fi
    
    # PKCS#7 bundles
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "PKCS#7 bundle (PEM)" \
        "openssl crl2pkcs7 -nocrl -certfile '$chain_file' -out '$cert_dir/$cn.pkcs7.pem'" \
        "$cert_dir/$cn.pkcs7.pem" \
        false; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("PKCS#7 bundle (PEM)")
    fi
    
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "PKCS#7 bundle (DER)" \
        "openssl crl2pkcs7 -nocrl -certfile '$chain_file' -outform DER -out '$cert_dir/$cn.pkcs7.p7b'" \
        "$cert_dir/$cn.pkcs7.p7b" \
        false; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("PKCS#7 bundle (DER)")
    fi
    
    # PKCS#12 bundles
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "PKCS#12 bundle (with password)" \
        "openssl pkcs12 -export -in '$chain_file' -inkey '$key_file' -out '$cert_dir/$cn.pkcs12.p12' -name '$cn' -passout pass:'$password'" \
        "$cert_dir/$cn.pkcs12.p12" \
        false; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("PKCS#12 bundle (with password)")
    fi
    
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "PKCS#12 bundle (without password)" \
        "openssl pkcs12 -export -in '$chain_file' -inkey '$key_file' -out '$cert_dir/$cn.nopass.pkcs12.p12' -name '$cn' -passout pass:" \
        "$cert_dir/$cn.nopass.pkcs12.p12" \
        false; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("PKCS#12 bundle (without password)")
    fi
    
    # PFX (same as PKCS#12)
    ((STATS_TOTAL_FILES++))
    if atomic_file_operation \
        "PFX bundle (Windows)" \
        "openssl pkcs12 -export -in '$chain_file' -inkey '$key_file' -out '$cert_dir/$cn.pfx' -name '$cn' -passout pass:'$password'" \
        "$cert_dir/$cn.pfx" \
        false; then
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        ((STATS_FAILED_FILES++))
        FAILED_OPERATIONS+=("PFX bundle (Windows)")
    fi
    
    # Java KeyStore formats (if available)
    generate_java_keystores "$cn" "$cert_dir" "$password"
    
    return 0
}

generate_java_keystores() {
    local cn="$1"
    local cert_dir="$2"
    local password="$3"
    
    if ! command -v keytool >/dev/null 2>&1; then
        # Don't add warning here - already handled in validate_prerequisites
        log_debug "JKS/BKS creation skipped - Java keytool not available"
        return 0
    fi
    
    local pkcs12_file="$cert_dir/$cn.pkcs12.p12"
    local pkcs12_nopass_file="$cert_dir/$cn.nopass.pkcs12.p12"
    
    # JKS KeyStore
    ((STATS_TOTAL_FILES++))
    if keytool -importkeystore -deststorepass "$password" -destkeypass "$password" \
        -destkeystore "$cert_dir/$cn.keystore.jks" \
        -srckeystore "$pkcs12_file" -srcstoretype PKCS12 -srcstorepass "$password" \
        -alias "$cn" >/dev/null 2>>"$LOG_FILE"; then
        log_success "Java KeyStore (JKS) created successfully"
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        log_warning "JKS KeyStore creation failed"
        ((STATS_FAILED_FILES++))
    fi
    
    # BKS KeyStore (with password)
    ((STATS_TOTAL_FILES++))
    if keytool -importkeystore -deststorepass "$password" -destkeypass "$password" \
        -deststoretype BKS -destkeystore "$cert_dir/$cn.keystore.bks" \
        -srckeystore "$pkcs12_file" -srcstoretype PKCS12 -srcstorepass "$password" \
        -alias "$cn" -provider org.bouncycastle.jce.provider.BouncyCastleProvider \
        -providerpath /usr/share/java/bcprov.jar >/dev/null 2>>"$LOG_FILE"; then
        log_success "BKS KeyStore (with password) created successfully"
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        log_warning "BKS KeyStore creation failed - Bouncy Castle provider may not be available"
        ((STATS_FAILED_FILES++))
    fi
    
    # BKS KeyStore (without password)
    ((STATS_TOTAL_FILES++))
    if keytool -importkeystore -deststorepass "" -destkeypass "" \
        -deststoretype BKS -destkeystore "$cert_dir/$cn.nopass.keystore.bks" \
        -srckeystore "$pkcs12_nopass_file" -srcstoretype PKCS12 -srcstorepass "" \
        -alias "$cn" -provider org.bouncycastle.jce.provider.BouncyCastleProvider \
        -providerpath /usr/share/java/bcprov.jar >/dev/null 2>>"$LOG_FILE"; then
        log_success "BKS KeyStore (without password) created successfully"
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        log_warning "BKS KeyStore (no password) creation failed"
        ((STATS_FAILED_FILES++))
    fi
}

# =============================================================================
# USER INTERFACE FUNCTIONS
# =============================================================================

get_password_input() {
    local default_password="$1"
    
    # Ensure all previous output is flushed
    sync
    
    echo ""
    echo -e "${CYAN}🔐 Password Configuration${NC}"
    echo "========================"
    echo "   Press Enter for default password ('$default_password')"
    echo -n "   Or enter custom password: "
    
    # Read password silently
    local user_password
    read -s user_password
    echo ""  # New line after hidden input
    
    # Use Bash version-appropriate method to return the password
    if [[ ${BASH_VERSION%%.*} -ge 4 ]] && [[ ${BASH_VERSION#*.} -ge 3 ]] 2>/dev/null; then
        # Bash 4.3+ supports nameref - use modern approach
        local -n password_var="$2"
        if [[ -z "$user_password" ]]; then
            password_var="$default_password"
            log_info "Using default password"
        else
            password_var="$user_password"
            log_info "Using custom password (hidden for security)"
        fi
    else
        # Bash < 4.3 - use eval fallback for compatibility
        local password_var_name="$2"
        if [[ -z "$user_password" ]]; then
            eval "$password_var_name=\"$default_password\""
            log_info "Using default password"
        else
            eval "$password_var_name=\"$user_password\""
            log_info "Using custom password (hidden for security)"
        fi
        log_debug "Using Bash compatibility mode for password input (Bash $BASH_VERSION)"
    fi
}

show_available_cas() {
    echo -e "${YELLOW}Available CAs:${NC}"
    if [[ -d "$BASE_CA_DIR" ]]; then
        for ca in "$BASE_CA_DIR"/*/; do
            if [[ -d "$ca" ]]; then
                local ca_name
                ca_name=$(basename "$ca")
                echo "  - $ca_name"
            fi
        done
    else
        echo "  No CAs found. Run create_ca.sh first."
    fi
}

# =============================================================================
# OUTPUT AND REPORTING
# =============================================================================

display_certificate_details() {
    local cert_file="$1"
    
    if [[ -f "$cert_file" ]]; then
        echo ""
        echo -e "${BLUE}🔍 Certificate Details:${NC}"
        echo "======================"
        
        local subject validity sans
        subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject=//')
        validity=$(openssl x509 -in "$cert_file" -noout -dates 2>/dev/null)
        sans=$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | grep -v "X509v3 Subject Alternative Name:" | tr -d ' ' || echo "None")
        
        echo "   Subject: $subject"
        echo "   $validity"
        echo "   SANs: $sans"
        echo ""
    fi
}

generate_summary_report() {
    local cn="$1"
    local cert_dir="$2"
    local password="$3"
    local duration="$4"
    
    echo ""
    echo -e "${GREEN}${BOLD}📊 CERTIFICATE GENERATION SUMMARY${NC}"
    echo "=================================="
    echo "📅 Completed at: $(date)"
    echo "⏱️  Duration: $(format_duration $duration)"
    echo ""
    echo "📈 Statistics:"
    echo "   📁 Total files attempted: $STATS_TOTAL_FILES"
    echo "   ✅ Successfully created: $STATS_SUCCESS_FILES"
    echo "   ❌ Failed to create: $STATS_FAILED_FILES"
    echo "   ⚠️  Warnings: $STATS_WARNINGS"
    echo ""
    
    # Show failed operations if any
    if [[ ${#FAILED_OPERATIONS[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Failed Operations:${NC}"
        for failed in "${FAILED_OPERATIONS[@]}"; do
            echo "   - $failed"
        done
        echo ""
    fi
    
    # Show warnings if any
    if [[ ${#WARNING_MESSAGES[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Warnings:${NC}"
        for warning in "${WARNING_MESSAGES[@]}"; do
            echo "   - $warning"
        done
        echo ""
    fi
    
    # Display file inventory
    display_file_inventory "$cn" "$cert_dir"
    
    # Display usage guidelines
    display_usage_guidelines "$cn" "$cert_dir" "$password"
}

display_file_inventory() {
    local cn="$1"
    local cert_dir="$2"
    
    echo -e "${BLUE}📁 Generated Files:${NC}"
    echo "=================="
    echo ""
    
    # Private Keys
    echo -e "${PURPLE}🔑 Private Keys:${NC}"
    check_and_display_file "$cert_dir/$cn.key.pem" "Unencrypted PEM"
    check_and_display_file "$cert_dir/$cn.key.der" "Unencrypted DER"
    check_and_display_file "$cert_dir/$cn.pwd.key.pem" "Encrypted PEM"
    check_and_display_file "$cert_dir/$cn.pwd.key.der" "Encrypted DER"
    echo ""
    
    # Certificates
    echo -e "${GREEN}🎫 Certificates:${NC}"
    check_and_display_file "$cert_dir/$cn.cert.pem" "Certificate (PEM)"
    check_and_display_file "$cert_dir/$cn.cert.der" "Certificate (DER)"
    check_and_display_file "$cert_dir/$cn.chain.cert.pem" "Chain (PEM)"
    check_and_display_file "$cert_dir/$cn.chain.cert.der" "Chain (DER)"
    echo ""
    
    # Certificate Bundles
    echo -e "${CYAN}📦 Certificate Bundles:${NC}"
    check_and_display_file "$cert_dir/$cn.pkcs7.pem" "PKCS#7 (PEM)"
    check_and_display_file "$cert_dir/$cn.pkcs7.p7b" "PKCS#7 (DER/P7B)"
    check_and_display_file "$cert_dir/$cn.pkcs12.p12" "PKCS#12 (with password)"
    check_and_display_file "$cert_dir/$cn.nopass.pkcs12.p12" "PKCS#12 (no password)"
    check_and_display_file "$cert_dir/$cn.pfx" "PFX (Windows)"
    
    # Only show Java keystores if Java is available
    if command -v keytool >/dev/null 2>&1; then
        check_and_display_file "$cert_dir/$cn.keystore.jks" "Java KeyStore (JKS)"
        check_and_display_file "$cert_dir/$cn.keystore.bks" "BKS KeyStore (with pass)"
        check_and_display_file "$cert_dir/$cn.nopass.keystore.bks" "BKS KeyStore (no pass)"
    else
        echo "   ⚠️  Java KeyStore (JKS):     Skipped (Java not available)"
        echo "   ⚠️  BKS KeyStore formats:    Skipped (Java not available)"
    fi
    
    echo ""
    
    # Other Files
    echo -e "${YELLOW}📋 Other Files:${NC}"
    check_and_display_file "$cert_dir/$cn.csr.pem" "CSR"
    echo ""
}

display_usage_guidelines() {
    local cn="$1"
    local cert_dir="$2"
    local password="$3"
    
    echo -e "${BLUE}💡 Usage Guidelines:${NC}"
    echo "==================="
    echo "   🌐 Web servers (Apache/Nginx):    Use $cert_dir/$cn.chain.cert.pem + $cert_dir/$cn.key.pem"
    echo "   🪟 Windows Certificate Store:     Import $cert_dir/$cn.pfx or $cert_dir/$cn.pkcs7.p7b"
    echo "   ☕ Java applications:             Use $cert_dir/$cn.keystore.jks or $cert_dir/$cn.pkcs12.p12"
    echo "   📱 Android applications:          Use $cert_dir/$cn.keystore.bks"
    echo "   📧 Email/S-MIME:                  Use $cert_dir/$cn.pkcs12.p12 or $cert_dir/$cn.pfx"
    echo "   🔧 Legacy/Binary systems:         Use $cert_dir/$cn.cert.der + $cert_dir/$cn.key.der"
    echo "   🧪 Testing purposes:              Use appropriate format for your test environment"
    echo ""
    echo -e "${RED}🔐 Password for encrypted files: (stored securely by user)${NC}"
    echo -e "${RED}   Note: Use the password you entered during setup${NC}"
    echo ""
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat << EOF
${BOLD}Enhanced Certificate Generation Script${NC}

${BOLD}Usage:${NC}
  $0 <CA_NAME> <COMMON_NAME> [SANs...]

${BOLD}Environment Variables:${NC}
  DEBUG=1                    Enable debug logging
  DEFAULT_PASSWORD=<pass>    Set default password (default: from config)
  LOG_LEVEL=<level>          Set log level (DEBUG|INFO|WARNING|ERROR)

${BOLD}Options:${NC}
  --config FILE              Use custom configuration file
  --no-backup               Don't backup existing certificates
  --no-validation           Skip validation after creation
  --key-size SIZE           Override default key size (2048|3072|4096)
  --validity-days DAYS      Override default validity period

$(show_available_cas)

${BOLD}Examples:${NC}
  $0 IssuingCA1 server1.local www.server1.local 127.0.0.1
  DEBUG=1 $0 IssuingCA1 server1.local
  $0 --key-size 4096 IssuingCA2 api.example.com
EOF
}

validate_arguments() {
    if [[ $# -lt 2 ]]; then
        log_error "Insufficient arguments provided"
        show_usage
        return 1
    fi
    
    local ca_name="$1"
    local cn="$2"
    shift 2
    local sans=("$@")
    
    # Validate input parameters
    validate_input_parameters "$ca_name" "$cn" || return 1
    
    # Validate SANs if provided
    if [[ ${#sans[@]} -gt 0 ]]; then
        validate_sans "${sans[@]}" || return 1
    fi
    
    return 0
}

main() {
    OPERATION_START_TIME=$(date +%s)
    
    # Parse arguments
    local custom_config=""
    local override_key_size=""
    local override_validity=""
    local args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)
                custom_config="$2"
                shift 2
                ;;
            --no-backup)
                BACKUP_EXISTING_CERTS=false
                shift
                ;;
            --no-validation)
                VALIDATE_AFTER_CREATION=false
                shift
                ;;
            --key-size)
                override_key_size="$2"
                shift 2
                ;;
            --validity-days)
                override_validity="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done
    
    # Use custom config if provided
    if [[ -n "$custom_config" ]]; then
        CONFIG_FILE="$custom_config"
    fi
    
    # Set overrides from environment
    [[ -n "${DEBUG:-}" ]] && LOG_LEVEL="DEBUG"
    [[ -n "${LOG_LEVEL:-}" ]] && export LOG_LEVEL="$LOG_LEVEL"
    
    # Initialize logging
    setup_logging "cert_issuance"
    
    # Load and validate configuration
    log_debug "Loading configuration from: $CONFIG_FILE"
    if ! load_configuration; then
        log_error "Configuration loading failed"
        exit 1
    fi
    
    # Apply overrides
    [[ -n "$override_key_size" ]] && DEFAULT_KEY_SIZE="$override_key_size"
    [[ -n "$override_validity" ]] && DEFAULT_VALIDITY_DAYS="$override_validity"
    [[ -n "${DEFAULT_PASSWORD:-}" ]] && DEFAULT_PASSWORD="$DEFAULT_PASSWORD"
    
    # Validate arguments
    if ! validate_arguments "${args[@]}"; then
        exit 1
    fi
    
    local ca_name="${args[0]}"
    local cn="${args[1]}"
    local sans=("${args[@]:2}")
    
    local cert_dir="$CERT_OUTPUT_DIR/$cn"
    
    # Display header
    echo -e "${CYAN}${BOLD}🚀 Enhanced Certificate Generation${NC}"
    echo "=================================="
    echo "📅 Started at: $(date)"
    echo "🖥️  System: $(uname -s) $(uname -r)"
    echo ""
    
    # Display parameters
    echo -e "${PURPLE}🎫 Certificate Generation Parameters${NC}"
    echo "==================================="
    echo "📋 CA: $ca_name"
    echo "🏷️  Common Name: $cn"
    [[ ${#sans[@]} -gt 0 ]] && echo "🔗 Subject Alternative Names: ${sans[*]}"
    echo "📁 Output Directory: $cert_dir"
    echo "🔑 Key Size: $DEFAULT_KEY_SIZE bits"
    echo "📅 Validity: $DEFAULT_VALIDITY_DAYS days"
    echo ""
    
    # Get password for encryption
    local password
    get_password_input "$DEFAULT_PASSWORD" password
    
    # Initialize progress tracking (17 total steps)
    log_debug "Initializing progress tracking with 17 steps"
    init_progress 17
    log_debug "Progress tracking initialized successfully"
    
    # Validate prerequisites
    log_debug "About to validate prerequisites"
    if ! validate_prerequisites; then
        log_error "Prerequisites validation failed"
        exit 1
    fi
    log_debug "Prerequisites validation completed, updating progress"
    update_progress
    log_debug "Progress updated successfully"
    
    # Validate CA structure
    log_debug "About to validate CA structure for: $ca_name"
    if ! validate_ca_structure "$ca_name"; then
        log_error "CA structure validation failed"
        exit 1
    fi
    log_debug "CA structure validation completed, updating progress"
    update_progress
    log_debug "Progress updated successfully"
    
    # Create output directory
    log_info "Setting up output directory"
    if [[ "$BACKUP_EXISTING_CERTS" == "true" ]]; then
        backup_directory "$cert_dir" "$BACKUP_EXISTING_CERTS" || log_warning "Failed to backup existing directory"
    fi
    mkdir -p "$cert_dir"
    update_progress
    
    # Generate certificate files
    log_info "Starting certificate generation process"
    
    # Steps 4-7: Generate private keys
    generate_private_keys "$cn" "$cert_dir" "$DEFAULT_KEY_SIZE" "$password" || exit 1
    
    # Step 8: Generate CSR
    generate_csr_with_sans "$cn" "$cert_dir" "${sans[@]}" || exit 1
    
    # Step 9: Sign certificate
    sign_certificate "$ca_name" "$cn" "$cert_dir" "${sans[@]}" || exit 1
    
    # Step 10: Build certificate chain
    build_certificate_chain "$ca_name" "$cn" "$cert_dir" || exit 1
    
    # Steps 11-17: Generate all certificate formats
    generate_certificate_formats "$cn" "$cert_dir" "$password" || exit 1
    
    local end_time=$(date +%s)
    local duration=$((end_time - OPERATION_START_TIME))
    
    # Display certificate details
    display_certificate_details "$cert_dir/$cn.cert.pem"

    # Generate and display summary report
    generate_summary_report "$cn" "$cert_dir" "$password" "$duration"
    
    # Final status
    if [[ $STATS_FAILED_FILES -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}🎉 Certificate generation completed successfully!${NC}"
        exit 0
    else
        echo -e "${YELLOW}${BOLD}⚠️  Certificate generation completed with $STATS_FAILED_FILES failures${NC}"
        exit 1
    fi
}

# Execute main function
main "$@"