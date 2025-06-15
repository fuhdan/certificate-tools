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

# Global state
declare -g OPERATION_START_TIME
declare -g CONFIG_LOADED=false
declare -g STATS_TOTAL_FILES=0
declare -g STATS_SUCCESS_FILES=0
declare -g STATS_FAILED_FILES=0
declare -g STATS_WARNINGS=0
declare -g FAILED_OPERATIONS=()
declare -g WARNING_MESSAGES=()

# Certificate generation formats
declare -Ar CERT_FORMATS=(
    ["unencrypted_key_pem"]="Unencrypted Private Key (PEM)"
    ["unencrypted_key_der"]="Unencrypted Private Key (DER)"
    ["encrypted_key_pem"]="Encrypted Private Key (PEM)"
    ["encrypted_key_der"]="Encrypted Private Key (DER)"
    ["csr_pem"]="Certificate Signing Request"
    ["cert_pem"]="Certificate (PEM)"
    ["cert_der"]="Certificate (DER)"
    ["chain_pem"]="Certificate Chain (PEM)"
    ["chain_der"]="Certificate Chain (DER)"
    ["pkcs7_pem"]="PKCS#7 Bundle (PEM)"
    ["pkcs7_der"]="PKCS#7 Bundle (DER/P7B)"
    ["pkcs12_pwd"]="PKCS#12 Bundle (with password)"
    ["pkcs12_no_pwd"]="PKCS#12 Bundle (no password)"
    ["pfx"]="PFX Bundle (Windows)"
    ["jks"]="Java KeyStore (JKS)"
    ["bks_pwd"]="BKS KeyStore (with password)"
    ["bks_no_pwd"]="BKS KeyStore (no password)"
)

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

load_configuration() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_info "Creating default configuration file: $CONFIG_FILE"
        echo "$DEFAULT_CONFIG" > "$CONFIG_FILE"
    fi
    
    if source "$CONFIG_FILE" 2>/dev/null; then
        validate_configuration
        CONFIG_LOADED=true
        log_debug "Configuration loaded successfully"
    else
        log_error "Failed to load configuration from $CONFIG_FILE"
        return 1
    fi
}

validate_configuration() {
    local errors=()
    
    # Validate key size
    [[ "$DEFAULT_KEY_SIZE" =~ ^(2048|3072|4096)$ ]] || errors+=("Invalid DEFAULT_KEY_SIZE: $DEFAULT_KEY_SIZE")
    
    # Validate validity days
    [[ "$DEFAULT_VALIDITY_DAYS" =~ ^[0-9]+$ ]] && [[ "$DEFAULT_VALIDITY_DAYS" -gt 0 ]] || errors+=("Invalid DEFAULT_VALIDITY_DAYS: $DEFAULT_VALIDITY_DAYS")
    
    # Validate directories
    [[ -n "$BASE_CA_DIR" ]] || errors+=("BASE_CA_DIR cannot be empty")
    [[ -n "$CERT_OUTPUT_DIR" ]] || errors+=("CERT_OUTPUT_DIR cannot be empty")
    
    # Validate log level
    [[ "$LOG_LEVEL" =~ ^(DEBUG|INFO|WARNING|ERROR)$ ]] || errors+=("Invalid LOG_LEVEL: $LOG_LEVEL")
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        log_error "Configuration validation failed:"
        printf '%s\n' "${errors[@]}" >&2
        return 1
    fi
}

# =============================================================================
# ENHANCED LOGGING SYSTEM
# =============================================================================

setup_logging() {
    local log_dir="${SCRIPT_DIR}/logs"
    mkdir -p "$log_dir"
    LOG_FILE="${log_dir}/cert_issuance_$(date +%Y%m%d_%H%M%S).log"
    
    echo "=== Enhanced Certificate Issuance Log - $(date) ===" > "$LOG_FILE"
    echo "Configuration: $CONFIG_FILE" >> "$LOG_FILE"
    echo "Log Level: $LOG_LEVEL" >> "$LOG_FILE"
    echo "=========================================" >> "$LOG_FILE"
}

log_with_level() {
    local level="$1"
    local message="$2"
    local color="$3"
    local symbol="$4"
    
    # Check if we should log this level
    case "$LOG_LEVEL" in
        ERROR) [[ "$level" == "ERROR" ]] || return 0 ;;
        WARNING) [[ "$level" =~ ^(ERROR|WARNING)$ ]] || return 0 ;;
        INFO) [[ "$level" =~ ^(ERROR|WARNING|INFO)$ ]] || return 0 ;;
        DEBUG) ;; # Log everything
    esac
    
    local timestamp="$(date '+%H:%M:%S')"
    local log_entry="[$timestamp] [$level] $message"
    
    echo -e "${color}${symbol} ${level}:${NC} $message"
    echo "$log_entry" >> "$LOG_FILE"
}

log_debug() { log_with_level "DEBUG" "$1" "$PURPLE" "🔍"; }
log_info() { log_with_level "INFO" "$1" "$BLUE" "ℹ️ "; }
log_success() { log_with_level "INFO" "$1" "$GREEN" "✅"; }
log_warning() { log_with_level "WARNING" "$1" "$YELLOW" "⚠️ "; }
log_error() { log_with_level "ERROR" "$1" "$RED" "❌"; }

# =============================================================================
# PROGRESS TRACKING
# =============================================================================

init_progress() {
    TOTAL_STEPS="$1"
    CURRENT_STEP=0
    log_info "Starting certificate generation with $TOTAL_STEPS steps"
}

update_progress() {
    ((CURRENT_STEP++))
    local percentage=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    local bar_length=40
    local filled_length=$((percentage * bar_length / 100))
    
    printf "\r${BLUE}Progress: ${NC}["
    printf "%*s" $filled_length | tr ' ' '█'
    printf "%*s" $((bar_length - filled_length)) | tr ' ' '░'
    printf "] %d%% (%d/%d)" $percentage $CURRENT_STEP $TOTAL_STEPS
    
    if [[ $CURRENT_STEP -eq $TOTAL_STEPS ]]; then
        echo ""
        log_success "All certificate generation steps completed"
    fi
}

# =============================================================================
# ATOMIC OPERATIONS & RECOVERY
# =============================================================================

add_temp_file() {
    TEMP_FILES+=("$1")
    log_debug "Added temp file: $1"
}

atomic_file_operation() {
    local description="$1"
    local command="$2"
    local target_file="$3"
    local is_critical="${4:-true}"
    
    local temp_file="${target_file}.tmp.$"
    add_temp_file "$temp_file"
    
    log_debug "Starting atomic operation: $description"
    ((STATS_TOTAL_FILES++))
    
    # Execute command with temp file
    if eval "${command//$target_file/$temp_file}" 2>>"$LOG_FILE"; then
        if [[ -f "$temp_file" && -s "$temp_file" ]]; then
            # Atomic move
            if mv "$temp_file" "$target_file"; then
                log_success "$description completed successfully"
                local file_size
                file_size=$(stat -f%z "$target_file" 2>/dev/null || stat -c%s "$target_file" 2>/dev/null || echo "unknown")
                log_debug "File: $target_file ($file_size bytes)"
                ((STATS_SUCCESS_FILES++))
                # Remove from temp files since it's now permanent
                TEMP_FILES=("${TEMP_FILES[@]/$temp_file}")
                update_progress
                return 0
            else
                log_error "Failed to move temporary file to final location"
            fi
        else
            log_error "$description failed - temporary file is empty or missing"
        fi
    else
        log_error "$description failed - command execution error"
    fi
    
    FAILED_OPERATIONS+=("$description")
    ((STATS_FAILED_FILES++))
    
    if [[ "$is_critical" == "true" ]]; then
        return 1
    else
        update_progress
        return 0
    fi
}

backup_existing_cert_dir() {
    local cert_dir="$1"
    
    if [[ -d "$cert_dir" && "$BACKUP_EXISTING_CERTS" == "true" ]]; then
        local backup_dir="${cert_dir}.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "Backing up existing certificate directory to: $backup_dir"
        
        if cp -r "$cert_dir" "$backup_dir"; then
            log_success "Backup created successfully"
            return 0
        else
            log_error "Failed to create backup"
            return 1
        fi
    fi
    return 0
}

cleanup_on_exit() {
    local exit_code=$?
    
    log_debug "Cleanup started (exit code: $exit_code)"
    
    # Clean up temporary files
    if [[ ${#TEMP_FILES[@]} -gt 0 ]]; then
        log_info "Cleaning up ${#TEMP_FILES[@]} temporary files"
        for temp_file in "${TEMP_FILES[@]}"; do
            [[ -f "$temp_file" ]] && rm -f "$temp_file" 2>/dev/null
        done
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script exited with error. Check log: $LOG_FILE"
    else
        log_success "Script completed successfully"
    fi
    
    exit $exit_code
}

trap cleanup_on_exit EXIT

# =============================================================================
# CA AND CERTIFICATE VALIDATION
# =============================================================================

validate_ca_structure() {
    local ca_name="$1"
    local ca_dir="$BASE_CA_DIR/$ca_name"
    
    log_info "Validating CA structure for '$ca_name'"
    
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
    done
    
    # Validate CA certificate
    if ! openssl x509 -in "$ca_dir/certs/ca.cert.pem" -noout -text >/dev/null 2>>"$LOG_FILE"; then
        log_error "CA certificate is invalid or corrupted"
        return 1
    fi
    
    # Validate CA private key
    if ! openssl rsa -in "$ca_dir/private/ca.key.pem" -check -noout >/dev/null 2>>"$LOG_FILE"; then
        log_error "CA private key is invalid or corrupted"
        return 1
    fi
    
    log_success "CA structure validation passed for '$ca_name'"
    return 0
}

validate_prerequisites() {
    log_info "Validating prerequisites"
    
    # Check OpenSSL
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "OpenSSL is not installed or not in PATH"
        return 1
    fi
    
    local openssl_version
    openssl_version=$(openssl version)
    log_debug "OpenSSL version: $openssl_version"
    
    # Check Java for JKS and BKS (optional)
    if ! command -v keytool >/dev/null 2>&1; then
        log_warning "Java keytool not found - JKS and BKS generation will be skipped"
        WARNING_MESSAGES+=("Java keytool not available")
        ((STATS_WARNINGS++))
    else
        local java_version
        java_version=$(java -version 2>&1 | head -n1)
        log_debug "Java version: $java_version"
        
        # Check for Bouncy Castle provider (for BKS)
        if ! keytool -storetype BKS -help >/dev/null 2>&1; then
            log_warning "Bouncy Castle provider not available - BKS generation may fail"
            WARNING_MESSAGES+=("BKS support requires Bouncy Castle provider")
            ((STATS_WARNINGS++))
        fi
    fi
    
    log_success "Prerequisites validation completed"
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
    atomic_file_operation \
        "Unencrypted private key (PEM)" \
        "openssl genrsa -out '$key_file' $key_size" \
        "$key_file" || return 1
    
    # Generate unencrypted private key (DER)
    atomic_file_operation \
        "Unencrypted private key (DER)" \
        "openssl rsa -in '$key_file' -outform DER -out '$key_der_file'" \
        "$key_der_file" || return 1
    
    # Generate encrypted private key (PEM)
    atomic_file_operation \
        "Encrypted private key (PEM)" \
        "openssl rsa -in '$key_file' -aes256 -out '$pwd_key_file' -passout pass:'$password'" \
        "$pwd_key_file" || return 1
    
    # Generate encrypted private key (DER)
    atomic_file_operation \
        "Encrypted private key (DER)" \
        "openssl rsa -in '$pwd_key_file' -aes256 -outform DER -out '$pwd_key_der_file' -passin pass:'$password' -passout pass:'$password'" \
        "$pwd_key_der_file" || return 1
    
    return 0
}

generate_csr_with_sans() {
    local cn="$1"
    local cert_dir="$2"
    local sans=("${@:3}")
    
    local key_file="$cert_dir/$cn.key.pem"
    local csr_file="$cert_dir/$cn.csr.pem"
    local config_file="$cert_dir/openssl_san.cnf"
    
    log_info "Creating certificate signing request configuration"
    
    # Generate CSR config with SANs
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
subjectAltName = @alt_names

[ alt_names ]
EOF

    # Add SANs to config
    local index=1
    echo "DNS.$index = $cn" >> "$config_file"
    
    for san in "${sans[@]}"; do
        ((index++))
        if [[ $san =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "IP.$((index - 1)) = $san" >> "$config_file"
        else
            echo "DNS.$index = $san" >> "$config_file"
        fi
    done
    
    # Generate CSR
    atomic_file_operation \
        "Certificate signing request" \
        "openssl req -new -key '$key_file' -out '$csr_file' -config '$config_file'" \
        "$csr_file" || return 1
    
    return 0
}

sign_certificate() {
    local ca_name="$1"
    local cn="$2"
    local cert_dir="$3"
    local sans=("${@:4}")
    
    local ca_dir="$BASE_CA_DIR/$ca_name"
    local csr_file="$cert_dir/$cn.csr.pem"
    local cert_file="$cert_dir/$cn.cert.pem"
    local temp_ca_config="$ca_dir/temp_openssl.cnf"
    
    # Create temporary CA config with SANs
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
    
    # Sign certificate
    atomic_file_operation \
        "Signed certificate" \
        "openssl ca -batch -config '$temp_ca_config' -extensions v3_usr -days $DEFAULT_VALIDITY_DAYS -notext -md sha256 -in '$csr_file' -out '$cert_file'" \
        "$cert_file" || return 1
    
    return 0
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
    atomic_file_operation \
        "Certificate (DER)" \
        "openssl x509 -in '$cert_file' -outform DER -out '$cert_dir/$cn.cert.der'" \
        "$cert_dir/$cn.cert.der" \
        false
    
    atomic_file_operation \
        "Certificate chain (DER)" \
        "openssl x509 -in '$chain_file' -outform DER -out '$cert_dir/$cn.chain.cert.der'" \
        "$cert_dir/$cn.chain.cert.der" \
        false
    
    # PKCS#7 bundles
    atomic_file_operation \
        "PKCS#7 bundle (PEM)" \
        "openssl crl2pkcs7 -nocrl -certfile '$chain_file' -out '$cert_dir/$cn.pkcs7.pem'" \
        "$cert_dir/$cn.pkcs7.pem" \
        false
    
    atomic_file_operation \
        "PKCS#7 bundle (DER)" \
        "openssl crl2pkcs7 -nocrl -certfile '$chain_file' -outform DER -out '$cert_dir/$cn.pkcs7.p7b'" \
        "$cert_dir/$cn.pkcs7.p7b" \
        false
    
    # PKCS#12 bundles
    atomic_file_operation \
        "PKCS#12 bundle (with password)" \
        "openssl pkcs12 -export -in '$chain_file' -inkey '$key_file' -out '$cert_dir/$cn.pkcs12.p12' -name '$cn' -passout pass:'$password'" \
        "$cert_dir/$cn.pkcs12.p12" \
        false
    
    atomic_file_operation \
        "PKCS#12 bundle (without password)" \
        "openssl pkcs12 -export -in '$chain_file' -inkey '$key_file' -out '$cert_dir/$cn.nopass.pkcs12.p12' -name '$cn' -passout pass:" \
        "$cert_dir/$cn.nopass.pkcs12.p12" \
        false
    
    # PFX (same as PKCS#12)
    atomic_file_operation \
        "PFX bundle (Windows)" \
        "openssl pkcs12 -export -in '$chain_file' -inkey '$key_file' -out '$cert_dir/$cn.pfx' -name '$cn' -passout pass:'$password'" \
        "$cert_dir/$cn.pfx" \
        false
    
    # Java KeyStore formats (if available)
    generate_java_keystores "$cn" "$cert_dir" "$password"
    
    return 0
}

generate_java_keystores() {
    local cn="$1"
    local cert_dir="$2"
    local password="$3"
    
    if ! command -v keytool >/dev/null 2>&1; then
        log_warning "JKS/BKS creation skipped - Java keytool not available"
        WARNING_MESSAGES+=("JKS/BKS creation skipped")
        ((STATS_WARNINGS++))
        return 0
    fi
    
    local pkcs12_file="$cert_dir/$cn.pkcs12.p12"
    local pkcs12_nopass_file="$cert_dir/$cn.nopass.pkcs12.p12"
    
    # JKS KeyStore
    if keytool -importkeystore -deststorepass "$password" -destkeypass "$password" \
        -destkeystore "$cert_dir/$cn.keystore.jks" \
        -srckeystore "$pkcs12_file" -srcstoretype PKCS12 -srcstorepass "$password" \
        -alias "$cn" >/dev/null 2>>"$LOG_FILE"; then
        log_success "Java KeyStore (JKS) created successfully"
        ((STATS_SUCCESS_FILES++))
        update_progress
    else
        log_warning "JKS KeyStore creation failed"
        WARNING_MESSAGES+=("JKS KeyStore creation failed")
        ((STATS_WARNINGS++))
        ((STATS_FAILED_FILES++))
    fi
    ((STATS_TOTAL_FILES++))
    
    # BKS KeyStore (with password)
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
        WARNING_MESSAGES+=("BKS KeyStore creation failed")
        ((STATS_WARNINGS++))
        ((STATS_FAILED_FILES++))
    fi
    ((STATS_TOTAL_FILES++))
    
    # BKS KeyStore (without password)
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
        WARNING_MESSAGES+=("BKS KeyStore (no password) creation failed")
        ((STATS_WARNINGS++))
        ((STATS_FAILED_FILES++))
    fi
    ((STATS_TOTAL_FILES++))
}

# =============================================================================
# INPUT VALIDATION AND USER INTERACTION
# =============================================================================

validate_input_parameters() {
    local ca_name="$1"
    local cn="$2"
    
    # Validate CA name
    if [[ ! "$ca_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_error "Invalid CA name: $ca_name (only alphanumeric, underscore, and dash allowed)"
        return 1
    fi
    
    # Validate Common Name
    if [[ -z "$cn" ]]; then
        log_error "Common Name cannot be empty"
        return 1
    fi
    
    if [[ ${#cn} -gt 64 ]]; then
        log_error "Common Name too long (max 64 characters): $cn"
        return 1
    fi
    
    # Validate CN format (basic check)
    if [[ ! "$cn" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        log_error "Invalid Common Name format: $cn"
        return 1
    fi
    
    log_success "Input parameters validation passed"
    return 0
}

validate_sans() {
    local sans=("$@")
    
    for san in "${sans[@]}"; do
        # Check if it's an IP address
        if [[ $san =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Basic IP validation
            IFS='.' read -ra ADDR <<< "$san"
            for i in "${ADDR[@]}"; do
                if [[ $i -lt 0 || $i -gt 255 ]]; then
                    log_error "Invalid IP address in SANs: $san"
                    return 1
                fi
            done
        else
            # DNS name validation
            if [[ ! "$san" =~ ^[a-zA-Z0-9._-]+$ ]] || [[ ${#san} -gt 253 ]]; then
                log_error "Invalid DNS name in SANs: $san"
                return 1
            fi
        fi
    done
    
    log_success "SANs validation passed"
    return 0
}

get_password_input() {
    local default_password="$1"
    
    echo ""
    echo -e "${CYAN}🔐 Password Configuration${NC}"
    echo "========================"
    echo "   Press Enter for default password ('$default_password')"
    echo -n "   Or enter custom password: "
    read -s user_password
    echo ""
    
    if [[ -z "$user_password" ]]; then
        echo "$default_password"
        log_info "Using default password"
    else
        echo "$user_password"
        log_info "Using custom password"
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
        echo "  No CAs found. Run create_ca_hierarchy.sh first."
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
        
        # Extract and display certificate information
        local subject
        local validity
        local sans
        
        subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject=//')
        validity=$(openssl x509 -in "$cert_file" -noout -dates 2>/dev/null)
        sans=$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | grep -v "X509v3 Subject Alternative Name:" | tr -d ' ')
        
        echo "   Subject: $subject"
        echo "   $validity"
        [[ -n "$sans" ]] && echo "   SANs: $sans"
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
    echo "⏱️  Duration: ${duration}s"
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
    check_and_display_file "$cert_dir/$cn.keystore.jks" "Java KeyStore (JKS)"
    check_and_display_file "$cert_dir/$cn.keystore.bks" "BKS KeyStore (with pass)"
    check_and_display_file "$cert_dir/$cn.nopass.keystore.bks" "BKS KeyStore (no pass)"
    echo ""
    
    # Other Files
    echo -e "${YELLOW}📋 Other Files:${NC}"
    check_and_display_file "$cert_dir/$cn.csr.pem" "CSR"
    echo ""
}

check_and_display_file() {
    local file_path="$1"
    local description="$2"
    
    if [[ -f "$file_path" ]]; then
        local file_size
        file_size=$(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path" 2>/dev/null || echo "unknown")
        printf "   ✅ %-25s %s (%s bytes)\n" "$description:" "$file_path" "$file_size"
    else
        printf "   ❌ %-25s %s\n" "$description:" "$file_path"
    fi
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
    echo -e "${RED}🔐 Password for encrypted files: $password${NC}"
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
    [[ -n "${LOG_LEVEL:-}" ]] && LOG_LEVEL="$LOG_LEVEL"
    
    # Initialize logging
    setup_logging "cert_issuance"
    
    # Load and validate configuration
    load_configuration || exit 1
    
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
    
    # Initialize progress (17 total steps)
    init_progress 17
    
    # Validate prerequisites
    validate_prerequisites || exit 1
    
    # Validate CA structure
    validate_ca_structure "$ca_name" || exit 1
    
    # Create output directory
    log_info "Setting up output directory"
    backup_existing_cert_dir "$cert_dir"
    mkdir -p "$cert_dir"
    update_progress
    
    # Get password
    local password
    password=$(get_password_input "$DEFAULT_PASSWORD")
    
    # Generate certificate files
    log_info "Starting certificate generation process"
    
    # Step 1-4: Generate private keys
    generate_private_keys "$cn" "$cert_dir" "$DEFAULT_KEY_SIZE" "$password" || exit 1
    
    # Step 5: Generate CSR
    generate_csr_with_sans "$cn" "$cert_dir" "${sans[@]}" || exit 1
    
    # Step 6: Sign certificate
    sign_certificate "$ca_name" "$cn" "$cert_dir" "${sans[@]}" || exit 1
    
    # Step 7: Build certificate chain
    build_certificate_chain "$ca_name" "$cn" "$cert_dir" || exit 1
    
    # Steps 8-17: Generate all certificate formats
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