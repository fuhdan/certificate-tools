#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# Certificate Authority Creation Script
# =============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/ca_config.conf"

# Global verbose and debug flag
VERBOSE_MODE=false
DEBUG_MODE=false

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly GRAY='\033[0;90m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'  # No Color (reset)

# =============================================================================
# OS DETECTION
# =============================================================================

detect_os() {
    case "$(uname -s)" in
        Darwin*)    OS_TYPE="macos" ;;
        Linux*)     
            if [[ -f /etc/redhat-release ]]; then
                OS_TYPE="rhel"
            elif [[ -f /etc/debian_version ]]; then
                OS_TYPE="ubuntu"
            else
                OS_TYPE="linux"
            fi
            ;;
        *)          
            echo "❌ ERROR: Unsupported OS: $(uname -s)"
            exit 1
            ;;
    esac
    
    # Detect SSL implementation
    if command -v openssl >/dev/null 2>&1; then
        if openssl version | grep -q "LibreSSL"; then
            SSL_TYPE="libressl"
        else
            SSL_TYPE="openssl"
        fi
    else
        echo "❌ ERROR: OpenSSL not found"
        exit 1
    fi
    
    echo "🖥️  Detected: $OS_TYPE with $SSL_TYPE"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Operating system details: $(uname -a)"
        echo -e "${PURPLE}🔍 VERBOSE:${NC} OpenSSL version: $(openssl version)"
    fi
}

# =============================================================================
# CONFIGURATION LOADING
# =============================================================================

create_default_config() {
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Creating default configuration file"
    fi
    
    cat > "$CONFIG_FILE" << 'EOF'
# =============================================================================
# Certificate Authority Infrastructure Configuration
# =============================================================================

# Infrastructure Topology
ROOT_CA_NAME="RootCA"
ROOT_CA_CN="DanielF Root Certificate Authority"

# Intermediate CAs: CA_NAME:COMMON_NAME:PARENT_CA:DESCRIPTION
INTERMEDIATE_CAS=(
    "IntermediateCA1:DanielF Intermediate CA 1:RootCA:Primary intermediate CA"
)

# Issuing CAs: CA_NAME:COMMON_NAME:PARENT_CA:DESCRIPTION
ISSUING_CAS=(
    "IssuingCA1:DanielF Issuing CA 1:IntermediateCA1:3-tier chain issuing CA"
    "IssuingCA2:DanielF Issuing CA 2:RootCA:2-tier chain issuing CA"
)

# Enable/Disable CAs
CREATE_ROOT_CA=true
CREATE_INTERMEDIATE_CA1=true
CREATE_ISSUING_CA1=true
CREATE_ISSUING_CA2=true

# Cryptographic Parameters
ROOT_KEY_SIZE=4096
INTERMEDIATE_KEY_SIZE=3072
ISSUING_KEY_SIZE=3072
ROOT_VALIDITY_DAYS=3650
INTERMEDIATE_VALIDITY_DAYS=1825
ISSUING_VALIDITY_DAYS=825
HASH_ALGORITHM="sha256"

# Distinguished Name Components
DEFAULT_COUNTRY="CH"
DEFAULT_STATE="BE"
DEFAULT_LOCALITY=""
DEFAULT_ORG="DanielF"
DEFAULT_OU="IT Infrastructure"
DEFAULT_EMAIL=""

# Directory Structure
BASE_DIR="./CertificateAuthority"

# Security Settings
BACKUP_EXISTING_CAS=true
VALIDATE_AFTER_CREATION=true
RUN_COMPREHENSIVE_TESTS=true
SERIAL_START=1000

# Logging
LOG_LEVEL="INFO"
USE_COLORS=true
SHOW_PROGRESS=true
EOF
}

load_config() {
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Loading configuration from: $CONFIG_FILE"
    fi
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        create_default_config
        echo "📝 Created default config: $CONFIG_FILE"
    fi
    
    source "$CONFIG_FILE"
    echo "✅ Configuration loaded"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} BASE_DIR: $BASE_DIR"
        echo -e "${YELLOW}🐛 DEBUG:${NC} ROOT_KEY_SIZE: $ROOT_KEY_SIZE"
        echo -e "${YELLOW}🐛 DEBUG:${NC} DEFAULT_ORG: $DEFAULT_ORG"
    fi
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log_info() { echo -e "${BLUE}ℹ️  INFO:${NC} $1"; }
log_success() { echo -e "${GREEN}✅ SUCCESS:${NC} $1"; }
log_error() { echo -e "${RED}❌ ERROR:${NC} $1"; }

validate_prerequisites() {
    log_info "Validating prerequisites"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Checking OpenSSL availability"
    fi
    
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "OpenSSL not found"
        return 1
    fi
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} OpenSSL path: $(which openssl)"
    fi
    
    local parent_dir=$(dirname "$BASE_DIR")
    if [[ ! -w "$parent_dir" ]]; then
        log_error "No write permission for directory: $parent_dir"
        return 1
    fi
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Parent directory: $parent_dir"
        echo -e "${YELLOW}🐛 DEBUG:${NC} Directory permissions: $(ls -ld "$parent_dir")"
    fi
    
    log_success "Prerequisites validation completed"
}

# =============================================================================
# CA REGISTRY AND DEPENDENCY RESOLUTION
# =============================================================================

declare -A CA_REGISTRY=()
declare -A CA_TYPES=()
declare -A CA_DEPENDENCIES=()
declare -a CA_CREATION_ORDER=()

parse_ca_config() {
    log_info "Parsing CA configuration"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Processing CA configuration arrays"
    fi
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Root CA name: $ROOT_CA_NAME"
        echo -e "${YELLOW}🐛 DEBUG:${NC} Intermediate CAs count: ${#INTERMEDIATE_CAS[@]}"
        echo -e "${YELLOW}🐛 DEBUG:${NC} Issuing CAs count: ${#ISSUING_CAS[@]}"
    fi
    
    # Register Root CA
    if [[ "${CREATE_ROOT_CA:-true}" == "true" ]]; then
        CA_REGISTRY["$ROOT_CA_NAME"]="$ROOT_CA_CN"
        CA_TYPES["$ROOT_CA_NAME"]="root"
        CA_DEPENDENCIES["$ROOT_CA_NAME"]=""
        log_info "Registered Root CA: $ROOT_CA_NAME"
    fi
    
    # Parse and register Intermediate CAs
    for ca_def in "${INTERMEDIATE_CAS[@]}"; do
        IFS=':' read -r ca_name cn parent_ca description <<< "$ca_def"
        
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Processing intermediate CA: $ca_def"
        fi
        
        # Check if this CA is enabled
        local enable_var="CREATE_${ca_name^^}"
        enable_var="${enable_var//[^A-Z0-9_]/_}"  # Replace non-alphanumeric with underscore
        
        if [[ "${!enable_var:-true}" == "true" ]]; then
            CA_REGISTRY["$ca_name"]="$cn"
            CA_TYPES["$ca_name"]="intermediate"
            CA_DEPENDENCIES["$ca_name"]="$parent_ca"
            log_info "Registered Intermediate CA: $ca_name -> $parent_ca"
        else
            log_info "Skipping disabled Intermediate CA: $ca_name"
        fi
    done
    
    # Parse and register Issuing CAs
    for ca_def in "${ISSUING_CAS[@]}"; do
        IFS=':' read -r ca_name cn parent_ca description <<< "$ca_def"
        
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Processing issuing CA: $ca_def"
        fi
        
        # Check if this CA is enabled
        local enable_var="CREATE_${ca_name^^}"
        enable_var="${enable_var//[^A-Z0-9_]/_}"
        
        if [[ "${!enable_var:-true}" == "true" ]]; then
            CA_REGISTRY["$ca_name"]="$cn"
            CA_TYPES["$ca_name"]="issuing"
            CA_DEPENDENCIES["$ca_name"]="$parent_ca"
            log_info "Registered Issuing CA: $ca_name -> $parent_ca"
        else
            log_info "Skipping disabled Issuing CA: $ca_name"
        fi
    done

    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Total CAs registered: ${#CA_REGISTRY[@]}"
    fi

    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Complete CA registry:"
        for ca in "${!CA_REGISTRY[@]}"; do
            echo -e "${YELLOW}🐛 DEBUG:${NC}   $ca: ${CA_REGISTRY[$ca]} (${CA_TYPES[$ca]}, parent: ${CA_DEPENDENCIES[$ca]:-none})"
        done
    fi
}

resolve_dependencies() {
    log_info "Resolving CA dependencies"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Starting topological sort"
    fi
    
    local -A visited=()
    local -A temp_mark=()
    
    topological_sort() {
        local ca="$1"
        
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Visiting CA: $ca"
        fi
        
        if [[ "${temp_mark[$ca]:-}" == "true" ]]; then
            log_error "Circular dependency detected involving CA: $ca"
            return 1
        fi
        
        if [[ "${visited[$ca]:-}" == "true" ]]; then
            return 0
        fi
        
        temp_mark["$ca"]="true"
        
        # Visit dependencies first
        local parent="${CA_DEPENDENCIES[$ca]}"
        if [[ -n "$parent" && "${CA_REGISTRY[$parent]:-}" ]]; then
            if [[ "$DEBUG_MODE" == "true" ]]; then
                echo -e "${YELLOW}🐛 DEBUG:${NC} CA $ca depends on $parent, processing parent first"
            fi
            topological_sort "$parent"
        fi
        
        temp_mark["$ca"]="false"
        visited["$ca"]="true"
        CA_CREATION_ORDER+=("$ca")
        
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Added $ca to creation order"
        fi
    }
    
    # Sort all CAs
    for ca in "${!CA_REGISTRY[@]}"; do
        if [[ "${visited[$ca]:-}" != "true" ]]; then
            topological_sort "$ca"
        fi
    done
    
    log_success "Dependency resolution completed"
    log_info "Creation order: ${CA_CREATION_ORDER[*]}"
}

# =============================================================================
# OPENSSL CONFIGURATION GENERATION
# =============================================================================

generate_openssl_config() {
    local ca_dir="$1"
    local cn="$2"
    local ca_type="$3"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Generating OpenSSL config for $ca_type CA: $ca_dir/openssl.cnf"
    fi
    
    local locality_line=""
    [[ -n "${DEFAULT_LOCALITY:-}" ]] && locality_line="L  = $DEFAULT_LOCALITY"
    
    local email_line=""
    [[ -n "${DEFAULT_EMAIL:-}" ]] && email_line="emailAddress = $DEFAULT_EMAIL"
    
    cat > "$ca_dir/openssl.cnf" << EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ca_dir
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem
default_days      = ${ISSUING_VALIDITY_DAYS:-825}
default_md        = ${HASH_ALGORITHM:-sha256}
policy            = policy_loose
unique_subject    = no

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
prompt              = no
default_md          = ${HASH_ALGORITHM:-sha256}
distinguished_name  = dn
x509_extensions     = v3_ca

[ dn ]
C  = ${DEFAULT_COUNTRY:-CH}
ST = ${DEFAULT_STATE:-BE}
${locality_line}
O  = ${DEFAULT_ORG:-DanielF}
OU = ${DEFAULT_OU:-IT Infrastructure}
CN = $cn
${email_line}

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_issuing_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF
}

# =============================================================================
# CA CREATION FUNCTIONS
# =============================================================================

setup_ca_directory() {
    local ca_name="$1"
    local ca_dir="$BASE_DIR/$ca_name"
    
    log_info "Setting up directory structure for $ca_name"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} CA directory: $ca_dir"
    fi
    
    # Backup existing if present
    if [[ -d "$ca_dir" && "${BACKUP_EXISTING_CAS:-true}" == "true" ]]; then
        local backup_dir="${ca_dir}.backup.$(date +%Y%m%d_%H%M%S)"
        mv "$ca_dir" "$backup_dir"
        log_info "Backed up existing CA to: $backup_dir"
    fi
    
    # Create directory structure
    mkdir -p "$ca_dir"/{certs,crl,newcerts,private}
    chmod 700 "$ca_dir/private"
    
    # Initialize database files
    touch "$ca_dir/index.txt"
    
    # Serial number - use randomization if enabled
    if [[ "${USE_SERIAL_RANDOMIZATION:-false}" == "true" ]]; then
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Using random serial number"
        fi
        # Generate random 16-byte hex serial number
        local random_serial
        random_serial=$(openssl rand -hex 16 | tr '[:lower:]' '[:upper:]')
        echo "$random_serial" > "$ca_dir/serial"
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Generated random serial: $random_serial"
        fi
    else
        echo "${SERIAL_START:-1000}" > "$ca_dir/serial"
        if [[ "$DEBUG_MODE" == "true" ]]; then
            echo -e "${YELLOW}🐛 DEBUG:${NC} Using sequential serial starting from: ${SERIAL_START:-1000}"
        fi
    fi
    
    echo "${SERIAL_START:-1000}" > "$ca_dir/crlnumber"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Created directories: certs, crl, newcerts, private"
        echo -e "${YELLOW}🐛 DEBUG:${NC} Initialized database files"
    fi
    
    log_success "Directory structure created for $ca_name"
}

get_ca_key_size() {
    local ca_type="$1"
    
    case "$ca_type" in
        "root") echo "${ROOT_KEY_SIZE:-4096}" ;;
        "intermediate") echo "${INTERMEDIATE_KEY_SIZE:-3072}" ;;
        "issuing") echo "${ISSUING_KEY_SIZE:-3072}" ;;
        *) echo "3072" ;;
    esac
}

get_ca_validity() {
    local ca_type="$1"
    
    case "$ca_type" in
        "root") echo "${ROOT_VALIDITY_DAYS:-3650}" ;;
        "intermediate") echo "${INTERMEDIATE_VALIDITY_DAYS:-1825}" ;;
        "issuing") echo "${ISSUING_VALIDITY_DAYS:-825}" ;;
        *) echo "825" ;;
    esac
}

generate_ca_key() {
    local ca_name="$1"
    local ca_type="$2"
    local ca_dir="$BASE_DIR/$ca_name"
    local key_file="$ca_dir/private/ca.key.pem"
    local key_size=$(get_ca_key_size "$ca_type")
    
    log_info "Generating private key for $ca_name ($key_size bits)"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Key file: $key_file"
        local start_time=$(date +%s)
    fi

    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Starting RSA key generation"
        local start_time=$(date +%s)
    fi
    
    openssl genrsa -out "$key_file" "$key_size"
    chmod 400 "$key_file"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${YELLOW}🐛 DEBUG:${NC} Key generation completed in ${duration}s"
        echo -e "${YELLOW}🐛 DEBUG:${NC} Set permissions to 400"
    fi
    
    log_success "Private key generated for $ca_name"
}

create_root_certificate() {
    local ca_name="$1"
    local cn="$2"
    local ca_dir="$BASE_DIR/$ca_name"
    local validity_days=$(get_ca_validity "root")
    
    log_info "Creating self-signed root certificate for $ca_name"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Validity: $validity_days days"
        echo -e "${PURPLE}🔍 VERBOSE:${NC} SSL type: $SSL_TYPE"
    fi
    
    generate_openssl_config "$ca_dir" "$cn" "root"
    
    local cert_file="$ca_dir/certs/ca.cert.pem"
    local key_file="$ca_dir/private/ca.key.pem"
    
    if [[ "$SSL_TYPE" == "libressl" ]]; then
        if [[ "$VERBOSE_MODE" == "true" ]]; then
            echo -e "${PURPLE}🔍 VERBOSE:${NC} Using LibreSSL compatible method"
        fi
        
        # LibreSSL compatible approach
        local ext_file="$ca_dir/v3_ca.ext"
        cat > "$ext_file" << EOF
[ v3_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF
        
        local csr_temp="$ca_dir/temp_root.csr"
        openssl req -config "$ca_dir/openssl.cnf" -key "$key_file" -new -out "$csr_temp"
        openssl x509 -req -in "$csr_temp" -signkey "$key_file" -out "$cert_file" \
            -days "$validity_days" -sha256 -extensions v3_ca -extfile "$ext_file"
        rm -f "$csr_temp" "$ext_file"
    else
        if [[ "$VERBOSE_MODE" == "true" ]]; then
            echo -e "${PURPLE}🔍 VERBOSE:${NC} Using standard OpenSSL method"
        fi
        
        # Standard OpenSSL approach
        openssl req -config "$ca_dir/openssl.cnf" -key "$key_file" -new -x509 \
            -days "$validity_days" -sha256 -extensions v3_ca -out "$cert_file"
    fi
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject=//')
        echo -e "${YELLOW}🐛 DEBUG:${NC} Certificate subject: $subject"
    fi
    
    log_success "Root certificate created for $ca_name"
}

create_subordinate_certificate() {
    local ca_name="$1"
    local cn="$2"
    local parent_ca="$3"
    local ca_type="$4"
    local ca_dir="$BASE_DIR/$ca_name"
    local parent_ca_dir="$BASE_DIR/$parent_ca"
    local validity_days=$(get_ca_validity "$ca_type")
    
    log_info "Creating $ca_type certificate for $ca_name (signed by $parent_ca)"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Validity: $validity_days days"
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Parent CA: $parent_ca"
    fi
    
    generate_openssl_config "$ca_dir" "$cn" "$ca_type"
    
    local cert_file="$ca_dir/certs/ca.cert.pem"
    local key_file="$ca_dir/private/ca.key.pem"
    local csr_file="$ca_dir/$ca_name.csr.pem"
    
    # Create CSR
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Creating certificate signing request"
    fi
    openssl req -config "$ca_dir/openssl.cnf" -key "$key_file" -new -sha256 -out "$csr_file"
    
    # Determine extension based on CA type
    local extension="v3_${ca_type}_ca"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        echo -e "${YELLOW}🐛 DEBUG:${NC} Using extension: $extension"
        echo -e "${YELLOW}🐛 DEBUG:${NC} Signing with parent CA"
    fi
    
    # Sign with parent CA
    openssl ca -config "$parent_ca_dir/openssl.cnf" -extensions "$extension" \
        -days "$validity_days" -notext -md sha256 -in "$csr_file" -out "$cert_file" -batch
    
    rm -f "$csr_file"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject=//')
        echo -e "${YELLOW}🐛 DEBUG:${NC} Certificate subject: $subject"
    fi
    
    log_success "$ca_type certificate created for $ca_name"
}

create_single_ca() {
    local ca_name="$1"
    local cn="$2"
    local ca_type="$3"
    local parent_ca="$4"
    
    log_info "Creating CA: $ca_name (type: $ca_type)"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} CA details: name=$ca_name, type=$ca_type, parent=${parent_ca:-none}"
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Key size: $(get_ca_key_size "$ca_type"), Validity: $(get_ca_validity "$ca_type") days"
    fi
    
    setup_ca_directory "$ca_name"
    generate_ca_key "$ca_name" "$ca_type"
    
    if [[ "$ca_type" == "root" ]]; then
        create_root_certificate "$ca_name" "$cn"
    else
        create_subordinate_certificate "$ca_name" "$cn" "$parent_ca" "$ca_type"
    fi
    
    log_success "CA '$ca_name' created successfully"
}

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

test_ca_hierarchy() {
    log_info "Testing CA hierarchy"
    local test_passed=true
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Validating certificate chains"
    fi
    
    # Test each issuing CA chain
    for ca_name in "${!CA_REGISTRY[@]}"; do
        if [[ "${CA_TYPES[$ca_name]}" == "issuing" ]]; then
            log_info "Testing chain for $ca_name"
            
            if [[ "$DEBUG_MODE" == "true" ]]; then
                echo -e "${YELLOW}🐛 DEBUG:${NC} Building certificate chain for: $ca_name"
            fi
            
            # Build chain to root
            local current_ca="$ca_name"
            local chain_certs=()
            local root_ca=""
            
            while [[ -n "$current_ca" ]]; do
                chain_certs+=("$BASE_DIR/$current_ca/certs/ca.cert.pem")
                local parent="${CA_DEPENDENCIES[$current_ca]}"
                
                if [[ -z "$parent" || "${CA_TYPES[$parent]}" == "root" ]]; then
                    root_ca="$parent"
                    break
                fi
                current_ca="$parent"
            done
            
            # Verify chain
            if [[ -n "$root_ca" ]]; then
                local verify_cmd="openssl verify -CAfile $BASE_DIR/$root_ca/certs/ca.cert.pem"
                
                # Add intermediate certificates if any
                if [[ ${#chain_certs[@]} -gt 1 ]]; then
                    local untrusted_certs=""
                    for ((i=1; i<${#chain_certs[@]}; i++)); do
                        untrusted_certs="$untrusted_certs ${chain_certs[i]}"
                    done
                    verify_cmd="$verify_cmd -untrusted <(cat$untrusted_certs)"
                fi
                
                verify_cmd="$verify_cmd ${chain_certs[0]}"
                
                if [[ "$DEBUG_MODE" == "true" ]]; then
                    echo -e "${YELLOW}🐛 DEBUG:${NC} Verification command: $verify_cmd"
                fi
                
                if eval "$verify_cmd" >/dev/null 2>&1; then
                    log_success "$ca_name chain validation passed"
                else
                    log_error "$ca_name chain validation failed"
                    test_passed=false
                fi
            fi
        fi
    done
    
    if [[ "$test_passed" == "true" ]]; then
        log_success "All hierarchy tests passed"
        return 0
    else
        log_error "Some hierarchy tests failed"
        return 1
    fi
}

display_ca_hierarchy() {
    echo ""
    echo "📁 Created CA Hierarchy:"
    echo "========================"
    
    # Display root CAs first
    for ca_name in "${CA_CREATION_ORDER[@]}"; do
        if [[ "${CA_TYPES[$ca_name]}" == "root" ]]; then
            echo "  📋 $ca_name (Root CA)"
            display_ca_children "$ca_name" "  "
        fi
    done
}

display_ca_children() {
    local parent_ca="$1"
    local indent="$2"
    
    for ca_name in "${CA_CREATION_ORDER[@]}"; do
        if [[ "${CA_DEPENDENCIES[$ca_name]}" == "$parent_ca" ]]; then
            local ca_type="${CA_TYPES[$ca_name]}"
            case "$ca_type" in
                "intermediate") echo "${indent}├── 📋 $ca_name (Intermediate CA)" ;;
                "issuing") echo "${indent}└── 📋 $ca_name (Issuing CA)" ;;
            esac
            display_ca_children "$ca_name" "${indent}│   "
        fi
    done
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat << EOF
Certificate Authority Creation Script

Usage: $0 [OPTIONS]

Options:
  -h, --help     Show this help message
  -c, --clean    Clean existing CAs before creating new ones
  -t, --test     Only test existing CA hierarchy
  -s, --show     Show configured CA hierarchy without creating
  -v, --verbose  Enable verbose output with detailed logging

Examples:
  $0             Create CA hierarchy from config
  $0 --clean     Clean and recreate CA hierarchy
  $0 --test      Test existing hierarchy
  $0 --show      Show what would be created
  $0 --verbose   Create with detailed verbose output

Configuration:
  Edit $CONFIG_FILE to define your CA infrastructure
EOF
}

main() {
    local clean_first=false
    local test_only=false
    local show_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -c|--clean)
                clean_first=true
                shift
                ;;
            -t|--test)
                test_only=true
                shift
                ;;
            -s|--show)
                show_only=true
                shift
                ;;
            -v|--verbose)
                VERBOSE_MODE=true
                shift
                ;;
            -d|--debug)
                DEBUG_MODE=true
                VERBOSE_MODE=true  # Debug includes verbose
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    echo "🚀 Certificate Authority Creation Script"
    echo "======================================="
    
    detect_os
    load_config
    parse_ca_config
    resolve_dependencies
    
    if [[ "$show_only" == "true" ]]; then
        echo ""
        echo "🔍 Configured CA Hierarchy (would be created):"
        display_ca_hierarchy
        exit 0
    fi
    
    if [[ "$test_only" == "true" ]]; then
        if [[ ! -d "$BASE_DIR" ]]; then
            log_error "No existing CA hierarchy found"
            exit 1
        fi
        test_ca_hierarchy
        exit 0
    fi
    
    validate_prerequisites
    
    if [[ "$clean_first" == "true" && -d "$BASE_DIR" ]]; then
        log_info "Cleaning existing CA hierarchy"
        if [[ "$VERBOSE_MODE" == "true" ]]; then
            echo -e "${PURPLE}🔍 VERBOSE:${NC} Removing directory: $BASE_DIR"
        fi
        rm -rf "$BASE_DIR"
    fi
    
    mkdir -p "$BASE_DIR"
    
    echo ""
    log_info "Creating CA hierarchy in dependency order..."
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Total CAs to create: ${#CA_CREATION_ORDER[@]}"
        local overall_start=$(date +%s)
    fi
    
    # Create CAs in dependency order
    for ca_name in "${CA_CREATION_ORDER[@]}"; do
        local cn="${CA_REGISTRY[$ca_name]}"
        local ca_type="${CA_TYPES[$ca_name]}"
        local parent_ca="${CA_DEPENDENCIES[$ca_name]}"
        
        create_single_ca "$ca_name" "$cn" "$ca_type" "$parent_ca"
    done
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        local overall_end=$(date +%s)
        local total_time=$((overall_end - overall_start))
        echo -e "${PURPLE}🔍 VERBOSE:${NC} Total creation time: ${total_time}s"
    fi
    
    echo ""
    log_success "CA hierarchy created successfully!"
    
    # Test the hierarchy if enabled
    if [[ "${RUN_COMPREHENSIVE_TESTS:-true}" == "true" ]]; then
        test_ca_hierarchy
    fi
    
    # Display created hierarchy
    display_ca_hierarchy
    
    echo ""
    echo "🎯 Next steps:"
    echo "  Use issuing CAs to sign end-entity certificates"
    echo "  Location: $BASE_DIR"
    echo "  Config: $CONFIG_FILE"
}

main "$@"
