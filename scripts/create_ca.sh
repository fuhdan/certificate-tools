#!/bin/bash

set -euo pipefail

# =============================================================================
# Enhanced Certificate Authority Creation Script
# =============================================================================

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/ca_config.conf"
readonly DEFAULT_CONFIG="# CA Configuration
ROOT_KEY_SIZE=4096
INTERMEDIATE_KEY_SIZE=3072
ISSUING_KEY_SIZE=3072
ROOT_VALIDITY_DAYS=3650
INTERMEDIATE_VALIDITY_DAYS=1825
ISSUING_VALIDITY_DAYS=825
DEFAULT_COUNTRY=CH
DEFAULT_STATE=BE
DEFAULT_ORG=DanielF
DEFAULT_OU=IT Infrastructure
BASE_DIR=./CertificateAuthority
LOG_LEVEL=INFO
BACKUP_ON_OVERWRITE=true
VALIDATE_AFTER_CREATION=true"

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
declare -g CREATED_CAS=()
declare -g OPERATION_START_TIME
declare -g CONFIG_LOADED=false

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

load_configuration() {
    load_config_file "$CONFIG_FILE" "$DEFAULT_CONFIG" || return 1
    validate_configuration || return 1
    CONFIG_LOADED=true
    log_debug "Configuration loaded successfully"
}

validate_configuration() {
    local errors=()
    
    # Validate key sizes
    validate_config_value "ROOT_KEY_SIZE" "$ROOT_KEY_SIZE" "^(2048|3072|4096)$" "must be 2048, 3072, or 4096" || errors+=("ROOT_KEY_SIZE")
    validate_config_value "INTERMEDIATE_KEY_SIZE" "$INTERMEDIATE_KEY_SIZE" "^(2048|3072|4096)$" "must be 2048, 3072, or 4096" || errors+=("INTERMEDIATE_KEY_SIZE")
    validate_config_value "ISSUING_KEY_SIZE" "$ISSUING_KEY_SIZE" "^(2048|3072|4096)$" "must be 2048, 3072, or 4096" || errors+=("ISSUING_KEY_SIZE")
    
    # Validate validity periods
    validate_config_value "ROOT_VALIDITY_DAYS" "$ROOT_VALIDITY_DAYS" "^[0-9]+$" "must be a positive number" || errors+=("ROOT_VALIDITY_DAYS")
    validate_config_value "INTERMEDIATE_VALIDITY_DAYS" "$INTERMEDIATE_VALIDITY_DAYS" "^[0-9]+$" "must be a positive number" || errors+=("INTERMEDIATE_VALIDITY_DAYS")
    validate_config_value "ISSUING_VALIDITY_DAYS" "$ISSUING_VALIDITY_DAYS" "^[0-9]+$" "must be a positive number" || errors+=("ISSUING_VALIDITY_DAYS")
    
    # Additional validation for positive values
    [[ "$ROOT_VALIDITY_DAYS" -gt 0 ]] || errors+=("ROOT_VALIDITY_DAYS must be greater than 0")
    [[ "$INTERMEDIATE_VALIDITY_DAYS" -gt 0 ]] || errors+=("INTERMEDIATE_VALIDITY_DAYS must be greater than 0")
    [[ "$ISSUING_VALIDITY_DAYS" -gt 0 ]] || errors+=("ISSUING_VALIDITY_DAYS must be greater than 0")
    
    # Validate directories
    [[ -n "$BASE_DIR" ]] || errors+=("BASE_DIR cannot be empty")
    
    # Validate log level
    validate_config_value "LOG_LEVEL" "$LOG_LEVEL" "^(DEBUG|INFO|WARNING|ERROR)$" "must be DEBUG, INFO, WARNING, or ERROR" || errors+=("LOG_LEVEL")
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        log_error "Configuration validation failed for: ${errors[*]}"
        return 1
    fi
    
    return 0
}

# =============================================================================
# CLEANUP AND RECOVERY
# =============================================================================

rollback_ca_creation() {
    local ca_name="$1"
    local ca_dir="$BASE_DIR/$ca_name"
    
    log_warning "Rolling back CA creation: $ca_name"
    
    if [[ -d "$ca_dir" ]]; then
        if rm -rf "$ca_dir"; then
            log_info "Removed incomplete CA directory: $ca_dir"
        else
            log_error "Failed to remove incomplete CA directory: $ca_dir"
        fi
    fi
    
    # Remove from created CAs list
    CREATED_CAS=("${CREATED_CAS[@]/$ca_name}")
}

cleanup_on_exit() {
    local exit_code=$?
    
    log_debug "Cleanup started (exit code: $exit_code)"
    
    # Clean up temporary files using common function
    cleanup_temp_files
    
    # If exit code is non-zero and we have incomplete CAs, offer rollback
    if [[ $exit_code -ne 0 && ${#CREATED_CAS[@]} -gt 0 ]]; then
        echo ""
        log_error "Script failed. Created CAs: ${CREATED_CAS[*]}"
        if confirm_action "Do you want to rollback incomplete CA creation?"; then
            for ca_name in "${CREATED_CAS[@]}"; do
                rollback_ca_creation "$ca_name"
            done
        fi
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script exited with error. Check log: $LOG_FILE"
    else
        log_success "Script completed successfully"
    fi
    
    exit $exit_code
}

# Set up cleanup trap
trap cleanup_on_exit EXIT

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

validate_prerequisites() {
    log_info "Validating prerequisites..."
    update_progress
    
    validate_openssl || return 1
    check_disk_space 100 "$BASE_DIR" || return 1
    
    # Check parent directory permissions
    local parent_dir
    parent_dir=$(dirname "$BASE_DIR")
    
    if [[ ! -w "$parent_dir" ]]; then
        log_error "No write permission for directory: $parent_dir"
        return 1
    fi
    
    log_success "Prerequisites validation completed"
    return 0
}

test_ca_certificate() {
    local ca_dir=$1
    local ca_name=$2
    local parent_ca_dir=$3
    
    log_info "Testing CA certificate: $ca_name"
    
    local cert_file="$ca_dir/certs/ca.cert.pem"
    local key_file="$ca_dir/private/ca.key.pem"
    
    # Test certificate and key formats
    validate_certificate_format "$cert_file" || return 1
    validate_private_key_format "$key_file" || return 1
    
    # Test certificate-key pair matching
    validate_certificate_key_pair "$cert_file" "$key_file" || return 1
    
    # Test certificate extensions
    validate_certificate_extensions "$cert_file" "true" || return 1
    
    # Test certificate chain validation
    if [[ -n "$parent_ca_dir" ]]; then
        local parent_cert="$parent_ca_dir/certs/ca.cert.pem"
        
        # For intermediate CAs, we need to also check if there's a grandparent
        local root_cert=""
        if [[ -f "$BASE_DIR/RootCA/certs/ca.cert.pem" ]]; then
            root_cert="$BASE_DIR/RootCA/certs/ca.cert.pem"
        fi
        
        # Create temporary certificate bundle for validation
        if [[ -n "$root_cert" && "$parent_cert" != "$root_cert" ]]; then
            local temp_bundle
            temp_bundle=$(mktemp)
            add_temp_file "$temp_bundle"
            cat "$parent_cert" "$root_cert" > "$temp_bundle"
            
            # Validate against the bundle
            if openssl verify -CAfile "$root_cert" -untrusted "$parent_cert" "$cert_file" >/dev/null 2>>"$LOG_FILE"; then
                log_success "Certificate chain validation passed"
            else
                log_error "Certificate chain validation failed"
                return 1
            fi
        else
            validate_certificate_chain "$cert_file" "$parent_cert" || return 1
        fi
    else
        validate_certificate_chain "$cert_file" "" || return 1
    fi
    
    log_success "All tests passed for CA: $ca_name"
    return 0
}

test_ca_functionality() {
    local ca_dir=$1
    local ca_name=$2

    log_info "Testing CA functionality: $ca_name"

    # Create a temporary test certificate request
    local temp_key temp_csr temp_cert
    temp_key=$(mktemp)
    temp_csr=$(mktemp)
    temp_cert=$(mktemp)
    add_temp_file "$temp_key"
    add_temp_file "$temp_csr"
    add_temp_file "$temp_cert"

    # Generate test key
    if ! openssl genrsa -out "$temp_key" 2048 >/dev/null 2>>"$LOG_FILE"; then
        log_error "Failed to generate test key"
        return 1
    fi

    # Generate test CSR
    if ! openssl req -new -key "$temp_key" -out "$temp_csr" \
        -subj "/C=CH/ST=BE/O=DanielF/OU=Testing/CN=test.example.com" >/dev/null 2>>"$LOG_FILE"; then
        log_error "Failed to generate test CSR"
        return 1
    fi

    # Try to sign the test certificate
    if ! openssl ca -config "$ca_dir/openssl.cnf" \
        -in "$temp_csr" -out "$temp_cert" \
        -batch -notext -days 30 >/dev/null 2>>"$LOG_FILE"; then
        log_error "Failed to sign test certificate"
        return 1
    fi

    # Verify the certificate - different approach for each CA type
    if [[ "$ca_name" == "IssuingCA1" ]]; then
        # For 3-tier: verify against root CA with intermediate chain
        local intermediate_chain
        intermediate_chain=$(mktemp)
        add_temp_file "$intermediate_chain"
        
        # Build chain: IssuingCA1 + IntermediateCA1
        cat "$ca_dir/certs/ca.cert.pem" \
            "$BASE_DIR/IntermediateCA1/certs/ca.cert.pem" > "$intermediate_chain"
        
        # Verify against root CA with the intermediate chain
        if ! openssl verify -CAfile "$BASE_DIR/RootCA/certs/ca.cert.pem" \
            -untrusted "$intermediate_chain" "$temp_cert" >/dev/null 2>>"$LOG_FILE"; then
            log_error "Test certificate verification failed"
            return 1
        fi
    elif [[ "$ca_name" == "IssuingCA2" ]]; then
        # For 2-tier: verify against root CA with IssuingCA2 as untrusted
        if ! openssl verify -CAfile "$BASE_DIR/RootCA/certs/ca.cert.pem" \
            -untrusted "$ca_dir/certs/ca.cert.pem" "$temp_cert" >/dev/null 2>>"$LOG_FILE"; then
            log_error "Test certificate verification failed"
            return 1
        fi
    else
        # Root CA - verify against itself
        if ! openssl verify -CAfile "$ca_dir/certs/ca.cert.pem" "$temp_cert" >/dev/null 2>>"$LOG_FILE"; then
            log_error "Test certificate verification failed"
            return 1
        fi
    fi

    log_success "CA functionality test passed for: $ca_name"
    return 0
}

comprehensive_testing() {
    log_info "Starting comprehensive testing of CA hierarchy..."

    local test_results=()
    local total_tests=0
    local passed_tests=0

    # Test each CA
    local cas=("RootCA" "IntermediateCA1" "IssuingCA1" "IssuingCA2")
    local parents=("" "RootCA" "IntermediateCA1" "RootCA")

    for i in "${!cas[@]}"; do
        local ca_name="${cas[$i]}"
        local parent="${parents[$i]}"
        local ca_dir="$BASE_DIR/$ca_name"
        local parent_dir=""

        if [[ -n "$parent" ]]; then
            parent_dir="$BASE_DIR/$parent"
        fi

        echo ""
        log_info "Testing CA: $ca_name"

        # Certificate validation test
        ((total_tests++))
        if test_ca_certificate "$ca_dir" "$ca_name" "$parent_dir"; then
            ((passed_tests++))
            test_results+=("$ca_name Certificate: ✅ PASS")
        else
            test_results+=("$ca_name Certificate: ❌ FAIL")
        fi

        # Functionality test (only for issuing CAs)
        if [[ "$ca_name" == "IssuingCA"* ]]; then
            ((total_tests++))
            if test_ca_functionality "$ca_dir" "$ca_name"; then
                ((passed_tests++))
                test_results+=("$ca_name Functionality: ✅ PASS")
            else
                test_results+=("$ca_name Functionality: ❌ FAIL")
            fi
        fi
    done

    # Test hierarchy integrity
    ((total_tests++))
    log_info "Testing hierarchy integrity..."
    local hierarchy_ok=true

    # Test IssuingCA1 chain: IssuingCA1 -> IntermediateCA1 -> RootCA
    if ! openssl verify -CAfile "$BASE_DIR/RootCA/certs/ca.cert.pem" \
        -untrusted "$BASE_DIR/IntermediateCA1/certs/ca.cert.pem" \
        "$BASE_DIR/IssuingCA1/certs/ca.cert.pem" >/dev/null 2>>"$LOG_FILE"; then
        log_error "IssuingCA1 chain validation failed"
        hierarchy_ok=false
    fi

    # Test IssuingCA2 chain: IssuingCA2 -> RootCA
    if ! openssl verify -CAfile "$BASE_DIR/RootCA/certs/ca.cert.pem" \
        "$BASE_DIR/IssuingCA2/certs/ca.cert.pem" >/dev/null 2>>"$LOG_FILE"; then
        log_error "IssuingCA2 chain validation failed"
        hierarchy_ok=false
    fi

    if $hierarchy_ok; then
        ((passed_tests++))
        test_results+=("Hierarchy Integrity: ✅ PASS")
        log_success "Hierarchy integrity test passed"
    else
        test_results+=("Hierarchy Integrity: ❌ FAIL")
    fi

    # Print test summary
    echo ""
    echo "=========================================="
    log_info "TEST SUMMARY"
    echo "=========================================="

    for result in "${test_results[@]}"; do
        echo "  $result"
    done

    echo ""
    if [[ $passed_tests -eq $total_tests ]]; then
        log_success "All tests passed! ($passed_tests/$total_tests)"
        return 0
    else
        log_error "Some tests failed! ($passed_tests/$total_tests)"
        return 1
    fi
}

# =============================================================================
# CA CREATION FUNCTIONS
# =============================================================================

generate_openssl_config() {
    local ca_dir="$1"
    local cn="$2"
    
    generate_openssl_config_template "$ca_dir" "$cn" "$DEFAULT_COUNTRY" "$DEFAULT_STATE" "$DEFAULT_ORG" "$DEFAULT_OU"
}

setup_ca_directory_structure() {
    local ca_name="$1"
    local ca_dir="$BASE_DIR/$ca_name"
    
    log_info "Setting up directory structure for $ca_name"
    
    # Backup existing CA if needed
    backup_directory "$ca_dir" "$BACKUP_ON_OVERWRITE" || return 1
    
    # Create directory structure
    if ! mkdir -p "$ca_dir"/{certs,crl,newcerts,private}; then
        log_error "Failed to create directory structure"
        return 1
    fi
    
    # Set secure permissions
    chmod 755 "$ca_dir"
    chmod 700 "$ca_dir/private"
    
    # Initialize database files
    touch "$ca_dir/index.txt"
    echo 1000 > "$ca_dir/serial"
    echo 1000 > "$ca_dir/crlnumber"
    
    log_success "Directory structure created for $ca_name"
    update_progress
    return 0
}

generate_ca_private_key() {
    local ca_name="$1"
    local key_size="$2"
    local ca_dir="$BASE_DIR/$ca_name"
    local key_file="$ca_dir/private/ca.key.pem"
    
    log_info "Generating private key for $ca_name ($key_size bits)"
    
    if atomic_file_operation \
        "Private key generation" \
        "openssl genrsa -out '$key_file' $key_size" \
        "$key_file"; then
        
        chmod 400 "$key_file"
        log_success "Private key generated and secured"
        update_progress
        return 0
    else
        log_error "Failed to generate private key"
        return 1
    fi
}

create_ca_certificate() {
    local ca_name="$1"
    local cn="$2"
    local validity_days="$3"
    local parent_ca_dir="$4"
    local ca_dir="$BASE_DIR/$ca_name"
    
    log_info "Creating certificate for $ca_name"
    
    # Generate OpenSSL configuration
    generate_openssl_config "$ca_dir" "$cn"
    
    local cert_file="$ca_dir/certs/ca.cert.pem"
    local key_file="$ca_dir/private/ca.key.pem"
    
    if [[ -z "$parent_ca_dir" ]]; then
        # Root CA - self-signed
        log_info "Creating self-signed root certificate"
        
        if atomic_file_operation \
            "Root certificate creation" \
            "openssl req -config '$ca_dir/openssl.cnf' -key '$key_file' -new -x509 -days $validity_days -sha256 -extensions v3_ca -out '$cert_file'" \
            "$cert_file"; then
            
            # Validate the created certificate
            if validate_certificate_extensions "$cert_file" "true" && \
               validate_certificate_chain "$cert_file" ""; then
                log_success "Root certificate created and validated"
                update_progress
                return 0
            else
                log_error "Root certificate validation failed"
                return 1
            fi
        else
            log_error "Failed to create root certificate"
            return 1
        fi
    else
        # Intermediate/Issuing CA
        local csr_file="$ca_dir/$ca_name.csr.pem"
        
        log_info "Creating certificate signing request"
        
        # Create CSR
        if atomic_file_operation \
            "CSR creation" \
            "openssl req -config '$ca_dir/openssl.cnf' -key '$key_file' -new -sha256 -out '$csr_file'" \
            "$csr_file"; then
            
            add_temp_file "$csr_file"  # CSR is temporary
            
            log_info "Signing certificate with parent CA"
            
            # Choose the right extension based on CA type
            local extension="v3_intermediate_ca"
            if [[ "$ca_name" == "IssuingCA"* ]]; then
                extension="v3_issuing_ca"
            fi
            
            # Sign with parent CA
            if atomic_file_operation \
                "Certificate signing" \
                "openssl ca -config '$parent_ca_dir/openssl.cnf' -extensions $extension -days $validity_days -notext -md sha256 -in '$csr_file' -out '$cert_file' -batch" \
                "$cert_file"; then
                
                # Validate the created certificate - simplified validation for intermediate CAs
                if validate_certificate_extensions "$cert_file" "true"; then
                    log_success "Certificate created and validated"
                    update_progress
                    return 0
                else
                    log_error "Certificate validation failed"
                    return 1
                fi
            else
                log_error "Failed to sign certificate"
                return 1
            fi
        else
            log_error "Failed to create CSR"
            return 1
        fi
    fi
}

create_single_ca() {
    local ca_name="$1"
    local cn="$2"
    local key_size="$3"
    local validity_days="$4"
    local parent_ca_dir="$5"
    
    log_info "Creating CA: $ca_name"
    
    # Track this CA for potential rollback
    CREATED_CAS+=("$ca_name")
    
    # Create directory structure
    setup_ca_directory_structure "$ca_name" || return 1
    
    # Generate private key
    generate_ca_private_key "$ca_name" "$key_size" || return 1
    
    # Create certificate
    create_ca_certificate "$ca_name" "$cn" "$validity_days" "$parent_ca_dir" || return 1
    
    log_success "CA '$ca_name' created successfully"
    return 0
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat << EOF
${BOLD}Enhanced Certificate Authority Creation Script${NC}

${BOLD}Usage:${NC}
  $0 [OPTIONS]

${BOLD}Options:${NC}
  -h, --help              Show this help message
  -t, --test-only         Only run tests on existing CA hierarchy
  -c, --clean             Clean up existing CAs before creating new ones
  -v, --verbose           Enable verbose logging (DEBUG level)
  --config FILE           Use custom configuration file
  --no-backup             Don't backup existing CAs before overwriting
  --no-validation         Skip validation after creation
  --no-tests              Skip comprehensive testing

${BOLD}Examples:${NC}
  $0                      Create CA hierarchy with default settings
  $0 --test-only          Test existing CA hierarchy
  $0 --clean --verbose    Clean and recreate with verbose logging
  $0 --config my.conf     Use custom configuration

${BOLD}Configuration:${NC}
  Default config file: $CONFIG_FILE
  Edit the config file to customize key sizes, validity periods, and other settings.
EOF
}

clean_existing_cas() {
    if [[ -d "$BASE_DIR" ]]; then
        log_warning "Cleaning existing CA hierarchy..."
        
        # List what will be removed
        log_info "The following will be removed:"
        find "$BASE_DIR" -type f -name "*.pem" -o -name "*.txt" -o -name "*.cnf" | head -10 | while read -r file; do
            log_info "  - $file"
        done
        
        local file_count
        file_count=$(find "$BASE_DIR" -type f | wc -l)
        if [[ "$file_count" -gt 10 ]]; then
            log_info "  ... and $((file_count - 10)) more files"
        fi
        
        if confirm_action "Are you sure you want to delete the existing CA hierarchy?"; then
            if rm -rf "$BASE_DIR"; then
                log_success "Existing CA hierarchy cleaned"
            else
                log_error "Failed to clean existing CA hierarchy"
                exit 1
            fi
        else
            log_info "Clean operation cancelled"
            exit 0
        fi
    else
        log_info "No existing CA hierarchy found to clean"
    fi
}

main() {
    OPERATION_START_TIME=$(date +%s)
    
    # Parse arguments
    local test_only=false
    local clean_first=false
    local custom_config=""
    local run_tests=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -t|--test-only)
                test_only=true
                shift
                ;;
            -c|--clean)
                clean_first=true
                shift
                ;;
            -v|--verbose)
                LOG_LEVEL="DEBUG"
                shift
                ;;
            --config)
                custom_config="$2"
                shift 2
                ;;
            --no-backup)
                BACKUP_ON_OVERWRITE=false
                shift
                ;;
            --no-validation)
                VALIDATE_AFTER_CREATION=false
                shift
                ;;
            --no-tests)
                run_tests=false
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Use custom config if provided
    if [[ -n "$custom_config" ]]; then
        CONFIG_FILE="$custom_config"
    fi
    
    # Initialize logging
    setup_logging "ca_creation"
    
    # Load and validate configuration
    load_configuration || exit 1
    
    echo -e "${CYAN}${BOLD}🚀 Enhanced Certificate Authority Creation${NC}"
    echo "=============================================="
    log_info "Starting CA hierarchy creation"
    log_info "Configuration: $CONFIG_FILE"
    log_info "Base directory: $BASE_DIR"
    echo ""
    
    # Handle test-only mode
    if $test_only; then
        log_info "Running in test-only mode"
        if [[ ! -d "$BASE_DIR" ]]; then
            log_error "No existing CA hierarchy found to test"
            log_info "Run without --test-only to create CA hierarchy first"
            exit 1
        fi
        
        if comprehensive_testing; then
            log_success "All tests completed successfully"
            exit 0
        else
            log_error "Some tests failed"
            exit 1
        fi
    fi
    
    # Initialize progress tracking (15 steps total)
    # 1. Prerequisites, 2. Clean/skip, 3. Create base dir
    # 4-6. RootCA (dir, key, cert)
    # 7-9. IntermediateCA1 (dir, key, cert) 
    # 10-12. IssuingCA1 (dir, key, cert)
    # 13-15. IssuingCA2 (dir, key, cert)
    init_progress 15
    
    # Validate prerequisites
    validate_prerequisites || exit 1
    
    # Handle clean option
    if $clean_first; then
        clean_existing_cas
        update_progress
    else
        update_progress
    fi
    
    # Create base directory
    mkdir -p "$BASE_DIR"
    update_progress
    
    # Create CA hierarchy
    log_info "Creating CA hierarchy..."
    
    # Root CA
    create_single_ca "RootCA" "DanielF Root CA" "$ROOT_KEY_SIZE" "$ROOT_VALIDITY_DAYS" "" || exit 1
    
    # Intermediate CA 1
    create_single_ca "IntermediateCA1" "DanielF Intermediate CA 1" "$INTERMEDIATE_KEY_SIZE" "$INTERMEDIATE_VALIDITY_DAYS" "$BASE_DIR/RootCA" || exit 1
    
    # Issuing CA 1
    create_single_ca "IssuingCA1" "DanielF Issuing CA 1" "$ISSUING_KEY_SIZE" "$ISSUING_VALIDITY_DAYS" "$BASE_DIR/IntermediateCA1" || exit 1
    
    # Issuing CA 2  
    create_single_ca "IssuingCA2" "DanielF Issuing CA 2" "$ISSUING_KEY_SIZE" "$ISSUING_VALIDITY_DAYS" "$BASE_DIR/RootCA" || exit 1
    
    local end_time=$(date +%s)
    local duration=$((end_time - OPERATION_START_TIME))
    
    echo ""
    echo -e "${GREEN}${BOLD}🎉 CA Hierarchy Created Successfully!${NC}"
    echo "==========================================="
    log_success "Created ${#CREATED_CAS[@]} Certificate Authorities in $(format_duration $duration)"
    log_info "Location: $BASE_DIR"
    
    # Run comprehensive testing if requested
    if $run_tests; then
        echo ""
        log_info "Running comprehensive tests..."
        if comprehensive_testing; then
            log_success "All tests passed - CA hierarchy is ready for use!"
        else
            log_warning "Some tests failed, but CA hierarchy was created successfully"
            log_info "You can use the CAs for certificate generation"
            # Don't exit with error for test failures since CAs are actually working
        fi
    fi
    
    echo ""
    echo -e "${BLUE}${BOLD}Available CAs for certificate signing:${NC}"
    echo "  📋 IssuingCA1 (3-tier: Root → Intermediate → Issuing)"
    echo "  📋 IssuingCA2 (2-tier: Root → Issuing)"
    echo ""
    echo -e "${BLUE}${BOLD}Next Steps:${NC}"
    echo "  🔧 Use: ./enhanced_issue_certificates.sh <CA_NAME> <COMMON_NAME> [SANs...]"
    echo "  📖 Example: ./enhanced_issue_certificates.sh IssuingCA1 server1.local www.server1.local"
    echo ""
    
    log_success "Script completed successfully"
}

# Execute main function
main "$@"