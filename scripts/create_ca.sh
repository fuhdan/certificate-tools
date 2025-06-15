#!/bin/bash

set -e

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

BASE_DIR="./CertificateAuthority"
LOG_FILE="./ca_creation.log"
TEMP_FILES=()

# Track temporary files for cleanup
add_temp_file() {
  TEMP_FILES+=("$1")
}

# Cleanup function
cleanup() {
  local exit_code=$?

  if [ ${#TEMP_FILES[@]} -gt 0 ]; then
    log_info "Cleaning up temporary files..."
    for temp_file in "${TEMP_FILES[@]}"; do
      if [ -f "$temp_file" ]; then
        rm -f "$temp_file" 2>/dev/null && log_info "Removed: $temp_file" || log_warning "Failed to remove: $temp_file"
      fi
    done
  fi

  if [ $exit_code -ne 0 ]; then
    log_error "Script exited with error code $exit_code"
    log_info "Check $LOG_FILE for detailed error information"
  fi

  exit $exit_code
}

# Set up cleanup trap
trap cleanup EXIT

# Error handling function
handle_error() {
  local exit_code=$?
  local line_number=$1
  log_error "Script failed at line $line_number with exit code $exit_code"
  log_error "Check $LOG_FILE for detailed logs"
  exit $exit_code
}

# Set up error trap
trap 'handle_error $LINENO' ERR

# Usage and help functions
show_usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  -h, --help              Show this help message"
  echo "  -t, --test-only         Only run tests on existing CA hierarchy"
  echo "  -c, --clean             Clean up existing CAs before creating new ones"
  echo "  -v, --verbose           Enable verbose logging"
  echo "  --no-tests              Skip testing after CA creation"
  echo ""
  echo "Examples:"
  echo "  $0                      Create CA hierarchy with testing"
  echo "  $0 --test-only          Test existing CA hierarchy"
  echo "  $0 --clean              Clean and recreate CA hierarchy"
  echo "  $0 --no-tests           Create CAs without testing"
}

clean_existing_cas() {
  if [ -d "$BASE_DIR" ]; then
    log_warning "Cleaning existing CA hierarchy..."
    
    # List what will be removed
    log_info "The following will be removed:"
    find "$BASE_DIR" -type f -name "*.pem" -o -name "*.txt" -o -name "*.cnf" | head -10 | while read -r file; do
      log_info "  - $file"
    done
    
    local file_count=$(find "$BASE_DIR" -type f | wc -l)
    if [ "$file_count" -gt 10 ]; then
      log_info "  ... and $((file_count - 10)) more files"
    fi
    
    echo -n "Are you sure you want to delete the existing CA hierarchy? [y/N]: "
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
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
log_info() {
  echo -e "${BLUE}ℹ️  INFO:${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
  echo -e "${GREEN}✅ SUCCESS:${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
  echo -e "${YELLOW}⚠️  WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
  echo -e "${RED}❌ ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

log_step() {
  echo -e "${PURPLE}🔄 STEP:${NC} $1" | tee -a "$LOG_FILE"
}

# Testing functions
test_ca_certificate() {
  local ca_dir=$1
  local ca_name=$2
  local parent_ca_dir=$3
  
  log_step "Testing CA certificate: $ca_name"
  
  local cert_file="$ca_dir/certs/ca.cert.pem"
  local key_file="$ca_dir/private/ca.key.pem"
  
  # Test 1: Certificate file exists and is readable
  if [ ! -f "$cert_file" ]; then
    log_error "Certificate file not found: $cert_file"
    return 1
  fi

  if [ ! -r "$cert_file" ]; then
    log_error "Certificate file not readable: $cert_file"
    return 1
  fi

  # Test 2: Private key file exists with correct permissions
  if [ ! -f "$key_file" ]; then
    log_error "Private key file not found: $key_file"
    return 1
  fi

  local key_perms=$(stat -c %a "$key_file" 2>/dev/null || stat -f %A "$key_file" 2>/dev/null)
  if [ "$key_perms" != "400" ]; then
    log_warning "Private key permissions are $key_perms, should be 400"
  fi

  # Test 3: Certificate format validation
  if ! openssl x509 -in "$cert_file" -noout -text >/dev/null 2>>"$LOG_FILE"; then
    log_error "Certificate format validation failed"
    return 1
  fi

  # Test 4: Private key format validation
  if ! openssl rsa -in "$key_file" -check -noout >/dev/null 2>>"$LOG_FILE"; then
    log_error "Private key validation failed"
    return 1
  fi

  # Test 5: Certificate-key pair matching
  local cert_modulus=$(openssl x509 -in "$cert_file" -noout -modulus 2>/dev/null | openssl md5)
  local key_modulus=$(openssl rsa -in "$key_file" -noout -modulus 2>/dev/null | openssl md5)

  if [ "$cert_modulus" != "$key_modulus" ]; then
    log_error "Certificate and private key do not match"
    return 1
  fi

  # Test 6: Certificate validity period
  local not_before=$(openssl x509 -in "$cert_file" -noout -startdate 2>/dev/null | cut -d= -f2)
  local not_after=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)

  if ! openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1; then
    log_error "Certificate is not yet valid or has expired"
    return 1
  fi

  # Test 7: Certificate chain validation (for intermediate/issuing CAs)
  if [ -n "$parent_ca_dir" ] && [ -f "$parent_ca_dir/certs/ca.cert.pem" ]; then
    local temp_chain=$(mktemp)
    add_temp_file "$temp_chain"

    cat "$cert_file" "$parent_ca_dir/certs/ca.cert.pem" > "$temp_chain"

    if ! openssl verify -CAfile "$parent_ca_dir/certs/ca.cert.pem" "$cert_file" >/dev/null 2>>"$LOG_FILE"; then
      log_error "Certificate chain validation failed"
      return 1
    fi
  fi

  # Test 8: Certificate extensions
  local basic_constraints=$(openssl x509 -in "$cert_file" -noout -ext basicConstraints 2>/dev/null)
  if [[ "$basic_constraints" != *"CA:TRUE"* ]]; then
    log_error "Certificate is missing CA:TRUE basic constraint"
    return 1
  fi

  # Test 9: Key usage validation
  local key_usage=$(openssl x509 -in "$cert_file" -noout -ext keyUsage 2>/dev/null)
  if [[ "$key_usage" != *"Certificate Sign"* ]] || [[ "$key_usage" != *"CRL Sign"* ]]; then
    log_error "Certificate is missing required key usage extensions"
    return 1
  fi

  log_success "All tests passed for CA: $ca_name"
  return 0
}

test_ca_functionality() {
  local ca_dir=$1
  local ca_name=$2

  log_step "Testing CA functionality: $ca_name"

  # Create a temporary test certificate request
  local temp_key=$(mktemp)
  local temp_csr=$(mktemp)
  local temp_cert=$(mktemp)
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

  # Verify the signed certificate
  if ! openssl verify -CAfile "$ca_dir/certs/ca.cert.pem" "$temp_cert" >/dev/null 2>>"$LOG_FILE"; then
    log_error "Test certificate verification failed"
    return 1
  fi

  log_success "CA functionality test passed for: $ca_name"
  return 0
}

comprehensive_testing() {
  log_step "Starting comprehensive testing of CA hierarchy..."

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

    if [ -n "$parent" ]; then
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
  log_step "Testing hierarchy integrity..."
  local hierarchy_ok=true

  # Test IssuingCA1 chain: IssuingCA1 -> IntermediateCA1 -> RootCA
  local temp_chain1=$(mktemp)
  add_temp_file "$temp_chain1"
  cat "$BASE_DIR/IssuingCA1/certs/ca.cert.pem" \
    "$BASE_DIR/IntermediateCA1/certs/ca.cert.pem" \
    "$BASE_DIR/RootCA/certs/ca.cert.pem" > "$temp_chain1"

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
  if [ $passed_tests -eq $total_tests ]; then
    log_success "All tests passed! ($passed_tests/$total_tests)"
    return 0
  else
    log_error "Some tests failed! ($passed_tests/$total_tests)"
    return 1
  fi
}

# Pre-flight checks
perform_preflight_checks() {
  log_step "Performing pre-flight checks..."

  # Check if OpenSSL is available
  if ! command -v openssl >/dev/null 2>&1; then
    log_error "OpenSSL is not installed or not in PATH"
    log_info "Please install OpenSSL to continue"
    exit 1
  fi
  log_success "OpenSSL found: $(openssl version)"

  # Check OpenSSL version (warn if too old)
  local openssl_version=$(openssl version | cut -d' ' -f2)
  log_info "OpenSSL version: $openssl_version"

  # Check write permissions for base directory
  local parent_dir=$(dirname "$BASE_DIR")
  if [ ! -w "$parent_dir" ]; then
    log_error "No write permission for directory: $parent_dir"
    exit 1
  fi
  log_success "Write permissions verified"

  # Check if CA directory already exists
  if [ -d "$BASE_DIR" ]; then
    log_warning "CA directory already exists: $BASE_DIR"
    echo -n "Do you want to continue? This will overwrite existing CAs [y/N]: "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
      log_info "Operation cancelled by user"
      exit 0
    fi
    log_info "User confirmed to overwrite existing CAs"
  fi

  # Create base directory
  if ! mkdir -p "$BASE_DIR"; then
    log_error "Failed to create base directory: $BASE_DIR"
    exit 1
  fi
  log_success "Base directory ready: $BASE_DIR"
}

CONFIG_TEMPLATE='[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = REPLACE_DIR
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 825
preserve          = no
policy            = policy_loose
email_in_dn       = no
unique_subject    = no

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied

[ req ]
default_bits        = 4096
prompt              = no
default_md          = sha256
distinguished_name  = dn
x509_extensions     = v3_ca

[ dn ]
C  = CH
ST = BE
O  = DanielF
OU = IT Infrastructure
CN = REPLACE_CN

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_usr ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
'

create_ca() {
  local NAME=$1
  local CN=$2
  local SIGNER_DIR=$3
  local start_time=$(date +%s)

  echo ""
  log_step "Creating CA: $NAME"
  log_info "Common Name: $CN"
  if [ -n "$SIGNER_DIR" ]; then
    log_info "Parent CA: $(basename "$SIGNER_DIR")"
  else
    log_info "Type: Root CA (self-signed)"
  fi

  local DIR="$BASE_DIR/$NAME"

  # Create directory structure
  log_step "Setting up directory structure..."
  if ! mkdir -p "$DIR"/{certs,crl,newcerts,private}; then
    log_error "Failed to create directory structure for $NAME"
    return 1
  fi

  # Set proper permissions on private directory
  if ! chmod 700 "$DIR/private"; then
    log_error "Failed to set permissions on private directory"
    return 1
  fi
  log_success "Directory structure created"

  # Initialize CA database files
  log_step "Initializing CA database..."
  if ! touch "$DIR/index.txt"; then
    log_error "Failed to create index.txt"
    return 1
  fi

  if ! echo 1000 > "$DIR/serial"; then
    log_error "Failed to create serial file"
    return 1
  fi

  if ! echo 1000 > "$DIR/crlnumber"; then
    log_error "Failed to create crlnumber file"
    return 1
  fi
  log_success "CA database initialized"

  # Generate openssl.cnf
  log_step "Generating OpenSSL configuration..."
  local config_content="${CONFIG_TEMPLATE/REPLACE_DIR/$DIR}"
  config_content="${config_content/REPLACE_CN/$CN}"

  if ! echo "$config_content" > "$DIR/openssl.cnf"; then
    log_error "Failed to create OpenSSL configuration"
    return 1
  fi
  log_success "OpenSSL configuration created"

  # Generate private key
  log_step "Generating private key (4096 bits)..."
  if ! openssl genrsa -out "$DIR/private/ca.key.pem" 4096 2>>"$LOG_FILE"; then
    log_error "Failed to generate private key"
    return 1
  fi

  if ! chmod 400 "$DIR/private/ca.key.pem"; then
    log_error "Failed to set private key permissions"
    return 1
  fi
  log_success "Private key generated and secured"

  # Generate certificate
  if [ -z "$SIGNER_DIR" ]; then
    # Root CA - self-signed
    log_step "Creating self-signed root certificate (10 years validity)..."
    if ! openssl req -config "$DIR/openssl.cnf" \
      -key "$DIR/private/ca.key.pem" \
      -new -x509 -days 3650 -sha256 -extensions v3_ca \
      -out "$DIR/certs/ca.cert.pem" 2>>"$LOG_FILE"; then
      log_error "Failed to create root certificate"
      return 1
    fi
    log_success "Root certificate created"
  else
    # Intermediate/Issuing CA
    log_step "Creating certificate signing request..."
    if ! openssl req -config "$DIR/openssl.cnf" \
      -key "$DIR/private/ca.key.pem" \
      -new -sha256 -out "$DIR/$NAME.csr.pem" 2>>"$LOG_FILE"; then
      log_error "Failed to create CSR"
      return 1
    fi
    log_success "CSR created"

    # Verify parent CA exists and is accessible
    if [ ! -f "$SIGNER_DIR/openssl.cnf" ]; then
      log_error "Parent CA configuration not found: $SIGNER_DIR/openssl.cnf"
      return 1
    fi
    
    if [ ! -f "$SIGNER_DIR/private/ca.key.pem" ]; then
      log_error "Parent CA private key not found: $SIGNER_DIR/private/ca.key.pem"
      return 1
    fi

    log_step "Signing certificate with parent CA (5 years validity)..."
    if ! openssl ca -config "$SIGNER_DIR/openssl.cnf" \
      -extensions v3_intermediate_ca -days 1825 -notext -md sha256 \
      -in "$DIR/$NAME.csr.pem" \
      -out "$DIR/certs/ca.cert.pem" -batch 2>>"$LOG_FILE"; then
      log_error "Failed to sign certificate with parent CA"
      return 1
    fi
    log_success "Certificate signed by parent CA"

    # Clean up CSR file
    if [ -f "$DIR/$NAME.csr.pem" ]; then
      add_temp_file "$DIR/$NAME.csr.pem"
      if ! rm "$DIR/$NAME.csr.pem"; then
        log_warning "Failed to clean up CSR file: $DIR/$NAME.csr.pem"
      else
        log_info "Cleaned up CSR file"
      fi
    fi
  fi

  # Verify certificate was created successfully
  if [ ! -f "$DIR/certs/ca.cert.pem" ]; then
    log_error "Certificate file was not created successfully"
    return 1
  fi

  # Validate certificate
  log_step "Validating created certificate..."
  if ! openssl x509 -in "$DIR/certs/ca.cert.pem" -noout -text >/dev/null 2>>"$LOG_FILE"; then
    log_error "Created certificate is invalid or corrupted"
    return 1
  fi

  # Log certificate details
  local cert_subject=$(openssl x509 -in "$DIR/certs/ca.cert.pem" -noout -subject 2>/dev/null | sed 's/subject=//')
  local cert_dates=$(openssl x509 -in "$DIR/certs/ca.cert.pem" -noout -dates 2>/dev/null)
  log_info "Certificate Subject: $cert_subject"
  log_info "Certificate Validity: $cert_dates"

  local end_time=$(date +%s)
  local duration=$((end_time - start_time))
  log_success "CA '$NAME' created successfully in ${duration}s"

  return 0
}

# Main execution
main() {
  local script_start=$(date +%s)
  local test_only=false
  local clean_first=false
  local verbose=false
  local run_tests=true
  
  # Parse command line arguments
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
        verbose=true
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

  # Initialize log file
  if $verbose; then
    echo "=== CA Hierarchy Creation Log (VERBOSE) - $(date) ===" > "$LOG_FILE"
  else
    echo "=== CA Hierarchy Creation Log - $(date) ===" > "$LOG_FILE"
  fi

  echo -e "${CYAN}🚀 Setting up Certificate Authority Hierarchy${NC}"
  echo "=============================================="
  log_info "Log file: $LOG_FILE"
  echo ""

  # Handle test-only mode
  if $test_only; then
    log_info "Running in test-only mode"
    if [ ! -d "$BASE_DIR" ]; then
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

  # Handle clean option
  if $clean_first; then
    clean_existing_cas
  fi

  # Perform pre-flight checks
  perform_preflight_checks

  # Create CA hierarchy
  log_step "Starting CA hierarchy creation..."

  local cas_created=0
  local total_cas=4

  # Create Root CA
  if create_ca "RootCA" "DanielF Root CA"; then
    ((cas_created++))
  else
    log_error "Failed to create Root CA - aborting"
    exit 1
  fi

  # Create Intermediate CA 1
  if create_ca "IntermediateCA1" "DanielF Intermediate CA 1" "$BASE_DIR/RootCA"; then
    ((cas_created++))
  else
    log_error "Failed to create Intermediate CA 1 - aborting"
    exit 1
  fi

  # Create Issuing CA 1
  if create_ca "IssuingCA1" "DanielF Issuing CA 1" "$BASE_DIR/IntermediateCA1"; then
    ((cas_created++))
  else
    log_error "Failed to create Issuing CA 1 - aborting"
    exit 1
  fi

  # Create Issuing CA 2
  if create_ca "IssuingCA2" "DanielF Issuing CA 2" "$BASE_DIR/RootCA"; then
    ((cas_created++))
  else
    log_error "Failed to create Issuing CA 2 - aborting"
    exit 1
  fi

  echo ""
  local script_end=$(date +%s)
  local total_duration=$((script_end - script_start))

  log_success "CA hierarchy created successfully!"
  log_info "CAs created: $cas_created/$total_cas"
  log_info "Total time: ${total_duration}s"
  log_info "Location: $BASE_DIR"

  # Run comprehensive testing if requested
  if $run_tests; then
    echo ""
    log_step "Running comprehensive tests..."
    if comprehensive_testing; then
      log_success "All tests passed - CA hierarchy is ready for use!"
    else
      log_error "Some tests failed - please review the CA hierarchy"
      exit 1
    fi
  fi

  echo ""
  echo -e "${GREEN}Available CAs for certificate signing:${NC}"
  echo "  - IssuingCA1 (via IntermediateCA1 -> RootCA)"
  echo "  - IssuingCA2 (via RootCA)"
  echo ""
  echo -e "${BLUE}Usage:${NC} ./issue_certificates.sh <CA_NAME> <COMMON_NAME> [SANs...]"
  echo -e "${BLUE}Example:${NC} ./issue_certificates.sh IssuingCA1 server1.local www.server1.local 127.0.0.1"
  echo ""
  log_info "Script completed successfully"
}

# Execute main function
main "$@"