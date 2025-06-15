#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
  if [ "$DEBUG" = "1" ]; then
    echo -e "${PURPLE}[DEBUG]${NC} $1"
  fi
}

# Statistics tracking
STATS_TOTAL_FILES=0
STATS_SUCCESS_FILES=0
STATS_FAILED_FILES=0
STATS_WARNINGS=0
FAILED_OPERATIONS=()
WARNING_MESSAGES=()

# Validation functions
validate_prerequisites() {
  log_info "Validating prerequisites..."

  local all_good=true

  # Check OpenSSL
  if ! command -v openssl >/dev/null 2>&1; then
    log_error "OpenSSL is not installed or not in PATH"
    all_good=false
  else
    local openssl_version=$(openssl version)
    log_debug "OpenSSL version: $openssl_version"
  fi

  # Check Java for JKS and BKS
  if ! command -v keytool >/dev/null 2>&1; then
    log_warning "Java keytool not found - JKS and BKS generation will be skipped"
    WARNING_MESSAGES+=("Java keytool not available")
    ((STATS_WARNINGS++))
  else
    local java_version=$(java -version 2>&1 | head -n1)
    log_debug "Java version: $java_version"
  fi

  # Check for Bouncy Castle provider (for BKS)
  if command -v keytool >/dev/null 2>&1; then
    if ! keytool -storetype BKS -help >/dev/null 2>&1; then
      log_warning "Bouncy Castle provider not available - BKS generation may fail"
      WARNING_MESSAGES+=("BKS support requires Bouncy Castle provider")
      ((STATS_WARNINGS++))
    fi
  fi

  if [ "$all_good" = false ]; then
    log_error "Prerequisites validation failed"
    exit 1
  fi

  log_success "Prerequisites validation passed"
}

validate_ca_structure() {
  local ca_name="$1"
  log_info "Validating CA structure for '$ca_name'..."

  local ca_dir="./CertificateAuthority/$ca_name"

  if [ ! -d "$ca_dir" ]; then
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
    if [ ! -f "$file" ]; then
      log_error "Required CA file missing: $file"
      return 1
    fi
  done

  # Validate CA certificate
  if ! openssl x509 -in "$ca_dir/certs/ca.cert.pem" -noout -text >/dev/null 2>&1; then
    log_error "CA certificate is invalid or corrupted"
    return 1
  fi

  # Validate CA private key
  if ! openssl rsa -in "$ca_dir/private/ca.key.pem" -check -noout >/dev/null 2>&1; then
    log_error "CA private key is invalid or corrupted"
    return 1
  fi

  log_success "CA structure validation passed"
  return 0
}

create_file_with_validation() {
  local description="$1"
  local command="$2"
  local output_file="$3"
  local is_critical="${4:-true}"

  log_info "Creating $description..."
  ((STATS_TOTAL_FILES++))

  if eval "$command" 2>/dev/null; then
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
      log_success "$description created successfully"
      log_debug "File: $output_file ($(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null || echo "unknown") bytes)"
      ((STATS_SUCCESS_FILES++))
      return 0
    else
      log_error "$description creation failed - file is empty or missing"
      FAILED_OPERATIONS+=("$description")
      ((STATS_FAILED_FILES++))
      if [ "$is_critical" = "true" ]; then
        return 1
      fi
    fi
  else
    log_error "$description creation failed - command error"
    FAILED_OPERATIONS+=("$description")
    ((STATS_FAILED_FILES++))
    if [ "$is_critical" = "true" ]; then
      return 1
    fi
  fi
  return 1
}

# Enhanced usage function
show_usage() {
  echo "❌ Usage: $0 <CA_NAME> <COMMON_NAME> [SANs...]"
  echo ""
  echo "Environment variables:"
  echo "  DEBUG=1                    Enable debug logging"
  echo "  DEFAULT_PASSWORD=<pass>    Set default password (default: changeme123)"
  echo ""
  echo "Available CAs:"
  if [ -d "./CertificateAuthority" ]; then
    for ca in ./CertificateAuthority/*/; do
      if [ -d "$ca" ]; then
        ca_name=$(basename "$ca")
        echo "  - $ca_name"
      fi
    done
  else
    echo "  No CAs found. Run create_ca_hierarchy.sh first."
  fi
  echo ""
  echo "Example: $0 IssuingCA1 server1.local www.server1.local 127.0.0.1"
  echo "Example: DEBUG=1 $0 IssuingCA1 server1.local"
  exit 1
}

# Check arguments
if [ $# -lt 2 ]; then
  show_usage
fi

CA_NAME="$1"
CN="$2"
shift 2
SANs=("$@")

CA_DIR="./CertificateAuthority/$CA_NAME"
CERT_DIR="./certificate/$CN"

# Script start
echo "🚀 Enhanced Certificate Generation Script"
echo "========================================"
echo "📅 Started at: $(date)"
echo "🖥️  System: $(uname -s) $(uname -r)"
echo ""

# Validate prerequisites
validate_prerequisites

# Validate CA
if ! validate_ca_structure "$CA_NAME"; then
  echo ""
  echo "Available CAs:"
  for ca in ./CertificateAuthority/*/; do
    if [ -d "$ca" ]; then
      ca_name=$(basename "$ca")
      echo "  - $ca_name"
    fi
  done
  exit 1
fi

echo ""
echo "🎫 Certificate Generation Parameters"
echo "==================================="
echo "📋 CA: $CA_NAME"
echo "🏷️  Common Name: $CN"
if [ ${#SANs[@]} -gt 0 ]; then
  echo "🔗 Subject Alternative Names: ${SANs[*]}"
fi
echo "📁 Output Directory: $CERT_DIR"
echo ""

# Create output directory
mkdir -p "$CERT_DIR"

# Define all file paths
KEY_FILE="$CERT_DIR/$CN.key.pem"
KEY_DER_FILE="$CERT_DIR/$CN.key.der"
PWD_KEY_FILE="$CERT_DIR/$CN.pwd.key.pem"
PWD_KEY_DER_FILE="$CERT_DIR/$CN.pwd.key.der"
CSR_FILE="$CERT_DIR/$CN.csr.pem"
CERT_FILE="$CERT_DIR/$CN.cert.pem"
CERT_DER_FILE="$CERT_DIR/$CN.cert.der"
CHAIN_FILE="$CERT_DIR/$CN.chain.cert.pem"
CHAIN_DER_FILE="$CERT_DIR/$CN.chain.cert.der"
PKCS7_PEM_FILE="$CERT_DIR/$CN.pkcs7.pem"
PKCS7_DER_FILE="$CERT_DIR/$CN.pkcs7.p7b"
PKCS12_FILE="$CERT_DIR/$CN.pkcs12.p12"
PKCS12_NOPASS_FILE="$CERT_DIR/$CN.nopass.pkcs12.p12"
PFX_FILE="$CERT_DIR/$CN.pfx"
JKS_FILE="$CERT_DIR/$CN.keystore.jks"
BKS_FILE="$CERT_DIR/$CN.keystore.bks"
BKS_NOPASS_FILE="$CERT_DIR/$CN.nopass.keystore.bks"
CONFIG_FILE="$CERT_DIR/openssl_san.cnf"

# Get password
DEFAULT_PASSWORD="${DEFAULT_PASSWORD:-changeme123}"
echo "🔐 Password Configuration"
echo "========================"
echo "   Press Enter for default password ('$DEFAULT_PASSWORD')"
echo -n "   Or enter custom password: "
read -s USER_PASSWORD
echo ""

if [ -z "$USER_PASSWORD" ]; then
  PASSWORD="$DEFAULT_PASSWORD"
  log_info "Using default password"
else
  PASSWORD="$USER_PASSWORD"
  log_info "Using custom password"
fi

echo ""
echo "🔨 Certificate Generation Process"
echo "================================="

# Generate private keys
create_file_with_validation "unencrypted private key (PEM)" \
  "openssl genrsa -out '$KEY_FILE' 2048" \
  "$KEY_FILE"

create_file_with_validation "unencrypted private key (DER)" \
  "openssl rsa -in '$KEY_FILE' -outform DER -out '$KEY_DER_FILE'" \
  "$KEY_DER_FILE"

create_file_with_validation "encrypted private key (PEM)" \
  "openssl rsa -in '$KEY_FILE' -aes256 -out '$PWD_KEY_FILE' -passout pass:'$PASSWORD'" \
  "$PWD_KEY_FILE"

create_file_with_validation "encrypted private key (DER)" \
  "openssl rsa -in '$PWD_KEY_FILE' -aes256 -outform DER -out '$PWD_KEY_DER_FILE' -passin pass:'$PASSWORD' -passout pass:'$PASSWORD'" \
  "$PWD_KEY_DER_FILE"

# Generate CSR config
log_info "Creating certificate signing request configuration..."
cat > "$CONFIG_FILE" <<EOF
[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
distinguished_name  = dn
req_extensions      = req_ext

[ dn ]
C  = CH
ST = BE
O  = DanielF
OU = IT Infrastructure
CN = $CN

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
EOF

# Add SANs
INDEX=1
echo "DNS.$INDEX = $CN" >> "$CONFIG_FILE"
for SAN in "${SANs[@]}"; do
  ((INDEX++))
  if [[ $SAN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.$((INDEX - 1)) = $SAN" >> "$CONFIG_FILE"
  else
    echo "DNS.$INDEX = $SAN" >> "$CONFIG_FILE"
  fi
done

# Generate CSR
create_file_with_validation "certificate signing request" \
  "openssl req -new -key '$KEY_FILE' -out '$CSR_FILE' -config '$CONFIG_FILE'" \
  "$CSR_FILE"

# Create temporary CA config
TEMP_CA_CONFIG="$CA_DIR/temp_openssl.cnf"
cp "$CA_DIR/openssl.cnf" "$TEMP_CA_CONFIG"

cat >> "$TEMP_CA_CONFIG" <<EOF

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
INDEX=1
echo "DNS.$INDEX = $CN" >> "$TEMP_CA_CONFIG"
for SAN in "${SANs[@]}"; do
  ((INDEX++))
  if [[ $SAN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.$((INDEX - 1)) = $SAN" >> "$TEMP_CA_CONFIG"
  else
    echo "DNS.$INDEX = $SAN" >> "$TEMP_CA_CONFIG"
  fi
done

# Sign certificate
create_file_with_validation "signed certificate" \
  "openssl ca -batch -config '$TEMP_CA_CONFIG' -extensions v3_usr -days 825 -notext -md sha256 -in '$CSR_FILE' -out '$CERT_FILE'" \
  "$CERT_FILE"

# Clean up
rm "$TEMP_CA_CONFIG"

# Create DER certificate
create_file_with_validation "certificate (DER)" \
  "openssl x509 -in '$CERT_FILE' -outform DER -out '$CERT_DER_FILE'" \
  "$CERT_DER_FILE"

# Build certificate chain (PEM)
log_info "Building certificate chain (PEM)..."
if [ -f "$CA_DIR/certs/ca.cert.pem" ]; then
  if [ -f "./CertificateAuthority/IntermediateCA1/certs/ca.cert.pem" ] && [ "$CA_NAME" = "IssuingCA1" ]; then
    cat "$CERT_FILE" \
      "$CA_DIR/certs/ca.cert.pem" \
      "./CertificateAuthority/IntermediateCA1/certs/ca.cert.pem" \
      "./CertificateAuthority/RootCA/certs/ca.cert.pem" > "$CHAIN_FILE"
  elif [ -f "./CertificateAuthority/RootCA/certs/ca.cert.pem" ] && [ "$CA_NAME" = "IssuingCA2" ]; then
    cat "$CERT_FILE" \
      "$CA_DIR/certs/ca.cert.pem" \
      "./CertificateAuthority/RootCA/certs/ca.cert.pem" > "$CHAIN_FILE"
  else
    cat "$CERT_FILE" "$CA_DIR/certs/ca.cert.pem" > "$CHAIN_FILE"
  fi

  if [ -f "$CHAIN_FILE" ] && [ -s "$CHAIN_FILE" ]; then
    log_success "Certificate chain (PEM) created successfully"
    ((STATS_SUCCESS_FILES++))
  else
    log_error "Certificate chain (PEM) creation failed"
    FAILED_OPERATIONS+=("Certificate chain (PEM)")
    ((STATS_FAILED_FILES++))
  fi
  ((STATS_TOTAL_FILES++))
fi

# Build certificate chain (DER)
create_file_with_validation "certificate chain (DER)" \
  "openssl x509 -in '$CHAIN_FILE' -outform DER -out '$CHAIN_DER_FILE'" \
  "$CHAIN_DER_FILE" \
  false

# Create PKCS#7 bundles
create_file_with_validation "PKCS#7 bundle (PEM)" \
  "openssl crl2pkcs7 -nocrl -certfile '$CHAIN_FILE' -out '$PKCS7_PEM_FILE'" \
  "$PKCS7_PEM_FILE"

create_file_with_validation "PKCS#7 bundle (DER)" \
  "openssl crl2pkcs7 -nocrl -certfile '$CHAIN_FILE' -outform DER -out '$PKCS7_DER_FILE'" \
  "$PKCS7_DER_FILE"

# Create PKCS#12 bundles
create_file_with_validation "PKCS#12 bundle (with password)" \
  "openssl pkcs12 -export -in '$CHAIN_FILE' -inkey '$KEY_FILE' -out '$PKCS12_FILE' -name '$CN' -passout pass:'$PASSWORD'" \
  "$PKCS12_FILE"

create_file_with_validation "PKCS#12 bundle (without password)" \
  "openssl pkcs12 -export -in '$CHAIN_FILE' -inkey '$KEY_FILE' -out '$PKCS12_NOPASS_FILE' -name '$CN' -passout pass:" \
  "$PKCS12_NOPASS_FILE"

# Create PFX (same as PKCS#12)
create_file_with_validation "PFX bundle (Windows)" \
  "openssl pkcs12 -export -in '$CHAIN_FILE' -inkey '$KEY_FILE' -out '$PFX_FILE' -name '$CN' -passout pass:'$PASSWORD'" \
  "$PFX_FILE"

# Create Java KeyStore (JKS)
if command -v keytool >/dev/null 2>&1; then
  create_file_with_validation "Java KeyStore (JKS)" \
    "keytool -importkeystore -deststorepass '$PASSWORD' -destkeypass '$PASSWORD' -destkeystore '$JKS_FILE' -srckeystore '$PKCS12_FILE' -srcstoretype PKCS12 -srcstorepass '$PASSWORD' -alias '$CN'" \
    "$JKS_FILE" \
    false
else
  log_warning "JKS creation skipped - Java keytool not available"
  WARNING_MESSAGES+=("JKS creation skipped")
  ((STATS_WARNINGS++))
fi

# Create BKS KeyStore
if command -v keytool >/dev/null 2>&1; then
  # Try to create BKS with password
  if keytool -importkeystore -deststorepass "$PASSWORD" -destkeypass "$PASSWORD" \
    -deststoretype BKS -destkeystore "$BKS_FILE" \
    -srckeystore "$PKCS12_FILE" -srcstoretype PKCS12 -srcstorepass "$PASSWORD" \
    -alias "$CN" -provider org.bouncycastle.jce.provider.BouncyCastleProvider \
    -providerpath /usr/share/java/bcprov.jar 2>/dev/null; then
    log_success "BKS KeyStore (with password) created successfully"
    ((STATS_SUCCESS_FILES++))
  else
    log_warning "BKS KeyStore creation failed - Bouncy Castle provider may not be available"
    WARNING_MESSAGES+=("BKS KeyStore creation failed")
    ((STATS_WARNINGS++))
  fi
  ((STATS_TOTAL_FILES++))

  # Try to create BKS without password
  if keytool -importkeystore -deststorepass "" -destkeypass "" \
    -deststoretype BKS -destkeystore "$BKS_NOPASS_FILE" \
    -srckeystore "$PKCS12_NOPASS_FILE" -srcstoretype PKCS12 -srcstorepass "" \
    -alias "$CN" -provider org.bouncycastle.jce.provider.BouncyCastleProvider \
    -providerpath /usr/share/java/bcprov.jar 2>/dev/null; then
    log_success "BKS KeyStore (without password) created successfully"
    ((STATS_SUCCESS_FILES++))
  else
    log_warning "BKS KeyStore (no password) creation failed"
    WARNING_MESSAGES+=("BKS KeyStore (no password) creation failed")
    ((STATS_WARNINGS++))
  fi
  ((STATS_TOTAL_FILES++))
else
  log_warning "BKS creation skipped - Java keytool not available"
  WARNING_MESSAGES+=("BKS creation skipped")
  ((STATS_WARNINGS++))
fi

echo ""
echo "📊 GENERATION SUMMARY"
echo "===================="
echo "📅 Completed at: $(date)"
echo "⏱️  Duration: $SECONDS seconds"
echo ""
echo "📈 Statistics:"
echo "   📁 Total files attempted: $STATS_TOTAL_FILES"
echo "   ✅ Successfully created: $STATS_SUCCESS_FILES"
echo "   ❌ Failed to create: $STATS_FAILED_FILES"
echo "   ⚠️  Warnings: $STATS_WARNINGS"
echo ""

if [ ${#FAILED_OPERATIONS[@]} -gt 0 ]; then
  echo "❌ Failed Operations:"
  for failed in "${FAILED_OPERATIONS[@]}"; do
    echo "   - $failed"
  done
  echo ""
fi

if [ ${#WARNING_MESSAGES[@]} -gt 0 ]; then
  echo "⚠️  Warnings:"
  for warning in "${WARNING_MESSAGES[@]}"; do
    echo "   - $warning"
  done
  echo ""
fi

echo "📁 Generated Files:"
echo "=================="
echo ""
echo "🔑 Private Keys:"
[ -f "$KEY_FILE" ] && echo "   ✅ Unencrypted PEM:           $KEY_FILE" || echo "   ❌ Unencrypted PEM:           $KEY_FILE"
[ -f "$KEY_DER_FILE" ] && echo "   ✅ Unencrypted DER:           $KEY_DER_FILE" || echo "   ❌ Unencrypted DER:           $KEY_DER_FILE"
[ -f "$PWD_KEY_FILE" ] && echo "   ✅ Encrypted PEM:             $PWD_KEY_FILE" || echo "   ❌ Encrypted PEM:             $PWD_KEY_FILE"
[ -f "$PWD_KEY_DER_FILE" ] && echo "   ✅ Encrypted DER:             $PWD_KEY_DER_FILE" || echo "   ❌ Encrypted DER:             $PWD_KEY_DER_FILE"
echo ""
echo "🎫 Certificates:"
[ -f "$CERT_FILE" ] && echo "   ✅ Certificate (PEM):         $CERT_FILE" || echo "   ❌ Certificate (PEM):         $CERT_FILE"
[ -f "$CERT_DER_FILE" ] && echo "   ✅ Certificate (DER):         $CERT_DER_FILE" || echo "   ❌ Certificate (DER):         $CERT_DER_FILE"
[ -f "$CHAIN_FILE" ] && echo "   ✅ Chain (PEM):               $CHAIN_FILE" || echo "   ❌ Chain (PEM):               $CHAIN_FILE"
[ -f "$CHAIN_DER_FILE" ] && echo "   ✅ Chain (DER):               $CHAIN_DER_FILE" || echo "   ❌ Chain (DER):               $CHAIN_DER_FILE"
echo ""
echo "📦 Certificate Bundles:"
[ -f "$PKCS7_PEM_FILE" ] && echo "   ✅ PKCS#7 (PEM):              $PKCS7_PEM_FILE" || echo "   ❌ PKCS#7 (PEM):              $PKCS7_PEM_FILE"
[ -f "$PKCS7_DER_FILE" ] && echo "   ✅ PKCS#7 (DER/P7B):          $PKCS7_DER_FILE" || echo "   ❌ PKCS#7 (DER/P7B):          $PKCS7_DER_FILE"
[ -f "$PKCS12_FILE" ] && echo "   ✅ PKCS#12 (with password):   $PKCS12_FILE" || echo "   ❌ PKCS#12 (with password):   $PKCS12_FILE"
[ -f "$PKCS12_NOPASS_FILE" ] && echo "   ✅ PKCS#12 (no password):     $PKCS12_NOPASS_FILE" || echo "   ❌ PKCS#12 (no password):     $PKCS12_NOPASS_FILE"
[ -f "$PFX_FILE" ] && echo "   ✅ PFX (Windows):              $PFX_FILE" || echo "   ❌ PFX (Windows):              $PFX_FILE"
[ -f "$JKS_FILE" ] && echo "   ✅ Java KeyStore (JKS):        $JKS_FILE" || echo "   ❌ Java KeyStore (JKS):        $JKS_FILE"
[ -f "$BKS_FILE" ] && echo "   ✅ BKS KeyStore (with pass):   $BKS_FILE" || echo "   ❌ BKS KeyStore (with pass):   $BKS_FILE"
[ -f "$BKS_NOPASS_FILE" ] && echo "   ✅ BKS KeyStore (no pass):     $BKS_NOPASS_FILE" || echo "   ❌ BKS KeyStore (no pass):     $BKS_NOPASS_FILE"
echo ""
echo "📋 Other Files:"
[ -f "$CSR_FILE" ] && echo "   ✅ CSR:                       $CSR_FILE" || echo "   ❌ CSR:                       $CSR_FILE"
echo ""
echo "🔐 Password for encrypted files: $PASSWORD"
echo ""

# Certificate validation and details
if [ -f "$CERT_FILE" ]; then
  echo "🔍 Certificate Details:"
  echo "======================"
  openssl x509 -in "$CERT_FILE" -noout -subject -dates -ext subjectAltName 2>/dev/null || log_warning "Could not display certificate details"
  echo ""
fi

echo "💡 Usage Guidelines:"
echo "==================="
echo "   🌐 Web servers (Apache/Nginx):    Use $CHAIN_FILE + $KEY_FILE"
echo "   🪟 Windows Certificate Store:     Import $PFX_FILE or $PKCS7_DER_FILE"
echo "   ☕ Java applications:             Use $JKS_FILE or $PKCS12_FILE"
echo "   📱 Android applications:          Use $BKS_FILE"
echo "   📧 Email/S-MIME:                  Use $PKCS12_FILE or $PFX_FILE"
echo "   🔧 Legacy/Binary systems:         Use $CERT_DER_FILE + $KEY_DER_FILE"
echo "   🧪 Testing purposes:              Use appropriate format for your test environment"
echo ""

# Final status
if [ $STATS_FAILED_FILES -eq 0 ]; then
  echo "🎉 Certificate generation completed successfully!"
  exit 0
else
  echo "⚠️  Certificate generation completed with $STATS_FAILED_FILES failures"
  exit 1
fi