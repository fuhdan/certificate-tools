#!/bin/bash

# =============================================================================
# Common Functions Library
# =============================================================================
# Shared utility functions for Certificate Authority and Certificate scripts
# This file should be sourced by other scripts, not executed directly

# Prevent multiple sourcing
if [[ "${_COMMON_FUNCTIONS_LOADED:-}" == "true" ]]; then
    return 0
fi
readonly _COMMON_FUNCTIONS_LOADED=true

# =============================================================================
# OS DETECTION AND PLATFORM-SPECIFIC SETTINGS
# =============================================================================

# Detect operating system and SSL implementation
detect_os() {
    case "$(uname -s)" in
        Darwin*)    
            OS_TYPE="macos" 
            ;;
        Linux*)     
            # Detect specific Linux distribution
            if [[ -f /etc/redhat-release ]]; then
                if grep -q "Red Hat Enterprise Linux" /etc/redhat-release; then
                    OS_TYPE="rhel"
                elif grep -q "CentOS" /etc/redhat-release; then
                    OS_TYPE="centos"
                elif grep -q "Fedora" /etc/redhat-release; then
                    OS_TYPE="fedora"
                else
                    OS_TYPE="redhat"  # Generic Red Hat family
                fi
            elif [[ -f /etc/debian_version ]]; then
                if [[ -f /etc/lsb-release ]] && grep -q "Ubuntu" /etc/lsb-release; then
                    OS_TYPE="ubuntu"
                else
                    OS_TYPE="debian"
                fi
            else
                OS_TYPE="linux"  # Generic Linux
            fi
            ;;
        CYGWIN*|MINGW*|MSYS*)  
            echo "❌ ERROR: Windows is not supported by this script"
            echo "This script requires a Unix-like environment (macOS or Linux)"
            echo "Consider using WSL (Windows Subsystem for Linux) or a Linux VM"
            exit 1
            ;;
        *)          
            OS_TYPE="unknown" 
            echo "❌ ERROR: Unknown operating system detected: $(uname -s)"
            echo "This script supports macOS and Linux distributions only"
            echo "Supported: macOS, Ubuntu, Debian, RHEL, CentOS, Fedora"
            exit 1
            ;;
    esac
    
    # Detect SSL implementation
    if command -v openssl >/dev/null 2>&1; then
        if openssl version | grep -q "LibreSSL"; then
            SSL_TYPE="libressl"
            SSL_VERSION=$(openssl version | cut -d' ' -f2)
        else
            SSL_TYPE="openssl"
            SSL_VERSION=$(openssl version | cut -d' ' -f2)
        fi
    else
        SSL_TYPE="none"
        SSL_VERSION="not installed"
    fi
    
    # Export for use in other functions
    export OS_TYPE SSL_TYPE SSL_VERSION
    log_debug "Detected OS: $OS_TYPE, SSL: $SSL_TYPE $SSL_VERSION"
}

# Platform-specific file size function
get_file_size_by_os() {
    local file_path="$1"
    if [[ ! -f "$file_path" ]]; then
        echo "0"
        return
    fi
    
    case "$OS_TYPE" in
        macos)
            stat -f%z "$file_path" 2>/dev/null || echo "unknown"
            ;;
        rhel|centos|fedora|redhat|ubuntu|debian)
            stat -c%s "$file_path" 2>/dev/null || echo "unknown"
            ;;
        *)
            # Fallback: try both and use whichever works
            stat -c%s "$file_path" 2>/dev/null || stat -f%z "$file_path" 2>/dev/null || echo "unknown"
            ;;
    esac
}

# Platform-specific disk space check
check_disk_space_by_os() {
    local required_mb="${1:-100}"
    local target_dir="${2:-.}"
    
    if ! command -v df >/dev/null 2>&1; then
        log_warning "Cannot check disk space - df command not available"
        return 0
    fi
    
    local available_mb
    case "$OS_TYPE" in
        macos)
            # macOS df uses 512-byte blocks by default, -m for MB
            available_mb=$(df -m "$(dirname "$target_dir")" | awk 'NR==2 {print $4}')
            ;;
        rhel|centos|fedora|redhat|ubuntu|debian)
            # Linux df, -BM for MB
            available_mb=$(df -BM "$(dirname "$target_dir")" | awk 'NR==2 {print $4}' | sed 's/M//')
            ;;
        *)
            # Fallback: try portable -m flag
            available_mb=$(df -m "$(dirname "$target_dir")" 2>/dev/null | awk 'NR==2 {print $4}' || echo "1000")
            ;;
    esac
    
    if [[ $available_mb -lt $required_mb ]]; then
        log_error "Insufficient disk space. Required: ${required_mb}MB, Available: ${available_mb}MB"
        return 1
    fi
    
    log_debug "Disk space check passed. Available: ${available_mb}MB"
    return 0
}

# Platform-specific OpenSSL validation
validate_openssl_by_os() {
    local min_version="${1:-1.1.1}"
    
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "OpenSSL not found in PATH"
        return 1
    fi
    
    log_info "SSL Implementation: $SSL_TYPE version $SSL_VERSION"
    
    # Check for LibreSSL and provide recommendations (only once)
    if [[ "$SSL_TYPE" == "libressl" ]]; then
        case "$OS_TYPE" in
            macos)
                log_warning "LibreSSL detected. Script includes compatibility fixes for LibreSSL."
                log_warning "For full OpenSSL features: brew install openssl && export PATH=\"/opt/homebrew/bin:\$PATH\""
                ;;
            *)
                log_warning "LibreSSL detected. Consider installing OpenSSL for better compatibility"
                ;;
        esac
    fi
    
    # Simple version comparison (works for both OpenSSL and LibreSSL)
    if [[ "$(printf '%s\n' "$min_version" "$SSL_VERSION" | sort -V | head -n1)" != "$min_version" ]]; then
        log_warning "$SSL_TYPE version $SSL_VERSION is older than recommended $min_version"
    fi
    
    return 0
}

# Platform-specific Java tools check
check_java_tools_by_os() {
    local warnings=()
    
    # Step 1: Check if keytool is available
    if ! command -v keytool >/dev/null 2>&1; then
        case "$OS_TYPE" in
            macos)
                warnings+=("Java keytool not available - JKS formats skipped")
                warnings+=("Install Java: brew install openjdk")
                ;;
            ubuntu|debian)
                warnings+=("Java keytool not available - JKS formats skipped")
                warnings+=("Install Java: sudo apt-get install openjdk-11-jdk (Ubuntu/Debian)")
                ;;
            rhel|centos|fedora|redhat)
                warnings+=("Java keytool not available - JKS formats skipped")
                warnings+=("Install Java: sudo dnf install java-21-openjdk-devel (Red/Debian)")
                ;;
            *)
                warnings+=("Java keytool not available - JKS formats skipped")
                ;;
        esac
        # If keytool is not available, we can't do anything
        printf '%s\n' "${warnings[@]}"
        return 0
    fi
    
    # Step 2: Check if Java runtime is available
    if ! java -version >/dev/null 2>&1; then
        case "$OS_TYPE" in
            macos)
                warnings+=("Java runtime not available - JKS formats skipped")
                warnings+=("Install Java runtime: brew install openjdk")
                ;;
            rhel|centos|fedora|redhat|ubuntu|debian)
                warnings+=("Java runtime not available - JKS formats skipped")
                warnings+=("Install Java runtime: sudo apt-get install openjdk-11-jre (Ubuntu/Debian)")
                ;;
            rhel|centos|fedora|redhat|ubuntu|debian)
                warnings+=("Java runtime not available - JKS formats skipped")
                warnings+=("Install Java runtime: sudo dnf install openjdk-21-jre (Red/Debian)")
                ;;
            *)
                warnings+=("Java runtime not available - JKS formats skipped")
                ;;
        esac
        # If Java runtime is not available, we can't do anything
        printf '%s\n' "${warnings[@]}"
        return 0
    fi
    
    # Step 3: keytool and Java are available - log version info
    local java_version
    java_version=$(java -version 2>&1 | head -n1)
    log_debug "Java version: $java_version"
    
    # Return warnings (empty if everything is available)
    printf '%s\n' "${warnings[@]}"
}

# =============================================================================
# CONSTANTS AND GLOBALS
# =============================================================================

# Color codes and formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Global state variables (will be set by importing scripts)
# Ensure compatibility with older Bash versions
if [[ ${BASH_VERSION%%.*} -ge 4 ]]; then
    declare -g LOG_FILE
    declare -g LOG_LEVEL="INFO"
    declare -g TEMP_FILES=()
    declare -g CURRENT_STEP=0
    declare -g TOTAL_STEPS=0
    declare -g PROGRESS_RESERVED=false
    declare -g OS_TYPE=""
    declare -g SSL_TYPE=""
    declare -g SSL_VERSION=""
else
    declare LOG_FILE
    declare LOG_LEVEL="INFO"
    declare TEMP_FILES
    declare CURRENT_STEP=0
    declare TOTAL_STEPS=0
    declare PROGRESS_RESERVED=false
    declare OS_TYPE=""
    declare SSL_TYPE=""
    declare SSL_VERSION=""
    # Initialize arrays separately for older Bash
    TEMP_FILES=()
fi

# =============================================================================
# LOGGING SYSTEM
# =============================================================================

setup_logging() {
    local script_name="$1"
    local log_dir="${SCRIPT_DIR}/logs"
    mkdir -p "$log_dir"
    LOG_FILE="${log_dir}/${script_name}_$(date +%Y%m%d_%H%M%S).log"
    
    echo "=== Enhanced $script_name Log - $(date) ===" > "$LOG_FILE"
    echo "Log Level: $LOG_LEVEL" >> "$LOG_FILE"
    echo "Operating System: $OS_TYPE" >> "$LOG_FILE"
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
    
    # Handle progress bar positioning if active
    if [[ "$PROGRESS_RESERVED" == "true" ]] && command -v tput >/dev/null 2>&1; then
        # Move cursor up to insert log message above progress bar
        tput cuu1
        tput el  # Clear line
        echo -e "${color}${symbol} ${level}:${NC} $message"
        # Redraw the progress bar immediately after the log message
        redraw_progress_bar
    else
        echo -e "${color}${symbol} ${level}:${NC} $message"
    fi
    
    [[ -n "${LOG_FILE:-}" ]] && echo "$log_entry" >> "$LOG_FILE"
}

log_debug() { log_with_level "DEBUG" "$1" "$PURPLE" "🔍"; }
log_info() { log_with_level "INFO" "$1" "$BLUE" "ℹ️ "; }
log_success() { log_with_level "INFO" "$1" "$GREEN" "✅"; }
log_warning() { log_with_level "WARNING" "$1" "$YELLOW" "⚠️ "; }
log_error() { log_with_level "ERROR" "$1" "$RED" "❌"; }

# Initialize OS detection
detect_os

# =============================================================================
# PROGRESS TRACKING (Updated with bottom positioning)
# =============================================================================

init_progress() {
    TOTAL_STEPS="$1"
    CURRENT_STEP=0
    PROGRESS_RESERVED=false
    log_info "Starting operation with $TOTAL_STEPS steps"
}

reserve_progress_line() {
    if [[ "$PROGRESS_RESERVED" == "false" ]]; then
        echo ""  # Reserve a line for progress bar
        draw_progress_bar  # Draw initial progress bar
        PROGRESS_RESERVED=true
    fi
}

draw_progress_bar() {
    local percentage=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    local bar_length=40
    local filled_length=$((percentage * bar_length / 100))
    
    # Ensure we don't exceed 100%
    if [[ $percentage -gt 100 ]]; then
        percentage=100
        filled_length=$bar_length
    fi
    
    printf "${BLUE}Progress: ${NC}["
    printf "%*s" $filled_length | tr ' ' '#'
    printf "%*s" $((bar_length - filled_length)) | tr ' ' '-'
    printf "] %d%% (%d/%d)" $percentage $CURRENT_STEP $TOTAL_STEPS
}

redraw_progress_bar() {
    # Only redraw if tput is available and progress is reserved
    if [[ "$PROGRESS_RESERVED" == "true" ]] && command -v tput >/dev/null 2>&1; then
        draw_progress_bar
        echo ""  # Move to next line for future log messages
    fi
}

update_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    
    # Check if tput is available, fallback to old method if not
    if ! command -v tput >/dev/null 2>&1; then
        update_progress_fallback
        return
    fi
    
    # Ensure we have reserved a line
    reserve_progress_line
    
    # Move to progress bar line and update it
    tput cuu1  # Move cursor up 1 line
    tput el    # Clear to end of line
    
    draw_progress_bar
    echo ""  # Move to next line
    
    # If we're done, show completion message
    if [[ $CURRENT_STEP -ge $TOTAL_STEPS ]]; then
        tput cuu1
        tput el
        printf "${GREEN}✅ Progress: [########################################] 100%% Complete!${NC}\n"
        log_success "All steps completed successfully"
        PROGRESS_RESERVED=false
    fi
}

# Fallback progress function for systems without tput
update_progress_fallback() {
    local percentage=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    local bar_length=40
    local filled_length=$((percentage * bar_length / 100))
    
    # Ensure we don't exceed 100%
    if [[ $percentage -gt 100 ]]; then
        percentage=100
        filled_length=$bar_length
    fi
    
    printf "\r${BLUE}Progress: ${NC}["
    printf "%*s" $filled_length | tr ' ' '#'
    printf "%*s" $((bar_length - filled_length)) | tr ' ' '-'
    printf "] %d%% (%d/%d)" $percentage $CURRENT_STEP $TOTAL_STEPS
    
    if [[ $CURRENT_STEP -ge $TOTAL_STEPS ]]; then
        echo ""
        log_success "All steps completed successfully"
    fi
}

# Enhanced progress for testing phases
init_testing_progress() {
    local total_tests="$1"
    log_info "Starting comprehensive testing ($total_tests tests)"
    # Note: Testing is now integrated into main progress, so this function
    # is kept for backward compatibility but doesn't reinitialize progress
}

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

load_config_file() {
    local config_file="$1"
    local default_config="$2"
    
    if [[ ! -f "$config_file" ]]; then
        log_info "Creating default configuration file: $config_file"
        echo "$default_config" > "$config_file"
    fi
    
    if source "$config_file" 2>/dev/null; then
        log_debug "Configuration loaded successfully from $config_file"
        return 0
    else
        log_error "Failed to load configuration from $config_file"
        return 1
    fi
}

validate_config_value() {
    local name="$1"
    local value="$2"
    local pattern="$3"
    local error_msg="$4"
    
    if [[ ! "$value" =~ $pattern ]]; then
        log_error "Invalid $name: $value - $error_msg"
        return 1
    fi
    return 0
}

# =============================================================================
# FILE OPERATIONS AND CLEANUP
# =============================================================================

add_temp_file() {
    TEMP_FILES+=("$1")
    log_debug "Added temp file: $1"
}

cleanup_temp_files() {
    if [[ ${#TEMP_FILES[@]} -gt 0 ]]; then
        log_info "Cleaning up ${#TEMP_FILES[@]} temporary files"

        for temp_file in "${TEMP_FILES[@]}"; do
            [[ -f "$temp_file" ]] && rm -f "$temp_file" 2>/dev/null
        done
        TEMP_FILES=()
    fi
}

atomic_file_operation() {
    local description="$1"
    local command="$2"
    local target_file="$3"
    local is_critical="${4:-true}"
    
    local temp_file="${target_file}.tmp.$$"
    add_temp_file "$temp_file"
    
    log_debug "Starting atomic operation: $description"
    
    # Execute command with temp file
    if eval "${command//$target_file/$temp_file}" 2>>"${LOG_FILE:-/dev/null}"; then
        if [[ -f "$temp_file" && -s "$temp_file" ]]; then
            # Atomic move
            if mv "$temp_file" "$target_file"; then
                log_success "$description completed successfully"
                local file_size
                file_size=$(get_file_size_by_os "$target_file")
                log_debug "File: $target_file ($file_size bytes)"
                # Remove from temp files since it's now permanent
                TEMP_FILES=("${TEMP_FILES[@]/$temp_file}")
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
    
    [[ "$is_critical" == "true" ]] && return 1 || return 0
}

backup_directory() {
    local source_dir="$1"
    local backup_enabled="${2:-true}"
    
    if [[ -d "$source_dir" && "$backup_enabled" == "true" ]]; then
        local backup_dir="${source_dir}.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "Backing up existing directory to: $backup_dir"
        
        if cp -r "$source_dir" "$backup_dir"; then
            log_success "Backup created successfully"
            return 0
        else
            log_error "Failed to create backup"
            return 1
        fi
    fi
    return 0
}

get_file_size() {
    # Wrapper function for backward compatibility
    get_file_size_by_os "$1"
}

# =============================================================================
# SYSTEM VALIDATION (Updated to use OS-specific functions)
# =============================================================================

check_disk_space() {
    check_disk_space_by_os "$@"
}

validate_openssl() {
    validate_openssl_by_os "$@"
}

check_java_tools() {
    check_java_tools_by_os
}

# =============================================================================
# CERTIFICATE VALIDATION
# =============================================================================

validate_certificate_format() {
    local cert_file="$1"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        return 1
    fi
    
    if ! openssl x509 -in "$cert_file" -noout -text >/dev/null 2>>"${LOG_FILE:-/dev/null}"; then
        log_error "Certificate format validation failed: $cert_file"
        return 1
    fi
    
    log_debug "Certificate format validation passed: $cert_file"
    return 0
}

validate_private_key_format() {
    local key_file="$1"
    
    if [[ ! -f "$key_file" ]]; then
        log_error "Private key file not found: $key_file"
        return 1
    fi
    
    if ! openssl rsa -in "$key_file" -check -noout >/dev/null 2>>"${LOG_FILE:-/dev/null}"; then
        log_error "Private key validation failed: $key_file"
        return 1
    fi
    
    log_debug "Private key validation passed: $key_file"
    return 0
}

validate_certificate_key_pair() {
    local cert_file="$1"
    local key_file="$2"
    
    local cert_modulus key_modulus
    cert_modulus=$(openssl x509 -in "$cert_file" -noout -modulus 2>/dev/null | openssl md5)
    key_modulus=$(openssl rsa -in "$key_file" -noout -modulus 2>/dev/null | openssl md5)
    
    if [[ "$cert_modulus" != "$key_modulus" ]]; then
        log_error "Certificate and private key do not match"
        return 1
    fi
    
    log_debug "Certificate-key pair validation passed"
    return 0
}

validate_certificate_chain() {
    local cert_file="$1"
    local parent_cert_file="$2"
    
    log_debug "Validating certificate chain: $cert_file -> $parent_cert_file"
    
    if [[ -n "$parent_cert_file" && -f "$parent_cert_file" ]]; then
        # For intermediate certificates, verify against parent
        if openssl verify -CAfile "$parent_cert_file" "$cert_file" >/dev/null 2>>"${LOG_FILE:-/dev/null}"; then
            log_success "Certificate chain validation passed"
            return 0
        else
            log_error "Certificate chain validation failed"
            log_debug "Attempted to verify $cert_file against CA $parent_cert_file"
            return 1
        fi
    else
        # For root certificates, verify self-signed
        if openssl verify -CAfile "$cert_file" "$cert_file" >/dev/null 2>>"${LOG_FILE:-/dev/null}"; then
            log_success "Self-signed certificate validation passed"
            return 0
        else
            log_error "Self-signed certificate validation failed"
            return 1
        fi
    fi
}

validate_certificate_extensions() {
    local cert_file="$1"
    local expected_ca_flag="$2"
    
    log_debug "Validating certificate extensions: $cert_file"
    
    # Check basic constraints - LibreSSL compatible approach
    local basic_constraints
    basic_constraints=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A 1 "Basic Constraints" | grep -i "CA:" || echo "")
    
    if [[ "$expected_ca_flag" == "true" ]]; then
        if [[ "$basic_constraints" != *"CA:TRUE"* ]] && [[ "$basic_constraints" != *"CA:true"* ]]; then
            log_error "Certificate is missing CA:TRUE basic constraint"
            log_debug "Found basic constraints: $basic_constraints"
            return 1
        fi
    fi
    
    # Check key usage for CA certificates
    if [[ "$expected_ca_flag" == "true" ]]; then
        local key_usage
        key_usage=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A 2 "Key Usage" || echo "")
        
        if [[ "$key_usage" != *"Certificate Sign"* ]] || [[ "$key_usage" != *"CRL Sign"* ]]; then
            log_warning "Certificate may be missing some CA key usage extensions"
            log_debug "Found key usage: $key_usage"
            # Don't fail for this on LibreSSL, just warn
        fi
    fi
    
    # Check validity period
    if ! openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1; then
        log_error "Certificate is not yet valid or has expired"
        return 1
    fi
    
    log_success "Certificate extensions validation passed"
    return 0
}

# =============================================================================
# INPUT VALIDATION
# =============================================================================

validate_common_name() {
    local cn="$1"
    local max_length="${2:-64}"
    
    if [[ -z "$cn" ]]; then
        log_error "Common Name cannot be empty"
        return 1
    fi
    
    if [[ ${#cn} -gt $max_length ]]; then
        log_error "Common Name too long (max $max_length characters): $cn"
        return 1
    fi
    
    # Basic CN format validation
    if [[ ! "$cn" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        log_error "Invalid Common Name format: $cn (only alphanumeric, dot, underscore, and dash allowed)"
        return 1
    fi
    
    return 0
}

validate_san_entry() {
    local san="$1"
    
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
    
    return 0
}

validate_ca_name() {
    local ca_name="$1"
    
    if [[ ! "$ca_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_error "Invalid CA name: $ca_name (only alphanumeric, underscore, and dash allowed)"
        return 1
    fi
    
    return 0
}

# =============================================================================
# CERTIFICATE INFORMATION DISPLAY
# =============================================================================

display_certificate_info() {
    local cert_file="$1"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        return 1
    fi
    
    echo -e "${BLUE}🔍 Certificate Details:${NC}"
    echo "======================"
    
    local subject validity sans issuer serial
    subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject=//')
    issuer=$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    validity=$(openssl x509 -in "$cert_file" -noout -dates 2>/dev/null)
    serial=$(openssl x509 -in "$cert_file" -noout -serial 2>/dev/null | sed 's/serial=//')
    sans=$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | grep -v "X509v3 Subject Alternative Name:" | tr -d ' ' || echo "None")
    
    echo "   Subject: $subject"
    echo "   Issuer: $issuer"
    echo "   Serial: $serial"
    echo "   $validity"
    echo "   SANs: $sans"
    echo ""
}

check_and_display_file() {
    local file_path="$1"
    local description="$2"
    local show_size="${3:-true}"
    
    if [[ -f "$file_path" ]]; then
        if [[ "$show_size" == "true" ]]; then
            local file_size
            file_size=$(get_file_size_by_os "$file_path")
            printf "   ✅ %-25s %s (%s bytes)\n" "$description:" "$file_path" "$file_size"
        else
            printf "   ✅ %-25s %s\n" "$description:" "$file_path"
        fi
        return 0
    else
        printf "   ❌ %-25s %s\n" "$description:" "$file_path"
        return 1
    fi
}

# =============================================================================
# ERROR HANDLING AND RECOVERY
# =============================================================================

setup_error_handling() {
    local cleanup_function="$1"
    
    # Set up cleanup trap
    trap "$cleanup_function" EXIT
    
    # Set up error trap  
    trap 'handle_error $LINENO $?' ERR
}

handle_error() {
    local line_number="$1"
    local exit_code="$2"
    
    log_error "Script failed at line $line_number with exit code $exit_code"
    [[ -n "${LOG_FILE:-}" ]] && log_error "Check log file for details: $LOG_FILE"
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

generate_timestamp() {
    date +%Y%m%d_%H%M%S
}

format_duration() {
    local seconds="$1"
    local hours=$((seconds / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local secs=$((seconds % 60))
    
    if [[ $hours -gt 0 ]]; then
        printf "%dh %dm %ds" $hours $minutes $secs
    elif [[ $minutes -gt 0 ]]; then
        printf "%dm %ds" $minutes $secs
    else
        printf "%ds" $secs
    fi
}

confirm_action() {
    local message="$1"
    local default="${2:-N}"
    
    echo -n "$message [y/N]: "
    read -r response
    
    case "$response" in
        [Yy]|[Yy][Ee][Ss]) return 0 ;;
        *) return 1 ;;
    esac
}

# =============================================================================
# OPENSSL CONFIGURATION GENERATION
# =============================================================================

generate_openssl_config_template() {
    local ca_dir="$1"
    local cn="$2"
    local country="${3:-CH}"
    local state="${4:-BE}"
    local org="${5:-DanielF}"
    local ou="${6:-IT Infrastructure}"
    
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
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl.pem
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
C  = $country
ST = $state
O  = $org
OU = $ou
CN = $cn

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

[ v3_usr ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
}

# =============================================================================
# LIBRARY INITIALIZATION
# =============================================================================

# Set safe defaults
umask 077

# Export functions that should be available to sourcing scripts
export -f setup_logging log_debug log_info log_success log_warning log_error
export -f init_progress update_progress init_testing_progress
export -f load_config_file validate_config_value
export -f add_temp_file cleanup_temp_files atomic_file_operation backup_directory
export -f check_disk_space validate_openssl check_java_tools
export -f validate_certificate_format validate_private_key_format validate_certificate_key_pair
export -f validate_certificate_chain validate_certificate_extensions
export -f validate_common_name validate_san_entry validate_ca_name
export -f display_certificate_info check_and_display_file
export -f setup_error_handling handle_error
export -f generate_timestamp format_duration confirm_action
export -f generate_openssl_config_template get_file_size
export -f detect_os get_file_size_by_os check_disk_space_by_os validate_openssl_by_os check_java_tools_by_os

log_debug "Common functions library loaded successfully"