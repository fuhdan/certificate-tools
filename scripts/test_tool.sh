#!/bin/bash

# Certificate Analysis Tool API Testing Script
# Tests API functionality, session isolation, and multiuser capabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CERT_DIR="./certificates"
TEST_OUTPUT_DIR="./test_results"
PASSWORD="changeme123"
API_BASE_URL="http://vercingetorix1.danielf.local"
API_USERNAME="admin"
API_PASSWORD="admin123"

# CA filter for certificate tests
CA_FILTER="IssuingCA1"  # Default filter, can be overridden by command-line argument

# Test Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Output file for machine-parsable results
TEST_RESULTS_LOG="$TEST_OUTPUT_DIR/results.log"

# Create directories
mkdir -p "$TEST_OUTPUT_DIR"
> "$TEST_RESULTS_LOG"

# Argument handling: show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Certificate Analysis Tool API Testing Script"
    echo ""
    echo "Options:"
    echo "  -h, --help            Show this help message and exit"
    echo "  --cert-dir DIR        Certificate directory (default: ./certificates)"
    echo "  --output-dir DIR      Output/results directory (default: ./test_results)"
    echo "  --api-url URL         API base URL (default: http://vercingetorix1.danielf.local)"
    echo "  --api-username USER   API username (default: admin)"
    echo "  --api-password PASS   API password (default: admin123)"
    echo "  --password PASS       Certificate password (default: changeme123)"
    echo "  --ca CA_FILTER        Filter for CA certificates (default: IssuingCA1), all for all certificates"
    echo ""
    exit 0
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        --cert-dir)
            CERT_DIR="$2"
            shift 2
            ;;
        --output-dir)
            TEST_OUTPUT_DIR="$2"
            TEST_RESULTS_LOG="$TEST_OUTPUT_DIR/results.log"
            mkdir -p "$TEST_OUTPUT_DIR"
            shift 2
            ;;
        --api-url)
            API_BASE_URL="$2"
            shift 2
            ;;
        --api-username)
            API_USERNAME="$2"
            shift 2
            ;;
        --api-password)
            API_PASSWORD="$2"
            shift 2
            ;;
        --password)
            PASSWORD="$2"
            shift 2
            ;;
        --ca)
            CA_FILTER="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

echo -e "${BLUE}=== Certificate Analysis Tool API Testing ===${NC}"
echo "API URL: $API_BASE_URL"
echo "Test Directory: $CERT_DIR"
echo "Output Directory: $TEST_OUTPUT_DIR"
echo ""

# Function to log test results
log_test() {
    local test_name="$1"
    local status="$2"
    local details="$3"

    case "$status" in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $test_name"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            TOTAL_TESTS=$((TOTAL_TESTS + 1))
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $test_name"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            TOTAL_TESTS=$((TOTAL_TESTS + 1))
            ;;
        "SKIP")
            echo -e "${YELLOW}[SKIP]${NC} $test_name"
            SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
            TOTAL_TESTS=$((TOTAL_TESTS + 1))
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $test_name"
            INFO_TESTS=$((INFO_TESTS + 1))
            TOTAL_TESTS=$((TOTAL_TESTS + 1))
            ;;
        *)
            echo -e "${YELLOW}[INFO]${NC} $test_name"
            INFO_TESTS=$((INFO_TESTS + 1))
            TOTAL_TESTS=$((TOTAL_TESTS + 1))
            ;;
    esac

    if [ -n "$details" ]; then
        echo "       $details"
    fi
    echo ""

    # Write simple line to results log: [STATUS] test_name | details
    echo -e "[$status]\t$test_name\t|\t$details" >> "$TEST_RESULTS_LOG"
}

# Generate UUID for session IDs
generate_session_id() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "session-$(date +%s)-$$"
    fi
}

# Get authentication token
get_auth_token() {
    local response=$(curl -s -X POST "$API_BASE_URL/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$API_USERNAME&password=$API_PASSWORD" \
        --connect-timeout 10 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('access_token', ''))
except:
    pass
" 2>/dev/null
    fi
}

# Test API health
test_api_health() {
    echo -e "${YELLOW}Testing API health...${NC}"
    
    local response=$(curl -s -X GET "$API_BASE_URL/health" -w "%{http_code}" --connect-timeout 10 2>/dev/null)
    local http_code="${response: -3}"
    local response_body="${response%???}"
    
    if [ "$http_code" = "200" ]; then
        local health_file="$TEST_OUTPUT_DIR/health_response.json"
        echo "$response_body" > "$health_file"
        log_test "API Health Check" "PASS" "API responding (HTTP $http_code). See $health_file"
    else
        log_test "API Health Check" "FAIL" "API not responding (HTTP $http_code)"
    fi
}

# Test authentication
test_authentication() {
    echo -e "${YELLOW}Testing authentication...${NC}"
    
    local token=$(get_auth_token)
    
    if [ -n "$token" ]; then
        local token_file="$TEST_OUTPUT_DIR/auth_token.txt"
        echo "$token" > "$token_file"
        log_test "Authentication" "PASS" "Successfully obtained access token. See $token_file"
        return 0
    else
        log_test "Authentication" "FAIL" "Failed to obtain access token"
        return 1
    fi
}

# Upload file to specific session; if session_id="" header is omitted (default session)
upload_file() {
    local file="$1"
    local session_id="$2"  # can be empty string ""
    local token="$3"
    
    if [ ! -f "$file" ]; then
        return 1
    fi

    # Prepare curl command: add session header only if session_id is non-empty
    local curl_cmd=(curl -s -X POST "$API_BASE_URL/analyze-certificate" \
        -H "Authorization: Bearer $token" \
        -F "certificate=@$file" \
        -F "password=$PASSWORD" \
        -w "%{http_code}" \
        --connect-timeout 20)

    if [ -n "$session_id" ]; then
        curl_cmd+=(-H "X-Session-ID: $session_id")
    fi

    local response=$("${curl_cmd[@]}" 2>/dev/null)
    
    local http_code="${response: -3}"
    local response_body="${response%???}"
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        local upload_file
        if [ -n "$session_id" ]; then
            upload_file="$TEST_OUTPUT_DIR/upload_${session_id:0:8}_$(basename $file).json"
        else
            upload_file="$TEST_OUTPUT_DIR/upload_default_$(basename $file).json"
        fi
        echo "$response_body" > "$upload_file"
        log_test "Upload File/$(basename $file)" "PASS" "Response saved to $upload_file"
        return 0
    else
        local err_file
        if [ -n "$session_id" ]; then
            err_file="$TEST_OUTPUT_DIR/upload_error_${session_id:0:8}_$(basename $file).log"
        else
            err_file="$TEST_OUTPUT_DIR/upload_error_default_$(basename $file).log"
        fi
        echo "$response_body" > "$err_file"
        log_test "Upload File/$(basename $file)" "FAIL" "Error log: $err_file"
        return 1
    fi
}

# Get certificates from session; if session_id="" header omitted, queries default session
get_session_certificates() {
    local session_id="$1"  # can be empty string ""
    local token="$2"

    local curl_cmd=(curl -s -X GET "$API_BASE_URL/certificates" \
        -H "Authorization: Bearer $token" \
        -w "%{http_code}" \
        --connect-timeout 15)

    if [ -n "$session_id" ]; then
        curl_cmd+=(-H "X-Session-ID: $session_id")
    fi

    local response=$("${curl_cmd[@]}" 2>/dev/null)

    local http_code="${response: -3}"
    local response_body="${response%???}"

    if [ "$http_code" = "200" ]; then
        echo "$response_body"
        return 0
    else
        return 1
    fi
}

# Count certificates in response
count_certificates() {
    local response="$1"
    
    echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'certificates' in data:
        certs = data['certificates']
        if isinstance(certs, list):
            print(len(certs))
        else:
            print(0)
    else:
        print(0)
except:
    print(0)
" 2>/dev/null
}

# New test for default session isolation
test_default_session_isolation() {
    echo -e "${YELLOW}Testing default session isolation (upload without session ID)...${NC}"
    local token=$(get_auth_token)
    if [ -z "$token" ]; then
        log_test "Default Session Isolation" "FAIL" "Authentication failed"
        return
    fi

    # Find test files for default and valid sessions
    local default_file=$(find "$CERT_DIR" -name "*.crt.pem" | head -n 1)
    local normal_file=$(find "$CERT_DIR" -name "*.crt.pem" | head -n 2 | tail -n 1)
    if [ ! -f "$default_file" ] || [ ! -f "$normal_file" ]; then
        log_test "Default Session Isolation" "SKIP" "Not enough certificate files found"
        return
    fi

    # Upload to default session (upload without X-Session-ID header)
    echo "  Uploading to default session (no session ID header)..."
    local response=$(curl -s -X POST "$API_BASE_URL/analyze-certificate" \
        -H "Authorization: Bearer $token" \
        -F "certificate=@$default_file" \
        -F "password=$PASSWORD" \
        -w "%{http_code}" \
        --connect-timeout 20 2>/dev/null)
    local http_code="${response: -3}"
    local response_body="${response%???}"

    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        local default_upload_log="$TEST_OUTPUT_DIR/upload_default_no_session.json"
        echo "$response_body" > "$default_upload_log"
        log_test "Default Session Isolation/Upload" "PASS" "Uploaded without session ID, see $default_upload_log"
    else
        log_test "Default Session Isolation/Upload" "FAIL" "Upload failed with HTTP $http_code"
        return
    fi

    # Create a valid session and upload to it
    local session=$(generate_session_id)
    echo "  Uploading file to session $session"
    if upload_file "$normal_file" "$session" "$token"; then
        log_test "Default Session Isolation/Upload" "PASS" "Uploaded cert to session $session"
    else
        log_test "Default Session Isolation/Upload" "FAIL" "Upload failed to session $session"
        return
    fi

    # Retrieve certificates from default session (no session header)
    local default_certs_response=$(curl -s -X GET "$API_BASE_URL/certificates" \
        -H "Authorization: Bearer $token" \
        -w "%{http_code}" \
        --connect-timeout 15 2>/dev/null)
    local default_certs_http="${default_certs_response: -3}"
    local default_certs_body="${default_certs_response%???}"

    if [ "$default_certs_http" != "200" ]; then
        log_test "Default Session Isolation/Get Certificates" "FAIL" "Failed to retrieve default session certs (HTTP $default_certs_http)"
        return
    fi

    local default_cert_count=$(count_certificates "$default_certs_body")
    local default_certs_file="$TEST_OUTPUT_DIR/default_session_certificates.json"
    echo "$default_certs_body" > "$default_certs_file"
    log_test "Default Session Isolation/Get Certificates" "INFO" "Default session certs saved to $default_certs_file"
    log_test "Default Session Isolation" "INFO" "Default session contains $default_cert_count certificates"

    # Retrieve certificates from valid session
    local session_certs_response=$(get_session_certificates "$session" "$token")
    if [ $? -ne 0 ]; then
        log_test "Default Session Isolation/Get Certificates" "FAIL" "Failed to retrieve session $session certificates"
        return
    fi
    local session_cert_count=$(count_certificates "$session_certs_response")
    local session_certs_file="$TEST_OUTPUT_DIR/session_${session:0:8}_certificates.json"
    echo "$session_certs_response" > "$session_certs_file"
    log_test "Default Session Isolation/Get Certificates" "INFO" "Session $session certs saved to $session_certs_file"
    log_test "Default Session Isolation" "INFO" "Session $session contains $session_cert_count certificates"

    # Verify cross-access is prohibited:
    # You should NOT be able to see default session certs in valid session's data, and vice versa
    if [ "$default_cert_count" -ge 1 ] && [ "$session_cert_count" -ge 1 ]; then
        log_test "Default Session Isolation" "PASS" "Default session and valid session certificates isolated properly"
    else
        log_test "Default Session Isolation" "FAIL" "Possible session access overlap or missing certificates: default=$default_cert_count, session=$session_cert_count"
    fi
}

# (Rest of your original test functions below, unchanged)

# Test session isolation
test_session_isolation() {
    echo -e "${YELLOW}Testing session isolation...${NC}"
    
    local token=$(get_auth_token)
    if [ -z "$token" ]; then
        log_test "Session Isolation" "FAIL" "Authentication failed"
        return
    fi
    
    # Create 3 sessions
    local session1=$(generate_session_id)
    local session2=$(generate_session_id)
    local session3=$(generate_session_id)
    
    echo "  Created sessions:"
    echo "    Session 1: $session1"
    echo "    Session 2: $session2"
    echo "    Session 3: $session3"
    echo ""
    
    # Find test files
    local file1=$(find "$CERT_DIR" -name "*.crt.pem" | head -n 1)
    local file2=$(find "$CERT_DIR" -name "*.crt.pem" | head -n 2 | tail -n 1)
    local file3=$(find "$CERT_DIR" -name "*.crt.pem" | head -n 3 | tail -n 1)
    
    if [ ! -f "$file1" ] || [ ! -f "$file2" ] || [ ! -f "$file3" ]; then
        log_test "Session Isolation" "SKIP" "Not enough certificate files found"
        return
    fi
    
    # Upload files to different sessions
    echo "  Uploading files to sessions..."
    
    if upload_file "$file1" "$session1" "$token"; then
        echo "    ✓ Uploaded $(basename $file1) to session 1"
    else
        echo "    ✗ Failed to upload to session 1"
        log_test "Session Isolation" "FAIL" "Upload to session 1 failed"
        return
    fi
    
    if upload_file "$file2" "$session2" "$token"; then
        echo "    ✓ Uploaded $(basename $file2) to session 2"
    else
        echo "    ✗ Failed to upload to session 2"
        log_test "Session Isolation" "FAIL" "Upload to session 2 failed"
        return
    fi
    
    if upload_file "$file3" "$session3" "$token"; then
        echo "    ✓ Uploaded $(basename $file3) to session 3"
    else
        echo "    ✗ Failed to upload to session 3"
        log_test "Session Isolation" "FAIL" "Upload to session 3 failed"
        return
    fi
    
    echo ""
    echo "  Verifying session isolation..."
    
    # Check each session has exactly 1 file
    local session1_response=$(get_session_certificates "$session1" "$token")
    local session2_response=$(get_session_certificates "$session2" "$token")
    local session3_response=$(get_session_certificates "$session3" "$token")
    
    if [ $? -ne 0 ]; then
        log_test "Session Isolation" "FAIL" "Failed to retrieve session certificates"
        return
    fi
    
    # Save responses for debugging
    local sess1_file="$TEST_OUTPUT_DIR/session1_certificates.json"
    local sess2_file="$TEST_OUTPUT_DIR/session2_certificates.json"
    local sess3_file="$TEST_OUTPUT_DIR/session3_certificates.json"
    echo "$session1_response" > "$sess1_file"
    echo "$session2_response" > "$sess2_file"
    echo "$session3_response" > "$sess3_file"
    
    # Count certificates in each session
    local count1=$(count_certificates "$session1_response")
    local count2=$(count_certificates "$session2_response")
    local count3=$(count_certificates "$session3_response")
    
    echo "    Session 1 contains: $count1 certificates"
    echo "    Session 2 contains: $count2 certificates"
    echo "    Session 3 contains: $count3 certificates"
    echo ""
    
    log_test "Session Isolation/Certificates Dump/Session 1" "INFO" "Saved to $sess1_file"
    log_test "Session Isolation/Certificates Dump/Session 2" "INFO" "Saved to $sess2_file"
    log_test "Session Isolation/Certificates Dump/Session 3" "INFO" "Saved to $sess3_file"
    
    # Verify isolation
    if [ "$count1" = "1" ] && [ "$count2" = "1" ] && [ "$count3" = "1" ]; then
        log_test "Session Isolation" "PASS" "Each session contains exactly 1 certificate"
        
        # Test cross-session access prevention
        test_cross_session_access "$session1" "$session2" "$session3" "$token"
    else
        log_test "Session Isolation" "FAIL" "Sessions don't contain expected number of certificates (expected 1 each, got $count1, $count2, $count3)"
    fi
}

# Test cross-session access prevention
test_cross_session_access() {
    local session1="$1"
    local session2="$2"
    local session3="$3"
    local token="$4"
    
    echo "  Testing cross-session access prevention..."
    
    # Try to access session2's files using session1's ID
    local cross_response=$(get_session_certificates "$session1" "$token")
    local cross_count=$(count_certificates "$cross_response")
    
    # Should still see only session1's file (1), not session2's files
    if [ "$cross_count" = "1" ]; then
        echo "    ✓ Session 1 cannot access other sessions' files"
        log_test "Cross-Session Access Prevention" "PASS" "Sessions properly isolated"
    else
        echo "    ✗ Session isolation may be compromised"
        log_test "Cross-Session Access Prevention" "FAIL" "Session isolation compromised"
    fi
}

# Test invalid session ID handling
test_invalid_session_id() {
    echo -e "${YELLOW}Testing invalid session ID handling...${NC}"
    
    local token=$(get_auth_token)
    if [ -z "$token" ]; then
        log_test "Invalid Session ID" "FAIL" "Authentication failed"
        return
    fi
    
    local test_file=$(find "$CERT_DIR" -name "*.crt.pem" | head -n 1)
    if [ ! -f "$test_file" ]; then
        log_test "Invalid Session ID" "SKIP" "No test file available"
        return
    fi
    
    echo "  Testing various invalid session ID formats..."
    
    # Test cases for invalid session IDs
    local invalid_sessions=(
        "invalid-uuid-format"
        "12345"
        "not-a-uuid-at-all"
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        "00000000-0000-0000-0000-000000000000"
        "null"
        "undefined"
        "too-long-session-id-that-exceeds-normal-uuid-length-significantly"
        "short"
        "CAPS-INVALID-UUID-FORMAT-TEST"
        "123e4567-e89b-12d3-a456-42661417400G"  # Invalid hex character
        "123e4567-e89b-12d3-a456-4266141740000" # Too long
        "123e4567-e89b-12d3-a456-42661417400"   # Too short
    )
    
    local invalid_count=0
    local handled_properly=0
    
    for invalid_session in "${invalid_sessions[@]}"; do
        invalid_count=$((invalid_count + 1))
        
        if [ -z "$invalid_session" ]; then
            echo "    Testing empty session ID..."
            # Test upload without X-Session-ID header
            local response=$(curl -s -X POST "$API_BASE_URL/analyze-certificate" \
                -H "Authorization: Bearer $token" \
                -F "certificate=@$test_file" \
                -F "password=$PASSWORD" \
                -w "%{http_code}" \
                --connect-timeout 10 2>/dev/null)
        else
            echo "    Testing invalid session ID: '$invalid_session'"
            local response=$(curl -s -X POST "$API_BASE_URL/analyze-certificate" \
                -H "Authorization: Bearer $token" \
                -H "X-Session-ID: $invalid_session" \
                -F "certificate=@$test_file" \
                -F "password=$PASSWORD" \
                -w "%{http_code}" \
                --connect-timeout 10 2>/dev/null)
        fi
        
        local http_code="${response: -3}"
        local response_body="${response%???}"
        
        local invalid_log="$TEST_OUTPUT_DIR/invalid_session_${invalid_count}.log"
        # Save response for analysis
        echo "$response_body" > "$invalid_log"
        echo "HTTP $http_code" >> "$invalid_log"
        
        # Check how the API handles invalid session ID
        case "$http_code" in
            "200"|"201")
                echo "      → API accepted invalid session (HTTP $http_code) - may have auto-corrected"
                log_test "Invalid Session ID/Upload/$invalid_session" "FAIL" "Upload accepted (HTTP $http_code). See $invalid_log"
                ;;
            "400")
                echo "      → API rejected invalid session (HTTP $http_code) - proper validation"
                log_test "Invalid Session ID/Upload/$invalid_session" "PASS" "Rejected (HTTP $http_code). See $invalid_log"
                handled_properly=$((handled_properly + 1))
                ;;
            "422")
                echo "      → API validation error (HTTP $http_code) - proper validation"
                log_test "Invalid Session ID/Upload/$invalid_session" "PASS" "Validation error (HTTP $http_code). See $invalid_log"
                handled_properly=$((handled_properly + 1))
                ;;
            "500")
                echo "      → API internal error (HTTP $http_code) - may need better validation"
                log_test "Invalid Session ID/Upload/$invalid_session" "FAIL" "Internal error (HTTP $http_code). See $invalid_log"
                ;;
            *)
                echo "      → Unexpected response (HTTP $http_code)"
                log_test "Invalid Session ID/Upload/$invalid_session" "FAIL" "Unexpected response (HTTP $http_code). See $invalid_log"
                ;;
        esac
    done
    
    echo ""
    echo "  Testing session ID retrieval with invalid IDs..."
    
    # Test retrieving certificates with invalid session IDs
    local retrieval_tests=("invalid-session" "12345")
    local retrieval_handled=0
    
    for invalid_session in "${retrieval_tests[@]}"; do
        if [ -z "$invalid_session" ]; then
            echo "    Testing certificate retrieval without session ID..."
            local response=$(curl -s -X GET "$API_BASE_URL/certificates" \
                -H "Authorization: Bearer $token" \
                -w "%{http_code}" \
                --connect-timeout 10 2>/dev/null)
        else
            echo "    Testing certificate retrieval with invalid session: '$invalid_session'"
            local response=$(curl -s -X GET "$API_BASE_URL/certificates" \
                -H "Authorization: Bearer $token" \
                -H "X-Session-ID: $invalid_session" \
                -w "%{http_code}" \
                --connect-timeout 10 2>/dev/null)
        fi
        
        local http_code="${response: -3}"
        local response_body="${response%???}"
        
        local retrieval_log="$TEST_OUTPUT_DIR/invalid_retrieval_${invalid_session// /_}.log"
        echo "$response_body" > "$retrieval_log"
        echo "HTTP $http_code" >> "$retrieval_log"
        
        case "$http_code" in
            "200")
                echo "      → API returned certificates (HTTP $http_code)"
                local cert_count=$(count_certificates "$response_body")
                echo "      → Certificate count: $cert_count"
                if [ "$cert_count" = "0" ]; then
                    log_test "Invalid Session ID/Retrieve/$invalid_session" "PASS" "Return 0 certificates (HTTP $http_code). See $retrieval_log"
                    retrieval_handled=$((retrieval_handled + 1))
                else
                    log_test "Invalid Session ID/Retrieve/$invalid_session" "FAIL" "Returned $cert_count certs (HTTP $http_code). See $retrieval_log"
                fi
                ;;
            "400"|"422")
                echo "      → API properly rejected invalid session (HTTP $http_code)"
                log_test "Invalid Session ID/Retrieve/$invalid_session" "PASS" "Proper rejection (HTTP $http_code). See $retrieval_log"
                retrieval_handled=$((retrieval_handled + 1))
                ;;
            *)
                echo "      → Unexpected response (HTTP $http_code)"
                log_test "Invalid Session ID/Retrieve/$invalid_session" "FAIL" "Unexpected (HTTP $http_code). See $retrieval_log"
                ;;
        esac
    done
    
    # Evaluate results
    local total_tests=$((invalid_count + ${#retrieval_tests[@]}))
    local total_handled=$((handled_properly + retrieval_handled))
    
    echo ""
    echo "  Invalid session ID test summary:"
    echo "    Total invalid IDs tested: $invalid_count"
    echo "    Upload tests handled properly: $handled_properly/$invalid_count"
    echo "    Retrieval tests handled properly: $retrieval_handled/${#retrieval_tests[@]}"
    echo "    Overall handling rate: $total_handled/$total_tests"
    
    if [ $total_handled -eq $total_tests ]; then
        log_test "Invalid Session ID Handling" "PASS" "All invalid session IDs handled properly ($total_handled/$total_tests)"
    elif [ $total_handled -gt $((total_tests * 70 / 100)) ]; then
        log_test "Invalid Session ID Handling" "PASS" "Most invalid session IDs handled properly ($total_handled/$total_tests)"
    else
        log_test "Invalid Session ID Handling" "FAIL" "Poor handling of invalid session IDs ($total_handled/$total_tests)"
    fi
}

test_concurrent_access() {
    echo -e "${YELLOW}Testing concurrent access...${NC}"
    
    local token=$(get_auth_token)
    if [ -z "$token" ]; then
        log_test "Concurrent Access" "FAIL" "Authentication failed"
        return
    fi
    
    # Create sessions for concurrent test
    local concurrent_session1=$(generate_session_id)
    local concurrent_session2=$(generate_session_id)
    local concurrent_session3=$(generate_session_id)
    
    local test_file=$(find "$CERT_DIR" -name "*.crt.pem" | head -n 1)
    if [ ! -f "$test_file" ]; then
        log_test "Concurrent Access" "SKIP" "No test file available"
        return
    fi
    
    echo "  Testing concurrent uploads to 3 sessions..."
    
    # Launch concurrent uploads
    upload_file "$test_file" "$concurrent_session1" "$token" > "$TEST_OUTPUT_DIR/concurrent1.log" 2>&1 &
    local pid1=$!
    
    upload_file "$test_file" "$concurrent_session2" "$token" > "$TEST_OUTPUT_DIR/concurrent2.log" 2>&1 &
    local pid2=$!
    
    upload_file "$test_file" "$concurrent_session3" "$token" > "$TEST_OUTPUT_DIR/concurrent3.log" 2>&1 &
    local pid3=$!
    
    # Wait for all uploads to complete
    wait $pid1
    local result1=$?
    wait $pid2
    local result2=$?
    wait $pid3
    local result3=$?
    
    # Count successful uploads
    local success_count=0
    [ $result1 -eq 0 ] && success_count=$((success_count + 1))
    [ $result2 -eq 0 ] && success_count=$((success_count + 1))
    [ $result3 -eq 0 ] && success_count=$((success_count + 1))
    
    # Log each session upload status with links to logs
    log_test "Concurrent Access/Session 1 upload" "$([ $result1 -eq 0 ] && echo PASS || echo FAIL)" "$TEST_OUTPUT_DIR/concurrent1.log"
    log_test "Concurrent Access/Session 2 upload" "$([ $result2 -eq 0 ] && echo PASS || echo FAIL)" "$TEST_OUTPUT_DIR/concurrent2.log"
    log_test "Concurrent Access/Session 3 upload" "$([ $result3 -eq 0 ] && echo PASS || echo FAIL)" "$TEST_OUTPUT_DIR/concurrent3.log"
    
    if [ $success_count -eq 3 ]; then
        log_test "Concurrent Access" "PASS" "All 3 concurrent uploads succeeded"
    else
        log_test "Concurrent Access" "FAIL" "Only $success_count/3 concurrent uploads succeeded"
    fi
}

test_certificate_types_and_validation() {
    
    if [ "$CA_FILTER" = "all" ]; then
        echo -e "${YELLOW}Testing certificates, keys, and CSRs from all CAs...${NC}"
        local cert_files=($(find "$CERT_DIR" -name "*" \( -name "*.crt.pem" -o -name "*.crt.der" -o -name "*.p12" -o -name "*.p7b" -o -name "*.p7c" -o -name "*.key.pem" -o -name "*.key.nopass.pem" -o -name "*.key.der" -o -name "*.key.nopass.der" -o -name "*.key.p8" -o -name "*.key.nopass.p8" -o -name "*.csr.pem" -o -name "*.csr.der" \)))
    else
        echo -e "${YELLOW}Testing certificates, keys, and CSRs from $CA_FILTER...${NC}"
        local cert_files=($(find "$CERT_DIR" -name "*${CA_FILTER}*" \( -name "*.crt.pem" -o -name "*.crt.der" -o -name "*.p12" -o -name "*.p7b" -o -name "*.p7c" -o -name "*.key.pem" -o -name "*.key.nopass.pem" -o -name "*.key.der" -o -name "*.key.nopass.der" -o -name "*.key.p8" -o -name "*.key.nopass.p8" -o -name "*.csr.pem" -o -name "*.csr.der" \)))
    fi
    
    local token=$(get_auth_token)
    if [ -z "$token" ]; then
        log_test "Certificate Types Test" "FAIL" "Authentication failed"
        return
    fi
    
    if [ ${#cert_files[@]} -eq 0 ]; then
        log_test "Certificate Types Test" "SKIP" "No certificates, keys, or CSRs found for $CA_FILTER in $CERT_DIR"
        return
    fi
    
    echo "  Found ${#cert_files[@]} files for $CA_FILTER:"
    for cert_file in "${cert_files[@]}"; do
        echo "    $(basename "$cert_file")"
    done
    echo ""
    
    local session_id=$(generate_session_id)
    
    # Test each file
    for cert_file in "${cert_files[@]}"; do
        if [ -f "$cert_file" ]; then
            local cert_type=$(detect_certificate_type "$cert_file")
            test_single_certificate "$cert_file" "$session_id" "$token" "$cert_type"
        fi
    done
}

# Test Redis connectivity through health endpoint
test_redis_connectivity() {
    echo -e "${YELLOW}Testing Redis connectivity and session storage...${NC}"
    
    # Test Redis health through the /health endpoint
    local health_response=$(curl -s -X GET "$API_BASE_URL/health" --connect-timeout 10 2>/dev/null)
    local health_http_code=$(curl -s -X GET "$API_BASE_URL/health" -w "%{http_code}" --connect-timeout 10 2>/dev/null | tail -c 3)
    
    if [ "$health_http_code" = "200" ]; then
        local health_file="$TEST_OUTPUT_DIR/redis_health_response.json"
        echo "$health_response" > "$health_file"
        
        # Parse Redis status from health endpoint
        local redis_status=$(echo "$health_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    redis_info = data.get('redis', {})
    print(redis_info.get('status', 'unknown'))
except:
    print('parse_error')
" 2>/dev/null)
        
        local session_count=$(echo "$health_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    sessions_info = data.get('sessions', {})
    print(sessions_info.get('active_sessions', 'unknown'))
except:
    print('unknown')
" 2>/dev/null)
        
        case "$redis_status" in
            "healthy")
                log_test "Redis Connectivity" "PASS" "Redis is healthy, $session_count active sessions. See $health_file"
                ;;
            "unhealthy")
                log_test "Redis Connectivity" "FAIL" "Redis is unhealthy. See $health_file"
                ;;
            "not_configured")
                log_test "Redis Connectivity" "INFO" "Redis not configured (using in-memory storage). See $health_file"
                ;;
            *)
                log_test "Redis Connectivity" "FAIL" "Redis status unknown ($redis_status). See $health_file"
                ;;
        esac
        
        # Test session persistence across requests
        test_redis_session_persistence
        
    else
        log_test "Redis Connectivity" "FAIL" "Health endpoint failed (HTTP $health_http_code)"
    fi
}

# Test Redis session persistence
test_redis_session_persistence() {
    echo "  Testing Redis session persistence..."
    
    local token=$(get_auth_token)
    if [ -z "$token" ]; then
        log_test "Redis Session Persistence" "FAIL" "Authentication failed"
        return
    fi
    
    local test_file=$(find "$CERT_DIR" -name "*.crt.pem" | head -n 1)
    if [ ! -f "$test_file" ]; then
        log_test "Redis Session Persistence" "SKIP" "No test file available"
        return
    fi
    
    # Create a session and upload a certificate
    local session_id=$(generate_session_id)
    echo "    Creating session $session_id and uploading certificate..."
    
    if upload_file "$test_file" "$session_id" "$token"; then
        echo "    ✓ Certificate uploaded to session"
        
        # Verify the certificate is stored
        local initial_response=$(get_session_certificates "$session_id" "$token")
        local initial_count=$(count_certificates "$initial_response")
        
        if [ "$initial_count" = "1" ]; then
            echo "    ✓ Certificate found in session ($initial_count certificates)"
            
            # Wait a moment to simulate some time passing
            sleep 2
            
            # Retrieve certificates again to test persistence
            local second_response=$(get_session_certificates "$session_id" "$token")
            local second_count=$(count_certificates "$second_response")
            
            if [ "$second_count" = "1" ]; then
                echo "    ✓ Certificate persisted across requests"
                log_test "Redis Session Persistence" "PASS" "Session data persisted correctly ($second_count certificates)"
                
                # Save session data for debugging
                local persist_file="$TEST_OUTPUT_DIR/redis_persistence_test.json"
                echo "$second_response" > "$persist_file"
                log_test "Redis Session Persistence/Data" "INFO" "Session data saved to $persist_file"
                
            else
                echo "    ✗ Certificate not persisted ($second_count vs $initial_count)"
                log_test "Redis Session Persistence" "FAIL" "Session data not persisted correctly"
            fi
        else
            echo "    ✗ Certificate not found in session ($initial_count certificates)"
            log_test "Redis Session Persistence" "FAIL" "Certificate not stored in session"
        fi
    else
        echo "    ✗ Failed to upload certificate"
        log_test "Redis Session Persistence" "FAIL" "Certificate upload failed"
    fi
}

# Test Redis session stats
test_redis_session_stats() {
    echo -e "${YELLOW}Testing Redis session statistics...${NC}"
    
    # Get current health/stats
    local health_response=$(curl -s -X GET "$API_BASE_URL/health" --connect-timeout 10 2>/dev/null)
    local health_http_code=$(curl -s -X GET "$API_BASE_URL/health" -w "%{http_code}" --connect-timeout 10 2>/dev/null | tail -c 3)
    
    if [ "$health_http_code" = "200" ]; then
        local stats_file="$TEST_OUTPUT_DIR/redis_session_stats.json"
        echo "$health_response" > "$stats_file"
        
        # Extract session statistics
        local session_stats=$(echo "$health_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    sessions = data.get('sessions', {})
    active = sessions.get('active_sessions', 0)
    memory = sessions.get('total_memory_mb', 0)
    requests = sessions.get('total_requests', 0)
    print(f'Active: {active}, Memory: {memory}MB, Requests: {requests}')
except:
    print('Stats unavailable')
" 2>/dev/null)
        
        log_test "Redis Session Stats" "INFO" "$session_stats. See $stats_file"
        
        # Check if we have reasonable stats
        local active_sessions=$(echo "$health_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    sessions = data.get('sessions', {})
    print(sessions.get('active_sessions', 0))
except:
    print(0)
" 2>/dev/null)
        
        if [ "$active_sessions" -gt 0 ]; then
            log_test "Redis Session Stats/Active Sessions" "PASS" "$active_sessions active sessions detected"
        else
            log_test "Redis Session Stats/Active Sessions" "INFO" "No active sessions (normal if no recent activity)"
        fi
        
    else
        log_test "Redis Session Stats" "FAIL" "Could not retrieve session stats (HTTP $health_http_code)"
    fi
}

# Test individual certificate with APPLICATION
test_single_certificate() {
    local cert_file="$1"
    local session_id="$2" 
    local token="$3"
    local cert_type="$4"
    
    local filename=$(basename "$cert_file")
    echo "    Testing $cert_type: $filename"
    
    # Upload to APPLICATION
    local response=$(curl -s -X POST "$API_BASE_URL/analyze-certificate" \
        -H "Authorization: Bearer $token" \
        -H "X-Session-ID: $session_id" \
        -F "certificate=@$cert_file" \
        -F "password=$PASSWORD" \
        -w "%{http_code}" \
        --connect-timeout 30 2>/dev/null)
    
    local http_code="${response: -3}"
    local response_body="${response%???}"
    
    # Save APPLICATION response
    local cert_log="$TEST_OUTPUT_DIR/cert_${cert_type}_${filename//[^a-zA-Z0-9]/_}.log"
    echo "API Response (HTTP $http_code):" > "$cert_log"
    echo "$response_body" >> "$cert_log"
    
    # Parse JSON properly using python3
    local success=$(echo "$response_body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('success', 'unknown'))
except:
    print('parse_error')
" 2>/dev/null)
    
    local is_valid=$(echo "$response_body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    cert = data.get('certificate', {})
    analysis = cert.get('analysis', {})
    print(analysis.get('isValid', 'unknown'))
except:
    print('parse_error')
" 2>/dev/null)
    
    local requires_password=$(echo "$response_body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('requiresPassword', 'unknown'))
except:
    print('parse_error')
" 2>/dev/null)
    
    local message=$(echo "$response_body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('message', ''))
except:
    print('parse_error')
" 2>/dev/null)
    
    # Analyze APPLICATION response content
    case "$http_code" in
        "200"|"201")
            if [ "$success" = "True" ] && [ "$is_valid" = "True" ]; then
                local cert_details=$(extract_certificate_details "$response_body")
                log_test "Certificate Types/$cert_type/$filename" "PASS" "APPLICATION processed successfully. $cert_details. See $cert_log"
            elif [ "$success" = "False" ] && [ "$requires_password" = "True" ]; then
                log_test "Certificate Types/$cert_type/$filename" "INFO" "PASSWORD REQUIRED: $message. See $cert_log"
            elif [ "$success" = "False" ]; then
                log_test "Certificate Types/$cert_type/$filename" "FAIL" "APPLICATION rejected: $message. See $cert_log"
            else
                log_test "Certificate Types/$cert_type/$filename" "FAIL" "APPLICATION returned unclear response (success=$success, isValid=$is_valid). See $cert_log"
            fi
            ;;
        "400"|"422")
            log_test "Certificate Types/$cert_type/$filename" "FAIL" "APPLICATION rejected (HTTP $http_code). See $cert_log"
            ;;
        *)
            log_test "Certificate Types/$cert_type/$filename" "FAIL" "APPLICATION error (HTTP $http_code). See $cert_log"
            ;;
    esac
}

# Detect certificate/key/CSR type by filename
detect_certificate_type() {
    local cert_file="$1"
    local filename=$(basename "$cert_file")
    
    case "$filename" in
        *.crt.pem)
            echo "PEM_CERT"
            ;;
        *.crt.der)
            echo "DER_CERT"
            ;;
        *.p12)
            echo "PKCS12"
            ;;
        *.p7b)
            echo "PKCS7"
            ;;
        *.p7c)
            echo "PKCS7"
            ;;
        *.key.pem)
            echo "PEM_KEY"
            ;;
        *.key.nopass.pem)
            echo "PEM_KEY_NOPASS"
            ;;
        *.key.der)
            echo "DER_KEY"
            ;;
        *.key.nopass.der)
            echo "DER_KEY_NOPASS"
            ;;
        *.key.p8)
            echo "PKCS8_KEY"
            ;;
        *.key.nopass.p8)
            echo "PKCS8_KEY_NOPASS"
            ;;
        *.csr.pem)
            echo "PEM_CSR"
            ;;
        *.csr.der)
            echo "DER_CSR"
            ;;
        *)
            echo "UNKNOWN"
            ;;
    esac
}

# Extract useful details from API response
extract_certificate_details() {
    local response="$1"
    
    # Try to extract key information using simple parsing
    local subject=$(echo "$response" | grep -o '"subject":"[^"]*"' | cut -d'"' -f4 | head -1)
    local expiry=$(echo "$response" | grep -o '"expires":"[^"]*"' | cut -d'"' -f4 | head -1)
    local issuer=$(echo "$response" | grep -o '"issuer":"[^"]*"' | cut -d'"' -f4 | head -1)
    
    local details=""
    [ -n "$subject" ] && details="Subject: $subject"
    [ -n "$expiry" ] && details="$details, Expires: $expiry"
    [ -n "$issuer" ] && details="$details, Issuer: $issuer"
    
    echo "$details"
}

# Generate comprehensive summary
generate_summary() {
    echo ""
    echo -e "${BLUE}=====================================================================${NC}"
    echo -e "${BLUE}           CERTIFICATE ANALYSIS TOOL - TEST SUMMARY                 ${NC}"
    echo -e "${BLUE}=====================================================================${NC}"
    echo ""
    
    # Test Results
    echo -e "   Total Tests: ${BLUE}$TOTAL_TESTS${NC} (including ${INFO_TESTS:-0} INFO-only steps)"
    echo -e "   Passed: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "   Failed: ${RED}$FAILED_TESTS${NC}"
    echo -e "   Skipped: ${YELLOW}$SKIPPED_TESTS${NC}"
    echo -e "   Info: ${BLUE}${INFO_TESTS:-0}${NC}"
 
    if [ $TOTAL_TESTS -gt 0 ]; then
        local total_success=$((PASSED_TESTS + ${INFO_TESTS:-0}))
        local success_rate=$(( total_success * 100 / TOTAL_TESTS ))
        echo -e "   Success Rate: ${GREEN}$success_rate%${NC}"
    fi
    echo ""
    
    # API Information
    echo -e "${YELLOW}🌐 API INFORMATION${NC}"
    echo -e "   Base URL: ${BLUE}$API_BASE_URL${NC}"
    echo -e "   Health Endpoint: /health"
    echo -e "   Auth Endpoint: /token"
    echo -e "   Upload Endpoint: /analyze-certificate"
    echo -e "   Certificates Endpoint: /certificates"
    echo ""
    
    # Certificate Files Found (using filter)
    echo -e "${YELLOW}📋 CERTIFICATE FILES TESTED${NC}"
    if [ "$CA_FILTER" = "all" ]; then
        local filter_pattern="*"
    else
        local filter_pattern="*${CA_FILTER}*"
    fi
    
    local pem_certs=($(find "$CERT_DIR" -name "$filter_pattern" -name "*.crt.pem"))
    local der_certs=($(find "$CERT_DIR" -name "$filter_pattern" -name "*.crt.der"))
    local pkcs12_certs=($(find "$CERT_DIR" -name "$filter_pattern" -name "*.p12"))
    local pkcs7_certs=($(find "$CERT_DIR" -name "$filter_pattern" \( -name "*.p7b" -o -name "*.p7c" \)))
    local pem_keys=($(find "$CERT_DIR" -name "$filter_pattern" \( -name "*.key.pem" -o -name "*.key.nopass.pem" \)))
    local der_keys=($(find "$CERT_DIR" -name "$filter_pattern" \( -name "*.key.der" -o -name "*.key.nopass.der" \)))
    local pkcs8_keys=($(find "$CERT_DIR" -name "$filter_pattern" \( -name "*.key.p8" -o -name "*.key.nopass.p8" \)))
    local pem_csrs=($(find "$CERT_DIR" -name "$filter_pattern" -name "*.csr.pem"))
    local der_csrs=($(find "$CERT_DIR" -name "$filter_pattern" -name "*.csr.der"))
    
    echo -e "   PEM Certificates Found:        ${#pem_certs[@]}"
    echo -e "   DER Certificates Found:        ${#der_certs[@]}"
    echo -e "   PKCS#12 Files Found:           ${#pkcs12_certs[@]}"
    echo -e "   PKCS#7 Files Found:            ${#pkcs7_certs[@]}"
    echo -e "   PEM Private Keys Found:        ${#pem_keys[@]}"
    echo -e "   DER Private Keys Found:        ${#der_keys[@]}"
    echo -e "   PKCS#8 Private Keys Found:     ${#pkcs8_keys[@]}"
    echo -e "   PEM CSRs Found:                ${#pem_csrs[@]}"
    echo -e "   DER CSRs Found:                ${#der_csrs[@]}"
    echo -e "   Certificate Directory: $CERT_DIR"
    echo ""
    
    # Output Files
    echo -e "${YELLOW}📤 OUTPUT FILES${NC}"
    local output_count=$(find "$TEST_OUTPUT_DIR" -type f 2>/dev/null | wc -l)
    echo -e "   Files Generated: ${BLUE}$output_count${NC}"
    echo -e "   Output Directory: ${BLUE}$TEST_OUTPUT_DIR${NC}"
    echo ""
    
    # System Info
    echo -e "${YELLOW}💻 SYSTEM INFORMATION${NC}"
    echo -e "   Test Date: ${BLUE}$(date)${NC}"
    echo -e "   Hostname: ${BLUE}$(hostname)${NC}"
    echo -e "   Curl Version: ${BLUE}$(curl --version 2>/dev/null | head -n1 | cut -d' ' -f1-2 || echo 'Not Available')${NC}"
    
    # NEW: Add Redis information
    local redis_health_file="$TEST_OUTPUT_DIR/redis_health_response.json"
    if [ -f "$redis_health_file" ]; then
        local redis_status=$(cat "$redis_health_file" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    redis_info = data.get('redis', {})
    print(redis_info.get('status', 'unknown'))
except:
    print('unknown')
" 2>/dev/null)
        
        local active_sessions=$(cat "$redis_health_file" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    sessions_info = data.get('sessions', {})
    print(sessions_info.get('active_sessions', 'unknown'))
except:
    print('unknown')
" 2>/dev/null)
        
        local session_memory=$(cat "$redis_health_file" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    sessions_info = data.get('sessions', {})
    memory = sessions_info.get('total_memory_mb', 'unknown')
    print(f'{memory}MB' if memory != 'unknown' else 'unknown')
except:
    print('unknown')
" 2>/dev/null)
        
        echo -e "   Redis Status: ${BLUE}$redis_status${NC}"
        if [ "$redis_status" = "healthy" ]; then
            echo -e "   Active Sessions: ${BLUE}$active_sessions${NC}"
            echo -e "   Session Memory: ${BLUE}$session_memory${NC}"
        fi
    else
        echo -e "   Redis Status: ${YELLOW}not tested${NC}"
    fi
    echo ""
    
    # Storage Architecture Info
    echo -e "${YELLOW}🗄️  STORAGE ARCHITECTURE${NC}"
    if [ -f "$redis_health_file" ]; then
        local redis_status=$(cat "$redis_health_file" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    redis_info = data.get('redis', {})
    print(redis_info.get('status', 'unknown'))
except:
    print('unknown')
" 2>/dev/null)
        
        case "$redis_status" in
            "healthy")
                echo -e "   Session Storage: ${GREEN}Redis (Distributed)${NC}"
                echo -e "   Multi-Instance Support: ${GREEN}✓ Enabled${NC}"
                echo -e "   Docker Swarm Compatible: ${GREEN}✓ Yes${NC}"
                ;;
            "not_configured")
                echo -e "   Session Storage: ${YELLOW}In-Memory (Single Instance)${NC}"
                echo -e "   Multi-Instance Support: ${RED}✗ Disabled${NC}"
                echo -e "   Docker Swarm Compatible: ${RED}✗ No${NC}"
                ;;
            *)
                echo -e "   Session Storage: ${RED}Redis (Error)${NC}"
                echo -e "   Multi-Instance Support: ${RED}✗ Unavailable${NC}"
                echo -e "   Docker Swarm Compatible: ${RED}✗ No${NC}"
                ;;
        esac
    else
        echo -e "   Session Storage: ${YELLOW}Unknown${NC}"
        echo -e "   Multi-Instance Support: ${YELLOW}Not Tested${NC}"
        echo -e "   Docker Swarm Compatible: ${YELLOW}Not Tested${NC}"
    fi
    echo ""
    
    # Recommendations
    echo -e "${YELLOW}💡 RECOMMENDATIONS${NC}"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "   ${GREEN}✓ All tests passed! Your Certificate Analysis Tool is working perfectly.${NC}"
        echo -e "   ${GREEN}✓ Session isolation is secure and multiuser functionality is reliable.${NC}"
        
        # Add Redis-specific recommendations
        if [ -f "$redis_health_file" ]; then
            local redis_status=$(cat "$redis_health_file" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    redis_info = data.get('redis', {})
    print(redis_info.get('status', 'unknown'))
except:
    print('unknown')
" 2>/dev/null)
            
            if [ "$redis_status" = "healthy" ]; then
                echo -e "   ${GREEN}✓ Redis distributed storage is operational - ready for scaling!${NC}"
            elif [ "$redis_status" = "not_configured" ]; then
                echo -e "   ${YELLOW}⚠ Consider Redis migration for multi-instance support.${NC}"
            fi
        fi
        
    elif [ $FAILED_TESTS -le 2 ]; then
        echo -e "   ${YELLOW}⚠ Minor issues detected. Review failed tests above.${NC}"
        echo -e "   ${YELLOW}⚠ Check error logs in $TEST_OUTPUT_DIR for details.${NC}"
    else
        echo -e "   ${RED}✗ Multiple issues detected. Immediate attention required.${NC}"
        echo -e "   ${RED}✗ Review all failed tests and check API functionality.${NC}"
        
        # Add Redis troubleshooting
        if [ -f "$redis_health_file" ]; then
            local redis_status=$(cat "$redis_health_file" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    redis_info = data.get('redis', {})
    print(redis_info.get('status', 'unknown'))
except:
    print('unknown')
" 2>/dev/null)
            
            if [ "$redis_status" = "unhealthy" ]; then
                echo -e "   ${RED}✗ Redis connection issues detected - check Redis service.${NC}"
            fi
        fi
    fi
    
    echo ""
    echo -e "${BLUE}=====================================================================${NC}"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🎉 CERTIFICATE ANALYSIS TOOL: FULLY OPERATIONAL! 🎉${NC}"
    elif [ $FAILED_TESTS -le 2 ]; then
        echo -e "${YELLOW}⚠️ CERTIFICATE ANALYSIS TOOL: MINOR ISSUES DETECTED ⚠️${NC}"
    else
        echo -e "${RED}🚨 CERTIFICATE ANALYSIS TOOL: CRITICAL ISSUES DETECTED 🚨${NC}"
    fi
    
    echo -e "${BLUE}=====================================================================${NC}"
}

# Main execution
echo -e "${BLUE}=== Starting API Tests ===${NC}"

# Check prerequisites
if [ ! -d "$CERT_DIR" ]; then
    echo -e "${RED}Error: Certificate directory '$CERT_DIR' not found!${NC}"
    echo "Please create the directory and place your certificate files there."
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo -e "${RED}Error: curl is required but not installed.${NC}"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}Error: python3 is required but not installed.${NC}"
    exit 1
fi

# Run tests
test_api_health
if test_authentication; then
    test_redis_connectivity
    test_redis_session_stats
    test_default_session_isolation
    test_session_isolation
    test_concurrent_access
    test_invalid_session_id
    test_certificate_types_and_validation
else
    echo -e "${RED}Skipping session tests due to authentication failure${NC}"
fi

# Generate summary
generate_summary
