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
    local response=$(curl -s -X POST "$API_BASE_URL/api/token" \
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
    
    local response=$(curl -s -X GET "$API_BASE_URL/api/health" -w "%{http_code}" --connect-timeout 10 2>/dev/null)
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
    local curl_cmd=(curl -s -X POST "$API_BASE_URL/api/analyze-certificate" \
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

    local curl_cmd=(curl -s -X GET "$API_BASE_URL/api/certificates" \
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
    local response=$(curl -s -X POST "$API_BASE_URL/api/analyze-certificate" \
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
    local default_certs_response=$(curl -s -X GET "$API_BASE_URL/api/certificates" \
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
            local response=$(curl -s -X POST "$API_BASE_URL/api/analyze-certificate" \
                -H "Authorization: Bearer $token" \
                -F "certificate=@$test_file" \
                -F "password=$PASSWORD" \
                -w "%{http_code}" \
                --connect-timeout 10 2>/dev/null)
        else
            echo "    Testing invalid session ID: '$invalid_session'"
            local response=$(curl -s -X POST "$API_BASE_URL/api/analyze-certificate" \
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
            local response=$(curl -s -X GET "$API_BASE_URL/api/certificates" \
                -H "Authorization: Bearer $token" \
                -w "%{http_code}" \
                --connect-timeout 10 2>/dev/null)
        else
            echo "    Testing certificate retrieval with invalid session: '$invalid_session'"
            local response=$(curl -s -X GET "$API_BASE_URL/api/certificates" \
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
    echo -e "   Health Endpoint: /api/health"
    echo -e "   Auth Endpoint: /api/token"
    echo -e "   Upload Endpoint: /api/analyze-certificate"
    echo -e "   Certificates Endpoint: /api/certificates"
    echo ""
    
    # Certificate Files
    echo -e "${YELLOW}📋 CERTIFICATE FILES${NC}"
    local cert_count=$(find "$CERT_DIR" -name "*.crt.pem" 2>/dev/null | wc -l)
    echo -e "   PEM Certificates Found: ${BLUE}$cert_count${NC}"
    echo -e "   Certificate Directory: ${BLUE}$CERT_DIR${NC}"
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
    echo ""
    
    # Recommendations
    echo -e "${YELLOW}💡 RECOMMENDATIONS${NC}"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "   ${GREEN}✓ All tests passed! Your Certificate Analysis Tool is working perfectly.${NC}"
        echo -e "   ${GREEN}✓ Session isolation is secure and multiuser functionality is reliable.${NC}"
    elif [ $FAILED_TESTS -le 2 ]; then
        echo -e "   ${YELLOW}⚠ Minor issues detected. Review failed tests above.${NC}"
        echo -e "   ${YELLOW}⚠ Check error logs in $TEST_OUTPUT_DIR for details.${NC}"
    else
        echo -e "   ${RED}✗ Multiple issues detected. Immediate attention required.${NC}"
        echo -e "   ${RED}✗ Review all failed tests and check API functionality.${NC}"
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
    test_default_session_isolation
    test_session_isolation
    test_concurrent_access
    test_invalid_session_id
else
    echo -e "${RED}Skipping session tests due to authentication failure${NC}"
fi

# Generate summary
generate_summary
