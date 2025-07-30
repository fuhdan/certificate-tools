#!/bin/bash

# Quick debug command to test certificate upload and show errors
echo "🔍 Quick Certificate Upload Debug"
echo "=================================="

# Get auth token
echo "Getting auth token..."
TOKEN=$(curl -s -X POST "http://localhost:8000/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123" | jq -r '.access_token')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
  echo "❌ Authentication failed"
  exit 1
fi

echo "✅ Got token: ${TOKEN:0:20}..."

# Generate session ID (fallback if uuidgen not available)
if command -v uuidgen >/dev/null 2>&1; then
    SESSION_ID=$(uuidgen)
else
    # Fallback UUID generation
    SESSION_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
fi
echo "📝 Session ID: $SESSION_ID"

# Create test certificate file
cat > /tmp/test_cert.crt << 'EOF'
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAMpX8BjqE8qlMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST
-----END CERTIFICATE-----
EOF

echo "📤 Testing certificate upload..."

# Test certificate upload
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" \
  -X POST "http://localhost:8000/analyze-certificate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Session-ID: $SESSION_ID" \
  -F "certificate=@/tmp/test_cert.crt")

# Extract status code
HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

echo "📥 Response Status: $HTTP_STATUS"
echo "📄 Response Body:"
echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"

# Analyze result
if [ "$HTTP_STATUS" = "500" ]; then
  echo ""
  echo "❌ SERVER ERROR (500) DETECTED!"
  echo "🔧 Check your FastAPI server logs for detailed error information"
  echo "💡 Common causes:"
  echo "   - Missing Python dependencies (cryptography, pyopenssl)"
  echo "   - Import errors in certificate analysis modules"
  echo "   - Session middleware configuration issues"
  echo ""
  echo "🚀 Try running server with debug logging:"
  echo "   uvicorn main:app --reload --log-level debug"
elif [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]; then
  echo "✅ Success! Certificate upload worked."
else
  echo "⚠️  Unexpected status: $HTTP_STATUS"
fi

# Cleanup
rm -f /tmp/test_cert.crt

echo ""
echo "🏁 Debug complete!"