# 🔐 Certificate Tools - PKI Analysis & Management Platform

![Certificate Tools](https://img.shields.io/badge/Certificate-Tools-gold?style=for-the-badge&logo=security&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-teal?style=for-the-badge)
![React](https://img.shields.io/badge/React-Frontend-blue?style=for-the-badge)
![PKI](https://img.shields.io/badge/PKI-Analysis-red?style=for-the-badge)

🌐 **[Try it live at certificate.danielf.ch](https://certificate.danielf.ch)** 🌐

> *"Because understanding your PKI components shouldn't require a PhD in cryptography"* 🎓

## 🎯 What This Actually Does

**Certificate Tools** is a comprehensive PKI analysis platform that makes certificate management as easy as uploading a file. Upload any certificate, private key, CSR, or PKCS#12 bundle and get instant analysis, validation, and insights about your PKI components.

### 🚀 Real Features (Not Marketing BS)

- **📤 Smart File Upload**: Drag & drop certificates, keys, CSRs, PKCS#12 files with automatic format detection
- **🔍 Deep PKI Analysis**: Parse and analyze X.509 certificates, private keys, and certificate signing requests  
- **✅ Cryptographic Validation**: Automatic validation between components (private key ↔ certificate matching, CSR ↔ certificate verification)
- **🏗️ PKI Hierarchy Detection**: Intelligently identifies Root CA, Intermediate CA, and End-Entity certificates
- **🔐 Encrypted File Support**: Handles password-protected PKCS#12 bundles and encrypted private keys
- **📊 Visual Dashboard**: React-based UI with real-time validation results and PKI component relationships
- **🧹 Session Management**: UUID-based sessions for secure, isolated analysis
- **📦 Bundle Downloads**: Generate secure ZIP bundles of your PKI components

## 🏗️ Architecture Overview

```
┌─────────────────┐    HTTPS    ┌──────────────────────┐
│   React SPA     │◄───────────►│   FastAPI Backend    │
│   (Frontend)    │             │   (Certificate API)  │
├─────────────────┤             ├──────────────────────┤
│ • File Upload   │             │ • Certificate Parser │
│ • PKI Dashboard │             │ • OpenSSL Engine     │
│ • Validation UI │             │ • Session Storage    │
│ • Auth System   │             │ • Validation Engine  │
└─────────────────┘             └──────────────────────┘
        │                                 │
        │                                 │
   ┌────▼────┐                      ┌─────▼─────┐
   │ Nginx   │                      │  Memory   │
   │ (Prod)  │                      │  Storage  │
   └─────────┘                      └───────────┘
```

## 🛠️ Tech Stack (The Real Deal)

### Backend (FastAPI) 🧠
- **FastAPI**: Modern Python web framework with automatic OpenAPI docs
- **OpenSSL**: Certificate parsing and cryptographic operations
- **Cryptography**: Python cryptographic library for advanced operations
- **Session Management**: UUID-based sessions with automatic cleanup
- **Memory Storage**: No persistent storage - everything in memory for security

### Frontend (React) 🎨
- **React 18**: Modern React with hooks and context
- **Vite**: Fast build tool and dev server
- **CSS Modules**: Scoped styling without conflicts
- **Lucide Icons**: Beautiful, consistent icon library
- **Axios**: HTTP client with interceptors and error handling

### Real API Endpoints (What Actually Works)

```bash
# Core Certificate Analysis
POST /analyze-certificate          # Upload & analyze certificate files
GET  /certificates                 # Get all PKI components for session
GET  /health                      # API health check
GET  /stats                       # Session statistics

# Download & Export
POST /downloads/zip-bundle         # Create secure ZIP bundle
GET  /downloads/ca-certificates   # Download CA certs only
GET  /downloads/end-entity        # Download end-entity components
GET  /downloads/full-chain        # Download complete certificate chain
```

## 📦 Installation (The "Actually Works" Guide)

### 🌐 Try Online First!

**Want to test it immediately?** Visit **[certificate.danielf.ch](https://certificate.danielf.ch)** - no installation required!

### Quick Start with Docker (Recommended)

```bash
# Clone the actual repository
git clone https://github.com/fuhdan/certificate-tools.git
cd certificate-tools

# Start everything with Docker Compose
docker-compose up -d

# Check if it's working
curl http://localhost:8000/health
# Should return: {"status": "online", "timestamp": "..."}

# Frontend should be available at: http://localhost:3000
```

### Manual Installation (For Developers)

#### Backend Setup
```bash
cd backend-fastapi

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# API docs available at: http://localhost:8000/docs
```

#### Frontend Setup
```bash
cd frontend

# Install Node.js dependencies
npm install

# Start development server
npm run dev

# Frontend available at: http://localhost:5173
```

## 🎮 Real Usage Examples

### Upload and Analyze a Certificate

```bash
# Using curl with session isolation
SESSION_ID=$(uuidgen)

curl -X POST "http://localhost:8000/analyze-certificate" \
     -H "X-Session-ID: $SESSION_ID" \
     -F "file=@my-certificate.crt"

# Response includes parsed certificate data
{
  "success": true,
  "component": {
    "id": "cert_abc123",
    "type": "Certificate",
    "filename": "my-certificate.crt",
    "metadata": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "not_valid_before": "2024-01-01T00:00:00Z",
      "not_valid_after": "2024-12-31T23:59:59Z",
      "is_ca": false,
      "public_key_algorithm": "RSA",
      "public_key_size": 2048
    }
  }
}
```

### Upload PKCS#12 Bundle with Password

```bash
# Upload encrypted P12 file
curl -X POST "http://localhost:8000/analyze-certificate" \
     -H "X-Session-ID: $SESSION_ID" \
     -F "file=@certificate.p12" \
     -F "password=your-password-here"

# Gets certificate + private key from bundle
```

### Get All PKI Components with Validation

```bash
# Retrieve all components for session
curl -X GET "http://localhost:8000/certificates" \
     -H "X-Session-ID: $SESSION_ID"

# Response includes validation results
{
  "success": true,
  "components": [
    {
      "id": "cert_abc123",
      "type": "Certificate", 
      "filename": "my-cert.crt"
    },
    {
      "id": "key_def456",
      "type": "PrivateKey",
      "filename": "my-key.key"
    }
  ],
  "validation_results": {
    "total_validations": 1,
    "overall_status": "valid",
    "validations": {
      "private_key_certificate_match": {
        "type": "Private Key ↔ Certificate Match",
        "is_valid": true,
        "confidence": "high",
        "components_involved": ["key_def456", "cert_abc123"]
      }
    }
  }
}
```

### Download PKI Bundle

```bash
# Create secure ZIP bundle
curl -X POST "http://localhost:8000/downloads/zip-bundle" \
     -H "X-Session-ID: $SESSION_ID" \
     -H "Content-Type: application/json" \
     -d '{"zip_password": "secure-password", "p12_password": "p12-password"}' \
     --output pki-bundle.zip
```

## 🔧 Configuration

### Backend Environment Variables

```bash
# config/.env
APP_NAME="Certificate Analysis API"
APP_VERSION="1.0.0"
DEBUG=true
LOG_LEVEL="INFO"

# Security
MAX_FILE_SIZE=10485760  # 10MB
SESSION_TIMEOUT=1800    # 30 minutes
DEFAULT_SESSION_ID="default-session"

# CORS
CORS_ORIGINS=["http://localhost:3000", "http://localhost:5173"]

# Authentication (if enabled)
SECRET_KEY="your-secret-key-here"
ACCESS_TOKEN_EXPIRE_MINUTES=60
```

### Frontend Environment Variables

```bash
# frontend/.env
VITE_API_URL=http://localhost:8000
VITE_APP_TITLE="Certificate Tools"
VITE_DEBUG=true
```

## 🧪 Testing (What Actually Gets Tested)

### Running Backend Tests

```bash
cd backend-fastapi

# Install test dependencies
pip install pytest pytest-cov requests

# Run tests with coverage
pytest -v --cov=. --cov-report=html tests/

# Run specific test file
pytest tests/test_live_server.py -v
```

### Test Script for Live API

```bash
# Use the included test script
chmod +x scripts/test_tool.sh
./scripts/test_tool.sh

# Tests real API endpoints with actual certificates
# Outputs detailed results to test_results/
```

### Frontend Testing

```bash
cd frontend

# Run component tests
npm test

# Run with coverage
npm run test:coverage
```

## 🔒 Security Features

### Session Isolation
- **UUID-based sessions**: Each user gets isolated storage
- **Memory-only storage**: No persistent data on disk
- **Automatic cleanup**: Sessions expire after 30 minutes
- **No cross-session leakage**: Components cannot access other sessions

### File Security
- **File type validation**: Strict MIME type checking
- **Size limits**: Maximum 10MB per file
- **Memory processing**: Files processed in memory only
- **Secure cleanup**: Sensitive data cleared after processing

### Example Session Security

```python
# Every request requires session ID
@router.post("/analyze-certificate")
async def analyze_certificate(
    file: UploadFile = File(...),
    session_id: str = Depends(get_session_id)  # Validates UUID format
):
    # session_id is guaranteed to be valid UUID
    # Each session has isolated storage
    result = analyze_uploaded_certificate(file_content, session_id)
    return result
```

## 🐛 Troubleshooting (When Reality Hits)

### Common Issues

#### "Session ID Required" Error
```bash
# Every API call needs X-Session-ID header
curl -X GET "http://localhost:8000/certificates" \
     -H "X-Session-ID: $(uuidgen)"
```

#### "Password Required" for PKCS#12
```bash
# Include password in form data
curl -X POST "http://localhost:8000/analyze-certificate" \
     -H "X-Session-ID: $(uuidgen)" \
     -F "file=@bundle.p12" \
     -F "password=your-password"
```

#### Frontend Not Connecting to Backend
```javascript
// Check CORS settings in backend config
CORS_ORIGINS=["http://localhost:3000", "http://localhost:5173"]

// Update frontend API URL
// frontend/.env
VITE_API_URL=http://localhost:8000
```

### Debug Mode

```bash
# Enable debug logging
export DEBUG=true
export LOG_LEVEL=DEBUG

# Start backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Watch logs for detailed information
```

## 📊 API Documentation

### Interactive Docs
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Core Response Formats

#### Certificate Analysis Response
```json
{
  "success": true,
  "component": {
    "id": "cert_abc123",
    "type": "Certificate",
    "filename": "example.crt",
    "size": 1234,
    "uploaded_at": "2024-01-01T12:00:00Z",
    "metadata": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "serial_number": "ABC123",
      "not_valid_before": "2024-01-01T00:00:00Z",
      "not_valid_after": "2024-12-31T23:59:59Z",
      "is_expired": false,
      "days_until_expiry": 365,
      "is_ca": false,
      "is_self_signed": false,
      "public_key_algorithm": "RSA",
      "public_key_size": 2048,
      "signature_algorithm": "SHA256WITHRSA",
      "fingerprint_sha256": "abc123...",
      "subject_alt_name": ["example.com", "www.example.com"],
      "key_usage": ["digitalSignature", "keyEncipherment"],
      "extended_key_usage": ["serverAuth", "clientAuth"]
    }
  }
}
```

#### Validation Results Response
```json
{
  "validation_results": {
    "total_validations": 2,
    "overall_status": "valid",
    "passed_validations": 2,
    "failed_validations": 0,
    "validations": {
      "private_key_certificate_match": {
        "type": "Private Key ↔ Certificate Match",
        "is_valid": true,
        "confidence": "high",
        "components_involved": ["key_def456", "cert_abc123"],
        "details": {
          "method": "public_key_comparison",
          "match_type": "exact"
        }
      },
      "certificate_chain_validation": {
        "type": "Certificate Chain Validation",
        "is_valid": true,
        "confidence": "medium",
        "components_involved": ["cert_abc123", "ca_cert_789"],
        "details": {
          "chain_length": 2,
          "trust_anchor": "ca_cert_789"
        }
      }
    }
  }
}
```

## 🤝 Contributing (Join the PKI Revolution)

### Development Workflow

1. **Fork the repo** (it's actually useful)
2. **Create feature branch** (`git checkout -b feature/awesome-pki-feature`)
3. **Write tests** (we actually run them)
4. **Test with real certificates** (use `scripts/test_tool.sh`)
5. **Update documentation** (README and API docs)
6. **Submit PR** (be ready for code review)

### Code Style

```bash
# Backend Python formatting
black . --line-length 88
isort . --profile black

# Frontend JavaScript formatting  
npm run format

# Linting
npm run lint
```

### Testing with Real Certificates

```bash
# Create test certificates directory
mkdir -p test-certificates/

# Add your test certificates (various formats)
cp your-certificates/* test-certificates/

# Run comprehensive test suite
./scripts/test_tool.sh
```

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

**Translation**: Use this code however you want, just don't blame us if your production certificates have an identity crisis. 😅

## 🙏 Acknowledgments

- **OpenSSL Team**: For making PKI possible (and complicated)
- **FastAPI**: For making Python APIs not suck
- **React Team**: For making UIs bearable to build
- **Cryptography Library**: For handling the crypto so we don't have to
- **Coffee**: For making late-night PKI debugging sessions possible
- **Stack Overflow**: For explaining why certificate validation failed... again

## 🎭 Fun PKI Facts

- 🏗️ Built during 127 different "Why won't this certificate validate?" moments
- 🐛 Contains approximately 42 edge cases for certificate parsing
- ⏰ Caused 15 sleepless nights debugging PKCS#12 password handling  
- 📚 Required reading 23 RFC documents about X.509 certificates
- ☕ Consumed 284 cups of coffee during development
- 🤯 Resulted in 3 existential crises about certificate authorities

## 📞 Support & Feedback

- 🌐 **Live Demo**: [certificate.danielf.ch](https://certificate.danielf.ch) - Try it now!
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/fuhdan/certificate-tools/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/fuhdan/certificate-tools/discussions)
- 🐦 **Twitter**: [@DanielFuhrer](https://x.com/DanielFuhrer)

# 🏖️ Certificate Analysis Tool - Because PKI Should Be Fun!

*Making PKI management as relaxing as a day at the beach* ☀️

---

## 🌅 Final Words

Remember: Life's too short for bad certificate management tools. Whether you're validating a single certificate or untangling a complex PKI hierarchy, this tool has your back. So grab your favorite beach drink, fire up those Docker containers, and let's make certificate analysis fun again!

**Certificate Analysis Tool** - *Making PKI management as relaxing as a day at the beach.* 🏖️

---

## 🏛️ Official Legal Disclaimer from Daniel's Totally Legit Certificate Authority™

*© 2025 Daniel's Totally Legit Certificate Authority™. All rights reserved.*

*This tool uses TLS 1.3 because anything less is just insecure spaghetti code.*

*Unauthorized access attempts will be ignored like your 10th failed login — but seriously, don't try.*

*Trust is established here by a Root CA, and shattered by expired certs and forgotten passwords.*

*If you don't understand this, please reboot your brain and try again.*

---

*P.S. - No actual certificates were harmed in the making of this tool. All certificates were treated with the utmost respect and given proper validation before being allowed to bask in the digital sunshine.* ☀️

*P.P.S. - The certificate authority mentioned above is purely fictional and exists only in the realm of beach-themed humor. Please don't try to get your certificates signed by the sun.* 🌞

---

<div align="center">

**"In certificates we trust, in validation we verify"** 🔐

Made with ❤️ (and lots of ☕) by [Daniel F](https://github.com/fuhdan)

*Remember: A validated certificate is a happy certificate!* ✅

![Certificate Tools](https://img.shields.io/badge/Powered%20by-PKI%20%26%20Coffee-brown?style=for-the-badge)

</div>
