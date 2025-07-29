# Certificate Analysis Tool

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-blue)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.2.0-blue.svg)](https://reactjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docs.docker.com/compose/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive, full-stack Public Key Infrastructure (PKI) analysis and management tool. This application provides deep inspection, validation, and management of certificates, private keys, certificate signing requests (CSRs), and complete PKI bundles.

## 🎯 Overview

The Certificate Analysis Tool is designed for security professionals, developers, and system administrators who need to:

- **Analyze** various certificate formats (PEM, DER, PKCS#12, PKCS#7, PKCS#8)
- **Validate** cryptographic relationships between PKI components
- **Manage** multi-user sessions with automatic cleanup
- **Visualize** PKI hierarchies and certificate chains
- **Generate** complete, ordered PKI bundles for deployment

## ✨ Key Features

### 🔍 Comprehensive Format Support
- **Certificates**: PEM, DER, CRT, CER formats
- **Private Keys**: PEM, DER, encrypted PKCS#8
- **PKCS#12 Bundles**: P12, PFX files with password protection
- **Certificate Requests**: CSR files in multiple formats
- **Certificate Chains**: PKCS#7 formatted chains

### 🔐 Advanced Cryptographic Validation
- Private key ↔ Certificate matching
- Private key ↔ CSR matching  
- Certificate ↔ CSR validation (certificate issued from CSR)
- Certificate chain verification and trust validation
- Signature verification across the entire PKI hierarchy

### 👥 Multi-User Session Management
- UUID-based session isolation per browser tab
- Automatic session cleanup with configurable timeouts
- Thread-safe concurrent user support
- In-memory storage with secure separation of sensitive data

### 🎨 Modern Web Interface
- Drag-and-drop file upload with format validation
- Real-time cryptographic validation feedback
- Interactive PKI hierarchy visualization
- Secure JWT-based authentication for protected features
- Responsive design optimized for various screen sizes

## 🏗️ Architecture & Complete Project Structure

### System Architecture Overview

```
Internet (Port 80/443)
         ↓
    Nginx Server
    ┌─────────────────┐
    │  Frontend       │ ← Static React files
    │  /api/*         │ → Backend FastAPI
    │  /docs          │ → API Documentation  
    └─────────────────┘
         ↓
    Docker Network
    ┌─────────────────┐
    │  React App      │ (Internal: Port 3000)
    │  FastAPI        │ (Internal: Port 8000)
    └─────────────────┘
```

### Complete Project Structure

```
certificate-analysis-tool/
├── backend-fastapi/                     # FastAPI Backend Service
│   ├── main.py                         # Application entry point & FastAPI setup
│   ├── config.py                       # Configuration management & environment settings  
│   ├── session_manager.py              # Multi-user session handling with UUID isolation
│   ├── shared_state.py                 # Application shared state (uptime tracking)
│   ├── requirements.txt                # Python dependencies (fastapi, uvicorn, cryptography, etc.)
│   ├── Dockerfile                      # Docker container configuration for FastAPI
│   ├── README.md                       # Backend documentation
│   ├── .gitignore                      # Backend-specific git ignore patterns
│   │
│   ├── auth/                          # JWT Authentication Module
│   │   ├── __init__.py                # Module initialization
│   │   ├── dependencies.py            # FastAPI auth dependencies & middleware
│   │   ├── models.py                  # Pydantic models (User, Token, TokenData)
│   │   └── security.py               # JWT creation, verification & password hashing
│   │
│   ├── certificates/                  # Core PKI Analysis Engine
│   │   ├── __init__.py                # Module initialization
│   │   ├── analyzer.py                # Main certificate analysis entry point
│   │   │
│   │   ├── formats/                   # Format-Specific Parsers
│   │   │   ├── __init__.py            # Format parsers initialization
│   │   │   ├── pem.py                 # PEM format analysis (certificates, keys, CSRs)
│   │   │   ├── der.py                 # DER format analysis  
│   │   │   ├── pkcs12.py              # PKCS#12/PFX bundle analysis
│   │   │   └── pkcs7.py               # PKCS#7 certificate chain analysis
│   │   │
│   │   ├── storage/                   # Secure In-Memory Storage
│   │   │   ├── __init__.py            # Storage module initialization
│   │   │   ├── certificate_storage.py # Main certificate storage interface
│   │   │   ├── crypto_storage.py      # Cryptographic objects storage (separate from JSON)
│   │   │   ├── hierarchy.py           # PKI hierarchy management & organization
│   │   │   ├── pki_bundle.py          # PKI bundle generation & management
│   │   │   └── utils.py               # Storage utility functions & validation
│   │   │
│   │   ├── utils/                     # Certificate Utilities
│   │   │   ├── __init__.py            # Utils initialization
│   │   │   ├── hashing.py             # Content hashing for duplicate detection
│   │   │   ├── extensions.py          # X.509 extension parsing utilities
│   │   │   └── validation_helpers.py  # Validation helper functions
│   │   │
│   │   └── validation/                # Cryptographic Validation Engine
│   │       ├── __init__.py            # Validation module initialization
│   │       ├── validator.py           # Main validation orchestrator
│   │       ├── key_matcher.py         # Private key to certificate/CSR matching
│   │       ├── chain_validator.py     # Certificate chain validation
│   │       └── signature_verifier.py  # Digital signature verification
│   │
│   ├── middleware/                    # Custom Middleware
│   │   ├── __init__.py                # Middleware initialization
│   │   └── session_middleware.py      # Session ID handling & validation
│   │
│   └── routers/                       # API Endpoints (FastAPI Routers)
│       ├── __init__.py                # Router module initialization & imports
│       ├── auth.py                    # Authentication endpoints (/token, /users/me)
│       ├── certificates.py           # Certificate management (/analyze-certificate, /certificates)
│       ├── health.py                 # Health check endpoints (/health, /api/health)
│       ├── pki.py                    # PKI bundle endpoints (/pki-bundle, /pki-bundle/download)
│       └── stats.py                  # Statistics endpoints (/api/stats)
│
├── frontend/                          # React Frontend Application
│   ├── dist/                         # Build output directory (generated by Vite)
│   ├── public/                       # Static assets directory
│   ├── src/                          # Source Code
│   │   ├── components/               # React Components
│   │   │   ├── CertificateDetails/   # Certificate Information Display
│   │   │   │   ├── CertificateDetails.jsx # Main certificate details component
│   │   │   │   └── CertificateDetails.module.css # Component-specific styles
│   │   │   │
│   │   │   ├── FileUpload/           # File Upload & Drag-Drop Interface
│   │   │   │   ├── FileUpload.jsx    # Main upload component with validation
│   │   │   │   ├── FileUpload.module.css # Upload component styles
│   │   │   │   └── PasswordPrompt.jsx # Password input for encrypted files
│   │   │   │
│   │   │   ├── FloatingPanel/        # System Side Panel
│   │   │   │   ├── FloatingPanel.jsx # Main floating panel container
│   │   │   │   ├── FloatingPanel.module.css # Panel styles
│   │   │   │   ├── ConnectionStatus.jsx # Backend connection status indicator
│   │   │   │   ├── FileManager.jsx   # Uploaded files management
│   │   │   │   └── SessionControls.jsx # Session management controls
│   │   │   │
│   │   │   ├── Footer/               # Application Footer
│   │   │   │   ├── Footer.jsx        # Footer component
│   │   │   │   └── Footer.module.css # Footer styles
│   │   │   │
│   │   │   ├── Header/               # Application Header with Auth
│   │   │   │   ├── Header.jsx        # Header with login/logout functionality
│   │   │   │   └── Header.module.css # Header styles
│   │   │   │
│   │   │   ├── Layout/               # Main Layout Orchestrator
│   │   │   │   ├── Layout.jsx        # Main layout component
│   │   │   │   └── Layout.module.css # Layout styles
│   │   │   │
│   │   │   └── ValidationPanel/      # Cryptographic Validation Display
│   │   │       ├── ValidationPanel.jsx # Validation results display
│   │   │       └── ValidationPanel.module.css # Validation panel styles
│   │   │
│   │   ├── contexts/                 # React Context Providers
│   │   │   ├── CertificateContext.js # Certificate state management context
│   │   │   └── AuthContext.js       # Authentication state context
│   │   │
│   │   ├── services/                 # API and External Services
│   │   │   ├── api.js                # Axios configuration & API methods
│   │   │   └── sessionManager.js    # Frontend session management (UUID generation)
│   │   │
│   │   ├── utils/                    # Utility Functions
│   │   │   ├── validation.js         # Client-side validation helpers
│   │   │   └── formatters.js        # Data formatting utilities
│   │   │
│   │   ├── App.jsx                   # Root React component
│   │   ├── main.jsx                  # Application entry point (Vite)
│   │   └── index.css                 # Global styles
│   │
│   ├── .gitignore                    # Frontend git ignore patterns
│   ├── Dockerfile                    # Multi-stage Docker build with Nginx
│   ├── index.html                    # Main HTML entry point for Vite
│   ├── logo.png                      # Application logo asset
│   ├── nginx.conf                    # Nginx configuration for production container
│   ├── package.json                  # Node.js dependencies & scripts (React, Vite, Axios)
│   ├── package-lock.json             # NPM dependency lock file
│   ├── README.md                     # Frontend documentation
│   └── vite.config.js               # Vite build configuration
│
├── nginx/                           # Nginx Reverse Proxy
│   ├── Dockerfile                   # Nginx container configuration
│   └── nginx.conf                   # Main Nginx configuration file
│
├── docker-compose.yml               # Multi-container orchestration (Nginx + Frontend + Backend)
├── .gitignore                       # Project-wide git ignore patterns
├── README.md                        # Main project documentation (this file)
└── TECHNICAL.md                     # Detailed technical implementation guide
```

### Technology Stack Breakdown

#### Backend Components
- **FastAPI Framework**: High-performance async web framework
- **Session Management**: UUID-based isolation with automatic cleanup
- **PKI Analysis Engine**: Multi-format certificate parsing and validation
- **Cryptographic Validation**: Comprehensive security verification
- **JWT Authentication**: Secure token-based authentication
- **In-Memory Storage**: Secure separation of sensitive data

#### Frontend Components  
- **React 18**: Modern component-based UI framework
- **Vite Build System**: Fast development and optimized production builds
- **Context API**: State management for certificates and authentication
- **CSS Modules**: Component-scoped styling system
- **Axios HTTP Client**: API communication with interceptors

#### Infrastructure Components
- **Nginx Reverse Proxy**: Unified access point on ports 80/443
- **Docker Containers**: Isolated, reproducible deployment
- **SSL/TLS Ready**: HTTPS support for production security

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Modern web browser with JavaScript enabled

### Installation & Deployment

1. **Clone the repository**
```bash
git clone <repository-url>
cd certificate-analysis-tool
```

2. **Start with Docker Compose**
```bash
docker-compose up -d
```

3. **Access the application**
- Frontend: http://localhost (port 80) or https://localhost (port 443)
- Backend API: http://localhost/api or https://localhost/api  
- API Documentation: http://localhost/docs or https://localhost/docs

### Development Setup

#### Backend Development
```bash
cd backend-fastapi
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Development  
```bash
cd frontend
npm install
npm run dev
```

## 📋 Usage Guide

### Basic Certificate Analysis

1. **Upload Files**: Drag and drop certificate files onto the upload area
2. **Password Protected Files**: Enter passwords when prompted for encrypted files
3. **View Analysis**: Examine detailed certificate information in the analysis panel
4. **Validation Results**: Check cryptographic validation results in the validation panel

### Advanced Features

#### PKI Bundle Generation
1. Upload all related PKI components (certificates, keys, CSRs)
2. Click "View PKI Bundle" in the system panel
3. Download or copy the complete, ordered PKI bundle as JSON

#### Session Management
- Each browser tab maintains an isolated session
- Use "Clear Session" to remove all uploaded files
- Sessions automatically expire after inactivity

#### File Management
- View all uploaded files in the system panel
- Delete individual files or clear entire session
- Monitor real-time backend connection status

## 🔧 Configuration

### Environment Variables

#### Backend Configuration
```bash
# Security
SECRET_KEY=your-secret-key-change-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application  
DEBUG=OFF
APP_NAME="Certificate Analysis API"

# Default Authentication (Development Only)
DEFAULT_USERNAME=admin
DEFAULT_PASSWORD=admin123

# File Upload
MAX_FILE_SIZE=10485760  # 10MB in bytes
```

#### Frontend Configuration
```bash
# API Endpoint (if different from default)
VITE_API_BASE_URL=http://localhost:8000

# Development
VITE_NODE_ENV=development
```

### Docker Configuration

The application includes production-ready Docker configurations with **Nginx reverse proxy**:

- **Frontend**: React SPA served by Nginx on ports 80/443
- **Backend**: FastAPI service proxied through Nginx at `/api` path
- **SSL/TLS**: Ready for HTTPS configuration on port 443
- **Docker Compose**: Orchestrates both services with proper networking and Nginx routing

## 🔒 Security Features

### Authentication & Authorization
- JWT-based authentication for protected endpoints
- Secure password hashing with bcrypt
- Session-based access control

### Data Protection
- Sensitive cryptographic objects stored separately from JSON data
- No private key passwords stored or logged  
- Automatic session cleanup prevents data persistence
- CORS protection with configurable origins

### Input Validation
- File format validation and size limits
- UUID format validation for session IDs
- Comprehensive error handling and logging

## 🧪 Testing

### Backend Testing
```bash
cd backend-fastapi
python -m pytest tests/ -v
```

### Frontend Testing  
```bash
cd frontend
npm test
```

### Integration Testing
```bash
# Run both services
docker-compose up -d

# Run integration tests
npm run test:integration
```

## 📚 API Documentation

### Core Endpoints

#### Certificate Management
- `POST /api/certificates/upload` - Upload and analyze certificate files
- `GET /api/certificates/list/{session_id}` - List all certificates in session
- `DELETE /api/certificates/{cert_id}` - Delete specific certificate
- `POST /api/certificates/clear/{session_id}` - Clear entire session

#### Validation
- `POST /api/validation/validate/{session_id}` - Run cryptographic validation
- `GET /api/validation/results/{session_id}` - Get validation results

#### PKI Bundle
- `GET /api/pki-bundle/{session_id}` - Generate complete PKI bundle (requires auth)

#### Authentication
- `POST /api/auth/login` - Authenticate and receive JWT token
- `GET /api/auth/me` - Get current user information

### Interactive API Documentation
Visit http://localhost/docs for full Swagger/OpenAPI documentation with interactive testing capabilities.

## 🐛 Troubleshooting

### Common Issues

#### File Upload Failures
- **Cause**: File size exceeds 10MB limit or unsupported format
- **Solution**: Check file size and ensure it's a supported PKI format

#### Password Protected Files
- **Cause**: Incorrect password for encrypted PKCS#12 or private key files
- **Solution**: Verify password and try again; check for special characters

#### Session Conflicts
- **Cause**: Multiple tabs using same session ID
- **Solution**: Each tab automatically gets isolated session; refresh if needed

#### Validation Failures
- **Cause**: Mismatched cryptographic components or corrupted files
- **Solution**: Verify file integrity and ensure related components are uploaded

### Logging & Debugging

#### Backend Logs
```bash
# View logs from Docker container
docker-compose logs backend

# Enable debug logging
DEBUG=ON docker-compose up
```

#### Frontend Debugging
```bash
# Check browser console for errors
# Enable verbose logging in sessionManager.js
sessionManager.debugSession()
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Use ESLint/Prettier for JavaScript formatting
- Add tests for new features
- Update documentation as needed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - High-performance Python web framework
- [React](https://reactjs.org/) - User interface library
- [cryptography](https://cryptography.io/) - Python cryptographic library
- [Vite](https://vitejs.dev/) - Next generation frontend tooling

## 📞 Support

For support, questions, or feature requests:
- Open an issue on GitHub
- Check the [Technical Documentation](TECHNICAL.md) for detailed implementation details
- Review the API documentation at `/docs` endpoint

---

**Certificate Analysis Tool** - Making PKI management accessible and secure.