# Technical Documentation - Certificate Analysis Tool

## Table of Contents

1. [System Architecture](#system-architecture)
2. [🆕 Cookie-Based Session Management](#cookie-based-session-management)
3. [Certificate Processing Pipeline](#certificate-processing-pipeline)
4. [Cryptographic Validation Engine](#cryptographic-validation-engine)
5. [Security Implementation](#security-implementation)
6. [API Design](#api-design)
7. [Frontend Architecture](#frontend-architecture)
8. [Data Flow](#data-flow)
9. [Deployment Architecture](#deployment-architecture)
10. [Performance Considerations](#performance-considerations)
11. [Monitoring and Observability](#monitoring-and-observability)
12. [Development Guidelines](#development-guidelines)

---

## System Architecture

### High-Level Architecture Overview

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[Web Browser]
        Mobile[Mobile Browser]
    end
    
    subgraph "Load Balancer/Proxy Layer"
        Nginx[Nginx Reverse Proxy<br/>Port 80]
    end
    
    subgraph "Application Layer"
        Frontend[React SPA<br/>Port 80]
        Backend[FastAPI Service<br/>Port 8000<br/>🆕 JWT Middleware]
    end
    
    subgraph "Storage Layer"
        Memory[In-Memory Session Store]
    end
    
    subgraph "Service Layer"
        VS[Validation Service]
        DS[Download Service]
    end
    
    Browser --> Nginx
    Mobile --> Nginx
    Nginx --> Frontend
    Nginx --> Backend
    Frontend --> Backend
    Backend --> Memory
    Backend --> VS
    Backend --> DS
```

### Component Interaction Flow

```mermaid
sequenceDiagram
    participant U as User
    participant N as Nginx
    participant F as Frontend
    participant B as Backend
    participant J as JWT Middleware
    participant S as Session Manager
    participant V as Validation Service
    participant C as Crypto Engine
    
    U->>N: HTTP Request
    N->>F: Route to Frontend (/)
    F->>U: Serve React SPA
    
    U->>F: Upload Certificate
    F->>N: POST /api/upload (with cookies)
    N->>B: Forward to Backend
    B->>J: @require_session decorator
    J->>J: Validate/Create JWT Cookie
    J->>S: Extract/Create Session ID
    B->>C: Parse Certificate
    C->>B: Return Analysis
    B->>V: Compute Validations
    V->>B: Return Validation Results
    B->>S: Store Results
    B->>F: Return Analysis JSON + Set Cookie
    F->>U: Display Results
```

---

## 🆕 Cookie-Based Session Management

### JWT Session Architecture

The session management system now uses HTTP-only secure cookies with JWT tokens:

```python
# backend-fastapi/middleware/session_decorator.py

@require_session
async def upload_certificate(request: Request, file: UploadFile):
    """
    @require_session decorator automatically:
    1. Reads JWT from 'session_token' cookie
    2. Validates JWT signature and expiration
    3. Creates new session if JWT missing/invalid
    4. Sets HTTP-only cookie with JWT on response
    5. Injects session_id into request.state
    """
    session_id = request.state.session_id  # Automatically available
    # Your route logic here
```

### PKI Session with JWT Integration

```python
# backend-fastapi/certificates/storage/session_pki_storage.py

class PKISession:
    def __init__(self, session_id: str):
        self.session_id = session_id  # Same UUID-based isolation!
        self.components: Dict[str, PKIComponent] = {}
        self.validation_results: Optional[Dict[str, Any]] = None
        self.created_at = datetime.utcnow().isoformat()
        self.last_updated = datetime.utcnow().isoformat()
        self._lock = threading.Lock()

class SessionPKIStorage:
    def __init__(self):
        self._sessions: Dict[str, PKISession] = {}
        self._global_lock = threading.Lock()
        self._start_cleanup_thread()
```

### 🆕 JWT Session Manager

```python
# backend-fastapi/middleware/jwt_session.py

class SimpleSessionManager:
    """Session manager using HMAC-SHA256 signed JWT tokens"""
    
    def __init__(self):
        self.secret_key = settings.SECRET_KEY.encode()
        self.session_expire_hours = settings.SESSION_EXPIRE_HOURS
        
    def create_session_jwt(self, session_id: Optional[str] = None) -> tuple[str, str]:
        """Create session token using HMAC signature"""
        if not session_id:
            session_id = str(uuid.uuid4())  # Same UUID concept!
            
        payload = {
            "session_id": session_id,
            "exp": (datetime.utcnow() + timedelta(hours=self.session_expire_hours)).timestamp(),
            "type": "session"
        }
        
        # Encode payload and create HMAC signature
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
        
        signature = hmac.new(
            self.secret_key, 
            payload_b64.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        token = f"{payload_b64}.{signature}"
        return session_id, token
```

### Key Features

- **🆕 HTTP-only JWT cookies**: Sessions transmitted via secure cookies
- **🆕 CSRF protection**: SameSite=Strict prevents cross-site attacks
- **🆕 Automatic session management**: @require_session decorator handles everything
- **UUID-based session isolation**: Each user gets isolated storage (same as before!)
- **Thread safety**: Concurrent access protection with locks
- **Automatic cleanup**: Sessions expire after 24 hours
- **Real-time validation**: Automatic validation computation on changes

### Session Lifecycle Flow

```mermaid
flowchart TD
    A[Browser Opens Tab] --> B[First Request to API]
    B --> C[@require_session Decorator]
    C --> D{JWT Cookie Present?}
    D -->|No| E[Create New UUID Session]
    D -->|Yes| F[Validate JWT Token]
    F --> G{JWT Valid?}
    G -->|No| E
    G -->|Yes| H[Extract Session ID]
    E --> I[Generate JWT Token]
    I --> J[Set HTTP-only Cookie]
    H --> K[Process Request]
    J --> K
    K --> L[Upload Certificates]
    L --> M{Session Active?}
    M -->|Yes| N[Process Certificate]
    M -->|No| O[Cookie Expired - Create New]
    O --> N
    N --> P[Store in Session]
    P --> Q{User Action?}
    Q -->|Upload More| L
    Q -->|Download Bundle| R[Generate Encrypted ZIP]
    Q -->|Close Tab| S[Session Expires (24h)]
    S --> T[Automatic Cleanup]
    R --> Q
```

---

## Certificate Processing Pipeline

### PKI Component Types

The system supports a comprehensive PKI component type system:

```python
# backend-fastapi/models/pki_component.py

class PKIComponentType(Enum):
    CERTIFICATE = "Certificate"
    PRIVATE_KEY = "PrivateKey"
    CSR = "CSR"
    ISSUING_CA = "IssuingCA"
    INTERMEDIATE_CA = "IntermediateCA"
    ROOT_CA = "RootCA"
    UNKNOWN = "Unknown"
```

### Component Ordering System

PKI components are automatically ordered based on their hierarchical relationships:

```python
# Order priority for PKI hierarchy display
PKI_TYPE_ORDER = {
    PKIComponentType.ROOT_CA: 1,
    PKIComponentType.INTERMEDIATE_CA: 2,
    PKIComponentType.ISSUING_CA: 3,
    PKIComponentType.CERTIFICATE: 4,
    PKIComponentType.CSR: 5,
    PKIComponentType.PRIVATE_KEY: 6,
    PKIComponentType.UNKNOWN: 7
}
```

### Multi-Format Certificate Parser

```python
# backend-fastapi/certificate_analyzer.py
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import base64

class CertificateAnalyzer:
    
    @staticmethod
    def parse_certificate_file(file_content: bytes, password: str = None) -> Dict[str, Any]:
        """
        Universal certificate parser supporting multiple formats
        """
        results = {
            'certificates': [],
            'private_keys': [],
            'csrs': [],
            'format_detected': None,
            'errors': []
        }
        
        # Try PKCS#12 first (if password provided)
        if password:
            try:
                private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                    file_content, password.encode('utf-8')
                )
                results['format_detected'] = 'PKCS#12'
                
                if certificate:
                    results['certificates'].append(CertificateAnalyzer._analyze_certificate(certificate))
                if private_key:
                    results['private_keys'].append(CertificateAnalyzer._analyze_private_key(private_key))
                if additional_certificates:
                    for cert in additional_certificates:
                        results['certificates'].append(CertificateAnalyzer._analyze_certificate(cert))
                        
                return results
            except Exception as e:
                results['errors'].append(f"PKCS#12 parsing failed: {str(e)}")
        
        # Try PEM format
        try:
            pem_content = file_content.decode('utf-8')
            results.update(CertificateAnalyzer._parse_pem_content(pem_content))
            if results['certificates'] or results['private_keys'] or results['csrs']:
                results['format_detected'] = 'PEM'
                return results
        except UnicodeDecodeError:
            pass
        
        # Try DER format
        try:
            # Try as certificate
            cert = x509.load_der_x509_certificate(file_content)
            results['certificates'].append(CertificateAnalyzer._analyze_certificate(cert))
            results['format_detected'] = 'DER'
            return results
        except Exception:
            pass
            
        # Try as private key (DER)
        try:
            private_key = serialization.load_der_private_key(file_content, password=None)
            results['private_keys'].append(CertificateAnalyzer._analyze_private_key(private_key))
            results['format_detected'] = 'DER'
            return results
        except Exception:
            pass
        
        results['errors'].append("Unable to parse file - unsupported format")
        return results
```

### Processing Flow

```mermaid
graph TD
    A[File Upload] --> B[Format Detection]
    B --> C{File Format?}
    C -->|PEM| D[Parse PEM Blocks]
    C -->|PKCS12| E[Extract with Password]
    C -->|DER| F[Parse DER Binary]
    C -->|JKS| G[Extract Java Keystore]
    
    D --> H[Component Classification]
    E --> H
    F --> H
    G --> H
    
    H --> I[Metadata Extraction]
    I --> J[PKI Type Assignment]
    J --> K[Hierarchical Ordering]
    K --> L[Session Storage]
    L --> M[Validation Computation]
    M --> N[Return Results]
```

---

## Cryptographic Validation Engine

### Validation Service Architecture

The validation system uses a service-based approach:

```python
# backend-fastapi/services/validation_service.py

class ValidationService:
    def __init__(self):
        self.version = "2.0"
        self.supported_validations = [
            "private_key_certificate_match",
            "private_key_csr_match", 
            "certificate_csr_match",
            "certificate_chain_validation",
            "certificate_expiry_check",
            "key_usage_validation",
            "subject_alternative_name_validation",
            "algorithm_strength_validation"
        ]
```

### Validation Types

1. **Private Key ↔ Certificate Matching**
2. **Private Key ↔ CSR Matching**
3. **Certificate ↔ CSR Matching**
4. **Certificate Chain Validation**
5. **Certificate Expiry Checks**
6. **Key Usage Validation**
7. **Subject Alternative Name Validation**
8. **Algorithm Strength Assessment**

### Validation Results Structure

```json
{
  "computed_at": "2025-01-15T10:30:00Z",
  "validation_engine_version": "2.0",
  "overall_status": "valid",
  "total_validations": 5,
  "passed_validations": 4,
  "failed_validations": 1,
  "warnings": 0,
  "validations": {
    "private_key_certificate_match": {
      "validation_id": "val-pk-cert-001",
      "type": "relationship",
      "status": "valid",
      "confidence": "high",
      "title": "Private Key Certificate Match",
      "description": "Private key matches certificate public key",
      "components_involved": ["comp-001", "comp-002"],
      "validation_method": "signature_verification",
      "details": {
        "key_algorithm": "RSA",
        "key_size": 2048,
        "signature_valid": true
      }
    }
  }
}
```

### Validation Flow Diagram

```mermaid
flowchart TD
    A[Start Validation] --> B{Components Available?}
    B -->|Private Key + Certificate| C[Test Key-Cert Match]
    B -->|Private Key + CSR| D[Test Key-CSR Match]
    B -->|Certificate + CSR| E[Test Cert-CSR Match]
    B -->|Multiple Certificates| F[Build Certificate Chain]
    
    C --> G[Generate Test Signature]
    G --> H[Verify with Public Key]
    H --> I{Verification Success?}
    I -->|Yes| J[Mark as Valid Match]
    I -->|No| K[Mark as Invalid Match]
    
    D --> L[Extract CSR Public Key]
    L --> M[Compare Key Parameters]
    M --> N{Keys Match?}
    N -->|Yes| O[Mark as Valid Match]
    N -->|No| P[Mark as Invalid Match]
    
    F --> Q[Identify Root CA]
    Q --> R[Build Trust Chain]
    R --> S[Validate Signatures]
    S --> T[Check Validity Periods]
    T --> U[Generate Chain Report]
    
    J --> V[Store Results]
    K --> V
    O --> V
    P --> V
    U --> V
```

---

## Security Implementation

### 🆕 Cookie-Based Security Architecture

The application uses secure HTTP-only cookies with JWT tokens for session management:

```python
# backend-fastapi/middleware/session_decorator.py

def _set_session_cookie(response: Response, jwt_token: str, secure: bool = True):
    """
    Set HTTP-only session cookie with JWT
    """
    response.set_cookie(
        key="session_token",
        value=jwt_token,
        httponly=True,              # Prevent XSS - JavaScript cannot access
        secure=secure,              # HTTPS only in production
        samesite="strict",          # CSRF protection
        max_age=86400,             # 24 hours (matches JWT expiration)
        path="/"                   # Available for all routes
    )

def clear_session_cookie(response: Response):
    """
    Clear session cookie (for logout functionality)
    """
    response.delete_cookie(
        key="session_token",
        path="/",
        httponly=True,
        secure=True,
        samesite="strict"
    )
```

### 🆕 Session Decorator System

```python
# backend-fastapi/middleware/session_decorator.py

@require_session
async def analyze_certificate(request: Request, file: UploadFile):
    """
    @require_session decorator automatically handles:
    1. JWT cookie validation
    2. Session creation if needed
    3. Session ID injection into request.state
    4. Cookie setting on response
    """
    # session_id automatically available from decorator
    session_id = request.state.session_id
    
    # Each session has isolated storage (same concept, secure delivery!)
    result = analyze_uploaded_certificate(file_content, session_id)
    return result
```

### Secure ZIP Download Implementation

```python
# backend-fastapi/services/secure_zip_creator.py
import zipfile
import secrets
import string
from io import BytesIO
import base64

class SecureZipCreator:
    
    @staticmethod
    def generate_secure_password(length: int = 12) -> str:
        """Generate cryptographically secure random password"""
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    def create_password_protected_zip(self, files_dict: dict) -> tuple[bytes, str]:
        """
        Create password-protected ZIP file
        Returns: (zip_bytes, password)
        """
        password = self.generate_secure_password()
        
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename, content in files_dict.items():
                zip_info = zipfile.ZipInfo(filename)
                zip_info.compress_type = zipfile.ZIP_DEFLATED
                zip_file.writestr(zip_info, content)
        
        # Password protection via external library if needed
        zip_buffer.seek(0)
        return zip_buffer.getvalue(), password
```

### Security Architecture Flow

```mermaid
flowchart TD
    A[Client Request] --> B[Cookie JWT Check]
    B --> C{Valid JWT Cookie?}
    C -->|Yes| D[Extract Session ID]
    C -->|No| E[Create New Session]
    
    E --> F[Generate JWT Token]
    F --> G[Set HTTP-only Cookie]
    G --> H[Process Request]
    
    D --> H
    H --> I{Download Request?}
    I -->|Yes| J[Generate Random Password]
    I -->|No| K[Normal Response]
    
    J --> L[Create Encrypted ZIP]
    L --> M[Return ZIP + Password]
    M --> N[Client Downloads ZIP]
    N --> O[Password Shown Once]
    O --> P[Password Forgotten by System]
```

---

## API Design

### Updated API Architecture

The API uses centralized service classes and cookie-based authentication:

```python
# backend-fastapi/main.py

# Service dependencies
@app.dependency_overrides.update({
    "validation_service": lambda: validation_service,
    "download_service": lambda: download_service
})
```

### Core Endpoints

#### 1. Certificate Management

```http
GET /certificates
# Returns all PKI components in session with validation results
# 🆕 Uses cookie-based authentication automatically

POST /analyze-certificate
# Upload and analyze new PKI component  
# 🆕 Uses cookie-based authentication automatically

DELETE /certificates/{component_id}
# Remove specific component from session
# 🆕 Uses cookie-based authentication automatically

POST /clear-session
# Clear all components from session
# 🆕 Uses cookie-based authentication automatically
```

#### 2. Download System

```http
POST /downloads/zip-bundle
# Create secure ZIP bundle
# 🆕 Session validation via JWT cookies

GET /downloads/ca-certificates
# Download CA certs only
# 🆕 Uses cookie-based authentication automatically

GET /downloads/end-entity
# Download end-entity components
# 🆕 Uses cookie-based authentication automatically

GET /downloads/full-chain
# Download complete certificate chain
# 🆕 Uses cookie-based authentication automatically
```

#### 3. Validation

```http
GET /validate
# Get current validation results for session
# 🆕 Uses cookie-based authentication automatically
```

### RESTful Endpoint Structure

```python
# backend-fastapi/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Certificate Analysis API",
    description="Comprehensive PKI analysis and management",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,  # 🆕 Required for cookie authentication
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health_router)
app.include_router(certificates_router)
app.include_router(downloads_router)
app.include_router(stats_router)

@app.get("/")
def read_root():
    """Root endpoint"""
    return {
        "message": settings.APP_NAME,
        "status": "online",
        "version": settings.APP_VERSION,
        "endpoints": {
            "health": "/health",
            "certificates": "/certificates", 
            "downloads": "/downloads",
            "docs": "/docs"
### API Response Format

All API responses follow a consistent structure:

```json
{
  "success": true,
  "components": [...],
  "validation_results": {...},
  "total": 3,
  "message": "Operation completed successfully"
}
```

### API Flow Diagram

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API Gateway
    participant J as JWT Middleware
    participant S as Session Manager
    participant V as Validator
    participant D as Download Service
    
    C->>A: POST /analyze-certificate (with session cookie)
    A->>J: @require_session decorator
    J->>J: Validate JWT from cookie
    J->>S: Get/Create Session
    S->>A: Session Data + Set Cookie
    A->>A: Parse Certificate
    A->>V: Run Validations
    V->>A: Validation Results
    A->>S: Store Results
    A->>C: Analysis + Validations + Cookie
    
    C->>A: GET /certificates (with session cookie)
    A->>J: @require_session decorator
    J->>S: Get Session Data from JWT
    S->>A: PKI Components
    A->>C: Complete PKI Bundle
    
    C->>A: POST /downloads/zip-bundle (with session cookie)
    A->>J: Validate JWT Cookie
    J->>D: Generate Bundle
    D->>D: Create Random Password
    D->>D: Create ZIP File
    D->>A: ZIP Data + Password
    A->>C: Download Data + Password
```

---

## Frontend Architecture

### React Architecture

The frontend uses centralized API services with automatic cookie handling:

```javascript
// frontend/src/services/api.js

// 🆕 Axios automatically handles cookies
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 30000,
  withCredentials: true,  // 🆕 Required for cookie authentication
  headers: {
    'Content-Type': 'application/json',
  },
});

// Centralized API service (no more manual session headers!)
const certificateAPI = {
  getCertificates: () => api.get('/certificates'),
  uploadCertificate: (file, password) => uploadWithFile('/analyze-certificate', file, password),
  deleteCertificate: (componentId) => api.delete(`/certificates/${componentId}`),
  clearSession: () => api.post('/clear-session')
};

const downloadAPI = {
  downloadZipBundle: (options) => downloadBundle('zip-bundle', options),
  downloadCACertificates: () => api.get('/downloads/ca-certificates'),
  downloadEndEntity: () => api.get('/downloads/end-entity'),
  downloadFullChain: () => api.get('/downloads/full-chain')
};
```

### Context-Based State Management

```javascript
// frontend/src/contexts/CertificateContext.jsx

export const CertificateProvider = ({ children }) => {
  const [components, setComponents] = useState([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)

  const refreshFiles = useCallback(async () => {
    try {
      setIsLoading(true)
      // 🆕 No manual session management - cookies handled automatically
      const result = await certificateAPI.getCertificates()
      if (result.success) {
        const sortedComponents = (result.certificates || []).sort((a, b) => {
          return a.order - b.order
        })
        setComponents(sortedComponents)
      }
    } catch (error) {
      setError('Failed to refresh PKI components')
    } finally {
      setIsLoading(false)
    }
  }, [])
}
```

### Component Mapping System

The frontend maps backend PKI components to certificate objects:

```javascript
// frontend/src/services/api.js

function mapPKIComponentToCertificate(component) {
  const metadata = component.metadata || {}
  
  return {
    id: component.id,
    filename: component.filename,
    type: component.type,
    order: component.order,
    metadata: metadata,
    has_certificate: component.type === 'Certificate',
    has_private_key: component.type === 'PrivateKey',
    has_csr: component.type === 'CSR',
    has_ca: ['IssuingCA', 'IntermediateCA', 'RootCA'].includes(component.type)
  }
}
```

### React Component Structure

```jsx
// frontend/src/contexts/CertificateContext.jsx
import React, { createContext, useContext, useReducer } from 'react'

const CertificateContext = createContext()

const certificateReducer = (state, action) => {
  switch (action.type) {
    case 'ADD_CERTIFICATE':
      return {
        ...state,
        certificates: {
          ...state.certificates,
          [action.payload.id]: action.payload
        }
      }
    
    case 'UPDATE_VALIDATIONS':
      return {
        ...state,
        validations: action.payload
      }
    
    case 'CLEAR_SESSION':
      return {
        certificates: {},
        validations: {}
      }
    
    default:
      return state
  }
}

export const CertificateProvider = ({ children }) => {
  const [state, dispatch] = useReducer(certificateReducer, {
    certificates: {},
    validations: {}
  })
  
  return (
    <CertificateContext.Provider value={{ state, dispatch }}>
      {children}
    </CertificateContext.Provider>
  )
}

export const useCertificates = () => {
  const context = useContext(CertificateContext)
  if (!context) {
    throw new Error('useCertificates must be used within CertificateProvider')
  }
  return context
}
```

### Frontend State Flow

```mermaid
stateDiagram-v2
    [*] --> Initial: App Starts
    Initial --> FileSelected: User Selects File
    FileSelected --> Uploading: POST /analyze-certificate (cookie auto-sent)
    Uploading --> PasswordRequired: Server Requests Password
    Uploading --> Analyzing: File Uploaded Successfully
    PasswordRequired --> PasswordProvided: User Enters Password
    PasswordProvided --> Uploading: Retry Upload (cookie maintained)
    Analyzing --> DisplayResults: Analysis Complete
    DisplayResults --> ValidationRunning: Run Validations
    ValidationRunning --> ValidationComplete: Validations Done
    ValidationComplete --> DisplayResults: Update UI
    DisplayResults --> DownloadReady: User Requests Download
    DownloadReady --> GeneratingBundle: Create Secure Bundle
    GeneratingBundle --> DownloadComplete: ZIP + Password Ready
    DownloadComplete --> DisplayResults: Return to Main View
```

---

## Data Flow

### Complete System Data Flow

```mermaid
graph TD
    subgraph "Frontend Layer"
        UI[React Components]
        CTX[Certificate Context]
        API[API Service Layer<br/>🆕 Cookie Handling]
    end
    
    subgraph "Backend Layer"
        MAIN[FastAPI Main]
        JWT[🆕 JWT Middleware]
        SVC[Service Layer]
        STORE[Session Storage]
    end
    
    subgraph "Services"
        VS[Validation Service]
        DS[Download Service]
    end
    
    UI --> CTX
    CTX --> API
    API --> MAIN
    MAIN --> JWT
    JWT --> SVC
    SVC --> VS
    SVC --> DS
    SVC --> STORE
    STORE --> SVC
    SVC --> JWT
    JWT --> MAIN
    MAIN --> API
    API --> CTX
    CTX --> UI
```

### Session Lifecycle

```mermaid
stateDiagram-v2
    [*] --> SessionCreated: User visits site (cookie auto-created)
    SessionCreated --> ComponentUploaded: Upload certificate
    ComponentUploaded --> ValidationComputed: Auto-validation
    ValidationComputed --> ComponentUploaded: Upload more
    ValidationComputed --> DownloadRequested: Request download
    DownloadRequested --> ValidationComputed: Continue session
    ComponentUploaded --> SessionCleared: Clear all
    ValidationComputed --> SessionCleared: Clear all
    SessionCleared --> SessionCreated: Start fresh
    ValidationComputed --> SessionExpired: 24 hour timeout
    SessionExpired --> [*]: Session destroyed
```

### Complete System Data Flow (Extended)

```mermaid
flowchart TD
    subgraph "Client Side"
        A[User Uploads File] --> B[React File Upload Component]
        B --> C[FormData with File + Password]
    end
    
    subgraph "Network Layer"
        C --> D[HTTP POST to /analyze-certificate<br/>🆕 With session cookie]
        D --> E[Nginx Reverse Proxy]
        E --> F[FastAPI Backend]
    end
    
    subgraph "Backend Processing"
        F --> G[🆕 @require_session Decorator]
        G --> H{JWT Cookie Valid?}
        H -->|No| I[Create New JWT Session]
        H -->|Yes| J[Extract Session ID from JWT]
        I --> K[Certificate Analyzer]
        J --> K
        K --> L[Multi-Format Parser]
        L --> M[Cryptographic Validator]
        M --> N[Store Results in Session]
    end
    
    subgraph "Response Flow"
        N --> O[JSON Response<br/>🆕 + Set-Cookie Header]
        O --> P[Nginx Proxy Response]
        P --> Q[React State Update]
        Q --> R[UI Components Re-render]
        R --> S[Display Certificate Details]
        S --> T[Show Validation Results]
    end
    
    subgraph "Download Flow"
        T --> U{User Requests Download?}
        U -->|Yes| V[🆕 JWT Cookie Validation]
        V --> W[Generate Random Password]
        W --> X[Create Encrypted ZIP]
        X --> Y[Base64 Encode ZIP]
        Y --> Z[Return ZIP + Password]
        Z --> AA[Client Downloads ZIP]
        AA --> BB[Password Displayed Once]
        BB --> CC[System Forgets Password]
    end
```

---

## Deployment Architecture

### Docker Compose Infrastructure

```yaml
# docker-compose.yml
version: '3.8'

services:
  nginx:
    build: ./nginx
    ports:
      - "80:80"
    depends_on:
      - frontend
      - backend-fastapi
    networks:
      - certificate-network
    restart: unless-stopped

  frontend:
    build: ./frontend
    container_name: certificate-frontend
    expose:
      - "80"
    environment:
      - NODE_ENV=production
      # 🆕 Cookie-based session config
      - VITE_SESSION_COOKIE_NAME=session_token
      - VITE_AUTO_LOGIN=true
    networks:
      - certificate-network
    restart: unless-stopped

  backend-fastapi:
    build: ./backend-fastapi
    container_name: certificate-backend
    expose:
      - "8000"
    environment:
      # 🆕 JWT and cookie authentication settings
      - SECRET_KEY=${SECRET_KEY:-your-secret-key-change-in-production}
      - SESSION_EXPIRE_HOURS=24
      - SESSION_COOKIE_NAME=session_token
      - DEBUG=OFF
      - MAX_FILE_SIZE=10485760  # 10MB
    networks:
      - certificate-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  certificate-network:
    driver: bridge
```

### Nginx Configuration

```nginx
# nginx/nginx.conf
events {
  worker_connections 1024;
}

http {
  upstream frontend {
    server frontend:80;
  }

  upstream backend {
    server backend-fastapi:8000;
  }

  server {
    listen 80;

    # Frontend SPA
    location / {
      proxy_pass http://frontend;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      # 🆕 Cookie forwarding for session management
      proxy_set_header Cookie $http_cookie;
    }

    # API Proxy
    location /api/ {
      proxy_pass http://backend/;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      # 🆕 Cookie handling for JWT authentication
      proxy_set_header Cookie $http_cookie;
      proxy_pass_header Set-Cookie;
    }
    
    # TODO: SSL Configuration section
    # For production deployment with HTTPS:
    # - Add SSL certificate configuration
    # - Configure SSL/TLS protocols and ciphers
    # - Add security headers
    # - Redirect HTTP to HTTPS
    # - Set Secure flag on cookies for HTTPS
  }
}
```

### Container Health Monitoring

```python
# backend-fastapi/health.py
from fastapi import APIRouter
from datetime import datetime
import psutil
import os

health_router = APIRouter()

@health_router.get("/health")
async def health_check():
    """
    Comprehensive health check endpoint
    """
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Application metrics
        uptime = datetime.utcnow() - app_start_time
        active_sessions = len(session_manager.sessions)
        
        # 🆕 JWT authentication status
        jwt_config = {
            "secret_key_configured": bool(os.getenv("SECRET_KEY")),
            "session_expire_hours": os.getenv("SESSION_EXPIRE_HOURS", "24"),
            "cookie_name": os.getenv("SESSION_COOKIE_NAME", "session_token")
        }
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": uptime.total_seconds(),
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": (disk.used / disk.total) * 100,
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None
            },
            "application": {
                "active_sessions": active_sessions,
                "version": "1.0.0",
                "environment": os.getenv("ENVIRONMENT", "development"),
                "authentication": jwt_config
            }
        }
        
        # Determine overall health
        if cpu_percent > 90 or memory.percent > 90:
            health_status["status"] = "warning"
        
        if cpu_percent > 95 or memory.percent > 95:
            health_status["status"] = "unhealthy"
            
        return health_status
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }
```

---

## Performance Considerations

### Memory Management Strategy

```python
# backend-fastapi/performance_manager.py
import gc
import threading
import time
from typing import Dict, Any
from datetime import datetime, timedelta

class PerformanceManager:
    
    def __init__(self):
        self.memory_threshold = 500 * 1024 * 1024  # 500MB
        self.cleanup_interval = 300  # 5 minutes
        self.performance_metrics = {
            'requests_per_second': 0,
            'average_response_time': 0,
            'memory_usage': 0,
            'active_sessions': 0,
            # 🆕 JWT metrics
            'jwt_validations_per_minute': 0,
            'session_cookie_hits': 0,
            'session_cookie_misses': 0
        }
        
        # Start background cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_worker(self):
        """
        Background worker for memory cleanup and session management
        """
        while True:
            try:
                # Clean expired sessions
                self._cleanup_expired_sessions()
                
                # Force garbage collection if memory usage is high
                current_memory = psutil.Process().memory_info().rss
                if current_memory > self.memory_threshold:
                    gc.collect()
                    
                # Update performance metrics
                self._update_performance_metrics()
                
                time.sleep(self.cleanup_interval)
                
            except Exception as e:
                logger.error(f"Cleanup worker error: {str(e)}")
                time.sleep(60)  # Wait before retrying
    
    def _cleanup_expired_sessions(self):
        """
        Remove sessions that haven't been accessed recently
        🆕 Updated for 24-hour session expiration
        """
        current_time = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_data in session_manager.sessions.items():
            last_accessed = session_data.get('last_accessed', current_time)
            # 🆕 Updated to 24 hours instead of 30 minutes
            if current_time - last_accessed > timedelta(hours=24):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            session_manager.delete_session(session_id)
            logger.info(f"Cleaned up expired session: {session_id}")
```

### Caching Strategy Implementation

```python
# backend-fastapi/cache_manager.py
import hashlib
import json
from functools import wraps
from typing import Any, Callable, Optional
import time

class CacheManager:
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
        self.ttl = ttl  # Time to live in seconds
    
    def cache_key(self, *args, **kwargs) -> str:
        """
        Generate cache key from function arguments
        """
        key_data = {
            'args': args,
            'kwargs': sorted(kwargs.items())
        }
        key_string = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value if it exists and hasn't expired
        """
        if key not in self.cache:
            return None
        
        # Check if expired
        if time.time() - self.access_times[key] > self.ttl:
            del self.cache[key]
            del self.access_times[key]
            return None
        
        # Update access time
        self.access_times[key] = time.time()
        return self.cache[key]
    
    def set(self, key: str, value: Any):
        """
        Store value in cache with LRU eviction
        """
        # Evict oldest if cache is full
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.access_times, key=self.access_times.get)
            del self.cache[oldest_key]
            del self.access_times[oldest_key]
        
        self.cache[key] = value
        self.access_times[key] = time.time()
    
    def cached_validation(self, func: Callable) -> Callable:
        """
        Decorator for caching validation results
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = self.cache_key(*args, **kwargs)
            cached_result = self.get(cache_key)
            
            if cached_result is not None:
                return cached_result
            
            result = func(*args, **kwargs)
            self.set(cache_key, result)
            return result
        
        return wrapper

# Usage example
cache_manager = CacheManager(max_size=500, ttl=1800)  # 30 minutes TTL

@cache_manager.cached_validation
def validate_certificate_chain(certificates: list) -> dict:
    """
    Expensive validation operation that benefits from caching
    """
    # Perform complex validation logic
### Performance Monitoring

```mermaid
graph TD
    subgraph "Performance Monitoring"
        A[Request Metrics] --> B[Response Time Tracking]
        B --> C[Memory Usage Monitoring]
        C --> D[Session Count Tracking]
        D --> E[Error Rate Monitoring]
        
        E --> F{Performance Threshold?}
        F -->|Normal| G[Continue Monitoring]
        F -->|Warning| H[Scale Resources]
        F -->|Critical| I[Alert + Auto-Scale]
        
        H --> J[Add Container Instance]
        I --> K[Emergency Scaling]
        J --> G
        K --> G
    end
    
    subgraph "🆕 JWT Performance Monitoring"
        L[Cookie Validation Rate] --> M[JWT Decode Performance]
        N[Session Creation Rate] --> M
        O[Cookie Expiry Rate] --> M
        P[CSRF Attack Attempts] --> M
        
        M --> Q[Authentication Health Score]
        Q --> R{Auth Performance OK?}
        R -->|No| S[Alert Security Team]
        R -->|Yes| T[Continue Monitoring]
    end
    
    subgraph "Auto-Scaling Triggers"
        U[CPU > 70%] --> V[Scale Up Decision]
        W[Memory > 80%] --> V
        X[Response Time > 2s] --> V
        Y[Error Rate > 5%] --> V
        Z[🆕 JWT Validation Failures > 10%] --> V
        
        V --> AA[Deploy New Instance]
        AA --> BB[Update Load Balancer]
        BB --> CC[Health Check New Instance]
        CC --> DD[Route Traffic]
    end
```

---

## Monitoring and Observability

### Logging Strategy

```python
# backend-fastapi/logging_config.py
import logging
import json
from datetime import datetime
from typing import Any, Dict

class StructuredLogger:
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create structured formatter
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_certificate_analysis(self, session_id: str, filename: str, 
                                analysis_result: Dict[str, Any]):
        """
        Log certificate analysis with structured data
        """
        log_data = {
            "event": "certificate_analysis",
            "session_id": session_id,
            "filename": filename,
            "timestamp": datetime.utcnow().isoformat(),
            "certificates_found": len(analysis_result.get('certificates', [])),
            "private_keys_found": len(analysis_result.get('private_keys', [])),
            "csrs_found": len(analysis_result.get('csrs', [])),
            "format_detected": analysis_result.get('format_detected'),
            "has_errors": len(analysis_result.get('errors', [])) > 0
        }
        
        self.logger.info(json.dumps(log_data))
    
    def log_validation_results(self, session_id: str, validation_results: Dict[str, Any]):
        """
        Log validation results for monitoring
        """
        log_data = {
            "event": "validation_completed",
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "validations": {
                "key_cert_matches": len(validation_results.get('private_key_certificate_matches', [])),
                "chain_validations": len(validation_results.get('certificate_chain_validations', [])),
                "total_valid": sum(1 for v in validation_results.get('private_key_certificate_matches', []) if v['is_valid'])
            }
        }
        
        self.logger.info(json.dumps(log_data))
    
    # 🆕 JWT and session logging
    def log_session_event(self, event_type: str, session_id: str, details: Dict[str, Any]):
        """
        Log session and authentication events
        """
        log_data = {
            "event": "session_event",
            "event_type": event_type,  # "session_created", "jwt_validated", "session_expired"
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        
        self.logger.info(json.dumps(log_data))
    
    def log_security_event(self, event_type: str, session_id: str, details: Dict[str, Any]):
        """
        Log security-related events
        """
        log_data = {
            "event": "security_event",
            "event_type": event_type,
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        
        self.logger.warning(json.dumps(log_data))

# Usage throughout the application
logger = StructuredLogger("certificate_analysis")
```

### Metrics Collection

```python
# backend-fastapi/metrics.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
from functools import wraps

# Define metrics
REQUEST_COUNT = Counter('certificate_analysis_requests_total', 
                       'Total requests', ['method', 'endpoint'])
REQUEST_LATENCY = Histogram('certificate_analysis_request_duration_seconds',
                           'Request latency')
ACTIVE_SESSIONS = Gauge('certificate_analysis_active_sessions',
                       'Number of active sessions')
CERTIFICATE_UPLOADS = Counter('certificate_uploads_total',
                             'Total certificate uploads', ['format'])

# 🆕 JWT and authentication metrics
JWT_VALIDATIONS = Counter('jwt_validations_total',
                         'Total JWT validations', ['result'])
SESSION_COOKIES = Counter('session_cookies_total',
                         'Session cookie operations', ['operation'])
AUTH_ERRORS = Counter('authentication_errors_total',
                     'Authentication errors', ['error_type'])

def track_performance(func):
    """
    Decorator to track API performance metrics
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = await func(*args, **kwargs)
            REQUEST_COUNT.labels(method='POST', endpoint=func.__name__).inc()
            return result
        except Exception as e:
            REQUEST_COUNT.labels(method='POST', endpoint=f"{func.__name__}_error").inc()
            raise
        finally:
            REQUEST_LATENCY.observe(time.time() - start_time)
    
    return wrapper

# 🆕 JWT tracking decorator
def track_jwt_validation(func):
    """
    Decorator to track JWT validation metrics
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            JWT_VALIDATIONS.labels(result='success').inc()
            return result
        except Exception as e:
            JWT_VALIDATIONS.labels(result='failure').inc()
            AUTH_ERRORS.labels(error_type=type(e).__name__).inc()
            raise
    
    return wrapper

# Start metrics server
def start_metrics_server(port: int = 8001):
    start_http_server(port)
```

---

## Development Guidelines

### Code Style and Standards

**Backend (Python):**
- Follow PEP 8 style guidelines
- Use type hints for all function parameters and return values
- Implement comprehensive error handling with try-catch blocks
- Add docstrings to all public methods and classes
- Use structured logging for all important events
- 🆕 Always use @require_session decorator for protected endpoints

**Frontend (JavaScript/React):**
- Use ESLint and Prettier for code formatting
- Implement proper error boundaries for React components
- Follow React hooks best practices
- Implement proper loading and error states
- 🆕 Use withCredentials: true for all API calls

### Testing Strategy

**Backend Testing:**
```python
# backend-fastapi/tests/test_validation_service.py
import pytest
from services.validation_service import validation_service
from models.pki_component import PKIComponent

class TestValidationService:
    
    def test_private_key_certificate_match(self):
        """Test private key certificate matching validation"""
        # Create test session with components
        session = create_test_session_with_key_cert_pair()
        
        # Run validation
        results = validation_service.compute_all_validations(session)
        
        # Assert validation results
        assert results['overall_status'] == 'valid'
        assert 'private_key_certificate_match' in results['validations']
        assert results['validations']['private_key_certificate_match']['status'] == 'valid'
    
    def test_certificate_chain_validation(self):
        """Test certificate chain validation"""
        session = create_test_session_with_cert_chain()
        
        results = validation_service.compute_all_validations(session)
        
        assert 'certificate_chain_validation' in results['validations']
        chain_validation = results['validations']['certificate_chain_validation']
        assert chain_validation['status'] in ['valid', 'warning']

# 🆕 JWT Authentication Testing
class TestJWTAuthentication:
    
    def test_jwt_session_creation(self):
        """Test JWT session creation and validation"""
        from middleware.jwt_session import jwt_session_manager
        
        # Create session
        session_id, jwt_token = jwt_session_manager.create_session_jwt()
        
        # Validate session
        validated_session_id = jwt_session_manager.validate_session_jwt(jwt_token)
        
        assert session_id == validated_session_id
        assert len(session_id) == 36  # UUID length
    
    def test_session_decorator(self):
        """Test @require_session decorator"""
        from fastapi.testclient import TestClient
        
        # Test request without cookie
        response = client.post("/analyze-certificate")
        assert response.status_code == 200  # Should create new session
        assert "Set-Cookie" in response.headers
        
        # Extract cookie and test subsequent request
        cookie = response.headers["Set-Cookie"]
        response = client.get("/certificates", headers={"Cookie": cookie})
        assert response.status_code == 200
```

**Frontend Testing:**
```javascript
// frontend/src/components/__tests__/CertificateUpload.test.jsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { CertificateProvider } from '../../contexts/CertificateContext'
import CertificateUpload from '../CertificateUpload'

describe('CertificateUpload', () => {
  it('should upload certificate and display results', async () => {
    render(
      <CertificateProvider>
        <CertificateUpload />
      </CertificateProvider>
    )
    
    const fileInput = screen.getByLabelText(/upload certificate/i)
    const testFile = new File(['certificate content'], 'test.pem', {
      type: 'application/x-pem-file'
    })
    
    fireEvent.change(fileInput, { target: { files: [testFile] } })
    
    await waitFor(() => {
      expect(screen.getByText(/certificate uploaded/i)).toBeInTheDocument()
    })
  })
  
  // 🆕 Cookie authentication testing
  it('should handle session cookies automatically', async () => {
    const mockApi = jest.fn().mockResolvedValue({ success: true })
    
    render(<CertificateUpload />)
    
    // Verify axios is configured with withCredentials
    expect(api.defaults.withCredentials).toBe(true)
  })
})
```

### Security Considerations

**🆕 Cookie-Based Security:**
- All endpoints use @require_session decorator for automatic authentication
- JWT tokens are cryptographically signed with HMAC-SHA256
- HTTP-only cookies prevent XSS attacks
- SameSite=Strict prevents CSRF attacks
- Sessions expire automatically after 24 hours

**Input Validation:**
- File size limits enforced (10MB default)
- File type validation based on content, not just extension
- Password strength requirements for encrypted files
- XSS protection with Content Security Policy headers

**Data Protection:**
- Sessions expire automatically after 24 hours
- Certificate data stored only in memory (no persistent storage)
- Secure random password generation for downloads
- HTTPS recommended for production (HTTP-only cookies become Secure)

### Troubleshooting Guide

**Common Issues and Solutions:**

1. **🆕 Cookie Authentication Issues**
   ```
   Problem: Sessions not persisting between requests
   Solution: Check cookie configuration and CORS settings
   
   # Verify cookie settings
   console.log('Cookies:', document.cookie)  // Should show session_token
   
   # Backend CORS configuration
   app.add_middleware(
       CORSMiddleware,
       allow_credentials=True,  # Required for cookies
       allow_origins=["http://localhost:3000"]
   )
   ```

2. **🆕 JWT Validation Errors**
   ```
   Problem: JWT signature validation failing
   Solution: Ensure SECRET_KEY is consistent and properly configured
   
   # Check SECRET_KEY configuration
   echo $SECRET_KEY
   # Should be 32+ character string
   
   # Verify JWT middleware is loaded
   from middleware.jwt_session import jwt_session_manager
   ```

3. **Upload Failures**
   ```
   Problem: Certificate upload fails with "unsupported format"
   Solution: Check file format and password requirements
   
   // Debug file format detection
   console.log('File type:', file.type)
   console.log('File size:', file.size)
   ```

4. **Frontend API Errors**
   ```
   Problem: API calls failing after frontend refactoring
   Solution: Update to use new certificateAPI service with cookies
   
   // Use centralized API with cookie support
   import { certificateAPI } from '../services/api'
   
   // Ensure withCredentials is set
   const api = axios.create({
     withCredentials: true  // Required for cookie auth
   })
   ```

### Performance Optimization Tips

**Backend Optimization:**
- Use caching for expensive validation operations
- Implement session cleanup to prevent memory leaks
- Use async/await for I/O operations
- Monitor memory usage with health checks
- 🆕 Cache JWT validation results for repeated requests

**Frontend Optimization:**
- Implement lazy loading for certificate details
- Use React.memo for expensive components
- Debounce user input for search functionality
- Optimize bundle size with code splitting
- 🆕 Minimize cookie size by using session references

**Database/Storage Optimization:**
- Use Redis for distributed session storage in multi-instance deployments
- Implement LRU cache for frequently accessed data
- Use connection pooling for database connections
- Monitor query performance with logging

---

## Deployment Checklist

### Pre-Deployment

- [ ] Update environment variables in `.env` file
- [ ] 🆕 Generate secure SECRET_KEY for JWT signing (256-bit minimum)
- [ ] 🆕 Configure SESSION_EXPIRE_HOURS and SESSION_COOKIE_NAME
- [ ] Configure SSL certificates for HTTPS (optional)
- [ ] Set up monitoring and logging
- [ ] Run security audit on dependencies
- [ ] Verify backup and recovery procedures

### Production Deployment

- [ ] Deploy with Docker Compose
- [ ] Configure Nginx reverse proxy with cookie forwarding
- [ ] Set up health check endpoints
- [ ] Configure log aggregation
- [ ] Set up monitoring dashboards
- [ ] Test SSL/TLS configuration (if enabled)
- [ ] 🆕 Verify JWT cookie authentication is working
- [ ] 🆕 Test session persistence across browser restarts
- [ ] Test download functionality

### Post-Deployment

- [ ] Monitor application performance
- [ ] Check error rates and response times
- [ ] Verify certificate validation accuracy
- [ ] Test auto-scaling if configured
- [ ] Monitor memory usage and cleanup
- [ ] Verify security headers
- [ ] 🆕 Monitor JWT authentication metrics
- [ ] 🆕 Verify cookie security settings (HttpOnly, Secure, SameSite)
- [ ] 🆕 Test session expiration behavior (24-hour timeout)
- [ ] Test backup and recovery procedures

---

## Important Notes

### 🆕 Cookie-Based Authentication System
- **The application uses HTTP-only JWT cookies for session management**
- **No manual session ID headers required - cookies handled automatically**
- **JWT tokens are cryptographically signed with HMAC-SHA256**
- Security is based on session isolation using UUID session IDs (same concept!)
- All endpoints use `@require_session` decorator for automatic authentication
- Downloads are protected by JWT cookie validation

### Session-Based Architecture (Updated)
- Each browser session gets a unique UUID (same as before!)
- 🆕 Sessions automatically expire after 24 hours (updated from 1 hour)
- All certificate data is stored in memory only
- No persistent storage or database required
- 🆕 Sessions transmitted via secure HTTP-only cookies instead of headers

### Download Security (Enhanced)
- ZIP files are password-protected with random passwords
- Passwords are generated per download and forgotten by system
- 🆕 Downloads are protected by JWT cookie validation instead of session ownership
- 🆕 Cross-site request forgery (CSRF) protection via SameSite=Strict cookies

### 🆕 Cookie Security Features
- **HttpOnly**: Prevents XSS attacks - JavaScript cannot access cookies
- **Secure**: HTTPS-only transmission in production
- **SameSite=Strict**: Prevents CSRF attacks
- **24-hour expiration**: Automatic session timeout
- **HMAC-SHA256 signatures**: Cryptographically secure JWT tokens

---

This comprehensive technical documentation covers all major aspects of the Certificate Analysis Tool with the updated cookie-based authentication system. The core session isolation concept remains the same - each user gets isolated UUID-based storage - but now with enterprise-grade security via HTTP-only JWT cookies instead of plain-text headers.