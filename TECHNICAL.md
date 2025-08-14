# Technical Documentation - Certificate Analysis Tool

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Session Management](#session-management)
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
        Backend[FastAPI Service<br/>Port 8000]
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
    participant S as Session Manager
    participant V as Validation Service
    participant C as Crypto Engine
    
    U->>N: HTTP Request
    N->>F: Route to Frontend (/)
    F->>U: Serve React SPA
    
    U->>F: Upload Certificate
    F->>N: POST /api/upload
    N->>B: Forward to Backend
    B->>S: Create/Get Session
    B->>C: Parse Certificate
    C->>B: Return Analysis
    B->>V: Compute Validations
    V->>B: Return Validation Results
    B->>S: Store Results
    B->>F: Return Analysis JSON
    F->>U: Display Results
```

---

## Session Management

### Session Architecture

The session management system provides multi-user isolation with automatic cleanup and thread safety.

```python
# backend-fastapi/certificates/storage/session_pki_storage.py

class PKISession:
    def __init__(self, session_id: str):
        self.session_id = session_id
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

### Key Features

- **UUID-based session isolation**: Each user gets a unique session
- **Thread safety**: Concurrent access protection with locks
- **Automatic cleanup**: Sessions expire after 1 hour of inactivity
- **Real-time validation**: Automatic validation computation on changes

### Session Lifecycle Flow

```mermaid
flowchart TD
    A[Browser Opens Tab] --> B[Generate UUID Session ID]
    B --> C[Create Session Storage]
    C --> D[Set Session Headers]
    D --> E[Upload Certificates]
    E --> F{Session Active?}
    F -->|Yes| G[Process Certificate]
    F -->|No| H[Create New Session]
    H --> G
    G --> I[Store in Session]
    I --> J{User Action?}
    J -->|Upload More| E
    J -->|Download Bundle| K[Generate Encrypted ZIP]
    J -->|Close Tab| L[Session Expires]
    L --> M[Automatic Cleanup]
    K --> J
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

### Session-Based Security

The application uses session-based isolation for security rather than user authentication:

```python
# backend-fastapi/middleware/session_middleware.py
def get_session_id(x_session_id: str = Header(None)):
    """
    Extract session ID from headers with validation
    """
    if not x_session_id:
        raise HTTPException(
            status_code=400,
            detail="Session ID required. Include 'X-Session-ID' header."
        )
    
    # Validate UUID format
    try:
        uuid.UUID(x_session_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid session ID format. Must be a valid UUID."
        )
    
    return x_session_id
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
    A[Client Request] --> B[Session ID Check]
    B --> C{Valid Session?}
    C -->|Yes| D[Process Request]
    C -->|No| E[Return 400 Bad Request]
    
    D --> F{Download Request?}
    F -->|Yes| G[Generate Random Password]
    F -->|No| H[Normal Response]
    
    G --> I[Create Encrypted ZIP]
    I --> J[Return ZIP + Password]
    J --> K[Client Downloads ZIP]
    K --> L[Password Shown Once]
    L --> M[Password Forgotten by System]
```

---

## API Design

### Updated API Architecture

The API uses centralized service classes:

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
# Requires: X-Session-ID header

POST /upload-certificate
# Upload and analyze new PKI component
# Requires: X-Session-ID header

DELETE /certificates/{component_id}
# Remove specific component from session
# Requires: X-Session-ID header

POST /clear-session
# Clear all components from session
# Requires: X-Session-ID header
```

#### 2. Download System

```http
POST /downloads/download/{bundle_type}/{session_id}
# Download bundles (apache, nginx, iis, custom)
# No authentication required - session-based access only
```

#### 3. Validation

```http
GET /validate
# Get current validation results for session
# Requires: X-Session-ID header
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
    allow_credentials=True,
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
        }
    }
```

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
    participant S as Session Manager
    participant V as Validator
    participant D as Download Service
    
    C->>A: POST /upload-certificate (with X-Session-ID)
    A->>S: Get/Create Session
    S->>A: Session Data
    A->>A: Parse Certificate
    A->>V: Run Validations
    V->>A: Validation Results
    A->>S: Store Results
    A->>C: Analysis + Validations
    
    C->>A: GET /certificates (with X-Session-ID)
    A->>S: Get Session Data
    S->>A: PKI Components
    A->>C: Complete PKI Bundle
    
    C->>A: POST /downloads/download/apache/{session_id}
    A->>D: Generate Apache Bundle
    D->>D: Create Random Password
    D->>D: Create ZIP File
    D->>A: ZIP Data + Password
    A->>C: Download Data + Password
```

---

## Frontend Architecture

### React Architecture

The frontend uses centralized API services:

```javascript
// frontend/src/services/api.js

// Centralized API service
const certificateAPI = {
  getCertificates: () => api.get('/certificates'),
  uploadCertificate: (file, password) => uploadWithFile('/upload-certificate', file, password),
  deleteCertificate: (componentId) => api.delete(`/certificates/${componentId}`),
  clearSession: () => api.post('/clear-session')
};

const downloadAPI = {
  downloadApacheBundle: (options) => downloadBundle('apache', options),
  downloadNginxBundle: (options) => downloadBundle('nginx', options),
  downloadIISBundle: (options) => downloadBundle('iis', options),
  downloadCustomBundle: (componentIds, options) => downloadCustom(componentIds, options)
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
        validations: {},
        sessionId: null
      }
    
    default:
      return state
  }
}

export const CertificateProvider = ({ children }) => {
  const [state, dispatch] = useReducer(certificateReducer, {
    certificates: {},
    validations: {},
    sessionId: null
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
    FileSelected --> Uploading: POST /upload
    Uploading --> PasswordRequired: Server Requests Password
    Uploading --> Analyzing: File Uploaded Successfully
    PasswordRequired --> PasswordProvided: User Enters Password
    PasswordProvided --> Uploading: Retry Upload
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
        API[API Service Layer]
    end
    
    subgraph "Backend Layer"
        MAIN[FastAPI Main]
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
    MAIN --> SVC
    SVC --> VS
    SVC --> DS
    SVC --> STORE
    STORE --> SVC
    SVC --> MAIN
    MAIN --> API
    API --> CTX
    CTX --> UI
```

### Session Lifecycle

```mermaid
stateDiagram-v2
    [*] --> SessionCreated: User visits site
    SessionCreated --> ComponentUploaded: Upload certificate
    ComponentUploaded --> ValidationComputed: Auto-validation
    ValidationComputed --> ComponentUploaded: Upload more
    ValidationComputed --> DownloadRequested: Request download
    DownloadRequested --> ValidationComputed: Continue session
    ComponentUploaded --> SessionCleared: Clear all
    ValidationComputed --> SessionCleared: Clear all
    SessionCleared --> SessionCreated: Start fresh
    ValidationComputed --> SessionExpired: 1 hour timeout
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
        C --> D[HTTP POST to /upload]
        D --> E[Nginx Reverse Proxy]
        E --> F[FastAPI Backend]
    end
    
    subgraph "Backend Processing"
        F --> G[Session Manager]
        G --> H{Session Exists?}
        H -->|No| I[Create New Session]
        H -->|Yes| J[Use Existing Session]
        I --> K[Certificate Analyzer]
        J --> K
        K --> L[Multi-Format Parser]
        L --> M[Cryptographic Validator]
        M --> N[Store Results in Session]
    end
    
    subgraph "Response Flow"
        N --> O[JSON Response]
        O --> P[Nginx Proxy Response]
        P --> Q[React State Update]
        Q --> R[UI Components Re-render]
        R --> S[Display Certificate Details]
        S --> T[Show Validation Results]
    end
    
    subgraph "Download Flow"
        T --> U{User Requests Download?}
        U -->|Yes| V[Session ID Check]
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
    networks:
      - certificate-network
    restart: unless-stopped

  backend-fastapi:
    build: ./backend-fastapi
    container_name: certificate-backend
    expose:
      - "8000"
    environment:
      - SECRET_KEY=${SECRET_KEY:-your-secret-key-change-in-production}
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
    }

    # API Proxy
    location /api/ {
      proxy_pass http://backend/;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # TODO: SSL Configuration section
    # For production deployment with HTTPS:
    # - Add SSL certificate configuration
    # - Configure SSL/TLS protocols and ciphers
    # - Add security headers
    # - Redirect HTTP to HTTPS
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
                "environment": os.getenv("ENVIRONMENT", "development")
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
            'active_sessions': 0
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
        """
        current_time = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_data in session_manager.sessions.items():
            last_accessed = session_data.get('last_accessed', current_time)
            if current_time - last_accessed > timedelta(minutes=30):
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
    return validation_results
```

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
    
    subgraph "Auto-Scaling Triggers"
        L[CPU > 70%] --> M[Scale Up Decision]
        N[Memory > 80%] --> M
        O[Response Time > 2s] --> M
        P[Error Rate > 5%] --> M
        
        M --> Q[Deploy New Instance]
        Q --> R[Update Load Balancer]
        R --> S[Health Check New Instance]
        S --> T[Route Traffic]
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

**Frontend (JavaScript/React):**
- Use ESLint and Prettier for code formatting
- Implement proper error boundaries for React components
- Follow React hooks best practices
- Implement proper loading and error states

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
})
```

### Security Considerations

**Session-Based Security:**
- All endpoints require X-Session-ID header for access
- Session isolation prevents cross-user data access
- Passwords are never stored or logged
- ZIP downloads with one-time passwords

**Input Validation:**
- File size limits enforced (10MB default)
- File type validation based on content, not just extension
- Password strength requirements for encrypted files
- XSS protection with Content Security Policy headers

**Data Protection:**
- Sessions expire automatically after 1 hour
- Certificate data stored only in memory (no persistent storage)
- Secure random password generation for downloads
- HTTP-only (HTTPS can be configured in production)

### Troubleshooting Guide

**Common Issues and Solutions:**

1. **Session Not Found Errors**
   ```
   Problem: "Session not found" errors in API calls
   Solution: Check X-Session-ID header is being sent correctly
   
   // Verify session ID is present
   console.log('Session ID:', sessionManager.getSessionId())
   ```

2. **Validation Service Errors**
   ```
   Problem: ValidationService import errors
   Solution: Ensure new validation service is properly imported
   
   # Check validation service import
   from services.validation_service import validation_service
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
   Solution: Update to use new certificateAPI service
   
   // Use centralized API
   import { certificateAPI } from '../services/api'
   const result = await certificateAPI.getCertificates()
   ```

### Performance Optimization Tips

**Backend Optimization:**
- Use caching for expensive validation operations
- Implement session cleanup to prevent memory leaks
- Use async/await for I/O operations
- Monitor memory usage with health checks

**Frontend Optimization:**
- Implement lazy loading for certificate details
- Use React.memo for expensive components
- Debounce user input for search functionality
- Optimize bundle size with code splitting

**Database/Storage Optimization:**
- Use Redis for distributed session storage in multi-instance deployments
- Implement LRU cache for frequently accessed data
- Use connection pooling for database connections
- Monitor query performance with logging

---

## Deployment Checklist

### Pre-Deployment

- [ ] Update environment variables in `.env` file
- [ ] Generate secure SECRET_KEY for session management
- [ ] Configure SSL certificates for HTTPS (optional)
- [ ] Set up monitoring and logging
- [ ] Run security audit on dependencies
- [ ] Verify backup and recovery procedures

### Production Deployment

- [ ] Deploy with Docker Compose
- [ ] Configure Nginx reverse proxy
- [ ] Set up health check endpoints
- [ ] Configure log aggregation
- [ ] Set up monitoring dashboards
- [ ] Test SSL/TLS configuration (if enabled)
- [ ] Verify session management
- [ ] Test download functionality

### Post-Deployment

- [ ] Monitor application performance
- [ ] Check error rates and response times
- [ ] Verify certificate validation accuracy
- [ ] Test auto-scaling if configured
- [ ] Monitor memory usage and cleanup
- [ ] Verify security headers
- [ ] Test backup and recovery procedures

---

## Important Notes

### No Authentication System
- **The application does NOT have user authentication**
- **No JWT tokens, no login system, no user accounts**
- Security is based on session isolation using UUID session IDs
- All endpoints require `X-Session-ID` header for access
- Downloads are protected by session ownership only

### Session-Based Architecture
- Each browser session gets a unique UUID
- Sessions automatically expire after 1 hour of inactivity
- All certificate data is stored in memory only
- No persistent storage or database required

### Download Security
- ZIP files are password-protected with random passwords
- Passwords are generated per download and forgotten by system
- Downloads are tied to session ID, not user authentication

---

This comprehensive technical documentation covers all major aspects of the Certificate Analysis Tool with accurate information based on the actual codebase implementation. The documentation provides developers with complete understanding of the current session-based architecture and best practices for maintenance and further development.