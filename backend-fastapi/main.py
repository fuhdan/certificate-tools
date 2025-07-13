# main.py - Modular FastAPI Certificate Analysis Backend
# Uses separated modules for better organization

import datetime
import logging
import time
import uuid
from typing import Annotated

from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm

# Import our modules
from config import settings
from auth.models import Token, User
from auth.security import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from auth.dependencies import get_current_active_user

# Define HealthResponse directly here since we deleted certificates.models
from pydantic import BaseModel

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    uptime: int

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
# logging.getLogger("certificates.analyzer").setLevel(logging.DEBUG)
# logging.getLogger("certificates.storage").setLevel(logging.DEBUG)
# logging.getLogger("certificates.extractors.certificate").setLevel(logging.DEBUG)
# logging.getLogger("certificates.extractors.csr").setLevel(logging.DEBUG)
# logging.getLogger("certificates.extractors.private_key").setLevel(logging.DEBUG)
# logging.getLogger("certificates.formats.der").setLevel(logging.DEBUG)
# logging.getLogger("certificates.formats.pem").setLevel(logging.DEBUG)
# logging.getLogger("certificates.formats.pkcs7").setLevel(logging.DEBUG)
# logging.getLogger("certificates.formats.pkcs12").setLevel(logging.DEBUG)
# logging.getLogger("certificates.utils.hashing").setLevel(logging.DEBUG)

# Track start time for uptime
start_time = time.time()

# ============================================================================
# FASTAPI APPLICATION SETUP (EXISTING - NO MERGE NEEDED)
# ============================================================================

app = FastAPI(
    title=settings.APP_NAME,
    description="FastAPI backend for certificate analysis and management",
    version=settings.APP_VERSION,
    debug=settings.DEBUG
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# CERTIFICATE ENDPOINTS - DIRECT IN MAIN (SAME AS HEALTH)
# ============================================================================

@app.post("/analyze-certificate", tags=["certificates"], status_code=201)
async def analyze_certificate(
    current_user: Annotated[User, Depends(get_current_active_user)],
    certificate: UploadFile = File(...),
    password: str = Form(None)  # Use Form() instead of regular parameter
):
    """Analyze uploaded certificate file with optional password support"""
    from certificates.storage import CertificateStorage
    from certificates.analyzer import analyze_uploaded_certificate
    
    try:
        file_content = await certificate.read()
        
        # Analyze the certificate with password support
        analysis = analyze_uploaded_certificate(file_content, certificate.filename, password)
        
        # Check if password is required
        if analysis.get('requiresPassword', False):
            if not password:
                return {
                    "success": False,
                    "requiresPassword": True,
                    "certificate": {
                        "filename": certificate.filename,
                        "analysis": analysis
                    },
                    "message": f"Password required for {certificate.filename}"
                }
            else:
                return {
                    "success": False,
                    "requiresPassword": True,
                    "certificate": {
                        "filename": certificate.filename,
                        "analysis": analysis
                    },
                    "message": f"Invalid password for {certificate.filename}"
                }
        
        # Check for duplicates based on content hash (normalized)
        logger.info(f"Checking for duplicates with content_hash: {analysis['content_hash']}")
        existing_cert = CertificateStorage.find_by_hash(analysis["content_hash"])
        
        if existing_cert:
            logger.info(f"Found duplicate: {existing_cert.get('filename')} has same content_hash")
        else:
            logger.info(f"No duplicate found for content_hash: {analysis['content_hash']}")
            # Debug: show all existing content hashes
            all_certs = CertificateStorage.get_all()
            for cert in all_certs:
                existing_hash = cert.get('analysis', {}).get('content_hash', 'NO_HASH')
                logger.info(f"  Existing cert: {cert.get('filename')} has content_hash: {existing_hash}")
        
        # Create certificate data
        certificate_data = {
            "id": str(uuid.uuid4()),
            "filename": certificate.filename,
            "analysis": analysis,
            "uploadedAt": datetime.datetime.now().isoformat(),
            "size": len(file_content)
        }
        
        # Store main certificate and collect additional items
        added_certificates = []
        
        if existing_cert:
            # Replace existing certificate
            replaced_cert = CertificateStorage.replace(existing_cert, certificate_data)
            added_certificates.append(replaced_cert)
        else:
            # Add new certificate
            new_cert = CertificateStorage.add(certificate_data)
            added_certificates.append(new_cert)
        
        # Handle additional items from PKCS12 (private keys, additional certificates)
        if analysis.get('additional_items'):
            logger.info(f"Processing {len(analysis['additional_items'])} additional items from PKCS12")
            for item in analysis['additional_items']:
                # Check for existing duplicate of this additional item
                existing_additional_item = None
                if item.get('content_hash'):
                    existing_additional_item = CertificateStorage.find_by_hash(item['content_hash'])
                
                # Create filename for additional item
                item_filename = f"{certificate.filename} ({item['type']})"
                
                additional_data = {
                    "id": str(uuid.uuid4()),
                    "filename": item_filename,
                    "analysis": item,
                    "uploadedAt": datetime.datetime.now().isoformat(),
                    "size": item.get('size', 0)
                }
                
                if existing_additional_item:
                    # Replace existing additional item
                    replaced_item = CertificateStorage.replace(existing_additional_item, additional_data)
                    added_certificates.append(replaced_item)
                    logger.info(f"Replaced duplicate {item['type']}: {existing_additional_item.get('filename')} -> {item_filename}")
                else:
                    # Add new additional item
                    added_item = CertificateStorage.add(additional_data)
                    added_certificates.append(added_item)
                    logger.info(f"Added new {item['type']} from PKCS12: {item_filename}")
        
        # Return response
        if existing_cert:
            return {
                "success": True,
                "isDuplicate": True,
                "replaced": True,
                "certificate": added_certificates[0],
                "additional_items": added_certificates[1:] if len(added_certificates) > 1 else [],
                "replacedCertificate": existing_cert,
                "message": f"Automatically replaced {existing_cert.get('filename')} with {certificate.filename} (identical content)",
                "timestamp": datetime.datetime.now().isoformat()
            }
        else:
            return {
                "success": True,
                "isDuplicate": False,
                "certificate": added_certificates[0],
                "additional_items": added_certificates[1:] if len(added_certificates) > 1 else [],
                "timestamp": datetime.datetime.now().isoformat()
            }
            
    except Exception as e:
        logger.error(f"Certificate analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to analyze certificate: {str(e)}"
        )

@app.get("/certificates", tags=["certificates"])
def get_certificates(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Get all uploaded certificates"""
    from certificates.storage import CertificateStorage
    
    certificates = CertificateStorage.get_all()
    return {
        "success": True,
        "certificates": certificates,
        "count": len(certificates)
    }

@app.delete("/certificates/{certificate_id}", tags=["certificates"])
def delete_certificate(
    current_user: Annotated[User, Depends(get_current_active_user)],
    certificate_id: str
):
    """Delete certificate by ID"""
    from certificates.storage import CertificateStorage
    
    success = CertificateStorage.remove_by_id(certificate_id)
    if success:
        return {
            "success": True,
            "message": "Certificate deleted successfully"
        }
    else:
        raise HTTPException(status_code=404, detail="Certificate not found")

@app.delete("/certificates", tags=["certificates"])
def clear_all_certificates(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Clear all certificates"""
    from certificates.storage import CertificateStorage
    
    CertificateStorage.clear_all()
    return {
        "success": True,
        "message": "All certificates cleared"
    }

# ============================================================================
# AUTHENTICATION ENDPOINTS (EXISTING - NO MERGE NEEDED)
# ============================================================================

@app.post("/token", response_model=Token, tags=["authentication"])
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """Login endpoint to get access token"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logger.info(f"User {user.username} logged in successfully")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User, tags=["authentication"])
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Get current user information"""
    return current_user

# ============================================================================
# HEALTH CHECK ENDPOINT (EXISTING - NO MERGE NEEDED)
# ============================================================================

@app.get("/health", response_model=HealthResponse, tags=["health"])
def health_check():
    """Health check endpoint for frontend connection status"""
    return HealthResponse(
        status="online",
        timestamp=datetime.datetime.now().isoformat(),
        uptime=int(time.time() - start_time)
    )

@app.get("/api/health", response_model=HealthResponse, tags=["health"])
def api_health_check():
    """Health check endpoint for API specifically"""
    return HealthResponse(
        status="online",
        timestamp=datetime.datetime.now().isoformat(),
        uptime=int(time.time() - start_time)
    )

# ============================================================================
# ROOT ENDPOINT (EXISTING - NO MERGE NEEDED)
# ============================================================================

@app.get("/", tags=["root"])
def read_root():
    """Root endpoint"""
    return {
        "message": settings.APP_NAME,
        "status": "online",
        "version": settings.APP_VERSION,
        "endpoints": {
            "health": "/health",
            "login": "/token",
            "certificates": "/api/certificates",
            "docs": "/docs"
        }
    }

# ============================================================================
# ADDITIONAL UTILITY ENDPOINTS (NEW - MERGE NEEDED)
# ============================================================================

@app.get("/api/stats", tags=["statistics"])
def get_system_stats(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Get system statistics"""
    from certificates.storage import CertificateStorage
    
    storage_summary = CertificateStorage.get_summary()
    
    return {
        "success": True,
        "stats": {
            "uptime_seconds": int(time.time() - start_time),
            "certificates": storage_summary,
            "system": {
                "version": settings.APP_VERSION,
                "debug": settings.DEBUG,
                "max_file_size": settings.MAX_FILE_SIZE,
                "allowed_extensions": list(settings.ALLOWED_EXTENSIONS)
            }
        },
        "timestamp": datetime.datetime.now().isoformat()
    }

# ============================================================================
# APPLICATION STARTUP/SHUTDOWN (EXISTING - NO MERGE NEEDED)
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    logger.info(f"Default login: {settings.DEFAULT_USERNAME} / {settings.DEFAULT_PASSWORD}")

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    logger.info(f"Shutting down {settings.APP_NAME}")

# ============================================================================
# DEVELOPMENT SERVER (EXISTING - NO MERGE NEEDED)
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )