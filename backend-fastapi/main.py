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

# Track start time for uptime
start_time = time.time()

# ============================================================================
# FASTAPI APPLICATION SETUP
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
# CERTIFICATE ENDPOINTS WITH FIXED PKCS12 CRYPTO OBJECT STORAGE
# ============================================================================

@app.post("/analyze-certificate", tags=["certificates"], status_code=201)
async def analyze_certificate(
    current_user: Annotated[User, Depends(get_current_active_user)],
    certificate: UploadFile = File(...),
    password: str = Form(None)
):
    """Analyze uploaded certificate file with crypto object storage"""
    from certificates.storage import CertificateStorage
    from certificates.analyzer import analyze_uploaded_certificate
    
    try:
        file_content = await certificate.read()
        
        # Analyze the certificate - returns both analysis and crypto objects
        result = analyze_uploaded_certificate(file_content, certificate.filename, password)
        
        # Extract analysis and crypto objects from the result
        if isinstance(result, dict) and 'analysis' in result:
            # NEW FORMAT: {analysis: {...}, crypto_objects: {...}}
            analysis = result['analysis']
            crypto_objects = result.get('crypto_objects', {})
        else:
            # FALLBACK: old format where result IS the analysis
            analysis = result
            crypto_objects = {}
        
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
        
        # Check for duplicates based on content hash
        logger.info(f"Checking for duplicates with content_hash: {analysis['content_hash']}")
        existing_cert = CertificateStorage.find_by_hash(analysis["content_hash"])
        
        if existing_cert:
            logger.info(f"Found duplicate: {existing_cert.get('filename')} has same content_hash")
        else:
            logger.info(f"No duplicate found for content_hash: {analysis['content_hash']}")
        
        # Create certificate data (without crypto objects)
        certificate_data = {
            "id": str(uuid.uuid4()),
            "filename": certificate.filename,
            "analysis": analysis,  # Only analysis data, no crypto objects
            "uploadedAt": datetime.datetime.now().isoformat(),
            "size": len(file_content)
        }
        
        # Store main certificate and collect additional items
        added_certificates = []
        
        if existing_cert:
            # Replace existing certificate
            replaced_cert = CertificateStorage.replace(existing_cert, certificate_data)
            added_certificates.append(replaced_cert)
            # Store crypto objects separately for the replaced certificate
            if crypto_objects:
                CertificateStorage.store_crypto_objects(replaced_cert['id'], crypto_objects)
        else:
            # Add new certificate
            new_cert = CertificateStorage.add(certificate_data)
            added_certificates.append(new_cert)
            # Store crypto objects separately for the new certificate
            if crypto_objects:
                CertificateStorage.store_crypto_objects(new_cert['id'], crypto_objects)
        
        # Handle additional items from PKCS12 (private keys, additional certificates) - FIXED VERSION
        if analysis.get('additional_items'):
            logger.info(f"Processing {len(analysis['additional_items'])} additional items from PKCS12")
            
            # Get all crypto objects from PKCS12
            pkcs12_private_key = crypto_objects.get('private_key')
            pkcs12_additional_certs = crypto_objects.get('additional_certificates', [])
            
            logger.debug(f"PKCS12 crypto objects available:")
            logger.debug(f"  Private key: {'YES' if pkcs12_private_key else 'NO'}")
            logger.debug(f"  Additional certificates: {len(pkcs12_additional_certs)}")
            
            additional_cert_index = 0  # Track which additional cert we're processing
            
            for item_index, item in enumerate(analysis['additional_items']):
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
                
                # Store crypto objects for additional items - FIXED LOGIC
                item_crypto_objects = {}
                
                if item['type'] == 'Private Key' and pkcs12_private_key:
                    item_crypto_objects['private_key'] = pkcs12_private_key
                    logger.info(f"✓ Storing private key crypto object for {item_filename}")
                    
                elif item['type'] == 'Certificate' and pkcs12_additional_certs:
                    # Use the corresponding additional certificate by index
                    if additional_cert_index < len(pkcs12_additional_certs):
                        item_crypto_objects['certificate'] = pkcs12_additional_certs[additional_cert_index]
                        logger.info(f"✓ Storing certificate crypto object for {item_filename} (cert index {additional_cert_index})")
                        additional_cert_index += 1
                    else:
                        logger.warning(f"No additional certificate available for {item_filename} at index {additional_cert_index}")
                
                if existing_additional_item:
                    # Replace existing additional item
                    replaced_item = CertificateStorage.replace(existing_additional_item, additional_data)
                    added_certificates.append(replaced_item)
                    # Store crypto objects for replaced item
                    if item_crypto_objects:
                        CertificateStorage.store_crypto_objects(replaced_item['id'], item_crypto_objects)
                        logger.debug(f"Stored crypto objects for replaced item: {list(item_crypto_objects.keys())}")
                    logger.info(f"Replaced duplicate {item['type']}: {existing_additional_item.get('filename')} -> {item_filename}")
                else:
                    # Add new additional item
                    added_item = CertificateStorage.add(additional_data)
                    added_certificates.append(added_item)
                    # Store crypto objects for new item
                    if item_crypto_objects:
                        CertificateStorage.store_crypto_objects(added_item['id'], item_crypto_objects)
                        logger.debug(f"Stored crypto objects for new item: {list(item_crypto_objects.keys())}")
                    logger.info(f"Added new {item['type']} from PKCS12: {item_filename}")
        
        # Return response (no crypto objects in JSON response)
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
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
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

@app.get("/validate", tags=["validation"])
def validate_certificates(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Run validation checks on uploaded certificates using real cryptographic comparison"""
    from certificates.storage import CertificateStorage
    from certificates.validation.validator import run_validations
    
    try:
        certificates = CertificateStorage.get_all()
        logger.info(f"Running cryptographic validations on {len(certificates)} certificates")
        
        # Enhanced debug logging for validation
        logger.debug("=== VALIDATION DEBUG ===")
        for cert in certificates:
            cert_id = cert.get('id')
            filename = cert.get('filename', 'NO_FILENAME')
            cert_type = cert.get('analysis', {}).get('type', 'NO_TYPE')
            crypto_objects = CertificateStorage.get_crypto_objects(cert_id)
            logger.debug(f"Cert: {filename} | Type: {cert_type} | Crypto: {list(crypto_objects.keys()) if crypto_objects else 'None'}")
        
        validations = run_validations(certificates)
        
        return {
            "success": True,
            "validations": [validation.to_dict() for validation in validations],
            "count": len(validations),
            "timestamp": datetime.datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Validation error: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to run validations: {str(e)}"
        )

# ============================================================================
# AUTHENTICATION ENDPOINTS
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
# HEALTH CHECK ENDPOINTS
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
# ROOT ENDPOINT
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
# ADDITIONAL UTILITY ENDPOINTS
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
# APPLICATION STARTUP/SHUTDOWN
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
# DEVELOPMENT SERVER
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