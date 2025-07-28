# routers/certificates.py
# Certificate analysis endpoints with session support

import datetime
import logging
import uuid
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, Form

from auth.models import User
from auth.dependencies import get_current_active_user
from middleware.session_middleware import get_session_id

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/analyze-certificate", tags=["certificates"], status_code=201)
async def analyze_certificate(
    certificate: UploadFile = File(...),
    password: str = Form(None),
    session_id: str = Depends(get_session_id)
):
    """Analyze uploaded certificate file with crypto object storage"""
    from certificates.storage import CertificateStorage
    from certificates.analyzer import analyze_uploaded_certificate
    
    try:
        file_content = await certificate.read()
        
        # Analyze the certificate - returns both analysis and crypto objects
        result = analyze_uploaded_certificate(file_content, certificate.filename or "unknown", password)
        
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
                        "filename": certificate.filename or "unknown",
                        "analysis": analysis
                    },
                    "message": f"Password required for {certificate.filename}",
                    "session_id": session_id
                }
            else:
                return {
                    "success": False,
                    "requiresPassword": True,
                    "certificate": {
                        "filename": certificate.filename or "unknown",
                        "analysis": analysis
                    },
                    "message": f"Invalid password for {certificate.filename}",
                    "session_id": session_id
                }
        
        # Check for duplicates based on content hash
        logger.info(f"[{session_id}] Checking for duplicates with content_hash: {analysis['content_hash']}")
        existing_cert = CertificateStorage.find_by_hash(analysis["content_hash"], session_id)
        
        if existing_cert:
            logger.info(f"[{session_id}] Found duplicate: {existing_cert.get('filename')} has same content_hash")
        else:
            logger.info(f"[{session_id}] No duplicate found for content_hash: {analysis['content_hash']}")
        
        # Create certificate data (without crypto objects)
        certificate_data = {
            "id": str(uuid.uuid4()),
            "filename": certificate.filename,
            "analysis": analysis,
            "uploadedAt": datetime.datetime.now().isoformat(),
            "size": len(file_content),
            "isDuplicate": existing_cert is not None
        }
        
        # Store main certificate and collect additional items
        added_certificates = []
        
        if existing_cert:
            # Replace existing certificate
            replaced_cert = CertificateStorage.replace(existing_cert, certificate_data, session_id)
            added_certificates.append(replaced_cert)
            # Store crypto objects separately for the replaced certificate
            if crypto_objects:
                CertificateStorage.store_crypto_objects(replaced_cert['id'], crypto_objects, session_id)
        else:
            # Add new certificate
            new_cert = CertificateStorage.add(certificate_data, session_id)
            added_certificates.append(new_cert)
            # Store crypto objects separately for the new certificate
            if crypto_objects:
                CertificateStorage.store_crypto_objects(new_cert['id'], crypto_objects, session_id)
        
        # Handle additional items from PKCS12 (private keys, additional certificates) - FIXED VERSION
        if analysis.get('additional_items'):
            logger.info(f"[{session_id}] Processing {len(analysis['additional_items'])} additional items from PKCS12")
            
            # Get all crypto objects from PKCS12
            pkcs12_private_key = crypto_objects.get('private_key')
            pkcs12_additional_certs = crypto_objects.get('additional_certificates', [])
            
            logger.debug(f"[{session_id}] PKCS12 crypto objects available:")
            logger.debug(f"  Private key: {'YES' if pkcs12_private_key else 'NO'}")
            logger.debug(f"  Additional certificates: {len(pkcs12_additional_certs)}")
            
            additional_cert_index = 0  # Track which additional cert we're processing
            
            for item_index, item in enumerate(analysis['additional_items']):
                # Check for existing duplicate of this additional item
                existing_additional_item = None
                if item.get('content_hash'):
                    existing_additional_item = CertificateStorage.find_by_hash(item['content_hash'], session_id)
                
                # Create filename for additional item
                item_filename = f"{certificate.filename or 'unknown'} ({item['type']})"
                
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
                    logger.info(f"[{session_id}] ✓ Storing private key crypto object for {item_filename}")
                    
                elif item['type'] == 'Certificate' and pkcs12_additional_certs:
                    # Use the corresponding additional certificate by index
                    if additional_cert_index < len(pkcs12_additional_certs):
                        item_crypto_objects['certificate'] = pkcs12_additional_certs[additional_cert_index]
                        logger.info(f"[{session_id}] ✓ Storing certificate crypto object for {item_filename} (cert index {additional_cert_index})")
                        additional_cert_index += 1
                    else:
                        logger.warning(f"[{session_id}] No additional certificate available for {item_filename} at index {additional_cert_index}")
                
                if existing_additional_item:
                    # Replace existing additional item
                    replaced_item = CertificateStorage.replace(existing_additional_item, additional_data, session_id)
                    added_certificates.append(replaced_item)
                    # Store crypto objects for replaced item
                    if item_crypto_objects:
                        CertificateStorage.store_crypto_objects(replaced_item['id'], item_crypto_objects, session_id)
                        logger.debug(f"[{session_id}] Stored crypto objects for replaced item: {list(item_crypto_objects.keys())}")
                    logger.info(f"[{session_id}] Replaced duplicate {item['type']}: {existing_additional_item.get('filename')} -> {item_filename}")
                else:
                    # Add new additional item
                    added_item = CertificateStorage.add(additional_data, session_id)
                    added_certificates.append(added_item)
                    # Store crypto objects for new item
                    if item_crypto_objects:
                        CertificateStorage.store_crypto_objects(added_item['id'], item_crypto_objects, session_id)
                        logger.debug(f"[{session_id}] Stored crypto objects for new item: {list(item_crypto_objects.keys())}")
                    logger.info(f"[{session_id}] Added new {item['type']} from PKCS12: {item_filename}")
        
        # Return response (no crypto objects in JSON response)
        if existing_cert:
            return {
                "success": True,
                "isDuplicate": True,
                "replaced": True,
                "certificate": added_certificates[0],
                "additional_items": added_certificates[1:] if len(added_certificates) > 1 else [],
                "replacedCertificate": existing_cert,
                "message": f"Automatically replaced {existing_cert.get('filename')} with {certificate.filename or 'unknown'} (identical content)",
                "timestamp": datetime.datetime.now().isoformat(),
                "session_id": session_id
            }
        else:
            return {
                "success": True,
                "isDuplicate": False,
                "certificate": added_certificates[0],
                "additional_items": added_certificates[1:] if len(added_certificates) > 1 else [],
                "timestamp": datetime.datetime.now().isoformat(),
                "session_id": session_id
            }
        
    except Exception as e:
        logger.error(f"[{session_id}] Certificate analysis error: {e}")
        import traceback
        logger.error(f"[{session_id}] Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to analyze certificate: {str(e)}"
        )

@router.get("/certificates", tags=["certificates"])
def get_certificates_simple(session_id: str = Depends(get_session_id)):
    """Get all stored certificates (simple endpoint - no auth required)"""
    from certificates.storage import CertificateStorage
    
    try:
        certificates = CertificateStorage.get_all(session_id)
        logger.info(f"[{session_id}] Retrieved {len(certificates)} certificates")
        
        return {
            "success": True,
            "certificates": certificates,
            "count": len(certificates),
            "session_id": session_id
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] Certificate retrieval error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve certificates: {str(e)}"
        )

@router.get("/api/certificates", tags=["certificates"])
def get_certificates(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Get all stored certificates"""
    from certificates.storage import CertificateStorage
    
    try:
        certificates = CertificateStorage.get_all(session_id)
        logger.info(f"[{session_id}] Retrieved {len(certificates)} certificates for user {current_user.username}")
        
        return {
            "success": True,
            "certificates": certificates,
            "count": len(certificates),
            "timestamp": datetime.datetime.now().isoformat(),
            "session_id": session_id
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] Certificate retrieval error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve certificates: {str(e)}"
        )

@router.get("/validate", tags=["validation"])
def validate_certificates_simple(session_id: str = Depends(get_session_id)):
    """Run validation checks on uploaded certificates using real cryptographic comparison"""
    from certificates.storage import CertificateStorage
    from certificates.validation.validator import run_validations
    
    try:
        certificates = CertificateStorage.get_all(session_id)
        logger.info(f"[{session_id}] Running cryptographic validations on {len(certificates)} certificates")
        
        # Enhanced debug logging for validation
        logger.debug(f"[{session_id}] === VALIDATION DEBUG ===")
        for cert in certificates:
            cert_id = cert.get('id')
            filename = cert.get('filename', 'NO_FILENAME')
            cert_type = cert.get('analysis', {}).get('type', 'NO_TYPE')
            if cert_id:  # Only call if cert_id is not None
                crypto_objects = CertificateStorage.get_crypto_objects(cert_id, session_id)
                logger.debug(f"[{session_id}] Cert: {filename} | Type: {cert_type} | Crypto: {list(crypto_objects.keys()) if crypto_objects else 'None'}")
            else:
                logger.debug(f"[{session_id}] Cert: {filename} | Type: {cert_type} | Crypto: NO_ID")
        
        # Prepare certificates with crypto objects for validation
        certificates_with_crypto = []
        for cert in certificates:
            cert_copy = cert.copy()
            cert_id = cert.get('id')
            if cert_id:
                try:
                    crypto_objects = CertificateStorage.get_crypto_objects(cert_id, session_id)
                    cert_copy['crypto_objects'] = crypto_objects
                except Exception as e:
                    logger.warning(f"[{session_id}] Could not get crypto objects for cert {cert_id}: {e}")
                    cert_copy['crypto_objects'] = {}
            else:
                cert_copy['crypto_objects'] = {}
            certificates_with_crypto.append(cert_copy)
        
        validations = run_validations(certificates_with_crypto)
        
        # CRITICAL DEBUG: Log exactly what we're returning
        logger.info(f"[{session_id}] === FINAL VALIDATION RESULTS ===")
        validation_dicts = []
        for i, validation in enumerate(validations):
            validation_dict = validation.to_dict()
            validation_dicts.append(validation_dict)
            
            logger.info(f"[{session_id}] Validation {i}:")
            logger.info(f"[{session_id}]   Type: {validation_dict.get('validationType')}")
            logger.info(f"[{session_id}]   isValid (dict): {validation_dict.get('isValid')}")
            logger.info(f"[{session_id}]   Raw is_valid: {validation.is_valid}")
            logger.info(f"[{session_id}]   Error: {validation_dict.get('error')}")
            
            # Check if there's any manipulation happening
            if validation.is_valid != validation_dict.get('isValid'):
                logger.error(f"[{session_id}] MISMATCH! Raw: {validation.is_valid}, Dict: {validation_dict.get('isValid')}")
        
        response_data = {
            "success": True,
            "validations": validation_dicts,
            "count": len(validations),
            "timestamp": datetime.datetime.now().isoformat(),
            "session_id": session_id
        }
        
        logger.info(f"[{session_id}] Returning response with {len(validation_dicts)} validations")
        return response_data
        
    except Exception as e:
        logger.error(f"[{session_id}] Validation error: {e}")
        import traceback
        logger.error(f"[{session_id}] Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to run validations: {str(e)}"
        )

@router.post("/api/certificates/validate", tags=["certificates"])
def validate_certificates(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Run validation checks on stored certificates"""
    from certificates.validation import run_validations
    from certificates.storage import CertificateStorage
    
    try:
        all_certificates = CertificateStorage.get_all(session_id)
        
        if not all_certificates:
            return {
                "success": False,
                "message": "No certificates found to validate",
                "validations": [],
                "session_id": session_id
            }
        
        # Prepare certificates with crypto objects for validation
        certificates_with_crypto = []
        for cert in all_certificates:
            cert_copy = cert.copy()
            cert_id = cert.get('id')
            if cert_id:
                try:
                    crypto_objects = CertificateStorage.get_crypto_objects(cert_id, session_id)
                    cert_copy['crypto_objects'] = crypto_objects
                except Exception as e:
                    logger.warning(f"[{session_id}] Could not get crypto objects for cert {cert_id}: {e}")
                    cert_copy['crypto_objects'] = {}
            else:
                cert_copy['crypto_objects'] = {}
            certificates_with_crypto.append(cert_copy)
        
        validations = run_validations(certificates_with_crypto)
        
        logger.info(f"[{session_id}] Validation completed: {len(validations)} results for user {current_user.username}")
        
        return {
            "success": True,
            "validations": validations,
            "count": len(validations),
            "timestamp": datetime.datetime.now().isoformat(),
            "session_id": session_id
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] Validation error: {e}")
        import traceback
        logger.error(f"[{session_id}] Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to run validations: {str(e)}"
        )

@router.delete("/certificates/{certificate_id}", tags=["certificates"])
def delete_certificate(
    certificate_id: str,
    session_id: str = Depends(get_session_id)
):
    """Delete certificate by ID"""
    from certificates.storage import CertificateStorage
    
    success = CertificateStorage.remove_by_id(certificate_id, session_id)
    if success:
        logger.info(f"[{session_id}] Certificate {certificate_id} deleted successfully")
        return {
            "success": True,
            "message": "Certificate deleted successfully",
            "session_id": session_id
        }
    else:
        logger.warning(f"[{session_id}] Certificate {certificate_id} not found for deletion")
        raise HTTPException(status_code=404, detail="Certificate not found")

@router.delete("/certificates", tags=["certificates"])
def clear_all_certificates(session_id: str = Depends(get_session_id)):
    """Clear all certificates"""
    from certificates.storage import CertificateStorage
    
    CertificateStorage.clear_all(session_id)
    logger.info(f"[{session_id}] All certificates cleared")
    return {
        "success": True,
        "message": "All certificates cleared",
        "session_id": session_id
    }