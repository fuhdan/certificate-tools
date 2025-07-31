# backend-fastapi/routers/certificates.py
# Updated certificate endpoints for unified storage

import datetime
import logging
import uuid
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, Form

from auth.models import User
from auth.dependencies import get_current_active_user
from middleware.session_middleware import get_session_id
from certificates.storage import CertificateStorage
from certificates.analyzer import analyze_uploaded_certificate
from certificates.models.certificate import storage_to_api_model

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/analyze-certificate", tags=["certificates"], status_code=201)
async def analyze_certificate(
    certificate: UploadFile = File(...),
    password: str = Form(None),
    session_id: str = Depends(get_session_id)
):
    """Analyze uploaded certificate file with unified storage"""
    
    try:
        file_content = await certificate.read()
        logger.info(f"[{session_id}] Analyzing certificate: {certificate.filename}")
        
        # Analyze the certificate - returns certificate ID
        cert_id = analyze_uploaded_certificate(
            file_content, 
            certificate.filename or "unknown", 
            password,
            session_id
        )
        
        # Get the stored certificate data
        cert_model = CertificateStorage.get_by_id(cert_id, session_id)
        
        if not cert_model:
            logger.error(f"[{session_id}] Certificate {cert_id} not found after storage")
            raise HTTPException(
                status_code=500,
                detail="Certificate analysis failed - storage error"
            )
        
        # Check if password is required
        if cert_model.requires_password and not password:
            logger.info(f"[{session_id}] Password required for '{certificate.filename}'")
            return {
                "success": False,
                "requiresPassword": True,
                "certificate": cert_model,
                "message": f"Password required for {certificate.filename}",
                "errors": []
            }
        
        # Check if certificate is valid
        if not cert_model.is_valid:
            logger.warning(f"[{session_id}] Invalid certificate: {certificate.filename}")
            logger.warning(f"[{session_id}] Validation errors: {cert_model.validation_errors}")
            
            return {
                "success": False,
                "requiresPassword": False,
                "certificate": cert_model,
                "message": f"Certificate analysis failed for {certificate.filename}",
                "errors": cert_model.validation_errors
            }
        
        logger.info(f"[{session_id}] Successfully analyzed: {certificate.filename}")
        
        return {
            "success": True,
            "requiresPassword": False,
            "certificate": cert_model,
            "message": f"Certificate '{certificate.filename}' analyzed successfully",
            "errors": []
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Certificate analysis error: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Certificate analysis failed: {str(e)}"
        )

@router.get("/api/certificates", tags=["certificates"])
def get_certificates(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Get all stored certificates from unified storage"""
    logger.info(f"[{session_id}] User '{current_user.username}' retrieving certificates")
    
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

@router.get("/certificates", tags=["certificates"])
def get_certificates_simple(session_id: str = Depends(get_session_id)):
    """Get all stored certificates - simple endpoint"""
    logger.info(f"[{session_id}] Retrieving certificates (simple)")
    
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

@router.get("/validate", tags=["validation"])
def validate_certificates_simple(session_id: str = Depends(get_session_id)):
    """Run validation checks on uploaded certificates using unified storage"""
    logger.info(f"[{session_id}] Starting certificate validation")
    
    from certificates.validation.validator import run_validations
    
    try:
        certificates = CertificateStorage.get_all(session_id)
        logger.info(f"[{session_id}] Running validations on {len(certificates)} certificates")
        
        if not certificates:
            return {
                "success": True,
                "validations": [],
                "count": 0,
                "timestamp": datetime.datetime.now().isoformat(),
                "session_id": session_id,
                "message": "No certificates to validate"
            }
        
        # Run validations with unified storage
        validations = run_validations(certificates, session_id)
        
        # Convert to dictionary format
        validation_dicts = []
        for validation in validations:
            validation_dict = validation.to_dict()
            validation_dicts.append(validation_dict)
        
        passed_count = sum(1 for v in validations if v.is_valid)
        failed_count = len(validations) - passed_count
        logger.info(f"[{session_id}] Validation complete: {passed_count} passed, {failed_count} failed ({len(validations)} total)")

        return {
            "success": True,
            "validations": validation_dicts,
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

@router.post("/api/certificates/validate", tags=["certificates"])
def validate_certificates(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Run validation checks on stored certificates using unified storage"""
    logger.info(f"[{session_id}] User '{current_user.username}' starting certificate validation")

    from certificates.validation.validator import run_validations
    
    try:
        all_certificates = CertificateStorage.get_all(session_id)
        
        if not all_certificates:
            return {
                "success": False,
                "message": "No certificates found to validate",
                "validations": [],
                "session_id": session_id
            }
        
        # Run validations directly on unified certificate models
        validations = run_validations(all_certificates, session_id)
        
        logger.debug(f"[{session_id}] Validation completed: {len(validations)} results for user {current_user.username}")
        
        # Convert to dict format for API response
        validation_dicts = []
        for validation in validations:
            validation_dict = validation.to_dict()
            validation_dicts.append(validation_dict)
        
        passed_count = sum(1 for v in validations if v.is_valid)
        failed_count = len(validations) - passed_count
        logger.info(f"[{session_id}] Validation complete for user '{current_user.username}': {passed_count} passed, {failed_count} failed")

        return {
            "success": True,
            "validations": validation_dicts,
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

@router.delete("/api/certificates/{cert_id}", tags=["certificates"])
def delete_certificate(
    cert_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Delete a certificate from unified storage"""
    logger.info(f"[{session_id}] User '{current_user.username}' deleting certificate {cert_id}")
    
    try:
        # Check if certificate exists
        cert = CertificateStorage.get_by_id(cert_id, session_id)
        if not cert:
            raise HTTPException(
                status_code=404,
                detail=f"Certificate {cert_id} not found"
            )
        
        # Remove from unified storage
        success = CertificateStorage.remove(cert_id, session_id)
        
        if success:
            logger.info(f"[{session_id}] Successfully deleted certificate {cert_id} for user {current_user.username}")
            return {
                "success": True,
                "message": f"Certificate {cert.filename} deleted successfully",
                "cert_id": cert_id
            }
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to delete certificate {cert_id}"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Certificate deletion error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete certificate: {str(e)}"
        )

@router.post("/api/certificates/clear", tags=["certificates"])
def clear_certificates(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Clear all certificates from unified storage"""
    logger.info(f"[{session_id}] User '{current_user.username}' clearing all certificates")
    
    try:
        CertificateStorage.clear_session(session_id)
        logger.info(f"[{session_id}] Successfully cleared all certificates for user {current_user.username}")
        
        return {
            "success": True,
            "message": "All certificates cleared successfully",
            "session_id": session_id
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] Certificate clearing error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to clear certificates: {str(e)}"
        )

@router.get("/api/certificates/session-summary", tags=["certificates"])
def get_session_summary(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Get session summary from unified storage"""
    logger.info(f"[{session_id}] User '{current_user.username}' requesting session summary")
    
    try:
        summary = CertificateStorage.get_session_summary(session_id)
        logger.debug(f"[{session_id}] Session summary retrieved for user {current_user.username}")
        
        return {
            "success": True,
            "summary": summary,
            "timestamp": datetime.datetime.now().isoformat(),
            "session_id": session_id
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] Session summary error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get session summary: {str(e)}"
        )