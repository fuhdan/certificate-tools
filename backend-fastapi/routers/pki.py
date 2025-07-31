# backend-fastapi/routers/pki.py
# Updated PKI bundle generation for session-based storage

import logging
import datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from ..auth.models import User
from ..auth.dependencies import get_current_active_user
from ..middleware.session_middleware import get_session_id
from ..certificates.storage.session_pki_storage import session_pki_storage, PKIComponentType

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/pki-bundle", tags=["pki"])
def get_pki_bundle(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Generate complete PKI bundle from session components"""
    
    logger.info(f"[{session_id}] Admin {current_user.username} requesting PKI bundle")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        
        if not session.components:
            raise HTTPException(
                status_code=404,
                detail="No PKI components found. Upload certificates to generate a bundle."
            )
        
        # Get components in order
        ordered_components = session.get_ordered_components()
        
        # Build PKI bundle
        bundle = {
            "version": "2.0",
            "generated": datetime.datetime.now().isoformat(),
            "description": "Complete PKI Bundle with Session-Based Components",
            "session_id": session_id,
            "components": []
        }
        
        # Add each component to bundle
        for component in ordered_components:
            bundle_component = {
                "componentId": component.id,
                "fileType": component.type.type_name,
                "order": component.order,
                "file": component.content,
                "details": {
                    "name": f"{component.filename}_{component.type.type_name.lower()}",
                    "originalFilename": component.filename,
                    "uploadedAt": component.uploaded_at,
                    "format": "PEM",
                    "isValid": True,
                    "componentType": component.type.type_name,
                    "metadata": component.metadata
                }
            }
            bundle["components"].append(bundle_component)
        
        # Add bundle statistics
        component_counts = {}
        for component in ordered_components:
            type_name = component.type.type_name
            component_counts[type_name] = component_counts.get(type_name, 0) + 1
        
        bundle["statistics"] = {
            "total_components": len(ordered_components),
            "component_counts": component_counts,
            "session_created": session.created_at,
            "session_updated": session.last_updated
        }
        
        logger.info(f"[{session_id}] PKI bundle generated with {len(ordered_components)} components for admin {current_user.username}")
        
        return JSONResponse(
            content={
                "success": True,
                "bundle": bundle,
                "timestamp": datetime.datetime.now().isoformat()
            },
            headers={
                "Content-Disposition": f"attachment; filename=pki-bundle-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] PKI bundle generation error for admin {current_user.username}: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PKI bundle: {str(e)}"
        )

@router.get("/pki-bundle/validation", tags=["pki"])
def validate_pki_bundle(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Validate PKI bundle completeness and relationships"""
    
    logger.info(f"[{session_id}] Admin {current_user.username} requesting PKI validation")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        
        validation_result = {
            "session_id": session_id,
            "is_valid": False,
            "is_complete": False,
            "components": {},
            "relationships": {},
            "issues": [],
            "recommendations": []
        }
        
        # Check component availability
        component_types = {}
        for component in session.components.values():
            type_name = component.type.type_name
            component_types[type_name] = component_types.get(type_name, 0) + 1
        
        validation_result["components"] = component_types
        
        # Validate component relationships
        has_private_key = PKIComponentType.PRIVATE_KEY.type_name in component_types
        has_certificate = PKIComponentType.CERTIFICATE.type_name in component_types
        has_csr = PKIComponentType.CSR.type_name in component_types
        has_issuing_ca = PKIComponentType.ISSUING_CA.type_name in component_types
        has_intermediate_ca = PKIComponentType.INTERMEDIATE_CA.type_name in component_types
        has_root_ca = PKIComponentType.ROOT_CA.type_name in component_types
        
        # Check for complete certificate chain
        has_ca_chain = has_issuing_ca or has_intermediate_ca or has_root_ca
        is_complete = has_certificate and has_ca_chain
        
        validation_result["is_complete"] = is_complete
        
        # Validate key-certificate matching
        if has_private_key and has_certificate:
            key_cert_match = _validate_key_certificate_match(session)
            validation_result["relationships"]["private_key_certificate_match"] = key_cert_match
            if not key_cert_match:
                validation_result["issues"].append("Private key does not match certificate")
        
        # Validate certificate chain
        if has_certificate and has_ca_chain:
            chain_valid = _validate_certificate_chain(session)
            validation_result["relationships"]["certificate_chain_valid"] = chain_valid
            if not chain_valid:
                validation_result["issues"].append("Certificate chain validation failed")
        
        # Validate CSR-certificate relationship
        if has_csr and has_certificate:
            csr_cert_match = _validate_csr_certificate_match(session)
            validation_result["relationships"]["csr_certificate_match"] = csr_cert_match
            if not csr_cert_match:
                validation_result["issues"].append("CSR does not match issued certificate")
        
        # Generate recommendations
        if not has_private_key:
            validation_result["recommendations"].append("Upload private key to enable PKCS#12 bundle creation")
        if not has_certificate:
            validation_result["recommendations"].append("Upload end-entity certificate")
        if not has_ca_chain:
            validation_result["recommendations"].append("Upload certificate authority chain for complete PKI")
        if has_certificate and not has_ca_chain:
            validation_result["recommendations"].append("Upload issuing CA certificate to validate certificate chain")
        
        # Overall validation status
        validation_result["is_valid"] = len(validation_result["issues"]) == 0
        
        logger.info(f"[{session_id}] PKI validation complete: valid={validation_result['is_valid']}, complete={validation_result['is_complete']}")
        
        return {
            "success": True,
            "validation": validation_result,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"[{session_id}] PKI validation error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to validate PKI bundle: {str(e)}"
        )

@router.post("/pki-bundle/download/{bundle_type}", tags=["pki"])
def download_pki_bundle(
    bundle_type: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Download PKI bundle in specific format (p12, pem, etc.)"""
    
    logger.info(f"[{session_id}] Admin {current_user.username} downloading {bundle_type} bundle")
    
    try:
        session = session_pki_storage.get_or_create_session(session_id)
        
        if not session.components:
            raise HTTPException(
                status_code=404,
                detail="No PKI components found"
            )
        
        if bundle_type == "p12":
            return _create_p12_bundle(session, session_id)
        elif bundle_type == "pem":
            return _create_pem_bundle(session, session_id)
        elif bundle_type == "chain":
            return _create_chain_bundle(session, session_id)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported bundle type: {bundle_type}"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{session_id}] Bundle download error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create {bundle_type} bundle: {str(e)}"
        )

def _validate_key_certificate_match(session) -> bool:
    """Validate that private key matches certificate"""
    try:
        # Get private key and certificate components
        private_key_comp = None
        certificate_comp = None
        
        for component in session.components.values():
            if component.type == PKIComponentType.PRIVATE_KEY:
                private_key_comp = component
            elif component.type == PKIComponentType.CERTIFICATE:
                certificate_comp = component
        
        if not (private_key_comp and certificate_comp):
            return False
        
        # Compare public key fingerprints
        key_fingerprint = private_key_comp.metadata.get('public_key_fingerprint')
        cert_metadata = certificate_comp.metadata
        
        # For certificate, we need to extract the public key fingerprint
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization, hashes
        import hashlib
        
        cert = x509.load_pem_x509_certificate(certificate_comp.content.encode())
        public_key = cert.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_key_fingerprint = hashlib.sha256(public_bytes).hexdigest().upper()
        
        return key_fingerprint == cert_key_fingerprint
        
    except Exception as e:
        logger.error(f"Key-certificate validation error: {e}")
        return False

def _validate_certificate_chain(session) -> bool:
    """Validate certificate chain integrity"""
    try:
        # Basic validation - check if we have certificate and CA
        has_cert = any(c.type == PKIComponentType.CERTIFICATE for c in session.components.values())
        has_ca = any(c.type in [PKIComponentType.ISSUING_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ROOT_CA] 
                    for c in session.components.values())
        
        return has_cert and has_ca
        
    except Exception as e:
        logger.error(f"Certificate chain validation error: {e}")
        return False

def _validate_csr_certificate_match(session) -> bool:
    """Validate that CSR matches issued certificate"""
    try:
        # Get CSR and certificate components
        csr_comp = None
        certificate_comp = None
        
        for component in session.components.values():
            if component.type == PKIComponentType.CSR:
                csr_comp = component
            elif component.type == PKIComponentType.CERTIFICATE:
                certificate_comp = component
        
        if not (csr_comp and certificate_comp):
            return False
        
        # Compare public key fingerprints
        csr_fingerprint = csr_comp.metadata.get('public_key_fingerprint')
        
        # Extract certificate public key fingerprint
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        import hashlib
        
        cert = x509.load_pem_x509_certificate(certificate_comp.content.encode())
        public_key = cert.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_key_fingerprint = hashlib.sha256(public_bytes).hexdigest().upper()
        
        return csr_fingerprint == cert_key_fingerprint
        
    except Exception as e:
        logger.error(f"CSR-certificate validation error: {e}")
        return False

def _create_p12_bundle(session, session_id: str):
    """Create PKCS#12 bundle from session components"""
    # Implementation for PKCS#12 bundle creation
    # This would create a binary PKCS#12 file from the PEM components
    raise HTTPException(status_code=501, detail="PKCS#12 bundle creation not yet implemented")

def _create_pem_bundle(session, session_id: str):
    """Create PEM bundle from session components"""
    # Implementation for PEM bundle creation
    # This would concatenate all PEM components
    raise HTTPException(status_code=501, detail="PEM bundle creation not yet implemented")

def _create_chain_bundle(session, session_id: str):
    """Create certificate chain bundle from session components"""
    # Implementation for certificate chain bundle creation
    # This would create a chain of certificates only
    raise HTTPException(status_code=501, detail="Chain bundle creation not yet implemented")