# backend-fastapi/certificates/storage/certificate_storage.py
# Clean certificate storage interface - unified storage only

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from .unified_storage import unified_storage, UnifiedCertificateData
from ..models.certificate import storage_to_api_model, UnifiedCertificateModel

logger = logging.getLogger(__name__)

class CertificateStorage:
    """Clean certificate storage interface using unified storage"""
    
    @staticmethod
    def _validate_session_id(session_id: str):
        """Validate session ID parameter"""
        if not session_id or not isinstance(session_id, str):
            raise ValueError("Invalid session_id provided")
    
    @staticmethod
    def get_all(session_id: str) -> List[UnifiedCertificateModel]:
        """Get all certificates for session as unified models"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.debug(f"[{session_id}] Getting all certificates from unified storage")
        
        # Get unified certificate data
        unified_certs = unified_storage.get_all_certificates(session_id)
        
        # Convert to API models
        api_models = [storage_to_api_model(cert) for cert in unified_certs]
        
        # Sort by PKI hierarchy
        sorted_models = sorted(api_models, key=lambda cert: (
            CertificateStorage._get_certificate_order(cert),
            cert.filename
        ))
        
        logger.debug(f"[{session_id}] Returning {len(sorted_models)} certificates")
        return sorted_models
    
    @staticmethod
    def store(unified_cert: UnifiedCertificateData, session_id: str) -> str:
        """Store unified certificate data"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.debug(f"[{session_id}] Storing certificate: {unified_cert.filename}")
        return unified_storage.store_certificate(unified_cert, session_id)
    
    @staticmethod
    def get_by_id(cert_id: str, session_id: str) -> Optional[UnifiedCertificateModel]:
        """Get certificate by ID as unified model"""
        CertificateStorage._validate_session_id(session_id)
        
        unified_cert = unified_storage.get_certificate(cert_id, session_id)
        if not unified_cert:
            return None
        
        return storage_to_api_model(unified_cert)
    
    @staticmethod
    def get_unified_by_id(cert_id: str, session_id: str) -> Optional[UnifiedCertificateData]:
        """Get raw unified certificate data by ID"""
        CertificateStorage._validate_session_id(session_id)
        return unified_storage.get_certificate(cert_id, session_id)
    
    @staticmethod
    def remove(cert_id: str, session_id: str) -> bool:
        """Remove certificate by ID"""
        CertificateStorage._validate_session_id(session_id)
        return unified_storage.remove_certificate(cert_id, session_id)
    
    @staticmethod
    def clear_session(session_id: str):
        """Clear all certificates for session"""
        CertificateStorage._validate_session_id(session_id)
        unified_storage.clear_session(session_id)
    
    @staticmethod
    def get_session_summary(session_id: str) -> Dict[str, Any]:
        """Get session summary"""
        CertificateStorage._validate_session_id(session_id)
        return unified_storage.get_session_summary(session_id)
    
    @staticmethod
    def _get_certificate_order(cert: UnifiedCertificateModel) -> int:
        """Get certificate order for PKI hierarchy sorting"""
        
        # PKCS12/PKCS7 bundles first
        if cert.original_format in ['PKCS12', 'PKCS7']:
            return 0
        
        # CA certificates
        if cert.certificate_info and cert.certificate_info.is_ca:
            return 1
        
        # Certificate chains (multiple certificates)
        if cert.additional_certs_count > 0:
            return 2
        
        # End entity certificates
        if cert.has_certificate:
            return 3
        
        # Private keys
        if cert.has_private_key:
            return 4
        
        # CSRs last
        if cert.has_csr:
            return 5
        
        return 6  # Unknown types

# Export for clean interface
__all__ = ['CertificateStorage']