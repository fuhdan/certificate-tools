# certificates/storage.py
# NEW - MERGE NEEDED
# In-memory storage for certificates (replace with your SQLite implementation later)

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# In-memory storage
uploaded_certificates: List[Dict[str, Any]] = []

class CertificateStorage:
    """Simple in-memory certificate storage"""
    
    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """Get all certificates"""
        return uploaded_certificates
    
    @staticmethod
    def add(certificate_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add certificate to storage"""
        uploaded_certificates.append(certificate_data)
        logger.info(f"Added certificate: {certificate_data.get('filename')}")
        return certificate_data
    
    @staticmethod
    def find_by_hash(content_hash: str) -> Optional[Dict[str, Any]]:
        """Find certificate by content hash (normalized for duplicate detection)"""
        for cert in uploaded_certificates:
            if cert.get('analysis', {}).get('content_hash') == content_hash:
                return cert
        return None
    
    @staticmethod
    def find_by_id(cert_id: str) -> Optional[Dict[str, Any]]:
        """Find certificate by ID"""
        for cert in uploaded_certificates:
            if cert.get('id') == cert_id:
                return cert
        return None
    
    @staticmethod
    def remove_by_id(cert_id: str) -> bool:
        """Remove certificate by ID"""
        global uploaded_certificates
        initial_count = len(uploaded_certificates)
        uploaded_certificates = [cert for cert in uploaded_certificates if cert.get('id') != cert_id]
        success = len(uploaded_certificates) < initial_count
        if success:
            logger.info(f"Removed certificate with ID: {cert_id}")
        return success
    
    @staticmethod
    def clear_all() -> bool:
        """Clear all certificates"""
        global uploaded_certificates
        count = len(uploaded_certificates)
        uploaded_certificates = []
        logger.info(f"Cleared all {count} certificates")
        return True
    
    @staticmethod
    def replace(existing_cert: Dict[str, Any], new_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Replace existing certificate"""
        for i, cert in enumerate(uploaded_certificates):
            if cert.get('id') == existing_cert.get('id'):
                uploaded_certificates[i] = new_cert
                logger.info(f"Replaced certificate: {existing_cert.get('filename')} -> {new_cert.get('filename')}")
                return new_cert
        # If not found, just add it
        uploaded_certificates.append(new_cert)
        return new_cert
    
    @staticmethod
    def count() -> int:
        """Get count of certificates"""
        return len(uploaded_certificates)
    
    @staticmethod
    def get_summary() -> Dict[str, Any]:
        """Get storage summary"""
        total = len(uploaded_certificates)
        valid_count = sum(1 for cert in uploaded_certificates 
                         if cert.get('analysis', {}).get('isValid', False))
        
        types = {}
        for cert in uploaded_certificates:
            cert_type = cert.get('analysis', {}).get('type', 'Unknown')
            types[cert_type] = types.get(cert_type, 0) + 1
        
        return {
            "total": total,
            "valid": valid_count,
            "invalid": total - valid_count,
            "types": types
        }