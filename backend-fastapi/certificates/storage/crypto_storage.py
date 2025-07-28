# backend-fastapi/certificates/storage/crypto_storage.py
# Session-aware cryptographic objects storage system - FIXED SIGNATURES

import logging
from typing import Dict, Any, List
from session_manager import SessionManager

logger = logging.getLogger(__name__)

class CryptoObjectsStorage:
    """Session-aware cryptographic objects storage"""
    
    @staticmethod
    def _validate_session_and_cert_id(session_id: str, cert_id: str):
        """Validate session_id and cert_id parameters"""
        if not session_id or not isinstance(session_id, str):
            raise ValueError("Invalid session_id provided")
        if not cert_id or not isinstance(cert_id, str):
            raise ValueError("Invalid cert_id provided")
    
    @staticmethod
    def store_crypto_objects(cert_id: str, crypto_objects: Dict[str, Any], session_id: str):
        """Store cryptographic objects for specific session
        
        Args:
            cert_id: Unique certificate identifier
            crypto_objects: Dictionary containing crypto objects:
                - private_key: RSA/ECDSA private key object
                - certificate: X.509 certificate object  
                - csr: Certificate signing request object
                - additional_certificates: List of CA certificates from PKCS#12
            session_id: Session identifier for isolation
        """
        CryptoObjectsStorage._validate_session_and_cert_id(session_id, cert_id)
        
        # Get or create session data
        session_data = SessionManager.get_or_create_session(session_id)
        
        # Initialize crypto_objects storage if not exists
        if "crypto_objects" not in session_data:
            session_data["crypto_objects"] = {}
        
        # Store crypto objects for this certificate
        session_data["crypto_objects"][cert_id] = crypto_objects
        
        # Log crypto object types (never log the actual objects for security)
        object_types = list(crypto_objects.keys())
        logger.debug(f"[{session_id}] Stored crypto objects for {cert_id}: {object_types}")
        logger.info(f"[{session_id}] Crypto objects stored for certificate {cert_id}")
    
    @staticmethod
    def get_crypto_objects(cert_id: str, session_id: str) -> Dict[str, Any]:
        """Retrieve cryptographic objects from specific session
        
        Args:
            cert_id: Certificate identifier
            session_id: Session identifier
            
        Returns:
            Dictionary of crypto objects for the certificate in this session
        """
        CryptoObjectsStorage._validate_session_and_cert_id(session_id, cert_id)
        
        # Get session data
        session_data = SessionManager.get_or_create_session(session_id)
        crypto_storage = session_data.get("crypto_objects", {})
        
        # Retrieve crypto objects for this certificate
        crypto_objects = crypto_storage.get(cert_id, {})
        
        if crypto_objects:
            object_types = list(crypto_objects.keys())
            logger.debug(f"[{session_id}] Retrieved crypto objects for {cert_id}: {object_types}")
        else:
            logger.debug(f"[{session_id}] No crypto objects found for {cert_id}")
        
        return crypto_objects
    
    @staticmethod
    def get_crypto_objects_count(session_id: str) -> int:
        """Get count of crypto objects in session
        
        Args:
            session_id: Session identifier
            
        Returns:
            Number of certificates with stored crypto objects in this session
        """
        if not session_id or not isinstance(session_id, str):
            raise ValueError("Invalid session_id provided")
        
        session_data = SessionManager.get_or_create_session(session_id)
        crypto_storage = session_data.get("crypto_objects", {})
        count = len(crypto_storage)
        
        logger.debug(f"[{session_id}] Total crypto objects count: {count}")
        return count
    
    @staticmethod
    def clear_crypto_objects(session_id: str):
        """Clear all crypto objects for session
        
        Args:
            session_id: Session identifier
        """
        if not session_id or not isinstance(session_id, str):
            raise ValueError("Invalid session_id provided")
        
        session_data = SessionManager.get_or_create_session(session_id)
        
        # Get count before clearing for logging
        crypto_storage = session_data.get("crypto_objects", {})
        count = len(crypto_storage)
        
        # Clear all crypto objects
        session_data["crypto_objects"] = {}
        
        logger.info(f"[{session_id}] Cleared {count} crypto objects from session")
    
    @staticmethod
    def remove_crypto_objects(cert_id: str, session_id: str) -> bool:
        """Remove crypto objects for specific certificate in session
        
        Args:
            cert_id: Certificate identifier
            session_id: Session identifier
            
        Returns:
            True if crypto objects were removed, False if not found
        """
        CryptoObjectsStorage._validate_session_and_cert_id(session_id, cert_id)
        
        session_data = SessionManager.get_or_create_session(session_id)
        crypto_storage = session_data.get("crypto_objects", {})
        
        if cert_id in crypto_storage:
            # Log object types before removal (for debugging)
            object_types = list(crypto_storage[cert_id].keys())
            
            # Remove crypto objects
            del crypto_storage[cert_id]
            
            logger.info(f"[{session_id}] Removed crypto objects for {cert_id}: {object_types}")
            return True
        else:
            logger.debug(f"[{session_id}] No crypto objects found to remove for {cert_id}")
            return False
    
    @staticmethod
    def debug_crypto_objects(session_id: str) -> Dict[str, Any]:
        """Debug info for crypto objects in session
        
        Args:
            session_id: Session identifier
            
        Returns:
            Debug information about stored crypto objects (no sensitive data)
        """
        if not session_id or not isinstance(session_id, str):
            raise ValueError("Invalid session_id provided")
        
        session_data = SessionManager.get_or_create_session(session_id)
        crypto_storage = session_data.get("crypto_objects", {})
        
        debug_info = {}
        for cert_id, crypto_objs in crypto_storage.items():
            debug_info[cert_id] = {
                "object_types": list(crypto_objs.keys()),
                "object_count": len(crypto_objs),
                "has_private_key": "private_key" in crypto_objs,
                "has_certificate": "certificate" in crypto_objs,
                "has_csr": "csr" in crypto_objs,
                "additional_certs_count": len(crypto_objs.get("additional_certificates", []))
            }
        
        logger.debug(f"[{session_id}] Crypto objects debug info: {len(debug_info)} certificates with crypto objects")
        return debug_info
    
    @staticmethod
    def has_crypto_objects(cert_id: str, session_id: str) -> bool:
        """Check if crypto objects exist for certificate in session
        
        Args:
            cert_id: Certificate identifier
            session_id: Session identifier
            
        Returns:
            True if crypto objects exist for this certificate in session
        """
        CryptoObjectsStorage._validate_session_and_cert_id(session_id, cert_id)
        
        session_data = SessionManager.get_or_create_session(session_id)
        crypto_storage = session_data.get("crypto_objects", {})
        
        exists = cert_id in crypto_storage and len(crypto_storage[cert_id]) > 0
        logger.debug(f"[{session_id}] Crypto objects exist for {cert_id}: {exists}")
        
        return exists
    
    @staticmethod
    def get_crypto_object_types(cert_id: str, session_id: str) -> List[str]:
        """Get list of crypto object types for certificate in session
        
        Args:
            cert_id: Certificate identifier
            session_id: Session identifier
            
        Returns:
            List of crypto object types (e.g., ['private_key', 'certificate'])
        """
        CryptoObjectsStorage._validate_session_and_cert_id(session_id, cert_id)
        
        crypto_objects = CryptoObjectsStorage.get_crypto_objects(cert_id, session_id)
        object_types = list(crypto_objects.keys())
        
        logger.debug(f"[{session_id}] Crypto object types for {cert_id}: {object_types}")
        return object_types
    
    @staticmethod
    def get_session_crypto_summary(session_id: str) -> Dict[str, Any]:
        """Get summary of all crypto objects in session
        
        Args:
            session_id: Session identifier
            
        Returns:
            Summary of crypto objects in session
        """
        if not session_id or not isinstance(session_id, str):
            raise ValueError("Invalid session_id provided")
        
        session_data = SessionManager.get_or_create_session(session_id)
        crypto_storage = session_data.get("crypto_objects", {})
        
        summary = {
            "total_certificates": len(crypto_storage),
            "certificates_with_private_keys": 0,
            "certificates_with_csrs": 0,
            "total_additional_certificates": 0,
            "session_id": session_id
        }
        
        for cert_id, crypto_objs in crypto_storage.items():
            if "private_key" in crypto_objs:
                summary["certificates_with_private_keys"] += 1
            if "csr" in crypto_objs:
                summary["certificates_with_csrs"] += 1
            if "additional_certificates" in crypto_objs:
                summary["total_additional_certificates"] += len(crypto_objs["additional_certificates"])
        
        logger.debug(f"[{session_id}] Crypto storage summary: {summary}")
        return summary


# Backward compatibility aliases - FIXED to require session_id
class CertificateStorage:
    """Legacy compatibility - delegates to session-aware storage"""
    
    @staticmethod
    def store_crypto_objects(cert_id: str, crypto_objects: Dict[str, Any], session_id: str):
        """Legacy method - now properly requires session_id"""
        return CryptoObjectsStorage.store_crypto_objects(cert_id, crypto_objects, session_id)
    
    @staticmethod
    def get_crypto_objects(cert_id: str, session_id: str) -> Dict[str, Any]:
        """Legacy method - now properly requires session_id"""
        return CryptoObjectsStorage.get_crypto_objects(cert_id, session_id)