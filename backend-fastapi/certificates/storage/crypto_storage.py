# backend-fastapi/certificates/storage/crypto_storage.py
# Cryptographic objects storage - separate from JSON data

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Separate storage for crypto objects (not serialized to JSON)
crypto_objects_storage: Dict[str, Dict[str, Any]] = {}

class CryptoObjectsStorage:
    """Manages cryptographic objects separately from certificate data"""
    
    @staticmethod
    def store_crypto_objects(cert_id: str, crypto_objects: Dict[str, Any]):
        """Store cryptographic objects separately (not serialized to JSON)"""
        global crypto_objects_storage
        crypto_objects_storage[cert_id] = crypto_objects
        logger.debug(f"Stored crypto objects for cert {cert_id}: {list(crypto_objects.keys())}")
    
    @staticmethod
    def get_crypto_objects(cert_id: str) -> Dict[str, Any]:
        """Retrieve cryptographic objects for validation"""
        return crypto_objects_storage.get(cert_id, {})
    
    @staticmethod
    def remove_crypto_objects(cert_id: str):
        """Remove crypto objects when certificate is deleted"""
        global crypto_objects_storage
        if cert_id in crypto_objects_storage:
            del crypto_objects_storage[cert_id]
            logger.debug(f"Removed crypto objects for cert {cert_id}")
    
    @staticmethod
    def clear_all_crypto_objects():
        """Clear all crypto objects"""
        global crypto_objects_storage
        crypto_objects_storage = {}
        logger.debug("Cleared all crypto objects")
    
    @staticmethod
    def get_crypto_objects_count() -> int:
        """Get count of stored crypto objects"""
        return len(crypto_objects_storage)
    
    @staticmethod
    def debug_crypto_objects():
        """Debug helper for crypto objects storage"""
        logger.info(f"=== CRYPTO OBJECTS DEBUG ===")
        logger.info(f"Total crypto objects stored: {len(crypto_objects_storage)}")
        
        # Import here to avoid circular import
        from .core import CertificateStorage
        
        for cert_id, crypto_objects in crypto_objects_storage.items():
            # Find corresponding certificate
            cert = CertificateStorage.find_by_id(cert_id)
            filename = cert.get('filename', 'UNKNOWN') if cert else 'NOT_FOUND'
            
            logger.info(f"  Certificate ID: {cert_id}")
            logger.info(f"  Filename: {filename}")
            logger.info(f"  Crypto objects: {list(crypto_objects.keys())}")
            
            for obj_type, obj in crypto_objects.items():
                logger.debug(f"    {obj_type}: {type(obj).__name__}")
        
        logger.info(f"=== END CRYPTO OBJECTS DEBUG ===")