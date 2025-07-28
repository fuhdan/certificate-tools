# backend-fastapi/certificates/storage/core.py
# Core storage functionality - main operations with session support

import logging
from typing import Dict, Any, List, Optional

from config import settings
from .crypto_storage import CryptoObjectsStorage
from .hierarchy import HierarchyManager
from .pki_bundle import PKIBundleManager
from .utils import StorageUtils

logger = logging.getLogger(__name__)

class CertificateStorage:
    """Main certificate storage class with session-aware modular components"""
    
    @staticmethod
    def _validate_session_id(session_id: str):
        """Validate session ID parameter"""
        if not session_id or not isinstance(session_id, str):
            raise ValueError("Invalid session_id provided")
    
    @staticmethod
    def get_all(session_id: str) -> List[Dict[str, Any]]:
        """Get all certificates for specific session sorted by PKI hierarchy"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.debug(f"=== STORAGE GET_ALL OPERATION [{session_id}] ===")
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        logger.debug(f"[{session_id}] Storage.get_all() called - returning {len(certificates)} certificates")
        
        # Log current unsorted state
        logger.debug(f"[{session_id}] Current unsorted certificates:")
        for i, cert in enumerate(certificates):
            analysis = cert.get('analysis', {})
            order = HierarchyManager.get_certificate_order(cert)
            logger.debug(f"  [{i}] {cert.get('filename')} - order: {order} - type: {analysis.get('type')} - hash: {analysis.get('content_hash', 'NO_HASH')[:16]}...")
        
        # Sort certificates by PKI hierarchy order
        logger.debug(f"[{session_id}] Sorting certificates by PKI hierarchy...")
        sorted_certs = sorted(certificates, key=lambda cert: (
            HierarchyManager.get_certificate_order(cert),
            cert.get('filename', '')
        ))
        
        # Log sorted state
        logger.info(f"[{session_id}] Certificate hierarchy order after sorting:")
        for i, cert in enumerate(sorted_certs):
            order = HierarchyManager.get_certificate_order(cert)
            analysis = cert.get('analysis', {})
            logger.info(f"  [{i}] Order {order}: {cert.get('filename')} - {analysis.get('type')}")
        
        logger.debug(f"[{session_id}] Returning {len(sorted_certs)} sorted certificates")
        return sorted_certs
    
    @staticmethod
    def add(certificate_data: Dict[str, Any], session_id: str) -> Dict[str, Any]:
        """Add certificate with PKI hierarchy enforcement and auto PKI bundle generation"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.debug(f"=== STORAGE ADD WITH HIERARCHY ENFORCEMENT [{session_id}] ===")
        logger.debug(f"[{session_id}] Adding certificate: {certificate_data.get('filename')}")
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        
        # Initialize certificates list if it doesn't exist
        if "certificates" not in session_data:
            session_data["certificates"] = []
        certificates = session_data["certificates"]
        
        # Log certificate type and analysis
        analysis = certificate_data.get('analysis', {})
        logger.debug(f"[{session_id}] Certificate type: {analysis.get('type')}")
        logger.debug(f"[{session_id}] Certificate valid: {analysis.get('isValid')}")
        logger.debug(f"[{session_id}] Content hash: {analysis.get('content_hash', 'NO_HASH')[:16]}...")
        
        # Validate certificate data structure
        StorageUtils.validate_certificate_data(certificate_data)
        
        # Check if this certificate should replace an existing one
        logger.debug(f"[{session_id}] Checking if certificate should replace existing one...")
        existing_to_replace = HierarchyManager.should_replace_certificate(
            certificate_data, certificates
        )
        
        result = None
        if existing_to_replace:
            logger.info(f"[{session_id}] REPLACEMENT OPERATION: {existing_to_replace.get('filename')} -> {certificate_data.get('filename')}")
            result = CertificateStorage.replace(existing_to_replace, certificate_data, session_id)
            logger.info(f"[{session_id}] Certificate replacement completed successfully")
        else:
            # Add as new certificate
            logger.info(f"[{session_id}] ADDITION OPERATION: Adding new certificate {certificate_data.get('filename')}")
            initial_count = len(certificates)
            certificates.append(certificate_data)
            final_count = len(certificates)
            
            logger.info(f"[{session_id}] Certificate added successfully")
            logger.info(f"[{session_id}] Storage count: {initial_count} -> {final_count}")
            logger.debug(f"[{session_id}] Storage state after add:")
            StorageUtils.log_storage_state(certificates, session_id)
            result = certificate_data
        
        # Auto-generate PKI bundle for this session (FIXED: correct parameter order)
        session_certificates = CertificateStorage.get_all(session_id)
        PKIBundleManager.auto_generate_pki_bundle(session_id, session_certificates)
        
        return result
    
    @staticmethod
    def find_by_hash(content_hash: str, session_id: str) -> Optional[Dict[str, Any]]:
        """Find certificate by content hash within session"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.debug(f"=== STORAGE HASH LOOKUP [{session_id}] ===")
        logger.debug(f"[{session_id}] Searching for hash: {content_hash[:16]}...")
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        # Check each certificate's hash
        for i, cert in enumerate(certificates):
            cert_hash = cert.get('analysis', {}).get('content_hash')
            cert_filename = cert.get('filename', 'NO_FILENAME')
            logger.debug(f"  [{i}] {cert_filename} - hash: {cert_hash[:16] if cert_hash else 'NO_HASH'}...")
            
            if cert_hash == content_hash:
                logger.info(f"[{session_id}] HASH MATCH FOUND: {cert_filename}")
                logger.debug(f"[{session_id}] Matched certificate details:")
                logger.debug(f"  ID: {cert.get('id')}")
                logger.debug(f"  Filename: {cert.get('filename')}")
                logger.debug(f"  Type: {cert.get('analysis', {}).get('type')}")
                logger.debug(f"  Upload time: {cert.get('uploadedAt')}")
                return cert
        
        logger.debug(f"[{session_id}] No hash match found for: {content_hash[:16]}...")
        return None
    
    @staticmethod
    def find_by_id(cert_id: str, session_id: str) -> Optional[Dict[str, Any]]:
        """Find certificate by ID within session"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.debug(f"=== STORAGE ID LOOKUP [{session_id}] ===")
        logger.debug(f"[{session_id}] Searching for ID: {cert_id}")
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        for i, cert in enumerate(certificates):
            cert_id_stored = cert.get('id')
            cert_filename = cert.get('filename', 'NO_FILENAME')
            logger.debug(f"  [{i}] {cert_filename} - ID: {cert_id_stored}")
            
            if cert_id_stored == cert_id:
                logger.info(f"[{session_id}] ID MATCH FOUND: {cert_filename}")
                return cert
        
        logger.debug(f"[{session_id}] No ID match found for: {cert_id}")
        return None
    
    @staticmethod
    def remove_by_id(cert_id: str, session_id: str) -> bool:
        """Remove certificate by ID with crypto objects cleanup"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.info(f"=== STORAGE REMOVE OPERATION [{session_id}] ===")
        logger.info(f"[{session_id}] Removing certificate with ID: {cert_id}")
        
        # Remove crypto objects first (session-aware)
        CryptoObjectsStorage.remove_crypto_objects(cert_id, session_id)
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        initial_count = len(certificates)
        
        # Find the certificate to remove
        cert_to_remove = None
        for cert in certificates:
            if cert.get('id') == cert_id:
                cert_to_remove = cert
                break
        
        if cert_to_remove:
            logger.info(f"[{session_id}] Found certificate to remove: {cert_to_remove.get('filename')}")
            logger.debug(f"[{session_id}] Certificate details:")
            logger.debug(f"  Type: {cert_to_remove.get('analysis', {}).get('type')}")
            logger.debug(f"  Hash: {cert_to_remove.get('analysis', {}).get('content_hash', 'NO_HASH')[:16]}...")
        else:
            logger.warning(f"[{session_id}] Certificate with ID {cert_id} not found for removal")
        
        # Remove the certificate from session storage
        certificates[:] = [cert for cert in certificates if cert.get('id') != cert_id]
        final_count = len(certificates)
        success = final_count < initial_count
        
        logger.info(f"[{session_id}] Remove operation result: {'SUCCESS' if success else 'FAILED'}")
        logger.info(f"[{session_id}] Storage count: {initial_count} -> {final_count}")
        
        if success:
            logger.debug(f"[{session_id}] Storage state after removal:")
            StorageUtils.log_storage_state(certificates, session_id)
            # Auto-generate PKI bundle after removal (FIXED: correct parameter order)
            session_certificates = CertificateStorage.get_all(session_id)
            PKIBundleManager.auto_generate_pki_bundle(session_id, session_certificates)
        
        return success
    
    @staticmethod
    def remove(cert_id: str, session_id: str) -> bool:
        """Remove certificate from session storage (alias for remove_by_id)"""
        return CertificateStorage.remove_by_id(cert_id, session_id)
    
    @staticmethod
    def replace(existing_cert: Dict[str, Any], new_cert: Dict[str, Any], session_id: str) -> Dict[str, Any]:
        """Replace existing certificate with new one in session"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.info(f"=== STORAGE REPLACE OPERATION [{session_id}] ===")
        logger.info(f"[{session_id}] Replacing {existing_cert.get('filename')} with {new_cert.get('filename')}")
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        existing_hash = existing_cert.get('analysis', {}).get('content_hash', 'NO_HASH')
        new_hash = new_cert.get('analysis', {}).get('content_hash', 'NO_HASH')
        logger.debug(f"[{session_id}] Content hashes - OLD: {existing_hash[:16]}... NEW: {new_hash[:16]}...")
        
        # Remove crypto objects for the old certificate (session-aware)
        old_cert_id = existing_cert.get('id')
        if old_cert_id:
            CryptoObjectsStorage.remove_crypto_objects(old_cert_id, session_id)
        
        result = None
        # Find and replace the certificate
        for i, cert in enumerate(certificates):
            if cert.get('id') == existing_cert.get('id'):
                logger.info(f"[{session_id}] Found certificate to replace at index {i}")
                logger.debug(f"[{session_id}] Before replace - cert at [{i}]: {cert.get('filename')}")
                
                certificates[i] = new_cert
                
                logger.debug(f"[{session_id}] After replace - cert at [{i}]: {certificates[i].get('filename')}")
                logger.info(f"[{session_id}] Certificate replaced successfully")
                logger.debug(f"[{session_id}] Storage state after replace:")
                StorageUtils.log_storage_state(certificates, session_id)
                result = new_cert
                break
        
        if result is None:
            # If not found, just add it
            logger.warning(f"[{session_id}] Original certificate not found for replacement, adding as new")
            certificates.append(new_cert)
            logger.info(f"[{session_id}] Certificate added as new instead of replaced")
            result = new_cert
        
        # Auto-generate PKI bundle after replace operation (FIXED: correct parameter order)
        session_certificates = CertificateStorage.get_all(session_id)
        PKIBundleManager.auto_generate_pki_bundle(session_id, session_certificates)
        
        return result
    
    @staticmethod
    def clear_all(session_id: str) -> bool:
        """Clear all certificates, crypto objects, and PKI bundle for session"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.info(f"=== STORAGE CLEAR ALL OPERATION [{session_id}] ===")
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        count = len(certificates)
        
        logger.info(f"[{session_id}] Clearing {count} certificates from session storage")
        for i, cert in enumerate(certificates):
            logger.debug(f"  Clearing [{i}]: {cert.get('filename')} - {cert.get('analysis', {}).get('type')}")
            # Remove crypto objects for each certificate (session-aware)
            cert_id = cert.get('id')
            if cert_id:
                CryptoObjectsStorage.remove_crypto_objects(cert_id, session_id)
        
        # Clear certificates from session
        certificates.clear()
        
        # Clear PKI bundle (session-aware)
        PKIBundleManager.clear_pki_bundle(session_id)
        
        logger.info(f"[{session_id}] All certificates, crypto objects, and PKI bundle cleared successfully")
        logger.debug(f"[{session_id}] Session storage is now empty: {len(certificates)} certificates")
        return True
    
    @staticmethod
    def count(session_id: str) -> int:
        """Get count of certificates in session"""
        CertificateStorage._validate_session_id(session_id)
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        count = len(certificates)
        logger.debug(f"[{session_id}] Storage count requested: {count} certificates")
        return count
    
    @staticmethod
    def get_summary(session_id: str) -> Dict[str, Any]:
        """Get storage summary for session"""
        CertificateStorage._validate_session_id(session_id)
        
        logger.debug(f"=== STORAGE SUMMARY GENERATION [{session_id}] ===")
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        total = len(certificates)
        valid_count = sum(1 for cert in certificates 
                         if cert.get('analysis', {}).get('isValid', False))
        
        types = {}
        orders = {}
        for cert in certificates:
            cert_type = cert.get('analysis', {}).get('type', 'Unknown')
            cert_order = HierarchyManager.get_certificate_order(cert)
            
            types[cert_type] = types.get(cert_type, 0) + 1
            orders[cert_order] = orders.get(cert_order, 0) + 1
        
        # Add crypto objects info (session-aware)
        crypto_count = CryptoObjectsStorage.get_crypto_objects_count(session_id)
        
        summary = {
            "total": total,
            "valid": valid_count,
            "invalid": total - valid_count,
            "types": types,
            "hierarchy_orders": orders,
            "crypto_objects_stored": crypto_count,
            "has_pki_bundle": PKIBundleManager.has_pki_bundle(session_id),
            "session_id": session_id
        }
        
        logger.debug(f"[{session_id}] Storage summary: {summary}")
        return summary
    
    @staticmethod
    def store_crypto_objects(cert_id: str, crypto_objects: Dict[str, Any], session_id: str):
        """Store cryptographic objects for certificate in session"""
        CertificateStorage._validate_session_id(session_id)
        CryptoObjectsStorage.store_crypto_objects(cert_id, crypto_objects, session_id)
    
    @staticmethod
    def get_crypto_objects(cert_id: str, session_id: str) -> Dict[str, Any]:
        """Get cryptographic objects for certificate from session"""
        CertificateStorage._validate_session_id(session_id)
        return CryptoObjectsStorage.get_crypto_objects(cert_id, session_id)
    
    @staticmethod
    def has_crypto_objects(cert_id: str, session_id: str) -> bool:
        """Check if crypto objects exist for certificate in session"""
        CertificateStorage._validate_session_id(session_id)
        return CryptoObjectsStorage.has_crypto_objects(cert_id, session_id)
    
    @staticmethod
    def remove_crypto_objects(cert_id: str, session_id: str) -> bool:
        """Remove crypto objects for certificate from session"""
        CertificateStorage._validate_session_id(session_id)
        return CryptoObjectsStorage.remove_crypto_objects(cert_id, session_id)
    
    @staticmethod
    def clear_all_crypto_objects(session_id: str):
        """Clear all crypto objects from session"""
        CertificateStorage._validate_session_id(session_id)
        return CryptoObjectsStorage.clear_crypto_objects(session_id)
    
    @staticmethod
    def get_crypto_objects_debug(session_id: str) -> Dict[str, Any]:
        """Get debug info for crypto objects in session"""
        CertificateStorage._validate_session_id(session_id)
        return CryptoObjectsStorage.debug_crypto_objects(session_id)
    
    # Delegate PKI bundle operations to PKIBundleManager (session-aware)
    @staticmethod
    def get_pki_bundle(session_id: str) -> Dict[str, Any]:
        """Get the current PKI bundle for session"""
        CertificateStorage._validate_session_id(session_id)
        return PKIBundleManager.get_pki_bundle(session_id)
    
    @staticmethod
    def has_pki_bundle(session_id: str) -> bool:
        """Check if PKI bundle exists for session"""
        CertificateStorage._validate_session_id(session_id)
        return PKIBundleManager.has_pki_bundle(session_id)
    
    # Delegate debug operations to StorageUtils
    @staticmethod
    def debug_hierarchy_enforcement(session_id: str, filename: str):
        """Debug helper for hierarchy enforcement issues"""
        CertificateStorage._validate_session_id(session_id)
        
        # Get session data from SessionManager
        from session_manager import SessionManager
        session_data = SessionManager.get_or_create_session(session_id)
        certificates = session_data.get("certificates", [])
        
        StorageUtils.debug_hierarchy_enforcement(certificates, filename, session_id)
    
    @staticmethod
    def debug_crypto_objects(session_id: str):
        """Debug helper for crypto objects storage"""
        CertificateStorage._validate_session_id(session_id)
        return CryptoObjectsStorage.debug_crypto_objects(session_id)
    
    # Backward compatibility methods (deprecated - will be removed)
    @staticmethod
    def get_all_legacy() -> List[Dict[str, Any]]:
        """Legacy method - deprecated, use get_all(session_id) instead"""
        logger.warning("get_all_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.get_all(default_session)
    
    @staticmethod
    def add_legacy(certificate_data: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy method - deprecated, use add(certificate_data, session_id) instead"""
        logger.warning("add_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.add(certificate_data, default_session)
    
    @staticmethod
    def find_by_hash_legacy(content_hash: str) -> Optional[Dict[str, Any]]:
        """Legacy method - deprecated, use find_by_hash(content_hash, session_id) instead"""
        logger.warning("find_by_hash_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.find_by_hash(content_hash, default_session)
    
    @staticmethod
    def find_by_id_legacy(cert_id: str) -> Optional[Dict[str, Any]]:
        """Legacy method - deprecated, use find_by_id(cert_id, session_id) instead"""
        logger.warning("find_by_id_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.find_by_id(cert_id, default_session)
    
    @staticmethod
    def replace_legacy(existing_cert: Dict[str, Any], new_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy method - deprecated, use replace(existing_cert, new_cert, session_id) instead"""
        logger.warning("replace_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.replace(existing_cert, new_cert, default_session)
    
    @staticmethod
    def remove_by_id_legacy(cert_id: str) -> bool:
        """Legacy method - deprecated, use remove_by_id(cert_id, session_id) instead"""
        logger.warning("remove_by_id_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.remove_by_id(cert_id, default_session)
    
    @staticmethod
    def clear_all_legacy() -> bool:
        """Legacy method - deprecated, use clear_all(session_id) instead"""
        logger.warning("clear_all_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.clear_all(default_session)
    
    @staticmethod
    def count_legacy() -> int:
        """Legacy method - deprecated, use count(session_id) instead"""
        logger.warning("count_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.count(default_session)
    
    @staticmethod
    def get_summary_legacy() -> Dict[str, Any]:
        """Legacy method - deprecated, use get_summary(session_id) instead"""
        logger.warning("get_summary_legacy() called - this method is deprecated")
        # For backward compatibility, create a default session
        default_session = settings.DEFAULT_SESSION_ID
        return CertificateStorage.get_summary(default_session)