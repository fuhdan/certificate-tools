# backend-fastapi/certificates/storage/core.py
# Core storage functionality - main operations

import logging
from typing import Dict, Any, List, Optional

from .crypto_storage import CryptoObjectsStorage
from .hierarchy import HierarchyManager
from .pki_bundle import PKIBundleManager
from .utils import StorageUtils

logger = logging.getLogger(__name__)

# In-memory storage
uploaded_certificates: List[Dict[str, Any]] = []

class CertificateStorage:
    """Main certificate storage class with modular components"""
    
    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """Get all certificates sorted by PKI hierarchy"""
        logger.debug(f"=== STORAGE GET_ALL OPERATION ===")
        logger.debug(f"Storage.get_all() called - returning {len(uploaded_certificates)} certificates")
        
        # Log current unsorted state
        logger.debug(f"Current unsorted certificates:")
        for i, cert in enumerate(uploaded_certificates):
            analysis = cert.get('analysis', {})
            order = HierarchyManager.get_certificate_order(cert)
            logger.debug(f"  [{i}] {cert.get('filename')} - order: {order} - type: {analysis.get('type')} - hash: {analysis.get('content_hash', 'NO_HASH')[:16]}...")
        
        # Sort certificates by PKI hierarchy order
        logger.debug(f"Sorting certificates by PKI hierarchy...")
        sorted_certs = sorted(uploaded_certificates, key=lambda cert: (
            HierarchyManager.get_certificate_order(cert),
            cert.get('filename', '')
        ))
        
        # Log sorted state
        logger.info(f"Certificate hierarchy order after sorting:")
        for i, cert in enumerate(sorted_certs):
            order = HierarchyManager.get_certificate_order(cert)
            analysis = cert.get('analysis', {})
            logger.info(f"  [{i}] Order {order}: {cert.get('filename')} - {analysis.get('type')}")
        
        logger.debug(f"Returning {len(sorted_certs)} sorted certificates")
        return sorted_certs
    
    @staticmethod
    def add(certificate_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add certificate with PKI hierarchy enforcement and auto PKI bundle generation"""
        logger.debug(f"=== STORAGE ADD WITH HIERARCHY ENFORCEMENT ===")
        logger.debug(f"Adding certificate: {certificate_data.get('filename')}")
        logger.debug(f"Certificate ID: {certificate_data.get('id')}")
        logger.debug(f"Certificate type: {certificate_data.get('analysis', {}).get('type')}")
        logger.debug(f"Content hash: {certificate_data.get('analysis', {}).get('content_hash', 'NO_HASH')}")
        
        # Validate certificate data structure
        StorageUtils.validate_certificate_data(certificate_data)
        
        # Check if this certificate should replace an existing one
        logger.debug(f"Checking if certificate should replace existing one...")
        existing_to_replace = HierarchyManager.should_replace_certificate(
            certificate_data, uploaded_certificates
        )
        
        result = None
        if existing_to_replace:
            logger.info(f"REPLACEMENT OPERATION: {existing_to_replace.get('filename')} -> {certificate_data.get('filename')}")
            result = CertificateStorage.replace(existing_to_replace, certificate_data)
            logger.info(f"Certificate replacement completed successfully")
        else:
            # Add as new certificate
            logger.info(f"ADDITION OPERATION: Adding new certificate {certificate_data.get('filename')}")
            initial_count = len(uploaded_certificates)
            uploaded_certificates.append(certificate_data)
            final_count = len(uploaded_certificates)
            
            logger.info(f"Certificate added successfully")
            logger.info(f"Storage count: {initial_count} -> {final_count}")
            logger.debug(f"Storage state after add:")
            StorageUtils.log_storage_state(uploaded_certificates)
            result = certificate_data
        
        # Auto-generate PKI bundle after any add/replace operation
        PKIBundleManager.auto_generate_pki_bundle(uploaded_certificates)
        
        return result
    
    @staticmethod
    def replace(existing_cert: Dict[str, Any], new_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Replace existing certificate with auto PKI bundle generation"""
        logger.info(f"=== STORAGE REPLACE OPERATION ===")
        logger.info(f"Replacing certificate:")
        logger.info(f"  OLD: {existing_cert.get('filename')} (ID: {existing_cert.get('id')})")
        logger.info(f"  NEW: {new_cert.get('filename')} (ID: {new_cert.get('id')})")
        
        existing_hash = existing_cert.get('analysis', {}).get('content_hash', 'NO_HASH')
        new_hash = new_cert.get('analysis', {}).get('content_hash', 'NO_HASH')
        logger.debug(f"Content hashes - OLD: {existing_hash[:16]}... NEW: {new_hash[:16]}...")
        
        # Remove crypto objects for the old certificate
        CryptoObjectsStorage.remove_crypto_objects(existing_cert.get('id'))
        
        result = None
        # Find and replace
        for i, cert in enumerate(uploaded_certificates):
            if cert.get('id') == existing_cert.get('id'):
                logger.info(f"Found certificate to replace at index {i}")
                logger.debug(f"Before replace - cert at [{i}]: {cert.get('filename')}")
                
                uploaded_certificates[i] = new_cert
                
                logger.debug(f"After replace - cert at [{i}]: {uploaded_certificates[i].get('filename')}")
                logger.info(f"Certificate replaced successfully")
                logger.debug(f"Storage state after replace:")
                StorageUtils.log_storage_state(uploaded_certificates)
                result = new_cert
                break
        
        if result is None:
            # If not found, just add it
            logger.warning(f"Original certificate not found for replacement, adding as new")
            uploaded_certificates.append(new_cert)
            logger.info(f"Certificate added as new instead of replaced")
            result = new_cert
        
        # Auto-generate PKI bundle after replace operation
        PKIBundleManager.auto_generate_pki_bundle(uploaded_certificates)
        
        return result
    
    @staticmethod
    def find_by_hash(content_hash: str) -> Optional[Dict[str, Any]]:
        """Find certificate by content hash"""
        logger.debug(f"=== STORAGE HASH LOOKUP ===")
        logger.debug(f"Searching for content_hash: {content_hash}")
        logger.debug(f"Total certificates in storage: {len(uploaded_certificates)}")
        
        for i, cert in enumerate(uploaded_certificates):
            cert_hash = cert.get('analysis', {}).get('content_hash')
            cert_filename = cert.get('filename', 'NO_FILENAME')
            logger.debug(f"  [{i}] {cert_filename} - hash: {cert_hash}")
            
            if cert_hash == content_hash:
                logger.info(f"HASH MATCH FOUND: {cert_filename} matches {content_hash[:16]}...")
                logger.debug(f"Matched certificate details:")
                logger.debug(f"  ID: {cert.get('id')}")
                logger.debug(f"  Filename: {cert.get('filename')}")
                logger.debug(f"  Type: {cert.get('analysis', {}).get('type')}")
                logger.debug(f"  Upload time: {cert.get('uploadedAt')}")
                return cert
        
        logger.debug(f"No hash match found for: {content_hash[:16]}...")
        return None
    
    @staticmethod
    def find_by_id(cert_id: str) -> Optional[Dict[str, Any]]:
        """Find certificate by ID"""
        logger.debug(f"=== STORAGE ID LOOKUP ===")
        logger.debug(f"Searching for ID: {cert_id}")
        
        for i, cert in enumerate(uploaded_certificates):
            cert_id_stored = cert.get('id')
            cert_filename = cert.get('filename', 'NO_FILENAME')
            logger.debug(f"  [{i}] {cert_filename} - ID: {cert_id_stored}")
            
            if cert_id_stored == cert_id:
                logger.info(f"ID MATCH FOUND: {cert_filename}")
                return cert
        
        logger.debug(f"No ID match found for: {cert_id}")
        return None
    
    @staticmethod
    def remove_by_id(cert_id: str) -> bool:
        """Remove certificate by ID with crypto objects cleanup"""
        logger.info(f"=== STORAGE REMOVE OPERATION ===")
        logger.info(f"Removing certificate with ID: {cert_id}")
        
        # Remove crypto objects first
        CryptoObjectsStorage.remove_crypto_objects(cert_id)
        
        global uploaded_certificates
        initial_count = len(uploaded_certificates)
        
        # Find the certificate to remove
        cert_to_remove = None
        for cert in uploaded_certificates:
            if cert.get('id') == cert_id:
                cert_to_remove = cert
                break
        
        if cert_to_remove:
            logger.info(f"Found certificate to remove: {cert_to_remove.get('filename')}")
            logger.debug(f"Certificate details:")
            logger.debug(f"  Type: {cert_to_remove.get('analysis', {}).get('type')}")
            logger.debug(f"  Hash: {cert_to_remove.get('analysis', {}).get('content_hash', 'NO_HASH')[:16]}...")
        else:
            logger.warning(f"Certificate with ID {cert_id} not found for removal")
        
        # Remove the certificate
        uploaded_certificates = [cert for cert in uploaded_certificates if cert.get('id') != cert_id]
        final_count = len(uploaded_certificates)
        success = final_count < initial_count
        
        logger.info(f"Remove operation result: {'SUCCESS' if success else 'FAILED'}")
        logger.info(f"Storage count: {initial_count} -> {final_count}")
        
        if success:
            logger.debug(f"Storage state after removal:")
            StorageUtils.log_storage_state(uploaded_certificates)
            # Auto-generate PKI bundle after removal
            PKIBundleManager.auto_generate_pki_bundle(uploaded_certificates)
        
        return success
    
    @staticmethod
    def clear_all() -> bool:
        """Clear all certificates, crypto objects, and PKI bundle"""
        logger.info(f"=== STORAGE CLEAR ALL OPERATION ===")
        
        # Clear crypto objects first
        CryptoObjectsStorage.clear_all_crypto_objects()
        
        global uploaded_certificates
        count = len(uploaded_certificates)
        
        logger.info(f"Clearing {count} certificates from storage")
        for i, cert in enumerate(uploaded_certificates):
            logger.debug(f"  Clearing [{i}]: {cert.get('filename')} - {cert.get('analysis', {}).get('type')}")
        
        uploaded_certificates = []
        
        # Clear PKI bundle
        PKIBundleManager.clear_pki_bundle()
        
        logger.info(f"All certificates, crypto objects, and PKI bundle cleared successfully")
        logger.debug(f"Storage is now empty: {len(uploaded_certificates)} certificates")
        return True
    
    @staticmethod
    def count() -> int:
        """Get count of certificates"""
        count = len(uploaded_certificates)
        logger.debug(f"Storage count requested: {count} certificates")
        return count
    
    @staticmethod
    def get_summary() -> Dict[str, Any]:
        """Get storage summary"""
        logger.debug(f"=== STORAGE SUMMARY GENERATION ===")
        total = len(uploaded_certificates)
        valid_count = sum(1 for cert in uploaded_certificates 
                         if cert.get('analysis', {}).get('isValid', False))
        
        types = {}
        orders = {}
        for cert in uploaded_certificates:
            cert_type = cert.get('analysis', {}).get('type', 'Unknown')
            cert_order = HierarchyManager.get_certificate_order(cert)
            types[cert_type] = types.get(cert_type, 0) + 1
            orders[cert_order] = orders.get(cert_order, 0) + 1
        
        # Add crypto objects info
        crypto_count = CryptoObjectsStorage.get_crypto_objects_count()
        
        summary = {
            "total": total,
            "valid": valid_count,
            "invalid": total - valid_count,
            "types": types,
            "hierarchy_distribution": orders,
            "crypto_objects_stored": crypto_count,
            "has_pki_bundle": PKIBundleManager.has_pki_bundle()
        }
        
        logger.debug(f"Storage summary:")
        logger.debug(f"  Total: {summary['total']}")
        logger.debug(f"  Valid: {summary['valid']}")
        logger.debug(f"  Invalid: {summary['invalid']}")
        logger.debug(f"  Types: {summary['types']}")
        logger.debug(f"  Hierarchy distribution: {summary['hierarchy_distribution']}")
        logger.debug(f"  Crypto objects stored: {summary['crypto_objects_stored']}")
        logger.debug(f"  Has PKI bundle: {summary['has_pki_bundle']}")
        
        return summary
    
    # Delegate crypto operations to CryptoObjectsStorage
    @staticmethod
    def store_crypto_objects(cert_id: str, crypto_objects: Dict[str, Any]):
        """Store cryptographic objects separately"""
        CryptoObjectsStorage.store_crypto_objects(cert_id, crypto_objects)
    
    @staticmethod
    def get_crypto_objects(cert_id: str) -> Dict[str, Any]:
        """Retrieve cryptographic objects for validation"""
        return CryptoObjectsStorage.get_crypto_objects(cert_id)
    
    # Delegate PKI bundle operations to PKIBundleManager
    @staticmethod
    def get_pki_bundle() -> Dict[str, Any]:
        """Get the current PKI bundle"""
        return PKIBundleManager.get_pki_bundle()
    
    @staticmethod
    def has_pki_bundle() -> bool:
        """Check if PKI bundle exists"""
        return PKIBundleManager.has_pki_bundle()
    
    # Delegate debug operations to StorageUtils
    @staticmethod
    def debug_hierarchy_enforcement(filename: str):
        """Debug helper for hierarchy enforcement issues"""
        StorageUtils.debug_hierarchy_enforcement(uploaded_certificates, filename)
    
    @staticmethod
    def debug_crypto_objects():
        """Debug helper for crypto objects storage"""
        CryptoObjectsStorage.debug_crypto_objects()