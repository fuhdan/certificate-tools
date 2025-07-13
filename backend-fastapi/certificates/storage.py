# certificates/storage.py
# In-memory storage for certificates with comprehensive debugging

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# In-memory storage
uploaded_certificates: List[Dict[str, Any]] = []

class CertificateStorage:
    """Simple in-memory certificate storage with comprehensive debugging"""
    
    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """Get all certificates"""
        logger.debug(f"Storage.get_all() called - returning {len(uploaded_certificates)} certificates")
        for i, cert in enumerate(uploaded_certificates):
            logger.debug(f"  [{i}] {cert.get('filename')} - type: {cert.get('analysis', {}).get('type')} - hash: {cert.get('analysis', {}).get('content_hash', 'NO_HASH')[:16]}...")
        return uploaded_certificates
    
    @staticmethod
    def add(certificate_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add certificate to storage"""
        logger.debug(f"=== STORAGE ADD OPERATION ===")
        logger.debug(f"Adding certificate: {certificate_data.get('filename')}")
        logger.debug(f"Certificate ID: {certificate_data.get('id')}")
        logger.debug(f"Certificate type: {certificate_data.get('analysis', {}).get('type')}")
        logger.debug(f"Content hash: {certificate_data.get('analysis', {}).get('content_hash', 'NO_HASH')}")
        
        # Validate certificate data structure
        required_fields = ['id', 'filename', 'analysis']
        missing_fields = [field for field in required_fields if field not in certificate_data]
        if missing_fields:
            logger.error(f"Certificate data missing required fields: {missing_fields}")
            logger.error(f"Certificate data keys: {list(certificate_data.keys())}")
        
        # Check for analysis structure
        analysis = certificate_data.get('analysis', {})
        if not isinstance(analysis, dict):
            logger.error(f"Analysis field is not a dictionary: {type(analysis)}")
        else:
            logger.debug(f"Analysis fields: {list(analysis.keys())}")
            if 'content_hash' not in analysis:
                logger.warning("Analysis missing content_hash field")
        
        # Add to storage
        initial_count = len(uploaded_certificates)
        uploaded_certificates.append(certificate_data)
        final_count = len(uploaded_certificates)
        
        logger.info(f"Certificate added successfully")
        logger.info(f"Storage count: {initial_count} -> {final_count}")
        logger.debug(f"Storage state after add:")
        CertificateStorage._log_storage_state()
        
        return certificate_data
    
    @staticmethod
    def find_by_hash(content_hash: str) -> Optional[Dict[str, Any]]:
        """Find certificate by content hash (normalized for duplicate detection)"""
        logger.debug(f"=== STORAGE HASH LOOKUP ===")
        logger.debug(f"Searching for content_hash: {content_hash}")
        logger.debug(f"Total certificates in storage: {len(uploaded_certificates)}")
        
        for i, cert in enumerate(uploaded_certificates):
            cert_hash = cert.get('analysis', {}).get('content_hash')
            logger.debug(f"  [{i}] {cert.get('filename')} - hash: {cert_hash}")
            
            if cert_hash == content_hash:
                logger.info(f"HASH MATCH FOUND: {cert.get('filename')} matches {content_hash[:16]}...")
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
            logger.debug(f"  [{i}] {cert.get('filename')} - ID: {cert_id_stored}")
            
            if cert_id_stored == cert_id:
                logger.info(f"ID MATCH FOUND: {cert.get('filename')}")
                return cert
        
        logger.debug(f"No ID match found for: {cert_id}")
        return None
    
    @staticmethod
    def remove_by_id(cert_id: str) -> bool:
        """Remove certificate by ID"""
        logger.info(f"=== STORAGE REMOVE OPERATION ===")
        logger.info(f"Removing certificate with ID: {cert_id}")
        
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
            CertificateStorage._log_storage_state()
        
        return success
    
    @staticmethod
    def clear_all() -> bool:
        """Clear all certificates"""
        logger.info(f"=== STORAGE CLEAR ALL OPERATION ===")
        global uploaded_certificates
        count = len(uploaded_certificates)
        
        logger.info(f"Clearing {count} certificates from storage")
        for i, cert in enumerate(uploaded_certificates):
            logger.debug(f"  Clearing [{i}]: {cert.get('filename')} - {cert.get('analysis', {}).get('type')}")
        
        uploaded_certificates = []
        logger.info(f"All certificates cleared successfully")
        logger.debug(f"Storage is now empty: {len(uploaded_certificates)} certificates")
        return True
    
    @staticmethod
    def replace(existing_cert: Dict[str, Any], new_cert: Dict[str, Any]) -> Dict[str, Any]:
        """Replace existing certificate"""
        logger.info(f"=== STORAGE REPLACE OPERATION ===")
        logger.info(f"Replacing certificate:")
        logger.info(f"  OLD: {existing_cert.get('filename')} (ID: {existing_cert.get('id')})")
        logger.info(f"  NEW: {new_cert.get('filename')} (ID: {new_cert.get('id')})")
        
        existing_hash = existing_cert.get('analysis', {}).get('content_hash', 'NO_HASH')
        new_hash = new_cert.get('analysis', {}).get('content_hash', 'NO_HASH')
        logger.debug(f"Content hashes - OLD: {existing_hash[:16]}... NEW: {new_hash[:16]}...")
        
        # Find and replace
        for i, cert in enumerate(uploaded_certificates):
            if cert.get('id') == existing_cert.get('id'):
                logger.info(f"Found certificate to replace at index {i}")
                logger.debug(f"Before replace - cert at [{i}]: {cert.get('filename')}")
                
                uploaded_certificates[i] = new_cert
                
                logger.debug(f"After replace - cert at [{i}]: {uploaded_certificates[i].get('filename')}")
                logger.info(f"Certificate replaced successfully")
                logger.debug(f"Storage state after replace:")
                CertificateStorage._log_storage_state()
                return new_cert
        
        # If not found, just add it
        logger.warning(f"Original certificate not found for replacement, adding as new")
        uploaded_certificates.append(new_cert)
        logger.info(f"Certificate added as new instead of replaced")
        return new_cert
    
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
        for cert in uploaded_certificates:
            cert_type = cert.get('analysis', {}).get('type', 'Unknown')
            types[cert_type] = types.get(cert_type, 0) + 1
        
        summary = {
            "total": total,
            "valid": valid_count,
            "invalid": total - valid_count,
            "types": types
        }
        
        logger.debug(f"Storage summary:")
        logger.debug(f"  Total: {summary['total']}")
        logger.debug(f"  Valid: {summary['valid']}")
        logger.debug(f"  Invalid: {summary['invalid']}")
        logger.debug(f"  Types: {summary['types']}")
        
        return summary
    
    @staticmethod
    def _log_storage_state():
        """Internal method to log current storage state for debugging"""
        logger.debug(f"=== CURRENT STORAGE STATE ===")
        logger.debug(f"Total certificates: {len(uploaded_certificates)}")
        
        for i, cert in enumerate(uploaded_certificates):
            analysis = cert.get('analysis', {})
            logger.debug(f"  [{i}] {cert.get('filename', 'NO_FILENAME')}")
            logger.debug(f"      ID: {cert.get('id', 'NO_ID')}")
            logger.debug(f"      Type: {analysis.get('type', 'NO_TYPE')}")
            logger.debug(f"      Valid: {analysis.get('isValid', 'NO_VALID')}")
            logger.debug(f"      Hash: {analysis.get('content_hash', 'NO_HASH')[:16] if analysis.get('content_hash') else 'NO_HASH'}...")
            logger.debug(f"      Uploaded: {cert.get('uploadedAt', 'NO_TIME')}")
        
        logger.debug(f"=== END STORAGE STATE ===")
    
    @staticmethod
    def debug_duplicate_detection(content_hash: str, filename: str):
        """Debug helper for duplicate detection issues"""
        logger.info(f"=== DUPLICATE DETECTION DEBUG ===")
        logger.info(f"Looking for duplicates of: {filename}")
        logger.info(f"Target content_hash: {content_hash}")
        
        logger.info(f"Current storage contents:")
        for i, cert in enumerate(uploaded_certificates):
            cert_hash = cert.get('analysis', {}).get('content_hash', 'NO_HASH')
            cert_filename = cert.get('filename', 'NO_FILENAME')
            cert_type = cert.get('analysis', {}).get('type', 'NO_TYPE')
            
            match_status = "MATCH" if cert_hash == content_hash else "no match"
            logger.info(f"  [{i}] {cert_filename} ({cert_type}) - {cert_hash[:16]}... - {match_status}")
        
        # Check for similar hashes (debugging hash generation issues)
        logger.debug("Checking for similar hashes:")
        for cert in uploaded_certificates:
            cert_hash = cert.get('analysis', {}).get('content_hash', 'NO_HASH')
            if cert_hash != 'NO_HASH' and content_hash != 'NO_HASH':
                # Compare first 16 characters to see if there are near-misses
                if cert_hash[:16] == content_hash[:16]:
                    logger.warning(f"Potential hash generation issue - similar prefix:")
                    logger.warning(f"  Target:  {content_hash}")
                    logger.warning(f"  Stored:  {cert_hash}")
                    logger.warning(f"  File:    {cert.get('filename')}")
        
        logger.info(f"=== END DUPLICATE DETECTION DEBUG ===")