# backend-fastapi/certificates/storage/utils.py
# Storage utility functions - validation and debugging - FIXED TYPES

import logging
from config import settings
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class StorageUtils:
    """Utility functions for storage operations - SESSION AWARE"""
    
    @staticmethod
    def validate_certificate_data(certificate_data: Dict[str, Any]):
        """Validate certificate data structure"""
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
    
    @staticmethod
    def log_storage_state(uploaded_certificates: List[Dict[str, Any]], session_id: Optional[str] = None):
        """Log current storage state for debugging - SESSION AWARE"""
        if session_id is None:
            session_id = settings.DEFAULT_SESSION_ID
            logger.warning("No session_id provided to log_storage_state, using default")
        
        logger.debug(f"[{session_id}] === CURRENT STORAGE STATE ===")
        logger.debug(f"[{session_id}] Total certificates: {len(uploaded_certificates)}")
        
        # Import here to avoid circular import
        from .crypto_storage import CryptoObjectsStorage
        from .hierarchy import HierarchyManager
        
        crypto_count = CryptoObjectsStorage.get_crypto_objects_count(session_id)
        logger.debug(f"[{session_id}] Total crypto objects: {crypto_count}")
        
        for i, cert in enumerate(uploaded_certificates):
            analysis = cert.get('analysis', {})
            order = HierarchyManager.get_certificate_order(cert)
            cert_id = cert.get('id', 'NO_ID')
            crypto_objects = CryptoObjectsStorage.get_crypto_objects(cert_id, session_id)
            has_crypto = bool(crypto_objects)
            crypto_types = list(crypto_objects.keys()) if has_crypto else []
            
            logger.debug(f"[{session_id}]   [{i}] Order {order}: {cert.get('filename', 'NO_FILENAME')}")
            logger.debug(f"[{session_id}]       ID: {cert_id}")
            logger.debug(f"[{session_id}]       Type: {analysis.get('type', 'NO_TYPE')}")
            logger.debug(f"[{session_id}]       Valid: {analysis.get('isValid', 'NO_VALID')}")
            logger.debug(f"[{session_id}]       Hash: {analysis.get('content_hash', 'NO_HASH')[:16] if analysis.get('content_hash') else 'NO_HASH'}...")
            logger.debug(f"[{session_id}]       Crypto objects: {crypto_types if has_crypto else 'None'}")
            logger.debug(f"[{session_id}]       Uploaded: {cert.get('uploadedAt', 'NO_TIME')}")
        
        logger.debug(f"[{session_id}] === END STORAGE STATE ===")
    
    @staticmethod
    def debug_hierarchy_enforcement(uploaded_certificates: List[Dict[str, Any]], filename: str, session_id: Optional[str] = None):
        """Debug helper for hierarchy enforcement issues - SESSION AWARE"""
        if session_id is None:
            session_id = settings.DEFAULT_SESSION_ID
            logger.warning("No session_id provided to debug_hierarchy_enforcement, using default")
        
        logger.info(f"[{session_id}] === HIERARCHY ENFORCEMENT DEBUG ===")
        logger.info(f"[{session_id}] Analyzing hierarchy for: {filename}")
        
        # Import here to avoid circular import
        from .hierarchy import HierarchyManager
        
        logger.info(f"[{session_id}] Current PKI hierarchy distribution:")
        hierarchy_counts = {}
        order_names = {
            1: "CSR",
            2: "Private Key", 
            3: "End-entity Certificate",
            4: "Issuing CA",
            5: "Intermediate CA",
            6: "Root CA",
            7: "Certificate Chain",
            8: "Other/Unknown"
        }
        
        for cert in uploaded_certificates:
            order = HierarchyManager.get_certificate_order(cert)
            order_name = order_names.get(order, f"Order {order}")
            hierarchy_counts[order_name] = hierarchy_counts.get(order_name, 0) + 1
        
        for order_name, count in hierarchy_counts.items():
            logger.info(f"[{session_id}]   {order_name}: {count}")
        
        # Check for violations
        violations = []
        if hierarchy_counts.get("CSR", 0) > 1:
            violations.append("Multiple CSRs detected")
        if hierarchy_counts.get("Private Key", 0) > 1:
            violations.append("Multiple Private Keys detected")
        if hierarchy_counts.get("End-entity Certificate", 0) > 1:
            violations.append("Multiple End-entity Certificates detected")
        if hierarchy_counts.get("Issuing CA", 0) > 1:
            violations.append("Multiple Issuing CAs detected")
        if hierarchy_counts.get("Root CA", 0) > 1:
            violations.append("Multiple Root CAs detected")
        
        if violations:
            logger.warning(f"[{session_id}] PKI Hierarchy violations detected:")
            for violation in violations:
                logger.warning(f"[{session_id}]   - {violation}")
        else:
            logger.info(f"[{session_id}] PKI Hierarchy is properly enforced")
        
        logger.info(f"[{session_id}] === END HIERARCHY ENFORCEMENT DEBUG ===")