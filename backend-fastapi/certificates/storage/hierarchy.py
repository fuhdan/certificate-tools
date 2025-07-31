# backend-fastapi/certificates/storage/hierarchy.py
# PKI hierarchy management and certificate ordering

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class HierarchyManager:
    """Manages PKI hierarchy ordering and replacement rules"""
    
    @staticmethod
    def get_certificate_order(cert_data: Dict[str, Any]) -> int:
        """Get certificate order using standardized certificate types"""
        from certificates.types import CertificateType, HierarchyOrder, normalize_certificate_type
        
        # Try fileType first (if available)
        file_type = cert_data.get('fileType')
        if file_type:
            try:
                cert_type = CertificateType(file_type)
                return HierarchyOrder.get_order(cert_type)
            except ValueError:
                # fileType not in enum, fall through to analysis
                pass
            
        # Fall back to analysis.type with normalization
        analysis = cert_data.get('analysis', {})
        raw_type = analysis.get('type')
        if raw_type:
            details = analysis.get('details')
            cert_type = normalize_certificate_type(raw_type, details)
            return HierarchyOrder.get_order(cert_type)
        
        # Default for unknown types
        return HierarchyOrder.get_order(CertificateType.UNKNOWN)
    
    @staticmethod
    def is_duplicate_certificate(cert1: Dict[str, Any], cert2: Dict[str, Any]) -> bool:
        """Check if two certificates are duplicates"""
        logger.debug(f"=== DUPLICATE CERTIFICATE CHECK ===")
        filename1 = cert1.get('filename', 'NO_FILENAME_1')
        filename2 = cert2.get('filename', 'NO_FILENAME_2')
        logger.debug(f"Comparing: {filename1} vs {filename2}")
        
        hash1 = cert1.get('analysis', {}).get('content_hash')
        hash2 = cert2.get('analysis', {}).get('content_hash')
        
        logger.debug(f"Hash 1: {hash1[:16] if hash1 else 'NO_HASH'}...")
        logger.debug(f"Hash 2: {hash2[:16] if hash2 else 'NO_HASH'}...")
        
        # Direct hash comparison
        if hash1 and hash2 and hash1 == hash2:
            logger.info(f"DUPLICATE DETECTED via hash match: {filename1} == {filename2}")
            return True
            
        # For certificates, check if they represent the same certificate
        type1 = cert1.get('analysis', {}).get('type', '')
        type2 = cert2.get('analysis', {}).get('type', '')
        
        logger.debug(f"Type 1: {type1}")
        logger.debug(f"Type 2: {type2}")
        
        is_cert1 = 'Certificate' in type1 and 'Chain' not in type1
        is_cert2 = 'Certificate' in type2 and 'Chain' not in type2
        
        logger.debug(f"Is certificate 1: {is_cert1}")
        logger.debug(f"Is certificate 2: {is_cert2}")
        
        if is_cert1 and is_cert2:
            details1 = cert1.get('analysis', {}).get('details', {})
            details2 = cert2.get('analysis', {}).get('details', {})
            
            # Compare key identifiers
            serial1 = details1.get('serialNumber')
            serial2 = details2.get('serialNumber')
            subject1 = details1.get('subject', {}).get('commonName')
            subject2 = details2.get('subject', {}).get('commonName')
            issuer1 = details1.get('issuer', {}).get('commonName')
            issuer2 = details2.get('issuer', {}).get('commonName')
            
            logger.debug(f"Certificate 1 identifiers:")
            logger.debug(f"  Serial: {serial1}")
            logger.debug(f"  Subject: {subject1}")
            logger.debug(f"  Issuer: {issuer1}")
            
            logger.debug(f"Certificate 2 identifiers:")
            logger.debug(f"  Serial: {serial2}")
            logger.debug(f"  Subject: {subject2}")
            logger.debug(f"  Issuer: {issuer2}")
            
            if all([serial1, serial2, subject1, subject2, issuer1, issuer2]):
                identifiers_match = (serial1 == serial2 and 
                                   subject1 == subject2 and 
                                   issuer1 == issuer2)
                
                if identifiers_match:
                    logger.info(f"DUPLICATE DETECTED via identifier match: {filename1} == {filename2}")
                    logger.debug(f"  Matching serial: {serial1}")
                    logger.debug(f"  Matching subject: {subject1}")
                    logger.debug(f"  Matching issuer: {issuer1}")
                    return True
                else:
                    logger.debug(f"Identifiers do not match:")
                    logger.debug(f"  Serial match: {serial1 == serial2}")
                    logger.debug(f"  Subject match: {subject1 == subject2}")
                    logger.debug(f"  Issuer match: {issuer1 == issuer2}")
            else:
                logger.debug(f"Missing some identifiers for comparison")
                missing = []
                if not serial1: missing.append("serial1")
                if not serial2: missing.append("serial2")
                if not subject1: missing.append("subject1")
                if not subject2: missing.append("subject2")
                if not issuer1: missing.append("issuer1")
                if not issuer2: missing.append("issuer2")
                logger.debug(f"  Missing: {missing}")
        
        logger.debug(f"No duplicate detected between {filename1} and {filename2}")
        return False
    
    @staticmethod
    def should_replace_certificate(new_cert: Dict[str, Any], existing_certs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Check if new certificate should replace an existing one"""
        logger.debug(f"=== REPLACEMENT CHECK ===")
        new_filename = new_cert.get('filename', 'NO_FILENAME')
        new_order = HierarchyManager.get_certificate_order(new_cert)
        new_type = new_cert.get('analysis', {}).get('type', 'NO_TYPE')
        
        logger.debug(f"New certificate: {new_filename}")
        logger.debug(f"New certificate order: {new_order}")
        logger.debug(f"New certificate type: {new_type}")
        logger.debug(f"Checking against {len(existing_certs)} existing certificates")
        
        # For unique certificates (CSR, Private Key, End-entity, Issuing CA, Root CA)
        if new_order in [1, 2, 3, 4, 6]:
            logger.debug(f"Certificate order {new_order} allows only one instance")
            
            for i, existing in enumerate(existing_certs):
                existing_order = HierarchyManager.get_certificate_order(existing)
                existing_filename = existing.get('filename', 'NO_FILENAME')
                existing_type = existing.get('analysis', {}).get('type', 'NO_TYPE')
                
                logger.debug(f"  Checking existing [{i}]: {existing_filename} (order {existing_order})")
                
                if existing_order == new_order:
                    logger.info(f"REPLACEMENT REQUIRED: Found existing certificate of same type")
                    logger.info(f"  Existing: {existing_filename} ({existing_type})")
                    logger.info(f"  New: {new_filename} ({new_type})")
                    logger.info(f"  Order: {new_order}")
                    return existing
        
        # For Intermediate CAs (order 5), check for duplicates
        elif new_order == 5:
            logger.debug(f"Certificate order 5 (Intermediate CA) allows multiple but checks duplicates")
            
            for i, existing in enumerate(existing_certs):
                existing_order = HierarchyManager.get_certificate_order(existing)
                existing_filename = existing.get('filename', 'NO_FILENAME')
                
                logger.debug(f"  Checking existing [{i}]: {existing_filename} (order {existing_order})")
                
                if existing_order == 5:
                    logger.debug(f"    Both are Intermediate CAs, checking for duplicate...")
                    if HierarchyManager.is_duplicate_certificate(new_cert, existing):
                        logger.info(f"REPLACEMENT REQUIRED: Found duplicate intermediate CA")
                        logger.info(f"  Existing: {existing_filename}")
                        logger.info(f"  New: {new_filename}")
                        return existing
                    else:
                        logger.debug(f"    Not a duplicate, will coexist")
        
        # For Certificate Chains (order 7), allow multiple
        elif new_order == 7:
            logger.debug(f"Certificate order 7 (Certificate Chain) allows multiple instances")
        
        # For everything else (order 8), allow multiple
        else:
            logger.debug(f"Certificate order {new_order} allows multiple instances")
        
        logger.debug(f"No replacement needed for {new_filename}")
        return None