# backend-fastapi/certificates/storage/hierarchy.py
# PKI hierarchy management and certificate ordering

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class HierarchyManager:
    """Manages PKI hierarchy ordering and replacement rules"""
    
    @staticmethod
    def get_certificate_order(cert_data: Dict[str, Any]) -> int:
        """Determine certificate order in PKI hierarchy"""
        logger.debug(f"=== CERTIFICATE ORDER DETERMINATION ===")
        analysis = cert_data.get('analysis', {})
        cert_type = analysis.get('type', '')
        details = analysis.get('details', {})
        filename = cert_data.get('filename', 'NO_FILENAME')
        
        logger.debug(f"Certificate: {filename}")
        logger.debug(f"Type: {cert_type}")
        logger.debug(f"Has details: {bool(details)}")
        
        # CSR = 1 (only one)
        if cert_type == 'CSR':
            logger.debug(f"Categorized as CSR (order 1)")
            return 1
            
        # Private Key = 2 (only one)
        if cert_type == 'Private Key':
            logger.debug(f"Categorized as Private Key (order 2)")
            return 2
            
        # For certificates, determine hierarchy
        if 'Certificate' in cert_type and 'Chain' not in cert_type:
            logger.debug(f"Processing certificate type: {cert_type}")
            extensions = details.get('extensions', {})
            basic_constraints = extensions.get('basicConstraints', {})
            is_ca = basic_constraints.get('isCA', False)
            
            subject_cn = details.get('subject', {}).get('commonName', '')
            issuer_cn = details.get('issuer', {}).get('commonName', '')
            
            logger.debug(f"Certificate analysis:")
            logger.debug(f"  Subject CN: {subject_cn}")
            logger.debug(f"  Issuer CN: {issuer_cn}")
            logger.debug(f"  Is CA: {is_ca}")
            logger.debug(f"  Has basic constraints: {bool(basic_constraints)}")
            
            if not is_ca:
                # End-entity certificate = 3 (only one)
                logger.debug(f"Categorized as End-entity Certificate (order 3)")
                return 3
            else:
                # CA certificates - determine hierarchy
                if issuer_cn == subject_cn:
                    # Self-signed = Root CA = 6 (only one)
                    logger.debug(f"Self-signed certificate detected - Root CA (order 6)")
                    return 6
                else:
                    # Check if this is an issuing CA
                    subject_lower = subject_cn.lower()
                    issuing_indicators = [
                        'issuing', 'leaf', 'server', 'client', 'ssl', 'tls',
                        'web', 'email', 'code', 'signing'
                    ]
                    
                    matching_indicators = [ind for ind in issuing_indicators if ind in subject_lower]
                    is_issuing_ca = len(matching_indicators) > 0
                    
                    logger.debug(f"Issuing CA analysis:")
                    logger.debug(f"  Subject (lowercase): {subject_lower}")
                    logger.debug(f"  Matching indicators: {matching_indicators}")
                    logger.debug(f"  Is issuing CA: {is_issuing_ca}")
                    
                    if is_issuing_ca:
                        # Issuing CA = 4 (only one)
                        logger.debug(f"Categorized as Issuing CA (order 4)")
                        return 4
                    else:
                        # Intermediate CA = 5 (can have multiple)
                        logger.debug(f"Categorized as Intermediate CA (order 5)")
                        return 5
        
        # Certificate Chain = 7
        if cert_type == 'Certificate Chain':
            logger.debug(f"Categorized as Certificate Chain (order 7)")
            return 7
            
        # Everything else = 8
        logger.debug(f"Categorized as Other/Unknown (order 8)")
        return 8
    
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