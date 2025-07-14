# backend-fastapi/certificates/storage.py
# Enhanced storage logic with comprehensive debugging and PKI hierarchy enforcement

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# In-memory storage
uploaded_certificates: List[Dict[str, Any]] = []

class CertificateStorage:
    """Enhanced certificate storage with PKI hierarchy enforcement and comprehensive debugging"""
    
    @staticmethod
    def get_certificate_order(cert_data: Dict[str, Any]) -> int:
        """Determine certificate order in PKI hierarchy with detailed logging"""
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
        """Check if two certificates are duplicates with comprehensive debugging"""
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
        """Check if new certificate should replace an existing one with comprehensive debugging"""
        logger.debug(f"=== REPLACEMENT CHECK ===")
        new_filename = new_cert.get('filename', 'NO_FILENAME')
        new_order = CertificateStorage.get_certificate_order(new_cert)
        new_type = new_cert.get('analysis', {}).get('type', 'NO_TYPE')
        
        logger.debug(f"New certificate: {new_filename}")
        logger.debug(f"New certificate order: {new_order}")
        logger.debug(f"New certificate type: {new_type}")
        logger.debug(f"Checking against {len(existing_certs)} existing certificates")
        
        # For unique certificates (CSR, Private Key, End-entity, Issuing CA, Root CA)
        if new_order in [1, 2, 3, 4, 6]:
            logger.debug(f"Certificate order {new_order} allows only one instance")
            
            for i, existing in enumerate(existing_certs):
                existing_order = CertificateStorage.get_certificate_order(existing)
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
                existing_order = CertificateStorage.get_certificate_order(existing)
                existing_filename = existing.get('filename', 'NO_FILENAME')
                
                logger.debug(f"  Checking existing [{i}]: {existing_filename} (order {existing_order})")
                
                if existing_order == 5:
                    logger.debug(f"    Both are Intermediate CAs, checking for duplicate...")
                    if CertificateStorage.is_duplicate_certificate(new_cert, existing):
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
    
    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """Get all certificates with comprehensive debugging"""
        logger.debug(f"=== STORAGE GET_ALL OPERATION ===")
        logger.debug(f"Storage.get_all() called - returning {len(uploaded_certificates)} certificates")
        
        # Log current unsorted state
        logger.debug(f"Current unsorted certificates:")
        for i, cert in enumerate(uploaded_certificates):
            analysis = cert.get('analysis', {})
            order = CertificateStorage.get_certificate_order(cert)
            logger.debug(f"  [{i}] {cert.get('filename')} - order: {order} - type: {analysis.get('type')} - hash: {analysis.get('content_hash', 'NO_HASH')[:16]}...")
        
        # Sort certificates by PKI hierarchy order
        logger.debug(f"Sorting certificates by PKI hierarchy...")
        sorted_certs = sorted(uploaded_certificates, key=lambda cert: (
            CertificateStorage.get_certificate_order(cert),
            cert.get('filename', '')
        ))
        
        # Log sorted state
        logger.info(f"Certificate hierarchy order after sorting:")
        for i, cert in enumerate(sorted_certs):
            order = CertificateStorage.get_certificate_order(cert)
            analysis = cert.get('analysis', {})
            logger.info(f"  [{i}] Order {order}: {cert.get('filename')} - {analysis.get('type')}")
        
        logger.debug(f"Returning {len(sorted_certs)} sorted certificates")
        return sorted_certs
    
    @staticmethod
    def add(certificate_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add certificate with PKI hierarchy enforcement and comprehensive debugging"""
        logger.debug(f"=== STORAGE ADD WITH HIERARCHY ENFORCEMENT ===")
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
        
        # Check if this certificate should replace an existing one
        logger.debug(f"Checking if certificate should replace existing one...")
        existing_to_replace = CertificateStorage.should_replace_certificate(
            certificate_data, uploaded_certificates
        )
        
        if existing_to_replace:
            logger.info(f"REPLACEMENT OPERATION: {existing_to_replace.get('filename')} -> {certificate_data.get('filename')}")
            replaced_cert = CertificateStorage.replace(existing_to_replace, certificate_data)
            logger.info(f"Certificate replacement completed successfully")
            return replaced_cert
        else:
            # Add as new certificate
            logger.info(f"ADDITION OPERATION: Adding new certificate {certificate_data.get('filename')}")
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
        """Find certificate by content hash with comprehensive debugging"""
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
        """Find certificate by ID with comprehensive debugging"""
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
        """Remove certificate by ID with comprehensive debugging"""
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
        """Clear all certificates with comprehensive debugging"""
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
        """Replace existing certificate with comprehensive debugging"""
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
        """Get count of certificates with debugging"""
        count = len(uploaded_certificates)
        logger.debug(f"Storage count requested: {count} certificates")
        return count
    
    @staticmethod
    def get_summary() -> Dict[str, Any]:
        """Get storage summary with comprehensive debugging"""
        logger.debug(f"=== STORAGE SUMMARY GENERATION ===")
        total = len(uploaded_certificates)
        valid_count = sum(1 for cert in uploaded_certificates 
                         if cert.get('analysis', {}).get('isValid', False))
        
        types = {}
        orders = {}
        for cert in uploaded_certificates:
            cert_type = cert.get('analysis', {}).get('type', 'Unknown')
            cert_order = CertificateStorage.get_certificate_order(cert)
            types[cert_type] = types.get(cert_type, 0) + 1
            orders[cert_order] = orders.get(cert_order, 0) + 1
        
        summary = {
            "total": total,
            "valid": valid_count,
            "invalid": total - valid_count,
            "types": types,
            "hierarchy_distribution": orders
        }
        
        logger.debug(f"Storage summary:")
        logger.debug(f"  Total: {summary['total']}")
        logger.debug(f"  Valid: {summary['valid']}")
        logger.debug(f"  Invalid: {summary['invalid']}")
        logger.debug(f"  Types: {summary['types']}")
        logger.debug(f"  Hierarchy distribution: {summary['hierarchy_distribution']}")
        
        return summary
    
    @staticmethod
    def _log_storage_state():
        """Internal method to log current storage state for debugging"""
        logger.debug(f"=== CURRENT STORAGE STATE ===")
        logger.debug(f"Total certificates: {len(uploaded_certificates)}")
        
        for i, cert in enumerate(uploaded_certificates):
            analysis = cert.get('analysis', {})
            order = CertificateStorage.get_certificate_order(cert)
            logger.debug(f"  [{i}] Order {order}: {cert.get('filename', 'NO_FILENAME')}")
            logger.debug(f"      ID: {cert.get('id', 'NO_ID')}")
            logger.debug(f"      Type: {analysis.get('type', 'NO_TYPE')}")
            logger.debug(f"      Valid: {analysis.get('isValid', 'NO_VALID')}")
            logger.debug(f"      Hash: {analysis.get('content_hash', 'NO_HASH')[:16] if analysis.get('content_hash') else 'NO_HASH'}...")
            logger.debug(f"      Uploaded: {cert.get('uploadedAt', 'NO_TIME')}")
        
        logger.debug(f"=== END STORAGE STATE ===")
    
    @staticmethod
    def debug_hierarchy_enforcement(filename: str):
        """Debug helper for hierarchy enforcement issues"""
        logger.info(f"=== HIERARCHY ENFORCEMENT DEBUG ===")
        logger.info(f"Analyzing hierarchy for: {filename}")
        
        logger.info(f"Current PKI hierarchy distribution:")
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
            order = CertificateStorage.get_certificate_order(cert)
            order_name = order_names.get(order, f"Order {order}")
            hierarchy_counts[order_name] = hierarchy_counts.get(order_name, 0) + 1
        
        for order_name, count in hierarchy_counts.items():
            logger.info(f"  {order_name}: {count}")
        
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
            logger.warning(f"PKI Hierarchy violations detected:")
            for violation in violations:
                logger.warning(f"  - {violation}")
        else:
            logger.info(f"PKI Hierarchy is properly enforced")
        
        logger.info(f"=== END HIERARCHY ENFORCEMENT DEBUG ===")