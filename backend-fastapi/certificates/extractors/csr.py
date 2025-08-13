# backend-fastapi/certificates/extractors/csr.py
# FIXED: Updated to use consistent sha256_fingerprint naming and proper error handling

import logging
from typing import Dict, Any, cast
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization
import hashlib
from .certificate import extract_public_key_details

logger = logging.getLogger(__name__)

logger.debug("extractors/csr.py initialized")

def extract_csr_metadata(csr: x509.CertificateSigningRequest) -> Dict[str, Any]:
    """Extract flattened CSR metadata for direct storage"""
    logger.info(f"=== CSR METADATA EXTRACTION ===")
    logger.debug(f"CSR object type: {type(csr)}")
    
    # FIXED: Calculate public key fingerprint using DER encoding for consistency
    public_key = csr.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,  # FIXED: Use DER instead of PEM
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha256_fingerprint = hashlib.sha256(public_key_der).hexdigest().upper()
    
    # FIXED: Initialize flattened metadata with consistent field name
    metadata = {
        'subject': csr.subject.rfc4514_string(),
        'signature_algorithm': csr.signature_algorithm_oid._name,
        'public_key_algorithm': type(csr.public_key()).__name__.replace('PublicKey', ''),
        'public_key_size': getattr(csr.public_key(), 'key_size', None),
        'sha256_fingerprint': sha256_fingerprint,  # FIXED: Consistent naming
        
        # Initialize all extension fields as empty
        'subject_alt_name': [],
        'key_usage': {},
        'extended_key_usage': [],
        'basic_constraints': {}
    }
    
    try:
        # Subject information (detailed)
        logger.debug("Extracting CSR subject information...")
        subject_attrs = {}
        subject_count = len(csr.subject)
        logger.debug(f"Found {subject_count} subject attributes")
        
        for i, attribute in enumerate(csr.subject):
            attr_name = attribute.oid._name
            attr_value = attribute.value
            subject_attrs[attr_name] = attr_value
            logger.debug(f"  Subject attribute [{i}]: {attr_name} = {attr_value}")
        
        # Add detailed subject fields
        metadata.update({
            'subject_common_name': subject_attrs.get("commonName", "N/A"),
            'subject_organization': subject_attrs.get("organizationName", "N/A"),
            'subject_organizational_unit': subject_attrs.get("organizationalUnitName", "N/A"),
            'subject_country': subject_attrs.get("countryName", "N/A"),
            'subject_state': subject_attrs.get("stateOrProvinceName", "N/A"),
            'subject_locality': subject_attrs.get("localityName", "N/A"),
            'subject_email': subject_attrs.get("emailAddress", "N/A")
        })
        logger.debug(f"CSR subject details extracted")
        
        # Public key information (detailed)
        logger.debug("Extracting CSR public key information...")
        public_key_details = extract_public_key_details(public_key)
        
        # Add detailed public key fields
        metadata.update({
            'public_key_algorithm_detailed': public_key_details.get("algorithm", "Unknown"),
            'public_key_size_detailed': public_key_details.get("keySize", 0)
        })
        
        # Add algorithm-specific details
        if public_key_details.get("algorithm") == "RSA":
            metadata['public_key_exponent'] = public_key_details.get("exponent", "N/A")
        elif public_key_details.get("algorithm") == "EC":
            metadata['public_key_curve'] = public_key_details.get("curve", "N/A")
        
        # Signature algorithm (detailed)
        logger.debug("Extracting CSR signature algorithm...")
        sig_alg_name = csr.signature_algorithm_oid._name
        sig_alg_oid = csr.signature_algorithm_oid.dotted_string
        logger.debug(f"  CSR signature algorithm: {sig_alg_name}")
        logger.debug(f"  CSR signature algorithm OID: {sig_alg_oid}")
        
        metadata['signature_algorithm_oid'] = sig_alg_oid

        # Extract extensions from CSR (comprehensive)
        logger.debug("Extracting CSR extensions...")
        extension_count = len(csr.extensions)
        logger.debug(f"Found {extension_count} CSR extensions")
        
        # Process Subject Alternative Name extension
        try:
            logger.debug("Checking for Subject Alternative Name extension in CSR...")
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = cast(x509.SubjectAlternativeName, san_ext.value)
            san_list = []
            
            logger.debug(f"Found SAN extension")
            for i, name in enumerate(san):
                if isinstance(name, x509.DNSName):
                    san_entry = f"DNS:{name.value}"
                    logger.debug(f"    SAN [{i}]: DNS = {name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_entry = f"IP:{str(name.value)}"
                    logger.debug(f"    SAN [{i}]: IP = {str(name.value)}")
                elif isinstance(name, x509.RFC822Name):
                    san_entry = f"Email:{name.value}"
                    logger.debug(f"    SAN [{i}]: Email = {name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_entry = f"URI:{name.value}"
                    logger.debug(f"    SAN [{i}]: URI = {name.value}")
                else:
                    san_entry = f"Other:{str(name)}"
                    logger.debug(f"    SAN [{i}]: Other = {str(name)} (type: {type(name)})")
                
                san_list.append(san_entry)
            
            if san_list:
                metadata['subject_alt_name'] = san_list
                logger.debug(f"Subject Alternative Name processed: {len(san_list)} entries")
                
        except x509.ExtensionNotFound:
            logger.debug("No Subject Alternative Name extension found in CSR")
            metadata['subject_alt_name'] = []  # FIXED: Ensure empty list instead of missing field
        except Exception as san_error:
            logger.error(f"Error processing SAN extension in CSR: {san_error}")
            metadata['subject_alt_name'] = []  # FIXED: Ensure empty list on error

        # Process Basic Constraints extension (if present in CSR)
        try:
            logger.debug("Checking for Basic Constraints extension in CSR...")
            bc_ext = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            bc_value = cast(x509.BasicConstraints, bc_ext.value)
            is_ca = bc_value.ca
            path_length = bc_value.path_length
            
            logger.debug(f"Found Basic Constraints - CA: {is_ca}, Path Length: {path_length}")
            metadata['basic_constraints'] = {
                'is_ca': is_ca,
                'path_length': path_length
            }
        except x509.ExtensionNotFound:
            logger.debug("No Basic Constraints extension found in CSR")
            metadata['basic_constraints'] = {}  # FIXED: Ensure empty dict
        except Exception as bc_error:
            logger.error(f"Error processing Basic Constraints in CSR: {bc_error}")
            metadata['basic_constraints'] = {}  # FIXED: Ensure empty dict on error

        # FIXED: Process Key Usage extension with proper error handling
        try:
            logger.debug("Checking for Key Usage extension in CSR...")
            ku_ext = csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku_value = cast(x509.KeyUsage, ku_ext.value)
            
            key_usage = {
                'digital_signature': ku_value.digital_signature,
                'key_encipherment': ku_value.key_encipherment,
                'key_agreement': ku_value.key_agreement,
                'key_cert_sign': ku_value.key_cert_sign,
                'crl_sign': ku_value.crl_sign,
                'content_commitment': ku_value.content_commitment,
                'data_encipherment': ku_value.data_encipherment,
                # FIXED: Only access encipher_only/decipher_only if key_agreement is True
                'encipher_only': ku_value.encipher_only if ku_value.key_agreement else False,
                'decipher_only': ku_value.decipher_only if ku_value.key_agreement else False,
            }
                
            logger.debug(f"Found Key Usage - flags: {key_usage}")
            metadata['key_usage'] = key_usage
            
        except x509.ExtensionNotFound:
            logger.debug("No Key Usage extension found in CSR")
            metadata['key_usage'] = {}  # FIXED: Ensure empty dict
        except Exception as ku_error:
            logger.error(f"Error processing Key Usage in CSR: {ku_error}")
            metadata['key_usage'] = {}  # FIXED: Ensure empty dict on error

        # Process Extended Key Usage extension (if present in CSR)
        try:
            logger.debug("Checking for Extended Key Usage extension in CSR...")
            eku_ext = csr.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_value = cast(x509.ExtendedKeyUsage, eku_ext.value)
            eku_usages = []
            
            logger.debug(f"Found Extended Key Usage extension")
            for i, usage_oid in enumerate(eku_value):
                usage_name = usage_oid.dotted_string  # Default to OID string
                
                # Map known OIDs to readable names
                if usage_oid == ExtendedKeyUsageOID.SERVER_AUTH:
                    usage_name = "serverAuth"
                    logger.debug(f"    EKU [{i}]: Server Authentication")
                elif usage_oid == ExtendedKeyUsageOID.CLIENT_AUTH:
                    usage_name = "clientAuth"
                    logger.debug(f"    EKU [{i}]: Client Authentication")
                elif usage_oid == ExtendedKeyUsageOID.CODE_SIGNING:
                    usage_name = "codeSigning"
                    logger.debug(f"    EKU [{i}]: Code Signing")
                elif usage_oid == ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    usage_name = "emailProtection"
                    logger.debug(f"    EKU [{i}]: Email Protection")
                else:
                    logger.debug(f"    EKU [{i}]: Unknown OID {usage_oid.dotted_string}")
                
                eku_usages.append(usage_name)
            
            if eku_usages:
                metadata['extended_key_usage'] = eku_usages
                logger.debug(f"Extended Key Usage processed: {eku_usages}")
                
        except x509.ExtensionNotFound:
            logger.debug("No Extended Key Usage extension found in CSR")
            metadata['extended_key_usage'] = []  # FIXED: Ensure empty list
        except Exception as eku_error:
            logger.error(f"Error processing Extended Key Usage in CSR: {eku_error}")
            metadata['extended_key_usage'] = []  # FIXED: Ensure empty list on error

        # Check for other extensions
        logger.debug("Checking for additional CSR extensions...")
        for i, ext in enumerate(csr.extensions):
            ext_oid = ext.oid.dotted_string
            ext_critical = ext.critical
            logger.debug(f"  Extension [{i}]: OID {ext_oid}, Critical: {ext_critical}")
            
            # Log unhandled extensions
            if (ext.oid != ExtensionOID.SUBJECT_ALTERNATIVE_NAME and 
                ext.oid != ExtensionOID.BASIC_CONSTRAINTS and
                ext.oid != ExtensionOID.KEY_USAGE and
                ext.oid != ExtensionOID.EXTENDED_KEY_USAGE):
                logger.debug(f"    Unhandled extension: {ext_oid}")
        
        logger.debug(f"Total CSR extensions processed")
        
    except Exception as e:
        logger.error(f"Error extracting CSR details: {e}")
        logger.error(f"CSR object: {csr}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
    
    logger.info(f"CSR metadata extraction complete")
    logger.debug(f"Final CSR metadata structure keys: {list(metadata.keys())}")
    return metadata