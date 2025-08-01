# backend-fastapi/certificates/extractors/certificate.py
# COMPLETE FILE - Fixed key usage extraction error that prevents SAN extraction

import datetime
import logging
from typing import Dict, Any, cast
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)
logger.debug("extractors/certificate.py initialized")

def extract_public_key_details(public_key) -> Dict[str, Any]:
    """Extract details from public key"""
    logger.debug(f"=== PUBLIC KEY EXTRACTION ===")
    logger.debug(f"Public key type: {type(public_key).__name__}")
    
    details = {
        "algorithm": "Unknown",
        "keySize": 0,
        "curve": "N/A"
    }
    
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            logger.debug("Extracting RSA public key details")
            details["algorithm"] = "RSA"
            details["keySize"] = public_key.key_size
            details["exponent"] = str(public_key.public_numbers().e)
            logger.debug(f"RSA key size: {details['keySize']} bits")
            logger.debug(f"RSA exponent: {details['exponent']}")
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            logger.debug("Extracting EC public key details")
            details["algorithm"] = "EC"
            details["curve"] = public_key.curve.name
            logger.debug(f"EC curve: {details['curve']}")
        else:
            logger.warning(f"Unknown public key type: {type(public_key)}")
            
    except Exception as e:
        logger.error(f"Error extracting public key details: {e}")
        logger.error(f"Public key object: {public_key}")
    
    logger.debug(f"Public key details extracted: {details}")
    return details

def extract_certificate_metadata(cert: x509.Certificate) -> Dict[str, Any]:
    """Extract flattened certificate metadata for direct storage"""
    logger.info(f"=== CERTIFICATE METADATA EXTRACTION ===")
    logger.debug(f"Certificate object type: {type(cert)}")
    
    # Calculate fingerprint
    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
    
    # Basic certificate info
    is_ca = _is_ca_certificate(cert)
    is_self_signed = cert.subject == cert.issuer
    
    # Initialize flattened metadata with basic info
    metadata = {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': str(cert.serial_number),
        'is_ca': is_ca,
        'is_self_signed': is_self_signed,
        'fingerprint_sha256': fingerprint_sha256,
        
        # Initialize all extension fields as empty
        'subject_alt_name': [],
        'key_usage': {},
        'extended_key_usage': [],
        'basic_constraints': {},
        'authority_key_identifier': None,
        'subject_key_identifier': None
    }
    
    logger.debug(f"Certificate serial number: {metadata['serial_number']}")
    
    try:
        # Subject information (detailed)
        logger.debug("Extracting subject information...")
        subject_attrs = {}
        subject_count = len(cert.subject)
        logger.debug(f"Found {subject_count} subject attributes")
        
        for i, attribute in enumerate(cert.subject):
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
        logger.debug(f"Subject details extracted")
        
        # Issuer information (detailed)
        logger.debug("Extracting issuer information...")
        issuer_attrs = {}
        issuer_count = len(cert.issuer)
        logger.debug(f"Found {issuer_count} issuer attributes")
        
        for i, attribute in enumerate(cert.issuer):
            attr_name = attribute.oid._name
            attr_value = attribute.value
            issuer_attrs[attr_name] = attr_value
            logger.debug(f"  Issuer attribute [{i}]: {attr_name} = {attr_value}")
        
        # Add detailed issuer fields
        metadata.update({
            'issuer_common_name': issuer_attrs.get("commonName", "N/A"),
            'issuer_organization': issuer_attrs.get("organizationName", "N/A"),
            'issuer_organizational_unit': issuer_attrs.get("organizationalUnitName", "N/A"),
            'issuer_country': issuer_attrs.get("countryName", "N/A"),
            'issuer_state': issuer_attrs.get("stateOrProvinceName", "N/A"),
            'issuer_locality': issuer_attrs.get("localityName", "N/A"),
            'issuer_email': issuer_attrs.get("emailAddress", "N/A")
        })
        logger.debug(f"Issuer details extracted")
        
        # Validity information (detailed)
        logger.debug("Extracting validity information...")
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        now = datetime.datetime.now(datetime.timezone.utc)
        is_expired = now > cert.not_valid_after_utc
        days_until_expiry = (cert.not_valid_after_utc - now).days
        
        logger.debug(f"  Not before: {not_before}")
        logger.debug(f"  Not after: {not_after}")
        logger.debug(f"  Is expired: {is_expired}")
        logger.debug(f"  Days until expiry: {days_until_expiry}")
        
        metadata.update({
            'not_valid_before': not_before,
            'not_valid_after': not_after,
            'is_expired': is_expired,
            'days_until_expiry': days_until_expiry
        })
        
        # Public key information (detailed)
        logger.debug("Extracting public key information...")
        public_key = cert.public_key()
        public_key_details = extract_public_key_details(public_key)
        
        metadata.update({
            'public_key_algorithm': public_key_details.get("algorithm", "Unknown"),
            'public_key_size': public_key_details.get("keySize", 0)
        })
        
        # Add algorithm-specific details
        if public_key_details.get("algorithm") == "RSA":
            metadata['public_key_exponent'] = public_key_details.get("exponent", "N/A")
        elif public_key_details.get("algorithm") == "EC":
            metadata['public_key_curve'] = public_key_details.get("curve", "N/A")
        
        # Signature algorithm (detailed)
        logger.debug("Extracting signature algorithm...")
        sig_alg_name = cert.signature_algorithm_oid._name
        sig_alg_oid = cert.signature_algorithm_oid.dotted_string
        logger.debug(f"  Signature algorithm: {sig_alg_name}")
        logger.debug(f"  Signature algorithm OID: {sig_alg_oid}")
        
        metadata.update({
            'signature_algorithm': sig_alg_name,
            'signature_algorithm_oid': sig_alg_oid
        })
        
        # Certificate extensions (detailed) - FIXED ORDERING
        logger.debug("Extracting certificate extensions...")
        ext_count = len(cert.extensions)
        logger.debug(f"Found {ext_count} extensions")
        
        # Process extensions individually with proper error handling
        for i, ext in enumerate(cert.extensions):
            logger.debug(f"  Extension [{i}]: OID {ext.oid.dotted_string}, Critical: {ext.critical}")
            
            try:
                # Subject Alternative Name - HIGHEST PRIORITY
                if isinstance(ext.value, x509.SubjectAlternativeName):
                    logger.debug("    Processing Subject Alternative Name extension")
                    san_list = []
                    san_count = len(ext.value)
                    logger.debug(f"      Found {san_count} SAN entries")
                    
                    for j, name in enumerate(ext.value):
                        if isinstance(name, x509.DNSName):
                            san_entry = f"DNS:{name.value}"
                            logger.debug(f"        SAN [{j}]: {san_entry}")
                            san_list.append(san_entry)
                        elif isinstance(name, x509.IPAddress):
                            san_entry = f"IP:{str(name.value)}"
                            logger.debug(f"        SAN [{j}]: {san_entry}")
                            san_list.append(san_entry)
                        elif isinstance(name, x509.RFC822Name):
                            san_entry = f"Email:{name.value}"
                            logger.debug(f"        SAN [{j}]: {san_entry}")
                            san_list.append(san_entry)
                        elif isinstance(name, x509.UniformResourceIdentifier):
                            san_entry = f"URI:{name.value}"
                            logger.debug(f"        SAN [{j}]: {san_entry}")
                            san_list.append(san_entry)
                        else:
                            san_entry = f"Other:{str(name)}"
                            logger.debug(f"        SAN [{j}]: {san_entry}")
                            san_list.append(san_entry)
                    
                    metadata['subject_alt_name'] = san_list
                    logger.debug(f"      Subject Alternative Names processed: {san_list}")
                    
                # Basic Constraints
                elif isinstance(ext.value, x509.BasicConstraints):
                    logger.debug("    Processing Basic Constraints extension")
                    is_ca = ext.value.ca
                    path_length = ext.value.path_length
                    logger.debug(f"      CA: {is_ca}")
                    logger.debug(f"      Path length: {path_length}")
                    metadata['basic_constraints'] = {
                        'is_ca': is_ca,
                        'path_length': path_length
                    }
                    
                # Key Usage - FIXED ERROR HANDLING
                elif isinstance(ext.value, x509.KeyUsage):
                    logger.debug("    Processing Key Usage extension")
                    
                    # Safe key usage extraction with proper conditionals
                    key_usage = {
                        'digital_signature': ext.value.digital_signature,
                        'content_commitment': ext.value.content_commitment,
                        'key_encipherment': ext.value.key_encipherment,
                        'data_encipherment': ext.value.data_encipherment,
                        'key_agreement': ext.value.key_agreement,
                        'key_cert_sign': ext.value.key_cert_sign,
                        'crl_sign': ext.value.crl_sign,
                    }
                    
                    # CRITICAL FIX: Only access encipher_only/decipher_only if key_agreement is true
                    if ext.value.key_agreement:
                        try:
                            key_usage['encipher_only'] = ext.value.encipher_only
                            key_usage['decipher_only'] = ext.value.decipher_only
                        except Exception as encipher_error:
                            logger.warning(f"      Could not extract encipher flags: {encipher_error}")
                            key_usage['encipher_only'] = False
                            key_usage['decipher_only'] = False
                    else:
                        key_usage['encipher_only'] = False
                        key_usage['decipher_only'] = False
                        
                    logger.debug(f"      Key usage flags: {key_usage}")
                    metadata['key_usage'] = key_usage
                    
                # Authority Key Identifier
                elif isinstance(ext.value, x509.AuthorityKeyIdentifier):
                    logger.debug("    Processing Authority Key Identifier extension")
                    try:
                        auth_key_id = ext.value.key_identifier.hex().upper() if ext.value.key_identifier else None
                        metadata['authority_key_identifier'] = auth_key_id
                        logger.debug(f"      Authority Key ID: {auth_key_id}")
                    except Exception as aki_error:
                        logger.error(f"      Error processing Authority Key Identifier: {aki_error}")
                        
                # Subject Key Identifier
                elif isinstance(ext.value, x509.SubjectKeyIdentifier):
                    logger.debug("    Processing Subject Key Identifier extension")
                    try:
                        subj_key_id = ext.value.digest.hex().upper()
                        metadata['subject_key_identifier'] = subj_key_id
                        logger.debug(f"      Subject Key ID: {subj_key_id}")
                    except Exception as ski_error:
                        logger.error(f"      Error processing Subject Key Identifier: {ski_error}")
                        
                else:
                    logger.debug(f"    Skipping unsupported extension: {ext.oid.dotted_string}")
                    
            except Exception as ext_error:
                logger.error(f"    Error processing extension {ext.oid.dotted_string}: {ext_error}")
                continue
        
        # Extended Key Usage (separate try block as it's optional)
        try:
            logger.debug("Checking for Extended Key Usage extension...")
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_value = cast(x509.ExtendedKeyUsage, eku_ext.value)
            eku_usages = []
            logger.debug(f"Found Extended Key Usage extension")
            
            j = 0
            for usage_oid in eku_value:
                if usage_oid == ExtendedKeyUsageOID.SERVER_AUTH:
                    usage_name = "serverAuth"
                    logger.debug(f"    EKU [{j}]: Server Authentication")
                elif usage_oid == ExtendedKeyUsageOID.CLIENT_AUTH:
                    usage_name = "clientAuth"
                    logger.debug(f"    EKU [{j}]: Client Authentication")
                elif usage_oid == ExtendedKeyUsageOID.CODE_SIGNING:
                    usage_name = "codeSign"
                    logger.debug(f"    EKU [{j}]: Code Signing")
                elif usage_oid == ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    usage_name = "emailProtection"
                    logger.debug(f"    EKU [{j}]: Email Protection")
                elif usage_oid == ExtendedKeyUsageOID.TIME_STAMPING:
                    usage_name = "timeStamping"
                    logger.debug(f"    EKU [{j}]: Time Stamping")
                elif usage_oid == ExtendedKeyUsageOID.OCSP_SIGNING:
                    usage_name = "OCSPSigning"
                    logger.debug(f"    EKU [{j}]: OCSP Signing")
                else:
                    usage_name = usage_oid.dotted_string
                    logger.debug(f"    EKU [{j}]: Unknown ({usage_name})")
                
                eku_usages.append(usage_name)
                j += 1
            
            metadata['extended_key_usage'] = eku_usages
            logger.debug(f"Extended Key Usage: {eku_usages}")
            
        except x509.ExtensionNotFound:
            logger.debug("No Extended Key Usage extension found")
        except Exception as eku_error:
            logger.error(f"Error processing Extended Key Usage: {eku_error}")
    
    except Exception as e:
        logger.error(f"Error extracting certificate details: {e}")
        logger.error(f"Certificate object: {cert}")
        
        # Import traceback for full error details
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
    
    logger.info(f"Certificate metadata extraction complete")
    logger.debug(f"Final metadata structure keys: {list(metadata.keys())}")
    return metadata

def _is_ca_certificate(cert: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate"""
    logger.debug(f"=== CA CERTIFICATE CHECK ===")
    
    try:
        # Check Basic Constraints extension
        basic_constraints_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        basic_constraints = cast(x509.BasicConstraints, basic_constraints_ext.value)
        is_ca = basic_constraints.ca
        logger.debug(f"Basic Constraints found - CA: {is_ca}")
        return is_ca
    except x509.ExtensionNotFound:
        logger.debug("No Basic Constraints extension found - assuming not CA")
        return False
    except Exception as e:
        logger.error(f"Error checking CA status: {e}")
        return False

def is_ca_certificate(cert: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate (public interface for imports)"""
    return _is_ca_certificate(cert)