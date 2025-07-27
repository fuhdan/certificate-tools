# certificates/extractors/certificate.py
# Certificate detail extraction functions with comprehensive debugging

import datetime
import logging
from typing import Dict, Any, cast
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec

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

def extract_x509_details(cert: x509.Certificate) -> Dict[str, Any]:
    """Extract detailed information from X.509 certificate"""
    logger.info(f"=== X.509 CERTIFICATE EXTRACTION ===")
    logger.debug(f"Certificate object type: {type(cert)}")
    
    details = {
        "subject": {},
        "issuer": {},
        "validity": {},
        "publicKey": {},
        "signature": {},
        "extensions": {},
        "serialNumber": str(cert.serial_number)
    }
    
    logger.debug(f"Certificate serial number: {details['serialNumber']}")
    
    try:
        # Subject information
        logger.debug("Extracting subject information...")
        subject_attrs = {}
        subject_count = len(cert.subject)
        logger.debug(f"Found {subject_count} subject attributes")
        
        for i, attribute in enumerate(cert.subject):
            attr_name = attribute.oid._name
            attr_value = attribute.value
            subject_attrs[attr_name] = attr_value
            logger.debug(f"  Subject attribute [{i}]: {attr_name} = {attr_value}")
        
        details["subject"] = {
            "commonName": subject_attrs.get("commonName", "N/A"),
            "organization": subject_attrs.get("organizationName", "N/A"),
            "organizationalUnit": subject_attrs.get("organizationalUnitName", "N/A"),
            "country": subject_attrs.get("countryName", "N/A"),
            "state": subject_attrs.get("stateOrProvinceName", "N/A"),
            "locality": subject_attrs.get("localityName", "N/A"),
            "emailAddress": subject_attrs.get("emailAddress", "N/A")
        }
        logger.debug(f"Subject details: {details['subject']}")
        
        # Issuer information
        logger.debug("Extracting issuer information...")
        issuer_attrs = {}
        issuer_count = len(cert.issuer)
        logger.debug(f"Found {issuer_count} issuer attributes")
        
        for i, attribute in enumerate(cert.issuer):
            attr_name = attribute.oid._name
            attr_value = attribute.value
            issuer_attrs[attr_name] = attr_value
            logger.debug(f"  Issuer attribute [{i}]: {attr_name} = {attr_value}")
        
        details["issuer"] = {
            "commonName": issuer_attrs.get("commonName", "N/A"),
            "organization": issuer_attrs.get("organizationName", "N/A"),
            "organizationalUnit": issuer_attrs.get("organizationalUnitName", "N/A"),
            "country": issuer_attrs.get("countryName", "N/A"),
            "state": issuer_attrs.get("stateOrProvinceName", "N/A"),
            "locality": issuer_attrs.get("localityName", "N/A"),
            "emailAddress": issuer_attrs.get("emailAddress", "N/A")
        }
        logger.debug(f"Issuer details: {details['issuer']}")
        
        # Validity information
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
        
        details["validity"] = {
            "notBefore": not_before,
            "notAfter": not_after,
            "isExpired": is_expired,
            "daysUntilExpiry": days_until_expiry
        }
        
        # Public key information
        logger.debug("Extracting public key information...")
        public_key = cert.public_key()
        details["publicKey"] = extract_public_key_details(public_key)
        
        # Signature algorithm
        logger.debug("Extracting signature algorithm...")
        sig_alg_name = cert.signature_algorithm_oid._name
        sig_alg_oid = cert.signature_algorithm_oid.dotted_string
        logger.debug(f"  Signature algorithm: {sig_alg_name}")
        logger.debug(f"  Signature algorithm OID: {sig_alg_oid}")
        
        details["signature"] = {
            "algorithm": sig_alg_name,
            "algorithmOid": sig_alg_oid
        }
        
        # Extensions
        logger.debug("Extracting certificate extensions...")
        extensions = {}
        extension_count = len(cert.extensions)
        logger.debug(f"Found {extension_count} extensions")
        
        for i, ext in enumerate(cert.extensions):
            ext_oid = ext.oid.dotted_string
            ext_critical = ext.critical
            logger.debug(f"  Extension [{i}]: OID {ext_oid}, Critical: {ext_critical}")
            
            if isinstance(ext.value, x509.SubjectAlternativeName):
                logger.debug("    Processing Subject Alternative Name extension")
                san_list = []
                for j, name in enumerate(ext.value):
                    if isinstance(name, x509.DNSName):
                        san_entry = {"type": 2, "typeName": "DNS", "value": name.value}
                        logger.debug(f"      SAN [{j}]: DNS = {name.value}")
                    elif isinstance(name, x509.IPAddress):
                        san_entry = {"type": 7, "typeName": "IP", "value": str(name.value)}
                        logger.debug(f"      SAN [{j}]: IP = {str(name.value)}")
                    elif isinstance(name, x509.RFC822Name):
                        san_entry = {"type": 1, "typeName": "Email", "value": name.value}
                        logger.debug(f"      SAN [{j}]: Email = {name.value}")
                    else:
                        san_entry = {"type": 0, "typeName": "Other", "value": str(name)}
                        logger.debug(f"      SAN [{j}]: Other = {str(name)}")
                    san_list.append(san_entry)
                extensions["subjectAltName"] = san_list
                logger.debug(f"    Total SAN entries: {len(san_list)}")
                
            elif isinstance(ext.value, x509.BasicConstraints):
                logger.debug("    Processing Basic Constraints extension")
                is_ca = ext.value.ca
                path_length = ext.value.path_length
                logger.debug(f"      CA: {is_ca}")
                logger.debug(f"      Path length: {path_length}")
                extensions["basicConstraints"] = {
                    "isCA": is_ca,
                    "pathLength": path_length
                }
                
            elif isinstance(ext.value, x509.KeyUsage):
                logger.debug("    Processing Key Usage extension")
                key_usage = {
                    "digitalSignature": ext.value.digital_signature,
                    "keyEncipherment": ext.value.key_encipherment,
                    "keyAgreement": ext.value.key_agreement,
                    "keyCertSign": ext.value.key_cert_sign,
                    "crlSign": ext.value.crl_sign
                }
                logger.debug(f"      Key usage flags: {key_usage}")
                extensions["keyUsage"] = key_usage

        # Extended Key Usage (separate try block as it's optional)
        try:
            logger.debug("Checking for Extended Key Usage extension...")
            # Fix: Get the extension object first, then access its value
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            # Use cast to tell type checker the correct type
            eku_value = cast(x509.ExtendedKeyUsage, eku_ext.value)
            eku_usages = []
            logger.debug(f"Found Extended Key Usage extension")
            
            # Use a counter instead of enumerate to avoid type issues
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
                    logger.debug(f"    EKU [{j}]: Unknown OID {usage_oid.dotted_string}")
                
                eku_usages.append(usage_name)
                j += 1
            
            extensions["extendedKeyUsage"] = eku_usages
            logger.debug(f"Extended Key Usage processed: {eku_usages}")
            
        except x509.ExtensionNotFound:
            logger.debug("No Extended Key Usage extension found")
        except Exception as eku_error:
            logger.error(f"Error processing Extended Key Usage: {eku_error}")
        
        details["extensions"] = extensions
        logger.debug(f"Total extensions processed: {len(extensions)}")
        
    except Exception as e:
        logger.error(f"Error extracting certificate details: {e}")
        logger.error(f"Certificate object: {cert}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
    
    logger.info(f"Certificate extraction complete")
    logger.debug(f"Final details structure keys: {list(details.keys())}")
    return details

def is_ca_certificate(cert: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate"""
    logger.debug("=== CA CERTIFICATE CHECK ===")
    
    try:
        # Fix: Get the extension object first, then access its value
        basic_constraints_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        # Use cast to tell type checker the correct type
        basic_constraints = cast(x509.BasicConstraints, basic_constraints_ext.value)
        is_ca = basic_constraints.ca
        logger.debug(f"Basic Constraints found - CA: {is_ca}")
        return is_ca
    except x509.ExtensionNotFound:
        logger.debug("No Basic Constraints extension found - assuming end-entity certificate")
        return False
    except Exception as e:
        logger.error(f"Error checking CA status: {e}")
        return False