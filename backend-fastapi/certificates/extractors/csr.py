# certificates/extractors/csr.py
# CSR detail extraction functions with comprehensive debugging

import logging
from typing import Dict, Any
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from .certificate import extract_public_key_details

logger = logging.getLogger(__name__)

logger.debug("extractors/csr.py initialized")

def extract_csr_details(csr: x509.CertificateSigningRequest) -> Dict[str, Any]:
    """Extract details from CSR"""
    logger.info(f"=== CSR EXTRACTION ===")
    logger.debug(f"CSR object type: {type(csr)}")
    
    details = {
        "subject": {},
        "publicKey": {},
        "signature": {},
        "extensions": {}
    }
    
    try:
        # Subject information
        logger.debug("Extracting CSR subject information...")
        subject_attrs = {}
        subject_count = len(csr.subject)
        logger.debug(f"Found {subject_count} subject attributes")
        
        for i, attribute in enumerate(csr.subject):
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
        logger.debug(f"CSR subject details: {details['subject']}")
        
        # Public key information
        logger.debug("Extracting CSR public key information...")
        public_key = csr.public_key()
        details["publicKey"] = extract_public_key_details(public_key)
        
        # Signature algorithm
        logger.debug("Extracting CSR signature algorithm...")
        sig_alg_name = csr.signature_algorithm_oid._name
        sig_alg_oid = csr.signature_algorithm_oid.dotted_string
        logger.debug(f"  CSR signature algorithm: {sig_alg_name}")
        logger.debug(f"  CSR signature algorithm OID: {sig_alg_oid}")
        
        details["signature"] = {
            "algorithm": sig_alg_name,
            "algorithmOid": sig_alg_oid
        }

        # Extract extensions from CSR
        logger.debug("Extracting CSR extensions...")
        extensions = {}
        extension_count = len(csr.extensions)
        logger.debug(f"Found {extension_count} CSR extensions")
        
        # Process Subject Alternative Name extension
        try:
            logger.debug("Checking for Subject Alternative Name extension in CSR...")
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = san_ext.value
            san_list = []
            
            logger.debug(f"Found SAN extension with {len(san)} entries")
            for i, name in enumerate(san):
                if isinstance(name, x509.DNSName):
                    san_entry = {"type": 2, "typeName": "DNS", "value": name.value}
                    logger.debug(f"    SAN [{i}]: DNS = {name.value}")
                elif isinstance(name, x509.IPAddress):
                    ip_str = str(name.value)
                    san_entry = {"type": 7, "typeName": "IP", "value": ip_str}
                    logger.debug(f"    SAN [{i}]: IP = {ip_str}")
                elif isinstance(name, x509.RFC822Name):
                    san_entry = {"type": 1, "typeName": "Email", "value": name.value}
                    logger.debug(f"    SAN [{i}]: Email = {name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_entry = {"type": 6, "typeName": "URI", "value": name.value}
                    logger.debug(f"    SAN [{i}]: URI = {name.value}")
                else:
                    san_entry = {"type": 0, "typeName": "Other", "value": str(name)}
                    logger.debug(f"    SAN [{i}]: Other = {str(name)} (type: {type(name)})")
                
                san_list.append(san_entry)
            
            if san_list:
                extensions["subjectAltName"] = san_list
                logger.debug(f"Subject Alternative Name processed: {len(san_list)} entries")
                
        except x509.ExtensionNotFound:
            logger.debug("No Subject Alternative Name extension found in CSR")
        except Exception as san_error:
            logger.error(f"Error processing SAN extension in CSR: {san_error}")
            logger.error(f"SAN extension details: {san_ext if 'san_ext' in locals() else 'Not available'}")

        # Process Basic Constraints extension (if present in CSR)
        try:
            logger.debug("Checking for Basic Constraints extension in CSR...")
            bc_ext = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            bc_value = bc_ext.value
            is_ca = bc_value.ca
            path_length = bc_value.path_length
            
            logger.debug(f"Found Basic Constraints - CA: {is_ca}, Path Length: {path_length}")
            extensions["basicConstraints"] = {
                "isCA": is_ca,
                "pathLength": path_length
            }
        except x509.ExtensionNotFound:
            logger.debug("No Basic Constraints extension found in CSR")
        except Exception as bc_error:
            logger.error(f"Error processing Basic Constraints in CSR: {bc_error}")

        # Process Key Usage extension (if present in CSR)
        try:
            logger.debug("Checking for Key Usage extension in CSR...")
            ku_ext = csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku_value = ku_ext.value
            
            key_usage = {
                "digitalSignature": ku_value.digital_signature,
                "keyEncipherment": ku_value.key_encipherment,
                "keyAgreement": ku_value.key_agreement,
                "keyCertSign": ku_value.key_cert_sign,
                "crlSign": ku_value.crl_sign
            }
            logger.debug(f"Found Key Usage - flags: {key_usage}")
            extensions["keyUsage"] = key_usage
            
        except x509.ExtensionNotFound:
            logger.debug("No Key Usage extension found in CSR")
        except Exception as ku_error:
            logger.error(f"Error processing Key Usage in CSR: {ku_error}")

        # Process Extended Key Usage extension (if present in CSR)
        try:
            logger.debug("Checking for Extended Key Usage extension in CSR...")
            eku_ext = csr.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_value = eku_ext.value
            eku_usages = []
            
            logger.debug(f"Found Extended Key Usage with {len(eku_value)} usages")
            for i, usage_oid in enumerate(eku_value):
                usage_name = usage_oid.dotted_string  # Default to OID string
                
                # Map known OIDs to readable names
                if hasattr(x509.oid.ExtendedKeyUsageOID, 'SERVER_AUTH') and usage_oid == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    usage_name = "serverAuth"
                    logger.debug(f"    EKU [{i}]: Server Authentication")
                elif hasattr(x509.oid.ExtendedKeyUsageOID, 'CLIENT_AUTH') and usage_oid == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    usage_name = "clientAuth"
                    logger.debug(f"    EKU [{i}]: Client Authentication")
                elif hasattr(x509.oid.ExtendedKeyUsageOID, 'CODE_SIGNING') and usage_oid == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                    usage_name = "codeSigning"
                    logger.debug(f"    EKU [{i}]: Code Signing")
                elif hasattr(x509.oid.ExtendedKeyUsageOID, 'EMAIL_PROTECTION') and usage_oid == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    usage_name = "emailProtection"
                    logger.debug(f"    EKU [{i}]: Email Protection")
                else:
                    logger.debug(f"    EKU [{i}]: Unknown OID {usage_oid.dotted_string}")
                
                eku_usages.append(usage_name)
            
            if eku_usages:
                extensions["extendedKeyUsage"] = eku_usages
                logger.debug(f"Extended Key Usage processed: {eku_usages}")
                
        except x509.ExtensionNotFound:
            logger.debug("No Extended Key Usage extension found in CSR")
        except Exception as eku_error:
            logger.error(f"Error processing Extended Key Usage in CSR: {eku_error}")

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

        details["extensions"] = extensions
        logger.debug(f"Total CSR extensions processed: {len(extensions)}")
        
        # CSR version (if available)
        try:
            if hasattr(csr, 'version'):
                details["version"] = csr.version
                logger.debug(f"CSR version: {csr.version}")
        except Exception as version_error:
            logger.debug(f"Could not extract CSR version: {version_error}")
        
    except Exception as e:
        logger.error(f"Error extracting CSR details: {e}")
        logger.error(f"CSR object: {csr}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
    
    logger.info(f"CSR extraction complete")
    logger.debug(f"Final CSR details structure keys: {list(details.keys())}")
    return details