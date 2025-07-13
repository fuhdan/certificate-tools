# certificates/formats/pkcs7.py
# PKCS7 format analysis functions

import logging
import re
import base64
import hashlib
from typing import Dict, Any, Optional, List
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

logger.debug("formats/pkcs7.py initialized")


def analyze_pkcs7(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Analyze PKCS7 content - main entry point"""
    try:
        # Try to decode as text first for PEM format
        try:
            content_str = file_content.decode('utf-8')
            is_pem = '-----BEGIN' in content_str
        except UnicodeDecodeError:
            content_str = None
            is_pem = False
        
        if is_pem and content_str:
            # Handle PEM PKCS7
            return _analyze_pkcs7_pem(content_str, file_content)
        else:
            # Handle DER PKCS7
            return _analyze_pkcs7_der(file_content)
            
    except Exception as e:
        logger.error(f"PKCS7 parsing failed: {e}")
        return {
            "type": "PKCS7 (Error)",
            "isValid": False,
            "content_hash": _generate_file_hash(file_content),
            "error": str(e)
        }

def _analyze_pkcs7_pem(content_str: str, file_content: bytes) -> Dict[str, Any]:
    """Analyze PEM PKCS7 content"""
    try:
        certificates = []
        
        # Handle -----BEGIN PKCS7----- format
        if '-----BEGIN PKCS7-----' in content_str:
            # Extract the base64 data between the markers
            pkcs7_match = re.search(
                r'-----BEGIN PKCS7-----\s*(.*?)\s*-----END PKCS7-----',
                content_str,
                re.DOTALL
            )
            
            if pkcs7_match:
                # Decode the base64 PKCS7 data
                pkcs7_b64 = pkcs7_match.group(1).replace('\n', '').replace('\r', '').replace(' ', '')
                pkcs7_der = base64.b64decode(pkcs7_b64)
                
                # Extract certificates from the DER data
                certificates = _extract_certificates_from_der(pkcs7_der)
        
        # Handle multiple -----BEGIN CERTIFICATE----- blocks (PKCS7-like)
        if not certificates:
            cert_blocks = re.findall(
                r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                content_str,
                re.DOTALL
            )
            
            if cert_blocks:
                for cert_block in cert_blocks:
                    try:
                        cert = x509.load_pem_x509_certificate(cert_block.encode())
                        certificates.append(cert)
                    except Exception as e:
                        logger.warning(f"Failed to parse certificate in PKCS7: {e}")
                        continue
        
        if certificates:
            return _process_certificate_chain(certificates, "PEM")
        else:
            return {
                "type": "PKCS7 (No certificates found)",
                "isValid": False,
                "content_hash": _generate_file_hash(file_content)
            }
            
    except Exception as e:
        logger.error(f"PEM PKCS7 parsing failed: {e}")
        return {
            "type": "PKCS7 (PEM Parse Error)",
            "isValid": False,
            "content_hash": _generate_file_hash(file_content),
            "error": str(e)
        }

def _analyze_pkcs7_der(file_content: bytes) -> Dict[str, Any]:
    """Analyze DER PKCS7 content"""
    try:
        # Extract certificates from DER PKCS7 structure
        certificates = _extract_certificates_from_der(file_content)
        
        if certificates:
            return _process_certificate_chain(certificates, "DER")
        else:
            # Fallback: try to parse as single DER certificate
            try:
                cert = x509.load_der_x509_certificate(file_content)
                return _process_certificate_chain([cert], "DER")
            except Exception as fallback_err:
                logger.info(f"DER PKCS7 single certificate fallback failed: {fallback_err}")
                return {
                    "type": "PKCS7 (DER Parse Error)",
                    "isValid": False,
                    "content_hash": _generate_file_hash(file_content),
                    "error": str(fallback_err)
                }
        
    except Exception as e:
        logger.error(f"DER PKCS7 parsing failed: {e}")
        return {
            "type": "PKCS7 (DER Error)",
            "isValid": False,
            "content_hash": _generate_file_hash(file_content),
            "error": str(e)
        }

def _process_certificate_chain(certificates: List, source_format: str) -> Dict[str, Any]:
    """Process a chain of certificates and return analysis result"""
    try:
        # Get the main certificate (first one)
        main_cert = certificates[0]
        
        # Determine certificate type based on main certificate
        cert_type = _determine_certificate_type(main_cert)
        
        # Generate content hash from main certificate
        content_hash = _generate_certificate_hash(main_cert)
        
        # Extract certificate details
        details = _extract_certificate_details(main_cert)
        
        logger.info(f"Successfully parsed {source_format} PKCS7 with {len(certificates)} certificates")
        
        result = {
            "type": cert_type,
            "isValid": True,
            "content_hash": content_hash,
            "details": details
        }
        
        # Add additional certificates if any
        if len(certificates) > 1:
            additional_items = []
            for i, cert in enumerate(certificates[1:], 1):
                try:
                    cert_hash = _generate_certificate_hash(cert)
                    cert_details = _extract_certificate_details(cert)
                    cert_type_additional = _determine_certificate_type(cert)
                    
                    additional_items.append({
                        "type": cert_type_additional,
                        "format": "PKCS7",
                        "isValid": True,
                        "size": 0,
                        "content_hash": cert_hash,
                        "details": cert_details
                    })
                    logger.info(f"Extracted additional certificate {i} from PKCS7")
                except Exception as cert_err:
                    logger.error(f"Error extracting additional certificate {i}: {cert_err}")
            
            if additional_items:
                result["additional_items"] = additional_items
        
        return result
        
    except Exception as e:
        logger.error(f"Error processing certificate chain: {e}")
        return {
            "type": "PKCS7 (Processing Error)",
            "isValid": False,
            "content_hash": _generate_file_hash(str(certificates).encode()),
            "error": str(e)
        }

def _extract_certificates_from_der(der_data: bytes) -> List:
    """Extract certificates from PKCS7 DER data"""
    certificates = []
    
    try:
        # Look for certificate sequences (30 82 indicates SEQUENCE with long form)
        data_hex = der_data.hex()
        
        # Find potential certificate starts
        i = 0
        while i < len(data_hex) - 8:
            if data_hex[i:i+4].lower() == '3082':
                try:
                    # Get the length (next 4 hex chars = 2 bytes)
                    length_hex = data_hex[i+4:i+8]
                    length = int(length_hex, 16)
                    
                    # Extract potential certificate
                    cert_start = i // 2  # Convert hex position to byte position
                    cert_length = length + 4  # Add the header length
                    
                    if cert_start + cert_length <= len(der_data):
                        cert_data = der_data[cert_start:cert_start + cert_length]
                        
                        # Try to parse as certificate
                        try:
                            cert = x509.load_der_x509_certificate(cert_data)
                            certificates.append(cert)
                            logger.info(f"Extracted certificate from PKCS7 DER at position {cert_start}")
                            
                            # Skip past this certificate
                            i += cert_length * 2
                            continue
                            
                        except Exception:
                            # Not a valid certificate, continue searching
                            pass
                except Exception:
                    pass
            
            i += 2  # Move to next byte
        
        return certificates
        
    except Exception as e:
        logger.error(f"Error extracting certificates from PKCS7 DER: {e}")
        return []

def _determine_certificate_type(cert) -> str:
    """Determine if certificate is CA or end-entity"""
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        is_ca = basic_constraints.ca
    except x509.ExtensionNotFound:
        is_ca = False
    
    if is_ca:
        return "CA Certificate"
    else:
        return "Certificate"

def _generate_certificate_hash(cert) -> str:
    """Generate hash from certificate DER encoding"""
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der_bytes).hexdigest()

def _generate_file_hash(file_content: bytes) -> str:
    """Generate hash from file content"""
    return hashlib.sha256(file_content).hexdigest()

def _extract_certificate_details(cert) -> Dict[str, Any]:
    """Extract details from X.509 certificate - simplified version"""
    details = {
        "subject": {},
        "issuer": {},
        "validity": {},
        "publicKey": {},
        "signature": {},
        "extensions": {},
        "serialNumber": str(cert.serial_number)
    }
    
    try:
        # Subject information
        subject_attrs = {}
        for attribute in cert.subject:
            subject_attrs[attribute.oid._name] = attribute.value
        
        details["subject"] = {
            "commonName": subject_attrs.get("commonName", "N/A"),
            "organization": subject_attrs.get("organizationName", "N/A"),
            "organizationalUnit": subject_attrs.get("organizationalUnitName", "N/A"),
            "country": subject_attrs.get("countryName", "N/A"),
            "state": subject_attrs.get("stateOrProvinceName", "N/A"),
            "locality": subject_attrs.get("localityName", "N/A"),
            "emailAddress": subject_attrs.get("emailAddress", "N/A")
        }
        
        # Issuer information
        issuer_attrs = {}
        for attribute in cert.issuer:
            issuer_attrs[attribute.oid._name] = attribute.value
        
        details["issuer"] = {
            "commonName": issuer_attrs.get("commonName", "N/A"),
            "organization": issuer_attrs.get("organizationName", "N/A"),
            "organizationalUnit": issuer_attrs.get("organizationalUnitName", "N/A"),
            "country": issuer_attrs.get("countryName", "N/A")
        }
        
        # Validity period
        import datetime
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        is_expired = cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc)
        days_until_expiry = (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days
        
        details["validity"] = {
            "notBefore": not_before,
            "notAfter": not_after,
            "isExpired": is_expired,
            "daysUntilExpiry": days_until_expiry
        }
        
        # Public key information
        public_key = cert.public_key()
        details["publicKey"] = {
            "algorithm": "Unknown",
            "keySize": 0,
            "curve": "N/A"
        }
        
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        if isinstance(public_key, rsa.RSAPublicKey):
            details["publicKey"]["algorithm"] = "RSA"
            details["publicKey"]["keySize"] = public_key.key_size
            details["publicKey"]["exponent"] = str(public_key.public_numbers().e)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            details["publicKey"]["algorithm"] = "EC"
            details["publicKey"]["curve"] = public_key.curve.name
        
        # Signature algorithm
        details["signature"] = {
            "algorithm": cert.signature_algorithm_oid._name,
            "algorithmOid": cert.signature_algorithm_oid.dotted_string
        }
        
        # Extensions
        extensions = {}
        for ext in cert.extensions:
            if isinstance(ext.value, x509.SubjectAlternativeName):
                san_list = []
                for name in ext.value:
                    if isinstance(name, x509.DNSName):
                        san_list.append({"type": 2, "typeName": "DNS", "value": name.value})
                    elif isinstance(name, x509.IPAddress):
                        san_list.append({"type": 7, "typeName": "IP", "value": str(name.value)})
                    elif isinstance(name, x509.RFC822Name):
                        san_list.append({"type": 1, "typeName": "Email", "value": name.value})
                extensions["subjectAltName"] = san_list
            elif isinstance(ext.value, x509.BasicConstraints):
                extensions["basicConstraints"] = {
                    "isCA": ext.value.ca,
                    "pathLength": ext.value.path_length
                }
        
        details["extensions"] = extensions
        
    except Exception as e:
        logger.warning(f"Error extracting certificate details: {e}")
    
    return details