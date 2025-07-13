# certificates/extractors/certificate.py
# Certificate detail extraction functions

import datetime
import logging
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

logger = logging.getLogger(__name__)

def extract_public_key_details(public_key) -> Dict[str, Any]:
    """Extract details from public key"""
    details = {
        "algorithm": "Unknown",
        "keySize": 0,
        "curve": "N/A"
    }
    
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            details["algorithm"] = "RSA"
            details["keySize"] = public_key.key_size
            details["exponent"] = str(public_key.public_numbers().e)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            details["algorithm"] = "EC"
            details["curve"] = public_key.curve.name
    except Exception as e:
        logger.warning(f"Error extracting public key details: {e}")
    
    return details

def extract_x509_details(cert: x509.Certificate) -> Dict[str, Any]:
    """Extract detailed information from X.509 certificate"""
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
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        is_expired = cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc)  # Check if end date is past
        days_until_expiry = (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days
        
        details["validity"] = {
            "notBefore": not_before,
            "notAfter": not_after,
            "isExpired": is_expired,
            "daysUntilExpiry": days_until_expiry
        }
        
        # Public key information
        public_key = cert.public_key()
        details["publicKey"] = extract_public_key_details(public_key)
        
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
            elif isinstance(ext.value, x509.KeyUsage):
                extensions["keyUsage"] = {
                    "digitalSignature": ext.value.digital_signature,
                    "keyEncipherment": ext.value.key_encipherment,
                    "keyAgreement": ext.value.key_agreement,
                    "keyCertSign": ext.value.key_cert_sign,
                    "crlSign": ext.value.crl_sign
                }
        
        details["extensions"] = extensions
        
    except Exception as e:
        logger.warning(f"Error extracting certificate details: {e}")
    
    return details

def is_ca_certificate(cert: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate"""
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        return basic_constraints.ca
    except x509.ExtensionNotFound:
        return False