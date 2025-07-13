# certificates/extractors/csr.py
# CSR detail extraction functions

import logging
from typing import Dict, Any
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from .certificate import extract_public_key_details

logger = logging.getLogger(__name__)

def extract_csr_details(csr: x509.CertificateSigningRequest) -> Dict[str, Any]:
    """Extract details from CSR"""
    details = {
        "subject": {},
        "publicKey": {},
        "signature": {},
        "extensions": {}
    }
    
    try:
        # Subject information
        subject_attrs = {}
        for attribute in csr.subject:
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
        
        # Public key information
        public_key = csr.public_key()
        details["publicKey"] = extract_public_key_details(public_key)
        
        # Signature algorithm
        details["signature"] = {
            "algorithm": csr.signature_algorithm_oid._name,
            "algorithmOid": csr.signature_algorithm_oid.dotted_string
        }

        # Extract extensions from CSR
        extensions = {}
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = san_ext.value
            san_list = []
            for name in san:
                if isinstance(name, x509.DNSName):
                    san_list.append({"type": 2, "typeName": "DNS", "value": name.value})
                elif isinstance(name, x509.IPAddress):
                    # Convert IPAddress object to string
                    ip_str = str(name.value)
                    san_list.append({"type": 7, "typeName": "IP", "value": ip_str})
            if san_list:
                extensions["subjectAltName"] = san_list
        except x509.ExtensionNotFound:
            # No SAN extension found
            pass

        details["extensions"] = extensions
        
    except Exception as e:
        logger.warning(f"Error extracting CSR details: {e}")
    
    return details