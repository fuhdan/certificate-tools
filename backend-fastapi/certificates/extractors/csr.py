# certificates/extractors/csr.py
# CSR detail extraction functions

import logging
from typing import Dict, Any
from cryptography import x509
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
        
    except Exception as e:
        logger.warning(f"Error extracting CSR details: {e}")
    
    return details