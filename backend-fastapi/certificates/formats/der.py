# certificates/formats/der.py
# DER and binary format analysis functions

import logging
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..extractors.certificate import extract_x509_details, is_ca_certificate
from ..extractors.csr import extract_csr_details
from ..extractors.private_key import extract_private_key_details
from ..utils.hashing import (
    generate_certificate_hash, generate_csr_hash,
    generate_normalized_private_key_hash, generate_file_hash
)

logger = logging.getLogger(__name__)

logger.debug("formats/der.py initialized")


def analyze_der_certificate(file_content: bytes) -> Dict[str, Any]:
    """Analyze DER certificate content"""
    cert = x509.load_der_x509_certificate(file_content)
    content_hash = generate_certificate_hash(cert)
    details = extract_x509_details(cert)
    
    # Determine certificate type
    cert_type = "CA Certificate" if is_ca_certificate(cert) else "Certificate"
    logger.info(f"Successfully parsed as DER {cert_type}")
    
    return {
        "type": cert_type,
        "isValid": True,
        "content_hash": content_hash,
        "details": details
    }

def analyze_der_csr(file_content: bytes) -> Dict[str, Any]:
    """Analyze DER CSR content"""
    csr = x509.load_der_x509_csr(file_content)
    content_hash = generate_csr_hash(csr)
    details = extract_csr_details(csr)
    
    logger.info(f"Successfully parsed as DER CSR")
    return {
        "type": "CSR",
        "isValid": True,
        "content_hash": content_hash,
        "details": details
    }

def analyze_der_private_key(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Analyze DER private key content"""
    try:
        # Try without password first
        private_key = serialization.load_der_private_key(file_content, password=None)
        
        # Unencrypted private key
        normalized_hash = generate_normalized_private_key_hash(private_key)
        details = extract_private_key_details(private_key)
        
        logger.info(f"Successfully parsed as DER Private Key")
        return {
            "type": "Private Key",
            "isValid": True,
            "content_hash": normalized_hash,
            "details": details
        }
    except Exception as key_error:
        # Check if it might be an encrypted DER/PKCS8 key
        error_str = str(key_error).lower()
        if any(keyword in error_str for keyword in ['encrypted', 'password', 'decrypt', 'bad decrypt']):
            logger.info(f"Detected encrypted DER private key")
            if password is None:
                return {
                    "type": "Private Key - Password Required",
                    "isValid": False,
                    "requiresPassword": True,
                    "content_hash": generate_file_hash(file_content),
                    "details": {
                        "algorithm": "Encrypted (password required)",
                        "keySize": 0,
                        "curve": "N/A",
                        "encrypted": True,
                        "format": "DER/PKCS8"
                    }
                }
            else:
                # Try with provided password
                try:
                    password_bytes = password.encode('utf-8')
                    private_key = serialization.load_der_private_key(file_content, password=password_bytes)
                    
                    # Success with password
                    normalized_hash = generate_normalized_private_key_hash(private_key)
                    details = extract_private_key_details(private_key)
                    
                    logger.info(f"Successfully decrypted DER Private Key with password")
                    return {
                        "type": "Private Key",
                        "isValid": True,
                        "content_hash": normalized_hash,
                        "details": details
                    }
                except Exception as pwd_error:
                    # Wrong password
                    return {
                        "type": "Private Key - Invalid Password",
                        "isValid": False,
                        "requiresPassword": True,
                        "content_hash": generate_file_hash(file_content),
                        "details": {
                            "algorithm": "Encrypted (incorrect password)",
                            "keySize": 0,
                            "curve": "N/A",
                            "encrypted": True,
                            "format": "DER/PKCS8"
                        }
                    }
        else:
            # Unknown DER format
            return {
                "type": "Unknown DER",
                "isValid": False,
                "content_hash": generate_file_hash(file_content)
            }

def analyze_der_formats(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Try different DER formats in order of likelihood"""
    # Try certificate first (most common)
    try:
        return analyze_der_certificate(file_content)
    except Exception:
        pass
    
    # Try CSR second
    try:
        return analyze_der_csr(file_content)
    except Exception:
        pass
    
    # Try private key third
    try:
        return analyze_der_private_key(file_content, password)
    except Exception as e:
        logger.error(f"DER parsing error: {e}")
        return {
            "type": "Unknown Binary",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }