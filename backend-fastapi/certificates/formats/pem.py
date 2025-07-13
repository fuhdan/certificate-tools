# certificates/formats/pem.py
# PEM format analysis functions

import hashlib
import logging
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..extractors.certificate import extract_x509_details, is_ca_certificate, extract_public_key_details
from ..extractors.csr import extract_csr_details  
from ..extractors.private_key import extract_private_key_details
from ..utils.hashing import (
    generate_certificate_hash, generate_csr_hash, generate_public_key_hash,
    generate_normalized_private_key_hash, generate_file_hash
)

logger = logging.getLogger(__name__)

def analyze_pem_certificate(content_str: str, file_content: bytes) -> Dict[str, Any]:
    """Analyze PEM certificate content"""
    cert_blocks = content_str.count('-----BEGIN CERTIFICATE-----')
    
    if cert_blocks > 1:
        # Certificate chain
        return {
            "type": "Certificate Chain",
            "isValid": True,
            "content_hash": hashlib.sha256(content_str.encode()).hexdigest(),
            "details": {"certificateCount": cert_blocks}
        }
    else:
        # Single certificate
        cert = x509.load_pem_x509_certificate(file_content)
        content_hash = generate_certificate_hash(cert)
        
        # Determine certificate type
        cert_type = "CA Certificate" if is_ca_certificate(cert) else "Certificate"
        details = extract_x509_details(cert)
        
        return {
            "type": cert_type,
            "isValid": True,
            "content_hash": content_hash,
            "details": details
        }

def analyze_pem_csr(file_content: bytes) -> Dict[str, Any]:
    """Analyze PEM CSR content"""
    csr = x509.load_pem_x509_csr(file_content)
    content_hash = generate_csr_hash(csr)
    details = extract_csr_details(csr)
    
    return {
        "type": "CSR",
        "isValid": True,
        "content_hash": content_hash,
        "details": details
    }

def analyze_pem_private_key(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Analyze PEM private key content"""
    try:
        # Try to load the private key without password first
        private_key = serialization.load_pem_private_key(file_content, password=None)
        
        # Unencrypted private key
        normalized_hash = generate_normalized_private_key_hash(private_key)
        details = extract_private_key_details(private_key)
        
        logger.info(f"Successfully parsed unencrypted PEM private key")
        return {
            "type": "Private Key",
            "isValid": True,
            "content_hash": normalized_hash,
            "details": details
        }
        
    except Exception as e:
        # Failed to load without password - check if it's encrypted
        error_str = str(e).lower()
        if any(keyword in error_str for keyword in ['password', 'decrypt', 'encrypted', 'bad decrypt']):
            # It's encrypted
            if not password:
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
                        "requiresPassword": True
                    }
                }
            else:
                # Try with provided password
                try:
                    password_bytes = password.encode('utf-8')
                    private_key = serialization.load_pem_private_key(file_content, password=password_bytes)
                    
                    # Success with password
                    normalized_hash = generate_normalized_private_key_hash(private_key)
                    details = extract_private_key_details(private_key)
                    
                    logger.info(f"Successfully decrypted PEM private key with password")
                    return {
                        "type": "Private Key",
                        "isValid": True,
                        "content_hash": normalized_hash,
                        "details": details
                    }
                except Exception as pwd_error:
                    # Wrong password
                    logger.info(f"Invalid password for encrypted PEM private key")
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
                            "requiresPassword": True
                        }
                    }
        else:
            # Some other parsing error
            logger.info(f"PEM private key parsing failed: {e}")
            return {
                "type": "Private Key",
                "isValid": False,
                "content_hash": generate_file_hash(file_content),
                "error": str(e)
            }

def analyze_pem_public_key(file_content: bytes) -> Dict[str, Any]:
    """Analyze PEM public key content"""
    try:
        public_key = serialization.load_pem_public_key(file_content)
        content_hash = generate_public_key_hash(public_key)
        details = extract_public_key_details(public_key)
        
        return {
            "type": "Public Key",
            "isValid": True,
            "content_hash": content_hash,
            "details": details
        }
    except Exception as e:
        return {
            "type": "Public Key",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }