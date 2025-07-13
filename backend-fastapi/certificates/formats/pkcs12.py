# certificates/formats/pkcs12.py
# PKCS12 format analysis functions

import logging
import json
from typing import Dict, Any, Optional, List
from cryptography.hazmat.primitives.serialization import pkcs12

from ..extractors.certificate import extract_x509_details
from ..extractors.private_key import extract_private_key_details
from ..utils.hashing import (
    generate_certificate_hash, generate_pkcs12_content_hash, 
    generate_normalized_private_key_hash, generate_file_hash
)

logger = logging.getLogger(__name__)

logger.debug("formats/pkcs12.py initialized")


def analyze_pkcs12(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Analyze PKCS12 content"""
    try:
        # Try to parse PKCS12 without password first (many have no password)
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
            file_content, password=None
        )
        
        # Success without password
        logger.info(f"Successfully parsed PKCS12 without password")
        return _process_pkcs12_success(cert, private_key, additional_certs)
        
    except Exception as p12_err:
        # Failed without password - check if it needs password
        error_str = str(p12_err).lower()
        logger.info(f"PKCS12 parsing without password failed: {p12_err}")
        
        if any(keyword in error_str for keyword in ['password', 'decrypt', 'invalid', 'mac', 'integrity']):
            # It's password-protected
            if not password:
                return {
                    "type": "PKCS12 Certificate - Password Required",
                    "isValid": False,
                    "requiresPassword": True,
                    "content_hash": generate_file_hash(file_content),
                    "details": {
                        "algorithm": "PKCS12 (password required)",
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
                    private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                        file_content, password_bytes
                    )
                    
                    # Success with password
                    logger.info(f"Successfully parsed PKCS12 with provided password")
                    return _process_pkcs12_success(cert, private_key, additional_certs)
                    
                except Exception as pwd_error:
                    # Wrong password
                    logger.info(f"PKCS12 parsing with provided password failed: {pwd_error}")
                    return {
                        "type": "PKCS12 Certificate - Invalid Password",
                        "isValid": False,
                        "requiresPassword": True,
                        "content_hash": generate_file_hash(file_content),
                        "details": {
                            "algorithm": "PKCS12 (incorrect password)",
                            "keySize": 0,
                            "curve": "N/A",
                            "encrypted": True,
                            "requiresPassword": True
                        }
                    }
        else:
            # Some other PKCS12 parsing error (not password related)
            logger.error(f"PKCS12 parsing failed with non-password error: {p12_err}")
            return {
                "type": "PKCS12 Certificate",
                "isValid": False,
                "content_hash": generate_file_hash(file_content),
                "error": str(p12_err)
            }

def _process_pkcs12_success(cert, private_key, additional_certs) -> Dict[str, Any]:
    """Process successfully parsed PKCS12 content - extract all components"""
    # Always use the main certificate hash for duplicate detection
    # This allows PKCS12 certificates to be detected as duplicates of standalone certificates
    if cert:
        # Use main certificate hash - same as standalone certificates
        content_hash = generate_certificate_hash(cert)
        logger.info(f"PKCS12 using main certificate hash for duplicate detection: {content_hash}")
    else:
        # No main certificate - use combined hash as fallback
        content_hash = generate_pkcs12_content_hash(cert, private_key, additional_certs)
        logger.info(f"PKCS12 no main certificate, using combined hash: {content_hash}")
    
    # Extract certificate details if available
    details = None
    if cert:
        details = extract_x509_details(cert)

        logger.debug("Certificate details:\n%s", json.dumps(details, indent=2))
    
    # Prepare main result (certificate)
    result = {
        "type": "PKCS12 Certificate",
        "isValid": True,
        "content_hash": content_hash,
        "details": details
    }
    
    # Extract additional components for separate storage
    additional_items = []
    
    # Extract private key if present
    if private_key:
        try:
            # Generate normalized hash for the private key (same as standalone private keys)
            key_hash = generate_normalized_private_key_hash(private_key)
            key_details = extract_private_key_details(private_key)
            
            additional_items.append({
                "type": "Private Key",
                "format": "PKCS12",
                "isValid": True,
                "size": 0,  # Size is part of the PKCS12 container
                "content_hash": key_hash,  # Use consistent hash based on key material
                "details": key_details
            })
            logger.info(f"Extracted private key from PKCS12 with hash: {key_hash}")
        except Exception as key_err:
            logger.error(f"Error extracting private key from PKCS12: {key_err}")
    
    # Extract additional certificates if present
    if additional_certs:
        for i, additional_cert in enumerate(additional_certs):
            if additional_cert:
                try:
                    cert_hash = generate_certificate_hash(additional_cert)
                    cert_details = extract_x509_details(additional_cert)
                    
                    additional_items.append({
                        "type": "Certificate",
                        "format": "PKCS12",
                        "isValid": True,
                        "size": 0,  # Size is part of the PKCS12 container
                        "content_hash": cert_hash,
                        "details": cert_details
                    })
                    logger.info(f"Extracted additional certificate {i} from PKCS12 with hash: {cert_hash}")
                except Exception as cert_err:
                    logger.error(f"Error extracting additional certificate {i} from PKCS12: {cert_err}")
    
    # Add additional items to result if any were found
    if additional_items:
        result["additional_items"] = additional_items
        logger.info(f"PKCS12 contains {len(additional_items)} additional items")
    
    return result