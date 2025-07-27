# certificates/formats/der.py
# DER and binary format analysis functions with comprehensive debugging

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
    logger.info(f"=== DER CERTIFICATE ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"First 16 bytes (hex): {file_content[:16].hex()}")
    
    try:
        logger.debug("Loading DER certificate with cryptography...")
        cert = x509.load_der_x509_certificate(file_content)
        logger.debug(f"DER certificate loaded successfully: {type(cert)}")
        
        content_hash = generate_certificate_hash(cert)
        logger.debug(f"DER certificate content hash: {content_hash[:16]}...")
        
        logger.debug("Extracting DER certificate details...")
        details = extract_x509_details(cert)
        logger.debug(f"DER certificate details extracted, keys: {list(details.keys())}")
        
        # Determine certificate type
        is_ca = is_ca_certificate(cert)
        cert_type = "CA Certificate" if is_ca else "Certificate"
        logger.debug(f"DER certificate type determined: {cert_type} (CA: {is_ca})")
        
        result = {
            "type": cert_type,
            "isValid": True,
            "content_hash": content_hash,
            "details": details
        }
        
        logger.info(f"DER certificate analysis complete: {cert_type}")
        return result
        
    except Exception as cert_error:
        logger.error(f"Error parsing DER certificate: {cert_error}")
        logger.error(f"Content analysis - length: {len(file_content)}, header: {file_content[:32].hex()}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise cert_error

def analyze_der_csr(file_content: bytes) -> Dict[str, Any]:
    """Analyze DER CSR content"""
    logger.info(f"=== DER CSR ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"First 16 bytes (hex): {file_content[:16].hex()}")
    
    try:
        logger.debug("Loading DER CSR with cryptography...")
        csr = x509.load_der_x509_csr(file_content)
        logger.debug(f"DER CSR loaded successfully: {type(csr)}")
        
        content_hash = generate_csr_hash(csr)
        logger.debug(f"DER CSR content hash: {content_hash[:16]}...")
        
        logger.debug("Extracting DER CSR details...")
        details = extract_csr_details(csr)
        logger.debug(f"DER CSR details extracted, keys: {list(details.keys())}")
        
        result = {
            "type": "CSR",
            "isValid": True,
            "content_hash": content_hash,
            "details": details
        }
        
        logger.info(f"DER CSR analysis complete")
        return result
        
    except Exception as csr_error:
        logger.error(f"Error parsing DER CSR: {csr_error}")
        logger.error(f"Content analysis - length: {len(file_content)}, header: {file_content[:32].hex()}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise csr_error

def analyze_der_private_key(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Analyze DER private key content"""
    logger.info(f"=== DER PRIVATE KEY ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"First 16 bytes (hex): {file_content[:16].hex()}")
    
    try:
        logger.debug("Attempting to load DER private key without password...")
        # Try without password first
        private_key = serialization.load_der_private_key(file_content, password=None)
        
        logger.info("Successfully loaded unencrypted DER private key")
        # Unencrypted private key
        normalized_hash = generate_normalized_private_key_hash(private_key)
        logger.debug(f"DER private key normalized hash: {normalized_hash[:16]}...")
        
        logger.debug("Extracting DER private key details...")
        details = extract_private_key_details(private_key)
        logger.debug(f"DER private key details: {details}")
        
        result = {
            "type": "Private Key",
            "isValid": True,
            "content_hash": normalized_hash,
            "details": details
        }
        
        logger.info(f"DER private key analysis complete: {details.get('algorithm', 'Unknown')} {details.get('keySize', 0)} bits")
        return result
        
    except Exception as key_error:
        # Check if it might be an encrypted DER/PKCS8 key
        error_str = str(key_error).lower()
        logger.debug(f"DER private key loading without password failed: {key_error}")
        logger.debug(f"Error string analysis: {error_str}")
        
        if any(keyword in error_str for keyword in ['encrypted', 'password', 'decrypt', 'bad decrypt']):
            logger.info("DER private key appears to be encrypted")
            if password is None:
                logger.info("No password provided for encrypted DER private key")
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
                logger.debug("Attempting to decrypt DER private key with provided password...")
                # Try with provided password
                try:
                    password_bytes = password.encode('utf-8')
                    logger.debug(f"Password encoded to {len(password_bytes)} bytes")
                    
                    private_key = serialization.load_der_private_key(file_content, password=password_bytes)
                    logger.info("Successfully decrypted DER private key with password")
                    
                    # Success with password
                    normalized_hash = generate_normalized_private_key_hash(private_key)
                    logger.debug(f"Decrypted DER private key hash: {normalized_hash[:16]}...")
                    
                    details = extract_private_key_details(private_key)
                    logger.debug(f"Decrypted DER private key details: {details}")
                    
                    result = {
                        "type": "Private Key",
                        "isValid": True,
                        "content_hash": normalized_hash,
                        "details": details
                    }
                    
                    logger.info(f"Encrypted DER private key analysis complete: {details.get('algorithm', 'Unknown')} {details.get('keySize', 0)} bits")
                    return result
                    
                except Exception as pwd_error:
                    logger.error(f"DER private key password decryption failed: {pwd_error}")
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
            logger.error(f"DER private key parsing failed with non-password error: {key_error}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            
            # Unknown DER format
            return {
                "type": "Unknown DER",
                "isValid": False,
                "content_hash": generate_file_hash(file_content),
                "error": str(key_error)
            }

def analyze_der_formats(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Try different DER formats in order of likelihood"""
    logger.info(f"=== DER FORMAT DETECTION ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"Content header (32 bytes): {file_content[:32].hex()}")
    
    # Initialize error variables to avoid unbound variable errors
    cert_err: Optional[Exception] = None
    csr_err: Optional[Exception] = None
    key_err: Optional[Exception] = None
    
    # Analyze ASN.1 structure
    if len(file_content) >= 2:
        tag = file_content[0]
        length_info = file_content[1]
        logger.debug(f"ASN.1 tag: 0x{tag:02x}")
        logger.debug(f"ASN.1 length info: 0x{length_info:02x}")
        
        if tag == 0x30:  # SEQUENCE
            logger.debug("ASN.1 SEQUENCE detected")
            if length_info & 0x80:  # Long form length
                length_octets = length_info & 0x7f
                logger.debug(f"Long form length with {length_octets} octets")
            else:
                logger.debug(f"Short form length: {length_info}")
    
    # Try certificate first (most common)
    logger.debug("Attempting DER certificate parsing...")
    try:
        result = analyze_der_certificate(file_content)
        logger.info("Successfully parsed as DER certificate")
        return result
    except Exception as e:
        cert_err = e
        logger.debug(f"DER certificate parsing failed: {cert_err}")
    
    # Try CSR second
    logger.debug("Attempting DER CSR parsing...")
    try:
        result = analyze_der_csr(file_content)
        logger.info("Successfully parsed as DER CSR")
        return result
    except Exception as e:
        csr_err = e
        logger.debug(f"DER CSR parsing failed: {csr_err}")
    
    # Try private key third
    logger.debug("Attempting DER private key parsing...")
    try:
        result = analyze_der_private_key(file_content, password)
        if result.get('isValid') or result.get('requiresPassword'):
            logger.info(f"Successfully processed as DER private key: {result.get('type')}")
            return result
    except Exception as e:
        key_err = e
        logger.debug(f"DER private key parsing failed: {key_err}")
    
    # If all specific formats fail
    logger.error("All DER format parsing attempts failed")
    logger.error(f"File analysis:")
    logger.error(f"  Length: {len(file_content)} bytes")
    logger.error(f"  Header: {file_content[:64].hex()}")
    logger.error(f"  Last certificate error: {cert_err}")
    logger.error(f"  Last CSR error: {csr_err}")
    logger.error(f"  Last key error: {key_err}")
    
    return {
        "type": "Unknown Binary",
        "isValid": False,
        "content_hash": generate_file_hash(file_content),
        "error": "Could not parse as any known DER format",
        "format_hints": {
            "certificate_error": str(cert_err) if cert_err else None,
            "csr_error": str(csr_err) if csr_err else None,
            "private_key_error": str(key_err) if key_err else None
        }
    }