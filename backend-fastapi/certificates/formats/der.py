# backend-fastapi/certificates/formats/der.py
# DER and binary format analysis functions with comprehensive debugging
# Updated to use centralized Password Entry Service

import logging
from typing import Dict, Any, Optional
from cryptography import x509

from ..extractors.certificate import extract_certificate_metadata, is_ca_certificate
from ..extractors.csr import extract_csr_metadata
from ..extractors.private_key import extract_private_key_metadata
from ..utils.hashing import (
    generate_certificate_hash, generate_csr_hash,
    generate_normalized_private_key_hash, generate_file_hash
)

# Import the centralized Password Entry Service
from services.password_entry_service import (
    password_entry_service,
    handle_encrypted_content,
    PasswordResult
)

logger = logging.getLogger(__name__)

logger.debug("formats/der.py initialized with Password Entry Service")

def analyze_der_certificate(file_content: bytes) -> Dict[str, Any]:
    """Analyze DER certificate content"""
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"First 16 bytes (hex): {file_content[:16].hex()}")
    
    try:
        logger.debug("Loading DER certificate with cryptography...")
        cert = x509.load_der_x509_certificate(file_content)
        logger.debug(f"DER certificate loaded successfully: {type(cert)}")
        
        content_hash = generate_certificate_hash(cert)
        logger.debug(f"DER certificate content hash: {content_hash[:16]}...")
        
        logger.debug("Extracting DER certificate metadata...")
        metadata = extract_certificate_metadata(cert)
        logger.debug(f"DER certificate metadata extracted, keys: {list(metadata.keys())}")
        
        # Determine certificate type
        is_ca = is_ca_certificate(cert)
        cert_type = "CA Certificate" if is_ca else "Certificate"
        logger.debug(f"DER certificate type determined: {cert_type} (CA: {is_ca})")
        
        result = {
            "type": cert_type,
            "isValid": True,
            "content_hash": content_hash,
            "details": metadata
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
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"First 16 bytes (hex): {file_content[:16].hex()}")
    
    try:
        logger.debug("Loading DER CSR with cryptography...")
        csr = x509.load_der_x509_csr(file_content)
        logger.debug(f"DER CSR loaded successfully: {type(csr)}")
        
        content_hash = generate_csr_hash(csr)
        logger.debug(f"DER CSR content hash: {content_hash[:16]}...")
        
        logger.debug("Extracting DER CSR metadata...")
        metadata = extract_csr_metadata(csr)
        logger.debug(f"DER CSR metadata extracted, keys: {list(metadata.keys())}")
        
        result = {
            "type": "CSR",
            "isValid": True,
            "content_hash": content_hash,
            "details": metadata
        }
        
        logger.info(f"DER CSR analysis complete")
        return result
        
    except Exception as csr_error:
        logger.error(f"Error parsing DER CSR: {csr_error}")
        logger.error(f"Content analysis - length: {len(file_content)}, header: {file_content[:32].hex()}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise csr_error

def analyze_der_private_key(file_content: bytes, password: Optional[str], filename: str = "") -> Dict[str, Any]:
    """
    Analyze DER private key content using centralized Password Entry Service
    
    This function now uses the Password Entry Service to handle all password-related
    logic consistently with PEM and PKCS12 formats.
    """
    logger.info(f"=== DER PRIVATE KEY ANALYSIS (with Password Service) ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"Filename: {filename}")
    logger.debug(f"First 16 bytes (hex): {file_content[:16].hex()}")
    
    try:
        # Use the centralized Password Entry Service
        result, private_key, error, content_type = handle_encrypted_content(
            file_content, password, filename
        )
        
        logger.debug(f"Password service result: {result}")
        logger.debug(f"Content type detected: {content_type}")
        
        if result == PasswordResult.SUCCESS:
            # Successfully loaded private key with password
            logger.info("DER private key successfully loaded via Password Entry Service")
            
            # Generate normalized hash and extract metadata
            normalized_hash = generate_normalized_private_key_hash(private_key)
            logger.debug(f"Normalized private key hash: {normalized_hash[:16]}...")
            
            metadata = extract_private_key_metadata(private_key, is_encrypted=(password is not None))
            logger.debug(f"Private key metadata: {metadata}")
            
            result_dict = {
                "type": "Private Key",
                "isValid": True,
                "content_hash": normalized_hash,
                "details": metadata
            }
            
            logger.info(f"DER private key analysis complete: {metadata.get('algorithm', 'Unknown')} {metadata.get('key_size', 0)} bits")
            return result_dict
            
        elif result == PasswordResult.NO_PASSWORD_NEEDED:
            # Unencrypted private key
            logger.info("DER private key loaded without password via Password Entry Service")
            
            normalized_hash = generate_normalized_private_key_hash(private_key)
            logger.debug(f"Normalized private key hash: {normalized_hash[:16]}...")
            
            metadata = extract_private_key_metadata(private_key, is_encrypted=False)
            logger.debug(f"Private key metadata: {metadata}")
            
            result_dict = {
                "type": "Private Key",
                "isValid": True,
                "content_hash": normalized_hash,
                "details": metadata
            }
            
            logger.info(f"Unencrypted DER private key analysis complete: {metadata.get('algorithm', 'Unknown')} {metadata.get('key_size', 0)} bits")
            return result_dict
            
        elif result == PasswordResult.PASSWORD_REQUIRED:
            # Password is required but not provided
            logger.info("Password required for encrypted DER private key")
            return password_entry_service.create_password_required_response(
                file_content, content_type, filename
            )
            
        elif result == PasswordResult.WRONG_PASSWORD:
            # Wrong password provided
            logger.error("Wrong password provided for encrypted DER private key")
            return password_entry_service.create_wrong_password_response(
                file_content, content_type
            )
            
        else:
            # Other error (INVALID_FORMAT, UNKNOWN_ERROR)
            logger.error(f"Password Entry Service error: {result} - {error}")
            return {
                "type": "Private Key",
                "isValid": False,
                "content_hash": generate_file_hash(file_content),
                "error": error or f"Password service error: {result}"
            }
            
    except Exception as e:
        logger.error(f"Unexpected error in DER private key analysis: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "Private Key",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }

def analyze_der_formats(file_content: bytes, password: Optional[str], filename: str = "") -> Dict[str, Any]:
    """
    Try different DER formats in order of likelihood
    Updated to use Password Entry Service for private key handling
    """
    logger.info(f"=== DER FORMAT DETECTION ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"Filename: {filename}")
    logger.debug(f"Content header (32 bytes): {file_content[:32].hex()}")
    
    # Initialize error variables to avoid unbound variable errors
    cert_err: Optional[Exception] = None
    csr_err: Optional[Exception] = None
    key_result: Optional[Dict[str, Any]] = None
    
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
    
    # Try private key third (now using Password Entry Service)
    logger.debug("Attempting DER private key parsing with Password Entry Service...")
    try:
        key_result = analyze_der_private_key(file_content, password, filename)
        if key_result.get('isValid') or key_result.get('requiresPassword'):
            logger.info(f"Successfully processed as DER private key: {key_result.get('type')}")
            return key_result
        else:
            logger.debug(f"DER private key processing returned invalid result: {key_result}")
    except Exception as e:
        logger.debug(f"DER private key parsing failed: {e}")
    
    # If all specific formats fail
    logger.error("All DER format parsing attempts failed")
    logger.error(f"File analysis:")
    logger.error(f"  Length: {len(file_content)} bytes")
    logger.error(f"  Header: {file_content[:64].hex()}")
    logger.error(f"  Last certificate error: {cert_err}")
    logger.error(f"  Last CSR error: {csr_err}")
    if key_result:
        logger.error(f"  Private key result: {key_result}")
    
    return {
        "type": "Unknown Binary",
        "isValid": False,
        "content_hash": generate_file_hash(file_content),
        "error": "Could not parse as any known DER format",
        "format_hints": {
            "certificate_error": str(cert_err) if cert_err else None,
            "csr_error": str(csr_err) if csr_err else None,
            "private_key_result": key_result.get('error') if key_result else None
        }
    }