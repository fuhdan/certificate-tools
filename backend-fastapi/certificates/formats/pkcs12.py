# certificates/formats/pkcs12.py
# PKCS12 format analysis functions with comprehensive debugging

import logging
import json
from typing import Dict, Any, Optional, List
from cryptography.hazmat.primitives.serialization import pkcs12

from ..extractors.certificate import extract_certificate_metadata
from ..extractors.private_key import extract_private_key_metadata
from ..utils.hashing import (
    generate_certificate_hash, generate_pkcs12_content_hash, 
    generate_normalized_private_key_hash, generate_file_hash
)

logger = logging.getLogger(__name__)

logger.debug("formats/pkcs12.py initialized")

def analyze_pkcs12(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Analyze PKCS12 content"""
    logger.info(f"=== PKCS12 ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"First 32 bytes (hex): {file_content[:32].hex()}")
    
    # Check PKCS12 file signature
    if len(file_content) >= 4:
        # PKCS12 files typically start with ASN.1 SEQUENCE (0x30)
        header = file_content[:4]
        logger.debug(f"PKCS12 header analysis: {header.hex()}")
        
        if header[0] == 0x30:
            logger.debug("PKCS12 ASN.1 SEQUENCE marker found")
        else:
            logger.warning(f"Unexpected PKCS12 header: expected 0x30, got 0x{header[0]:02x}")
    
    try:
        logger.debug("Attempting PKCS12 parsing without password...")
        # Try to parse PKCS12 without password first (many have no password)
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
            file_content, password=None
        )
        
        logger.info("Successfully parsed PKCS12 without password")
        logger.debug(f"PKCS12 components found:")
        logger.debug(f"  Main certificate: {'YES' if cert else 'NO'}")
        logger.debug(f"  Private key: {'YES' if private_key else 'NO'}")
        logger.debug(f"  Additional certificates: {len(additional_certs) if additional_certs else 0}")
        
        # Success without password
        return _process_pkcs12_success(cert, private_key, additional_certs)
        
    except Exception as p12_err:
        # Failed without password - check if it needs password
        error_str = str(p12_err).lower()
        logger.debug(f"PKCS12 parsing without password failed: {p12_err}")
        logger.debug(f"Error string analysis: {error_str}")
        
        # Check for password-related error indicators
        password_keywords = ['password', 'decrypt', 'invalid', 'mac', 'integrity', 'authentication']
        is_password_error = any(keyword in error_str for keyword in password_keywords)
        logger.debug(f"Password-related error detected: {is_password_error}")
        
        if is_password_error:
            logger.info("PKCS12 appears to be password-protected")
            # It's password-protected
            if not password:
                logger.debug("No password provided for password-protected PKCS12")
                return {
                    "type": "PKCS12 Certificate - Password Required",
                    "isValid": False,
                    "requiresPassword": True,
                    "content_hash": generate_file_hash(file_content),
                    "details": {
                        "algorithm": "PKCS12 (password required)",
                        "key_size": 0,
                        "curve": "N/A",
                        "is_encrypted": True,
                        "requiresPassword": True
                    }
                }
            else:
                logger.debug("Attempting PKCS12 parsing with provided password...")
                # Try with provided password
                try:
                    password_bytes = password.encode('utf-8')
                    logger.debug(f"Password encoded to {len(password_bytes)} bytes")
                    
                    private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                        file_content, password_bytes
                    )
                    
                    logger.info("Successfully parsed PKCS12 with provided password")
                    logger.debug(f"PKCS12 components found with password:")
                    logger.debug(f"  Main certificate: {'YES' if cert else 'NO'}")
                    logger.debug(f"  Private key: {'YES' if private_key else 'NO'}")
                    logger.debug(f"  Additional certificates: {len(additional_certs) if additional_certs else 0}")
                    
                    # Success with password
                    return _process_pkcs12_success(cert, private_key, additional_certs)
                    
                except Exception as pwd_error:
                    # Wrong password
                    logger.error(f"PKCS12 parsing with provided password failed: {pwd_error}")
                    logger.debug(f"Password error details: {str(pwd_error)}")
                    
                    return {
                        "type": "PKCS12 Certificate - Invalid Password",
                        "isValid": False,
                        "requiresPassword": True,
                        "content_hash": generate_file_hash(file_content),
                        "details": {
                            "algorithm": "PKCS12 (incorrect password)",
                            "key_size": 0,
                            "curve": "N/A",
                            "is_encrypted": True,
                            "requiresPassword": True
                        }
                    }
        else:
            # Some other PKCS12 parsing error (not password related)
            logger.error(f"PKCS12 parsing failed with non-password error: {p12_err}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            
            return {
                "type": "PKCS12 Certificate",
                "isValid": False,
                "content_hash": generate_file_hash(file_content),
                "error": str(p12_err)
            }

def _process_pkcs12_success(cert, private_key, additional_certs) -> Dict[str, Any]:
    """Process successfully parsed PKCS12 content - extract all components with standardized types"""
    logger.debug(f"=== PKCS12 SUCCESS PROCESSING ===")
    
    # Import standardization functions
    get_consistent_types = None
    use_standardized = False
    
    try:
        from ..types import get_consistent_types
        use_standardized = True
        logger.debug("Using standardized certificate types")
    except ImportError:
        logger.warning("Standardized types not available, using legacy types")
    
    # Log component details
    if cert:
        logger.debug("Main certificate found - extracting details...")
        try:
            subject_cn = None
            for attribute in cert.subject:
                if attribute.oid._name == 'commonName':
                    subject_cn = attribute.value
                    break
            logger.debug(f"  Certificate subject CN: {subject_cn}")
            logger.debug(f"  Certificate serial: {cert.serial_number}")
        except Exception as cert_info_err:
            logger.debug(f"  Error extracting certificate info: {cert_info_err}")
    else:
        logger.debug("No main certificate in PKCS12")
    
    if private_key:
        logger.debug("Private key found - extracting details...")
        try:
            key_type = type(private_key).__name__
            logger.debug(f"  Private key type: {key_type}")
            if hasattr(private_key, 'key_size'):
                logger.debug(f"  Private key size: {private_key.key_size} bits")
        except Exception as key_info_err:
            logger.debug(f"  Error extracting private key info: {key_info_err}")
    else:
        logger.debug("No private key in PKCS12")
    
    if additional_certs:
        logger.debug(f"Additional certificates found: {len(additional_certs)}")
        for i, add_cert in enumerate(additional_certs):
            try:
                subject_cn = None
                for attribute in add_cert.subject:
                    if attribute.oid._name == 'commonName':
                        subject_cn = attribute.value
                        break
                logger.debug(f"  Additional cert [{i}]: {subject_cn}")
            except Exception as add_cert_err:
                logger.debug(f"  Error extracting additional cert [{i}] info: {add_cert_err}")
    else:
        logger.debug("No additional certificates in PKCS12")
    
    # Always use the main certificate hash for duplicate detection
    # This allows PKCS12 certificates to be detected as duplicates of standalone certificates
    if cert:
        # Use main certificate hash - same as standalone certificates
        content_hash = generate_certificate_hash(cert)
        logger.debug(f"PKCS12 using main certificate hash for duplicate detection: {content_hash[:16]}...")
    else:
        # No main certificate - use combined hash as fallback
        content_hash = generate_pkcs12_content_hash(cert, private_key, additional_certs)
        logger.debug(f"PKCS12 no main certificate, using combined hash: {content_hash[:16]}...")
    
    # Extract certificate metadata if available using new extractor
    metadata = None
    if cert:
        logger.debug("Extracting main certificate metadata...")
        metadata = extract_certificate_metadata(cert)
        logger.debug("Certificate metadata:\n%s", json.dumps(metadata, indent=2, default=str))
    else:
        logger.debug("No main certificate to extract metadata from")
    
    # Determine main certificate type using standardization
    if use_standardized and get_consistent_types and cert:
        type_info = get_consistent_types("PKCS12 Certificate", metadata)
        main_type = type_info["type"]  # Will be "Certificate"
        logger.debug(f"Main certificate standardized type: {main_type}")
    else:
        main_type = "PKCS12 Certificate"  # Legacy fallback
        logger.debug(f"Main certificate legacy type: {main_type}")
    
    # Prepare main result (certificate)
    result = {
        "type": main_type,  # Now uses standardized type ("Certificate")
        "isValid": True,
        "content_hash": content_hash,
        "details": metadata
    }
    
    # Extract additional components for separate storage
    additional_items = []
    
    # Extract private key if present
    if private_key:
        logger.debug("Processing PKCS12 private key for separate storage...")
        try:
            # Generate normalized hash for the private key (same as standalone private keys)
            key_hash = generate_normalized_private_key_hash(private_key)
            key_metadata = extract_private_key_metadata(private_key, is_encrypted=False)
            
            logger.debug(f"Private key hash: {key_hash[:16]}...")
            logger.debug(f"Private key metadata: {key_metadata}")
            
            # Use standardized type if available
            if use_standardized and get_consistent_types:
                type_info = get_consistent_types("Private Key", key_metadata)
                item_type = type_info["type"]  # Will be "PrivateKey"
                logger.debug(f"Private key standardized type: {item_type}")
            else:
                item_type = "Private Key"  # Legacy fallback
                logger.debug(f"Private key legacy type: {item_type}")
            
            additional_items.append({
                "type": item_type,  # Now uses "PrivateKey" instead of "Private Key"
                "format": "PKCS12",
                "isValid": True,
                "size": 0,  # Size is part of the PKCS12 container
                "content_hash": key_hash,  # Use consistent hash based on key material
                "details": key_metadata
            })
            logger.debug(f"Extracted private key from PKCS12 with type: {item_type}")
        except Exception as key_err:
            logger.error(f"Error extracting private key from PKCS12: {key_err}")
            import traceback
            logger.error(f"Private key extraction traceback: {traceback.format_exc()}")
    
    # Extract additional certificates if present
    if additional_certs:
        logger.debug(f"Processing {len(additional_certs)} additional certificates...")
        for i, additional_cert in enumerate(additional_certs):
            if additional_cert:
                try:
                    logger.debug(f"Processing additional certificate [{i}]...")
                    cert_hash = generate_certificate_hash(additional_cert)
                    cert_metadata = extract_certificate_metadata(additional_cert)
                    
                    logger.debug(f"Additional cert [{i}] hash: {cert_hash[:16]}...")
                    
                    # Use standardized type if available
                    if use_standardized and get_consistent_types:
                        type_info = get_consistent_types("Certificate", cert_metadata)
                        item_type = type_info["type"]  # Will be "Certificate", "IssuingCA", "IntermediateCA", or "RootCA"
                        logger.debug(f"Additional cert [{i}] standardized type: {item_type}")
                    else:
                        item_type = "Certificate"  # Legacy fallback
                        logger.debug(f"Additional cert [{i}] legacy type: {item_type}")
                    
                    additional_items.append({
                        "type": item_type,  # Now uses standardized types
                        "format": "PKCS12",
                        "isValid": True,
                        "size": 0,  # Size is part of the PKCS12 container
                        "content_hash": cert_hash,
                        "details": cert_metadata
                    })
                    logger.debug(f"Extracted additional certificate {i} from PKCS12 with type: {item_type}")
                except Exception as cert_err:
                    logger.error(f"Error extracting additional certificate {i} from PKCS12: {cert_err}")
                    import traceback
                    logger.error(f"Additional cert extraction traceback: {traceback.format_exc()}")
    
    # Add additional items to result if any were found
    if additional_items:
        result["additional_items"] = additional_items
        logger.debug(f"PKCS12 contains {len(additional_items)} additional items")
        for i, item in enumerate(additional_items):
            logger.debug(f"  Additional item [{i}]: {item['type']} - {item['content_hash'][:16]}...")
    else:
        logger.debug("No additional items extracted from PKCS12")
    
    # Generate summary log with standardized types
    cert_count = int(bool(cert))
    key_count = int(bool(private_key))
    additional_count = len(additional_certs or [])
    
    parts = []
    if cert_count:
        parts.append(f"{cert_count} Certificate")
    if key_count:
        parts.append(f"{key_count} Private Key")
    if additional_count:
        parts.append(f"1 Chain ({additional_count} certs)")
    
    total = cert_count + key_count + additional_count
    logger.info(f"PKCS12 extraction complete: {', '.join(parts)} ({total} total)")

    logger.debug(f"PKCS12 processing complete - main type: {result['type']}")
    return result