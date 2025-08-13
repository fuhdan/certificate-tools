# backend-fastapi/certificates/formats/pkcs12.py
# PKCS12 format analysis functions with comprehensive debugging
# Updated to use centralized Password Entry Service

import logging
import json
from typing import Dict, Any, Optional, List

from ..extractors.certificate import extract_certificate_metadata
from ..extractors.private_key import extract_private_key_metadata
from ..utils.hashing import (
    generate_certificate_hash, generate_pkcs12_content_hash, 
    generate_normalized_private_key_hash, generate_file_hash
)

# Import the centralized Password Entry Service
from services.password_entry_service import (
    password_entry_service,
    handle_encrypted_content,
    PasswordResult
)

logger = logging.getLogger(__name__)

logger.debug("formats/pkcs12.py initialized with Password Entry Service")

def analyze_pkcs12(file_content: bytes, password: Optional[str], filename: str = "") -> Dict[str, Any]:
    """
    Analyze PKCS12 content using centralized Password Entry Service
    
    This function now uses the Password Entry Service to handle all password-related
    logic consistently with other formats, ensuring standardized behavior.
    """
    logger.info(f"=== PKCS12 ANALYSIS (with Password Service) ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"Filename: {filename}")
    logger.debug(f"First 32 bytes (hex): {file_content[:32].hex()}")
    
    # Check PKCS12 file signature for debugging
    if len(file_content) >= 4:
        header = file_content[:4]
        logger.debug(f"PKCS12 header analysis: {header.hex()}")
        
        if header[0] == 0x30:
            logger.debug("PKCS12 ASN.1 SEQUENCE marker found")
        else:
            logger.warning(f"Unexpected PKCS12 header: expected 0x30, got 0x{header[0]:02x}")
    
    try:
        # Use the centralized Password Entry Service
        result, components, error, content_type = handle_encrypted_content(
            file_content, password, filename
        )
        
        logger.debug(f"Password service result: {result}")
        logger.debug(f"Content type detected: {content_type}")
        
        if result == PasswordResult.SUCCESS:
            # Successfully loaded PKCS12 bundle
            logger.info("PKCS12 bundle successfully loaded via Password Entry Service")
            if components is None:
                raise ValueError("Password service returned None components for successful result")
                
            private_key, cert, additional_certs = components
            
            # Ensure additional_certs is a list (it can be None from cryptography)
            additional_certs = additional_certs or []
            
            logger.debug(f"PKCS12 components found:")
            logger.debug(f"  Main certificate: {'YES' if cert else 'NO'}")
            logger.debug(f"  Private key: {'YES' if private_key else 'NO'}")
            logger.debug(f"  Additional certificates: {len(additional_certs)}")
            
            return _process_pkcs12_success(cert, private_key, additional_certs, is_encrypted=(password is not None))
            
        elif result == PasswordResult.NO_PASSWORD_NEEDED:
            # Unencrypted PKCS12 bundle
            logger.info("PKCS12 bundle loaded without password via Password Entry Service")
            if components is None:
                raise ValueError("Password service returned None components for no-password-needed result")
                
            private_key, cert, additional_certs = components
            
            # Ensure additional_certs is a list (it can be None from cryptography)
            additional_certs = additional_certs or []
            
            logger.debug(f"PKCS12 components found (unencrypted):")
            logger.debug(f"  Main certificate: {'YES' if cert else 'NO'}")
            logger.debug(f"  Private key: {'YES' if private_key else 'NO'}")
            logger.debug(f"  Additional certificates: {len(additional_certs)}")
            
            return _process_pkcs12_success(cert, private_key, additional_certs, is_encrypted=False)
            
        elif result == PasswordResult.PASSWORD_REQUIRED:
            # Password is required but not provided
            logger.info("Password required for encrypted PKCS12 bundle")
            return password_entry_service.create_password_required_response(
                file_content, content_type, filename
            )
            
        elif result == PasswordResult.WRONG_PASSWORD:
            # Wrong password provided
            logger.error("Wrong password provided for encrypted PKCS12 bundle")
            return password_entry_service.create_wrong_password_response(
                file_content, content_type
            )
            
        else:
            # Other error (INVALID_FORMAT, UNKNOWN_ERROR)
            logger.error(f"Password Entry Service error: {result} - {error}")
            return {
                "type": "PKCS12 Certificate",
                "isValid": False,
                "content_hash": generate_file_hash(file_content),
                "error": error or f"Password service error: {result}"
            }
            
    except Exception as e:
        logger.error(f"Unexpected error in PKCS12 analysis: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "PKCS12 Certificate",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }

def _process_pkcs12_success(cert, private_key, additional_certs: List, is_encrypted: bool = False) -> Dict[str, Any]:
    """
    Process successfully parsed PKCS12 content - extract all components with standardized types
    Updated to use consistent metadata and type handling
    """
    logger.debug(f"=== PKCS12 SUCCESS PROCESSING ===")
    logger.debug(f"Bundle was encrypted: {is_encrypted}")
    
    # Import standardization functions
    get_consistent_types = None
    use_standardized = False
    
    try:
        from ..types import get_consistent_types
        use_standardized = True
        logger.debug("Using standardized certificate types")
    except ImportError:
        logger.debug("Certificate type standardization not available, using legacy types")
    
    # Generate content hash for main certificate (primary identifier)
    if cert:
        # Use main certificate hash - same as standalone certificates
        content_hash = generate_certificate_hash(cert)
        logger.debug(f"PKCS12 using main certificate hash for duplicate detection: {content_hash[:16]}...")
    else:
        # No main certificate - use combined hash as fallback
        content_hash = generate_pkcs12_content_hash(cert, private_key, additional_certs)
        logger.debug(f"PKCS12 no main certificate, using combined hash: {content_hash[:16]}...")
    
    # Extract certificate metadata if available using standardized extractor
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
            key_metadata = extract_private_key_metadata(private_key, is_encrypted=is_encrypted)
            
            logger.debug(f"Private key hash: {key_hash[:16]}...")
            logger.debug(f"Private key metadata: {key_metadata}")
            
            # Create private key item for additional items list
            key_item = {
                "type": "Private Key",
                "isValid": True,
                "content_hash": key_hash,
                "details": key_metadata
            }
            additional_items.append(key_item)
            logger.debug("Added private key to additional items")
            
        except Exception as key_err:
            logger.error(f"Error processing PKCS12 private key: {key_err}")
    
    # Extract additional certificates if present
    if additional_certs:
        logger.debug(f"Processing {len(additional_certs)} additional certificates...")
        for i, additional_cert in enumerate(additional_certs):
            try:
                # Generate hash for additional certificate
                additional_hash = generate_certificate_hash(additional_cert)
                additional_metadata = extract_certificate_metadata(additional_cert)
                
                logger.debug(f"Additional cert {i+1} hash: {additional_hash[:16]}...")
                
                # Determine certificate type for additional certs
                if use_standardized and get_consistent_types:
                    type_info = get_consistent_types("Certificate", additional_metadata)
                    additional_type = type_info["type"]
                else:
                    additional_type = "Certificate"
                
                # Create additional certificate item
                additional_item = {
                    "type": additional_type,
                    "isValid": True,
                    "content_hash": additional_hash,
                    "details": additional_metadata
                }
                additional_items.append(additional_item)
                logger.debug(f"Added additional certificate {i+1} to items")
                
            except Exception as additional_err:
                logger.error(f"Error processing additional certificate {i+1}: {additional_err}")
    
    # Add additional items to result if any were found
    if additional_items:
        result["additional_items"] = additional_items
        logger.debug(f"Added {len(additional_items)} additional items to result")
    
    # Add bundle-specific information
    bundle_info = {
        "bundle_type": "PKCS12",
        "has_main_certificate": cert is not None,
        "has_private_key": private_key is not None,
        "additional_certificate_count": len(additional_certs),
        "total_components": 1 + len(additional_items),  # Main cert + additional items
        "is_encrypted": is_encrypted
    }
    
    if metadata:
        # Add bundle info to the main certificate's metadata
        metadata["bundle_info"] = bundle_info
    else:
        # If no main cert metadata, create minimal metadata with bundle info
        result["details"] = {"bundle_info": bundle_info}
    
    logger.info(f"PKCS12 bundle processing complete:")
    logger.info(f"  Main certificate: {'YES' if cert else 'NO'}")
    logger.info(f"  Private key: {'YES' if private_key else 'NO'}")  
    logger.info(f"  Additional certificates: {bundle_info['additional_certificate_count']}")
    logger.info(f"  Total components: {bundle_info['total_components']}")
    logger.info(f"  Bundle encrypted: {is_encrypted}")
    
    return result