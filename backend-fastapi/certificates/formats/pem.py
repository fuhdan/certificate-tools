# backend-fastapi/certificates/formats/pem.py
# PEM format analysis functions with comprehensive debugging
# Updated to use centralized Password Entry Service

import hashlib
import logging
import json
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..extractors.certificate import extract_certificate_metadata, is_ca_certificate, extract_public_key_details
from ..extractors.csr import extract_csr_metadata
from ..extractors.private_key import extract_private_key_metadata
from ..utils.hashing import (
    generate_certificate_hash, generate_csr_hash, generate_public_key_hash,
    generate_normalized_private_key_hash, generate_file_hash
)

# Import the new Password Entry Service
from services.password_entry_service import (
    password_entry_service, 
    handle_encrypted_content, 
    PasswordResult
)

logger = logging.getLogger(__name__)

logger.debug("formats/pem.py initialized with Password Entry Service")

def analyze_pem_certificate(content_str: str, file_content: bytes) -> Dict[str, Any]:
    """Analyze PEM certificate content"""
    logger.info(f"=== PEM CERTIFICATE ANALYSIS ===")
    logger.debug(f"Content string length: {len(content_str)} characters")
    logger.debug(f"File content length: {len(file_content)} bytes")
    
    cert_blocks = content_str.count('-----BEGIN CERTIFICATE-----')
    logger.debug(f"Certificate blocks found: {cert_blocks}")
    
    if cert_blocks > 1:
        logger.info(f"Multiple certificates detected ({cert_blocks}), treating as certificate chain")
        # Certificate chain
        chain_hash = hashlib.sha256(content_str.encode()).hexdigest()
        logger.debug(f"Certificate chain hash: {chain_hash[:16]}...")
        
        return {
            "type": "Certificate Chain",
            "isValid": True,
            "content_hash": chain_hash,
            "details": {"certificateCount": cert_blocks}
        }
    else:
        logger.info("Single certificate detected, processing as individual certificate")
        # Single certificate
        try:
            logger.debug("Loading PEM certificate with cryptography...")
            cert = x509.load_pem_x509_certificate(file_content)
            logger.debug(f"Certificate loaded successfully: {type(cert)}")
            
            content_hash = generate_certificate_hash(cert)
            logger.debug(f"Certificate content hash: {content_hash[:16]}...")
            
            logger.debug("Extracting certificate metadata...")
            metadata = extract_certificate_metadata(cert)
            logger.debug(f"Certificate metadata extracted, keys: {list(metadata.keys())}")
            
            # Determine certificate type
            is_ca = is_ca_certificate(cert)
            cert_type = "CA Certificate" if is_ca else "Certificate"
            logger.debug(f"Certificate type determined: {cert_type} (CA: {is_ca})")
            
            result = {
                "type": cert_type,
                "isValid": True,
                "content_hash": content_hash,
                "details": metadata
            }
            
            logger.info(f"PEM certificate analysis complete: {cert_type}")
            return result
            
        except Exception as cert_error:
            logger.error(f"Error processing PEM certificate: {cert_error}")
            logger.error(f"Certificate content preview: {file_content[:200]}...")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            
            return {
                "type": "Certificate",
                "isValid": False,
                "content_hash": generate_file_hash(file_content),
                "error": str(cert_error)
            }

def analyze_pem_csr(file_content: bytes) -> Dict[str, Any]:
    """Analyze PEM CSR content"""
    logger.info(f"=== PEM CSR ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    
    try:
        logger.debug("Loading PEM CSR with cryptography...")
        csr = x509.load_pem_x509_csr(file_content)
        logger.debug(f"CSR loaded successfully: {type(csr)}")
        
        content_hash = generate_csr_hash(csr)
        logger.debug(f"CSR content hash: {content_hash[:16]}...")
        
        logger.debug("Extracting CSR metadata...")
        metadata = extract_csr_metadata(csr)
        logger.debug(f"CSR metadata extracted, keys: {list(metadata.keys())}")
        
        result = {
            "type": "CSR",
            "isValid": True,
            "content_hash": content_hash,
            "details": metadata
        }
        
        logger.info(f"PEM CSR analysis complete")
        return result
        
    except Exception as csr_error:
        logger.error(f"Error processing PEM CSR: {csr_error}")
        logger.error(f"CSR content preview: {file_content[:200]}...")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "CSR",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(csr_error)
        }

def analyze_pem_private_key(file_content: bytes, password: Optional[str], filename: str = "") -> Dict[str, Any]:
    """
    Analyze PEM private key content using centralized Password Entry Service
    
    This function now uses the Password Entry Service to handle all password-related
    logic consistently across all formats, fixing the PEM password entry issues.
    """
    logger.info(f"=== PEM PRIVATE KEY ANALYSIS (with Password Service) ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"Filename: {filename}")
    
    try:
        # Use the centralized Password Entry Service
        result, private_key, error, content_type = handle_encrypted_content(
            file_content, password, filename
        )
        
        logger.debug(f"Password service result: {result}")
        logger.debug(f"Content type detected: {content_type}")
        
        if result == PasswordResult.SUCCESS:
            # Successfully loaded private key
            logger.info("Private key successfully loaded via Password Entry Service")
            
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
            
            logger.info(f"PEM private key analysis complete: {metadata.get('algorithm', 'Unknown')} {metadata.get('key_size', 0)} bits")
            return result_dict
            
        elif result == PasswordResult.NO_PASSWORD_NEEDED:
            # Unencrypted private key
            logger.info("Private key loaded without password via Password Entry Service")
            
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
            
            logger.info(f"Unencrypted PEM private key analysis complete: {metadata.get('algorithm', 'Unknown')} {metadata.get('key_size', 0)} bits")
            return result_dict
            
        elif result == PasswordResult.PASSWORD_REQUIRED:
            # Password is required but not provided
            logger.info("Password required for encrypted PEM private key")
            return password_entry_service.create_password_required_response(
                file_content, content_type, filename
            )
            
        elif result == PasswordResult.WRONG_PASSWORD:
            # Wrong password provided
            logger.error("Wrong password provided for encrypted PEM private key")
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
        logger.error(f"Unexpected error in PEM private key analysis: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "Private Key",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }

def analyze_pem_public_key(file_content: bytes) -> Dict[str, Any]:
    """Analyze PEM public key content"""
    logger.info(f"=== PEM PUBLIC KEY ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    
    try:
        logger.debug("Loading PEM public key with cryptography...")
        public_key = serialization.load_pem_public_key(file_content)
        logger.debug(f"Public key loaded successfully: {type(public_key)}")
        
        content_hash = generate_public_key_hash(public_key)
        logger.debug(f"Public key content hash: {content_hash[:16]}...")
        
        logger.debug("Extracting public key details...")
        details = extract_public_key_details(public_key)
        logger.debug(f"Public key details: {details}")
        
        result = {
            "type": "Public Key",
            "isValid": True,
            "content_hash": content_hash,
            "details": details
        }
        
        logger.info(f"PEM public key analysis complete: {details.get('algorithm', 'Unknown')} {details.get('keySize', 0)} bits")
        return result
        
    except Exception as e:
        logger.error(f"Error processing PEM public key: {e}")
        logger.error(f"Public key content preview: {file_content[:200]}...")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return {
            "type": "Public Key",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "error": str(e)
        }