# certificates/formats/pem.py
# PEM format analysis functions with comprehensive debugging

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

logger = logging.getLogger(__name__)

logger.debug("formats/pem.py initialized")

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
            
            # Determine certificate type
            is_ca = is_ca_certificate(cert)
            cert_type = "CA Certificate" if is_ca else "Certificate"
            logger.debug(f"Certificate type determined: {cert_type} (CA: {is_ca})")
            
            logger.debug("Extracting certificate metadata...")
            metadata = extract_certificate_metadata(cert)
            logger.debug(f"Certificate metadata extracted, keys: {list(metadata.keys())}")
            
            logger.debug("Certificate metadata:\n%s", json.dumps(metadata, indent=2, default=str))

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
            logger.error(f"Certificate content preview: {content_str[:200]}...")
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

def analyze_pem_private_key(file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Analyze PEM private key content"""
    logger.info(f"=== PEM PRIVATE KEY ANALYSIS ===")
    logger.debug(f"File content length: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    
    # Check for encryption markers
    content_str = file_content.decode('utf-8', errors='ignore')
    encrypted_markers = ['-----BEGIN ENCRYPTED PRIVATE KEY-----', 'Proc-Type: 4,ENCRYPTED', 'DEK-Info:']
    is_encrypted = any(marker in content_str for marker in encrypted_markers)
    logger.debug(f"Encryption markers detected: {is_encrypted}")
    
    if is_encrypted:
        logger.debug("Encrypted private key markers found:")
        for marker in encrypted_markers:
            if marker in content_str:
                logger.debug(f"  Found: {marker}")
    
    try:
        logger.debug("Attempting to load private key without password...")
        # Try to load the private key without password first
        private_key = serialization.load_pem_private_key(file_content, password=None)
        
        logger.info("Successfully loaded unencrypted PEM private key")
        # Unencrypted private key
        normalized_hash = generate_normalized_private_key_hash(private_key)
        logger.debug(f"Normalized private key hash: {normalized_hash[:16]}...")
        
        logger.debug("Extracting private key metadata...")
        metadata = extract_private_key_metadata(private_key, is_encrypted=False)
        logger.debug(f"Private key metadata: {metadata}")

        result = {
            "type": "Private Key",
            "isValid": True,
            "content_hash": normalized_hash,
            "details": metadata
        }
        
        logger.info(f"PEM private key analysis complete: {metadata.get('algorithm', 'Unknown')} {metadata.get('key_size', 0)} bits")
        return result
        
    except Exception as e:
        # Failed to load without password - check if it's encrypted
        error_str = str(e).lower()
        logger.debug(f"Private key loading without password failed: {e}")
        logger.debug(f"Error string analysis: {error_str}")
        
        if any(keyword in error_str for keyword in ['password', 'decrypt', 'encrypted', 'bad decrypt']):
            logger.info("Private key is encrypted, checking password...")
            # It's encrypted
            if not password:
                logger.info("No password provided for encrypted private key")
                return {
                    "type": "Private Key - Password Required",
                    "isValid": False,
                    "requiresPassword": True,
                    "content_hash": generate_file_hash(file_content),
                    "details": {
                        "algorithm": "Encrypted (password required)",
                        "key_size": 0,
                        "curve": "N/A",
                        "is_encrypted": True,
                        "requiresPassword": True
                    }
                }
            else:
                logger.debug("Attempting to decrypt with provided password...")
                # Try with provided password
                try:
                    password_bytes = password.encode('utf-8')
                    logger.debug(f"Password encoded to {len(password_bytes)} bytes")
                    
                    private_key = serialization.load_pem_private_key(file_content, password=password_bytes)
                    logger.info("Successfully decrypted PEM private key with password")
                    
                    # Success with password
                    normalized_hash = generate_normalized_private_key_hash(private_key)
                    logger.debug(f"Decrypted private key hash: {normalized_hash[:16]}...")
                    
                    metadata = extract_private_key_metadata(private_key, is_encrypted=True)
                    logger.debug(f"Decrypted private key metadata: {metadata}")
                    
                    result = {
                        "type": "Private Key",
                        "isValid": True,
                        "content_hash": normalized_hash,
                        "details": metadata
                    }
                    
                    logger.info(f"Encrypted PEM private key analysis complete: {metadata.get('algorithm', 'Unknown')} {metadata.get('key_size', 0)} bits")
                    return result
                    
                except Exception as pwd_error:
                    logger.error(f"Password decryption failed: {pwd_error}")
                    # Wrong password
                    return {
                        "type": "Private Key - Invalid Password",
                        "isValid": False,
                        "requiresPassword": True,
                        "content_hash": generate_file_hash(file_content),
                        "details": {
                            "algorithm": "Encrypted (incorrect password)",
                            "key_size": 0,
                            "curve": "N/A",
                            "is_encrypted": True,
                            "requiresPassword": True
                        }
                    }
        else:
            # Some other parsing error
            logger.error(f"PEM private key parsing failed with non-password error: {e}")
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