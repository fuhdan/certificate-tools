# certificates/utils/hashing.py
# Hash generation utilities for certificate analysis

import hashlib
import logging
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

def generate_normalized_private_key_hash(private_key) -> str:
    """Generate a consistent hash for the same private key regardless of format or encryption"""
    try:
        # Always use the same normalization: DER + PKCS8 + No Encryption
        der_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.info(f"Generated normalized hash: {hash_value} for private key (DER bytes length: {len(der_bytes)})")
        return hash_value
    except Exception as e:
        logger.error(f"Error generating normalized hash: {e}")
        fallback_hash = hashlib.sha256(str(private_key).encode()).hexdigest()
        logger.warning(f"Using fallback hash: {fallback_hash}")
        return fallback_hash

def generate_pkcs12_content_hash(cert, private_key, additional_certs) -> str:
    """Generate a consistent hash for PKCS12 content regardless of password protection"""
    try:
        hash_components = []
        
        # Hash the main certificate
        if cert:
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            hash_components.append(cert_der)
            logger.debug(f"Added main certificate to PKCS12 hash (DER length: {len(cert_der)})")
        
        # Hash the private key if present
        if private_key:
            key_der = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            hash_components.append(key_der)
            logger.debug(f"Added private key to PKCS12 hash (DER length: {len(key_der)})")
        
        # Hash additional certificates
        if additional_certs:
            for i, additional_cert in enumerate(additional_certs):
                if additional_cert:
                    additional_der = additional_cert.public_bytes(serialization.Encoding.DER)
                    hash_components.append(additional_der)
                    logger.debug(f"Added additional certificate {i} to PKCS12 hash (DER length: {len(additional_der)})")
        
        # Combine all components and hash
        if hash_components:
            combined_content = b''.join(sorted(hash_components))  # Sort for consistency
            content_hash = hashlib.sha256(combined_content).hexdigest()
            logger.info(f"Generated PKCS12 content hash: {content_hash} from {len(hash_components)} components")
            return content_hash
        else:
            # Fallback if no components found
            fallback_hash = hashlib.sha256(b'empty_pkcs12').hexdigest()
            logger.warning(f"No PKCS12 components found, using fallback hash: {fallback_hash}")
            return fallback_hash
            
    except Exception as e:
        logger.error(f"Error generating PKCS12 content hash: {e}")
        fallback_hash = hashlib.sha256(f"pkcs12_error_{str(e)}".encode()).hexdigest()
        return fallback_hash

def generate_certificate_hash(cert) -> str:
    """Generate normalized hash for X.509 certificate"""
    try:
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.debug(f"Generated certificate hash: {hash_value}")
        return hash_value
    except Exception as e:
        logger.error(f"Error generating certificate hash: {e}")
        return hashlib.sha256(str(cert).encode()).hexdigest()

def generate_csr_hash(csr) -> str:
    """Generate normalized hash for CSR"""
    try:
        der_bytes = csr.public_bytes(serialization.Encoding.DER)
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.debug(f"Generated CSR hash: {hash_value}")
        return hash_value
    except Exception as e:
        logger.error(f"Error generating CSR hash: {e}")
        return hashlib.sha256(str(csr).encode()).hexdigest()

def generate_public_key_hash(public_key) -> str:
    """Generate normalized hash for public key"""
    try:
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.debug(f"Generated public key hash: {hash_value}")
        return hash_value
    except Exception as e:
        logger.error(f"Error generating public key hash: {e}")
        return hashlib.sha256(str(public_key).encode()).hexdigest()

def generate_file_hash(content: bytes) -> str:
    """Generate hash from file content as fallback"""
    return hashlib.sha256(content).hexdigest()