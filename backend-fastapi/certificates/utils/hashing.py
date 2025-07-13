# certificates/utils/hashing.py
# Hash generation utilities for certificate analysis with comprehensive debugging

import hashlib
import logging
from typing import Dict
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

def generate_normalized_private_key_hash(private_key) -> str:
    """Generate a consistent hash for the same private key regardless of format or encryption"""
    logger.debug(f"=== NORMALIZED PRIVATE KEY HASH GENERATION ===")
    logger.debug(f"Private key type: {type(private_key).__name__}")
    
    try:
        logger.debug("Converting private key to normalized DER format...")
        logger.debug("  Encoding: DER")
        logger.debug("  Format: PKCS8")
        logger.debug("  Encryption: None (for normalization)")
        
        # Always use the same normalization: DER + PKCS8 + No Encryption
        der_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        logger.debug(f"Normalized DER bytes length: {len(der_bytes)}")
        logger.debug(f"DER header (first 32 bytes): {der_bytes[:32].hex()}")
        
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.info(f"Generated normalized private key hash: {hash_value[:16]}... (full length: {len(hash_value)})")
        logger.debug(f"Hash input size: {len(der_bytes)} bytes -> SHA256: {hash_value}")
        
        return hash_value
        
    except Exception as e:
        logger.error(f"Error generating normalized private key hash: {e}")
        logger.error(f"Private key details: {type(private_key)}")
        
        # Log private key attributes for debugging
        try:
            logger.debug("Private key attributes analysis:")
            if hasattr(private_key, 'key_size'):
                logger.debug(f"  Key size: {private_key.key_size}")
            if hasattr(private_key, 'curve'):
                logger.debug(f"  Curve: {private_key.curve}")
            logger.debug(f"  Available methods: {[method for method in dir(private_key) if not method.startswith('_')]}")
        except Exception as attr_err:
            logger.debug(f"Could not analyze private key attributes: {attr_err}")
        
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Fallback hash generation
        logger.warning("Using fallback hash generation method...")
        fallback_input = f"private_key_{type(private_key).__name__}_{id(private_key)}"
        fallback_hash = hashlib.sha256(fallback_input.encode()).hexdigest()
        logger.warning(f"Fallback hash generated: {fallback_hash[:16]}...")
        
        return fallback_hash

def generate_pkcs12_content_hash(cert, private_key, additional_certs) -> str:
    """Generate a consistent hash for PKCS12 content regardless of password protection"""
    logger.debug(f"=== PKCS12 CONTENT HASH GENERATION ===")
    logger.debug(f"Components to hash:")
    logger.debug(f"  Main certificate: {'YES' if cert else 'NO'}")
    logger.debug(f"  Private key: {'YES' if private_key else 'NO'}")
    logger.debug(f"  Additional certificates: {len(additional_certs) if additional_certs else 0}")
    
    try:
        hash_components = []
        component_info = []
        
        # Hash the main certificate
        if cert:
            logger.debug("Processing main certificate for PKCS12 hash...")
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            hash_components.append(cert_der)
            component_info.append(f"main_cert:{len(cert_der)}bytes")
            logger.debug(f"  Main certificate DER length: {len(cert_der)} bytes")
            logger.debug(f"  Main certificate DER header: {cert_der[:16].hex()}")
            
            # Log certificate subject for identification
            try:
                subject_cn = None
                for attribute in cert.subject:
                    if attribute.oid._name == 'commonName':
                        subject_cn = attribute.value
                        break
                logger.debug(f"  Main certificate CN: {subject_cn}")
            except Exception as cert_info_err:
                logger.debug(f"  Could not extract certificate CN: {cert_info_err}")
        
        # Hash the private key if present
        if private_key:
            logger.debug("Processing private key for PKCS12 hash...")
            try:
                key_der = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                hash_components.append(key_der)
                component_info.append(f"private_key:{len(key_der)}bytes")
                logger.debug(f"  Private key DER length: {len(key_der)} bytes")
                logger.debug(f"  Private key DER header: {key_der[:16].hex()}")
                logger.debug(f"  Private key type: {type(private_key).__name__}")
            except Exception as key_der_err:
                logger.error(f"  Error converting private key to DER: {key_der_err}")
                # Use a fallback for private key
                key_fallback = f"private_key_{type(private_key).__name__}_{id(private_key)}".encode()
                hash_components.append(key_fallback)
                component_info.append(f"private_key_fallback:{len(key_fallback)}bytes")
                logger.warning(f"  Using private key fallback: {len(key_fallback)} bytes")
        
        # Hash additional certificates
        if additional_certs:
            logger.debug(f"Processing {len(additional_certs)} additional certificates...")
            for i, additional_cert in enumerate(additional_certs):
                if additional_cert:
                    try:
                        additional_der = additional_cert.public_bytes(serialization.Encoding.DER)
                        hash_components.append(additional_der)
                        component_info.append(f"add_cert_{i}:{len(additional_der)}bytes")
                        logger.debug(f"  Additional cert [{i}] DER length: {len(additional_der)} bytes")
                        
                        # Log additional certificate subject
                        try:
                            subject_cn = None
                            for attribute in additional_cert.subject:
                                if attribute.oid._name == 'commonName':
                                    subject_cn = attribute.value
                                    break
                            logger.debug(f"  Additional cert [{i}] CN: {subject_cn}")
                        except Exception as add_cert_info_err:
                            logger.debug(f"  Could not extract additional cert [{i}] CN: {add_cert_info_err}")
                            
                    except Exception as add_cert_err:
                        logger.error(f"  Error processing additional certificate [{i}]: {add_cert_err}")
        
        # Combine all components and hash
        if hash_components:
            logger.debug("Combining PKCS12 components for hashing...")
            logger.debug(f"Components to combine: {component_info}")
            
            # Sort components for consistency
            sorted_components = sorted(hash_components)
            logger.debug(f"Components sorted for consistency (lengths): {[len(comp) for comp in sorted_components]}")
            
            combined_content = b''.join(sorted_components)
            logger.debug(f"Combined content length: {len(combined_content)} bytes")
            logger.debug(f"Combined content header: {combined_content[:32].hex()}")
            
            content_hash = hashlib.sha256(combined_content).hexdigest()
            logger.info(f"Generated PKCS12 content hash: {content_hash[:16]}... from {len(hash_components)} components")
            logger.debug(f"Full PKCS12 hash: {content_hash}")
            
            return content_hash
        else:
            # Fallback if no components found
            logger.warning("No PKCS12 components found for hashing")
            fallback_hash = hashlib.sha256(b'empty_pkcs12').hexdigest()
            logger.warning(f"Using PKCS12 fallback hash: {fallback_hash[:16]}...")
            return fallback_hash
            
    except Exception as e:
        logger.error(f"Error generating PKCS12 content hash: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Generate error-based fallback hash
        error_input = f"pkcs12_error_{str(e)}_{id(cert)}_{id(private_key)}"
        fallback_hash = hashlib.sha256(error_input.encode()).hexdigest()
        logger.error(f"PKCS12 error fallback hash: {fallback_hash[:16]}...")
        return fallback_hash

def generate_certificate_hash(cert) -> str:
    """Generate normalized hash for X.509 certificate"""
    logger.debug(f"=== CERTIFICATE HASH GENERATION ===")
    logger.debug(f"Certificate type: {type(cert).__name__}")
    
    try:
        # Log certificate identification info
        try:
            subject_cn = None
            for attribute in cert.subject:
                if attribute.oid._name == 'commonName':
                    subject_cn = attribute.value
                    break
            logger.debug(f"Certificate subject CN: {subject_cn}")
            logger.debug(f"Certificate serial number: {cert.serial_number}")
        except Exception as cert_info_err:
            logger.debug(f"Could not extract certificate info: {cert_info_err}")
        
        logger.debug("Converting certificate to DER format...")
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        logger.debug(f"Certificate DER length: {len(der_bytes)} bytes")
        logger.debug(f"Certificate DER header: {der_bytes[:32].hex()}")
        
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.info(f"Generated certificate hash: {hash_value[:16]}... (full length: {len(hash_value)})")
        logger.debug(f"Certificate hash input: {len(der_bytes)} bytes -> SHA256: {hash_value}")
        
        return hash_value
        
    except Exception as e:
        logger.error(f"Error generating certificate hash: {e}")
        logger.error(f"Certificate object: {cert}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Fallback hash
        fallback_input = f"cert_error_{str(cert)}_{id(cert)}"
        fallback_hash = hashlib.sha256(fallback_input.encode()).hexdigest()
        logger.error(f"Certificate fallback hash: {fallback_hash[:16]}...")
        return fallback_hash

def generate_csr_hash(csr) -> str:
    """Generate normalized hash for CSR"""
    logger.debug(f"=== CSR HASH GENERATION ===")
    logger.debug(f"CSR type: {type(csr).__name__}")
    
    try:
        # Log CSR identification info
        try:
            subject_cn = None
            for attribute in csr.subject:
                if attribute.oid._name == 'commonName':
                    subject_cn = attribute.value
                    break
            logger.debug(f"CSR subject CN: {subject_cn}")
        except Exception as csr_info_err:
            logger.debug(f"Could not extract CSR info: {csr_info_err}")
        
        logger.debug("Converting CSR to DER format...")
        der_bytes = csr.public_bytes(serialization.Encoding.DER)
        logger.debug(f"CSR DER length: {len(der_bytes)} bytes")
        logger.debug(f"CSR DER header: {der_bytes[:32].hex()}")
        
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.info(f"Generated CSR hash: {hash_value[:16]}... (full length: {len(hash_value)})")
        logger.debug(f"CSR hash input: {len(der_bytes)} bytes -> SHA256: {hash_value}")
        
        return hash_value
        
    except Exception as e:
        logger.error(f"Error generating CSR hash: {e}")
        logger.error(f"CSR object: {csr}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Fallback hash
        fallback_input = f"csr_error_{str(csr)}_{id(csr)}"
        fallback_hash = hashlib.sha256(fallback_input.encode()).hexdigest()
        logger.error(f"CSR fallback hash: {fallback_hash[:16]}...")
        return fallback_hash

def generate_public_key_hash(public_key) -> str:
    """Generate normalized hash for public key"""
    logger.debug(f"=== PUBLIC KEY HASH GENERATION ===")
    logger.debug(f"Public key type: {type(public_key).__name__}")
    
    try:
        # Log public key info
        if hasattr(public_key, 'key_size'):
            logger.debug(f"Public key size: {public_key.key_size} bits")
        if hasattr(public_key, 'curve'):
            logger.debug(f"Public key curve: {public_key.curve}")
        
        logger.debug("Converting public key to DER format...")
        logger.debug("  Encoding: DER")
        logger.debug("  Format: SubjectPublicKeyInfo")
        
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        logger.debug(f"Public key DER length: {len(der_bytes)} bytes")
        logger.debug(f"Public key DER header: {der_bytes[:32].hex()}")
        
        hash_value = hashlib.sha256(der_bytes).hexdigest()
        logger.info(f"Generated public key hash: {hash_value[:16]}... (full length: {len(hash_value)})")
        logger.debug(f"Public key hash input: {len(der_bytes)} bytes -> SHA256: {hash_value}")
        
        return hash_value
        
    except Exception as e:
        logger.error(f"Error generating public key hash: {e}")
        logger.error(f"Public key object: {public_key}")
        logger.error(f"Public key type: {type(public_key)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Fallback hash
        fallback_input = f"pubkey_error_{str(public_key)}_{id(public_key)}"
        fallback_hash = hashlib.sha256(fallback_input.encode()).hexdigest()
        logger.error(f"Public key fallback hash: {fallback_hash[:16]}...")
        return fallback_hash

def generate_file_hash(content: bytes) -> str:
    """Generate hash from file content as fallback"""
    logger.debug(f"=== FILE HASH GENERATION ===")
    logger.debug(f"Content type: {type(content)}")
    logger.debug(f"Content length: {len(content)} bytes")
    
    if len(content) > 0:
        logger.debug(f"Content header: {content[:min(32, len(content))].hex()}")
        if len(content) > 64:
            logger.debug(f"Content trailer: {content[-32:].hex()}")
    else:
        logger.warning("Empty content for file hash generation")
    
    hash_value = hashlib.sha256(content).hexdigest()
    logger.info(f"Generated file hash: {hash_value[:16]}... (full length: {len(hash_value)})")
    logger.debug(f"File hash input: {len(content)} bytes -> SHA256: {hash_value}")
    
    return hash_value

def compare_hashes(hash1: str, hash2: str, context: str = "") -> bool:
    """Compare two hashes with detailed logging"""
    logger.debug(f"=== HASH COMPARISON ===")
    if context:
        logger.debug(f"Comparison context: {context}")
    
    logger.debug(f"Hash 1: {hash1}")
    logger.debug(f"Hash 2: {hash2}")
    logger.debug(f"Hash 1 length: {len(hash1)}")
    logger.debug(f"Hash 2 length: {len(hash2)}")
    
    # Check for obvious issues
    if not hash1 or not hash2:
        logger.warning("One or both hashes are empty/None")
        logger.debug(f"Hash 1 empty: {not hash1}")
        logger.debug(f"Hash 2 empty: {not hash2}")
        return False
    
    if len(hash1) != len(hash2):
        logger.warning(f"Hash length mismatch: {len(hash1)} vs {len(hash2)}")
        return False
    
    # Check for partial matches (debugging hash generation issues)
    if len(hash1) >= 16 and len(hash2) >= 16:
        prefix_match = hash1[:16] == hash2[:16]
        if prefix_match and hash1 != hash2:
            logger.warning("Hash prefixes match but full hashes differ - possible hash generation issue")
            logger.debug(f"Matching prefix: {hash1[:16]}")
            logger.debug(f"Hash 1 suffix: {hash1[16:]}")
            logger.debug(f"Hash 2 suffix: {hash2[16:]}")
    
    result = hash1 == hash2
    logger.debug(f"Hash comparison result: {'MATCH' if result else 'NO MATCH'}")
    
    if not result:
        # Log character differences for debugging
        differences = []
        for i, (c1, c2) in enumerate(zip(hash1, hash2)):
            if c1 != c2:
                differences.append(i)
        
        if differences:
            logger.debug(f"Hash differences at positions: {differences[:10]}{'...' if len(differences) > 10 else ''}")
            logger.debug(f"First difference at position {differences[0]}: '{hash1[differences[0]]}' vs '{hash2[differences[0]]}'")
    
    return result

def debug_hash_generation(obj, obj_type: str) -> Dict[str, str]:
    """Debug hash generation for various object types"""
    logger.debug(f"=== HASH GENERATION DEBUG ===")
    logger.debug(f"Object type: {obj_type}")
    logger.debug(f"Object class: {type(obj).__name__}")
    
    debug_info = {
        "object_type": obj_type,
        "object_class": type(obj).__name__,
        "object_id": str(id(obj))
    }
    
    try:
        if obj_type == "certificate":
            debug_info["hash"] = generate_certificate_hash(obj)
        elif obj_type == "csr":
            debug_info["hash"] = generate_csr_hash(obj)
        elif obj_type == "private_key":
            debug_info["hash"] = generate_normalized_private_key_hash(obj)
        elif obj_type == "public_key":
            debug_info["hash"] = generate_public_key_hash(obj)
        else:
            logger.warning(f"Unknown object type for hash debug: {obj_type}")
            debug_info["hash"] = "unknown_type"
            
    except Exception as e:
        logger.error(f"Error in debug hash generation: {e}")
        debug_info["error"] = str(e)
        debug_info["hash"] = "error_occurred"
    
    logger.debug(f"Debug hash generation result: {debug_info}")
    return debug_info