# Fix for the problematic validation function in csr_certificate.py
# This shows the corrected validate_csr_certificate_match function

import hashlib
import logging
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, x25519, x448
from .models import ValidationResult

logger = logging.getLogger(__name__)

def validate_csr_certificate_match(csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> ValidationResult:
    """Validate that CSR and certificate have matching public keys - COMPREHENSIVE approach"""
    logger.debug("=== CSR <-> CERTIFICATE VALIDATION ===")
    
    try:
        csr_public_key = csr.public_key()
        cert_public_key = certificate.public_key()
        
        logger.debug(f"CSR public key type: {type(csr_public_key).__name__}")
        logger.debug(f"Certificate public key type: {type(cert_public_key).__name__}")
        
        # First check: key types must match
        if type(csr_public_key) != type(cert_public_key):
            logger.warning(f"Key type mismatch: CSR has {type(csr_public_key).__name__}, Certificate has {type(cert_public_key).__name__}")
            return ValidationResult(
                is_valid=False,
                validation_type="CSR <-> Certificate",
                error=f"Key type mismatch: {type(csr_public_key).__name__} vs {type(cert_public_key).__name__}"
            )
    
        # Generate fingerprints FIRST (this is the most reliable method)
        csr_pubkey_der = csr_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_pubkey_der = cert_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        csr_fingerprint = hashlib.sha256(csr_pubkey_der).hexdigest()
        cert_fingerprint = hashlib.sha256(cert_pubkey_der).hexdigest()
        fingerprint_match = csr_fingerprint == cert_fingerprint
        
        logger.debug(f"Fingerprint comparison: {fingerprint_match}")
        logger.debug(f"CSR fingerprint: {csr_fingerprint}")
        logger.debug(f"Certificate fingerprint: {cert_fingerprint}")
        
        # Fix: Use type-safe key comparison based on actual key type
        direct_match = False
        details = {}
        
        if isinstance(csr_public_key, rsa.RSAPublicKey) and isinstance(cert_public_key, rsa.RSAPublicKey):
            # RSA keys - safe to access public_numbers()
            csr_numbers = csr_public_key.public_numbers()
            cert_numbers = cert_public_key.public_numbers()
            direct_match = (csr_numbers.n == cert_numbers.n and csr_numbers.e == cert_numbers.e)
            
            logger.debug(f"RSA direct comparison: modulus match = {csr_numbers.n == cert_numbers.n}, exponent match = {csr_numbers.e == cert_numbers.e}")
            
            details = {
                "algorithm": "RSA",
                "keySize": csr_numbers.n.bit_length()
            }
            
        elif isinstance(csr_public_key, ec.EllipticCurvePublicKey) and isinstance(cert_public_key, ec.EllipticCurvePublicKey):
            # EC keys - safe to access public_numbers() and curve
            csr_numbers = csr_public_key.public_numbers()
            cert_numbers = cert_public_key.public_numbers()
            direct_match = (csr_numbers.x == cert_numbers.x and 
                          csr_numbers.y == cert_numbers.y and
                          csr_public_key.curve.name == cert_public_key.curve.name)
            
            logger.debug(f"EC direct comparison: x match = {csr_numbers.x == cert_numbers.x}, y match = {csr_numbers.y == cert_numbers.y}, curve match = {csr_public_key.curve.name == cert_public_key.curve.name}")
            
            details = {
                "algorithm": "EC",
                "curve": csr_public_key.curve.name,
                "keySize": csr_public_key.curve.key_size
            }
            
        elif isinstance(csr_public_key, dsa.DSAPublicKey) and isinstance(cert_public_key, dsa.DSAPublicKey):
            # DSA keys - only compare via fingerprint since DSA public numbers structure is different
            logger.debug("DSA keys detected - using fingerprint comparison only")
            details = {
                "algorithm": "DSA",
                "keySize": csr_public_key.key_size if hasattr(csr_public_key, 'key_size') else 0
            }
            # For DSA, we rely on fingerprint match
            direct_match = fingerprint_match
            
        elif isinstance(csr_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey, x25519.X25519PublicKey, x448.X448PublicKey)):
            # Edwards/Montgomery curve keys - no public_numbers() method, use fingerprint only
            key_type = type(csr_public_key).__name__.replace('PublicKey', '')
            logger.debug(f"{key_type} keys detected - using fingerprint comparison only")
            
            key_size = 256 if isinstance(csr_public_key, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey)) else 448
            details = {
                "algorithm": key_type,
                "keySize": key_size
            }
            # For Edwards/Montgomery curves, we rely on fingerprint match
            direct_match = fingerprint_match
            
        else:
            logger.warning(f"Unsupported or unrecognized key type for detailed comparison: {type(csr_public_key).__name__}")
            direct_match = False
            details = {
                "algorithm": type(csr_public_key).__name__.replace('PublicKey', ''),
                "keySize": getattr(csr_public_key, 'key_size', 0)
            }
        
        logger.debug(f"Direct key comparison: {direct_match}")
        
        # THE KEY FIX: Both methods should agree, use fingerprint as authoritative
        # If fingerprints match, the keys ARE identical regardless of other comparisons
        is_valid = fingerprint_match
        
        # Add detailed comparison results
        details.update({
            "publicKeyComparison": {
                "directMatch": direct_match,
                "fingerprintMatch": fingerprint_match,
                "authoritativeResult": fingerprint_match  # This is the definitive answer
            },
            "fingerprints": {
                "csr": csr_fingerprint,
                "certificate": cert_fingerprint,
                "match": fingerprint_match
            }
        })
        
        # Log results
        if is_valid:
            logger.info("✅ CSR <-> Certificate validation: PUBLIC KEYS MATCH")
            logger.info(f"  ✓ Algorithm: {details['algorithm']}")
            logger.info(f"  ✓ Key size: {details['keySize']} bits")
            logger.info(f"  ✓ Fingerprint match: {fingerprint_match}")
            if 'directMatch' in details['publicKeyComparison']:
                logger.info(f"  ✓ Direct comparison: {direct_match}")
        else:
            logger.warning("❌ CSR <-> Certificate validation: PUBLIC KEYS DO NOT MATCH")
            logger.warning(f"  ✗ Fingerprint match: {fingerprint_match}")
            if 'directMatch' in details['publicKeyComparison']:
                logger.warning(f"  ✗ Direct comparison: {direct_match}")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="CSR <-> Certificate",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating CSR <-> Certificate: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return ValidationResult(
            is_valid=False,
            validation_type="CSR <-> Certificate",
            error=str(e)
        )