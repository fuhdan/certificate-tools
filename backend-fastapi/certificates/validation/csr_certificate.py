# backend-fastapi/certificates/validation/csr_certificate.py
# CSR <-> Certificate validation functions - TYPE-SAFE VERSION

import logging
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .models import ValidationResult
from .utils import compare_subject_names, compare_sans

logger = logging.getLogger(__name__)

def validate_csr_certificate_match(csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> ValidationResult:
    """Validate that CSR public key matches certificate public key using fingerprint comparison"""
    logger.info(f"=== CSR <-> CERTIFICATE VALIDATION ===")
    logger.debug(f"CSR type: {type(csr).__name__}")
    logger.debug(f"Certificate type: {type(certificate).__name__}")
    
    try:
        # Extract public keys
        csr_public_key = csr.public_key()
        cert_public_key = certificate.public_key()
        
        logger.debug(f"CSR public key type: {type(csr_public_key).__name__}")
        logger.debug(f"Certificate public key type: {type(cert_public_key).__name__}")
        
        # Check algorithm compatibility
        if type(csr_public_key) != type(cert_public_key):
            error_msg = f"Algorithm mismatch: CSR has {type(csr_public_key).__name__}, Certificate has {type(cert_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="CSR <-> Certificate",
                error=error_msg
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
        
        # TYPE-SAFE direct comparison based on key type
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
        else:
            # For other key types (DSA, Ed25519, Ed448, X25519, X448, etc.)
            # Use fingerprint comparison only since they don't have compatible public_numbers() methods
            logger.debug(f"Using fingerprint-only comparison for {type(csr_public_key).__name__}")
            direct_match = fingerprint_match  # For non-RSA/EC keys, fingerprint IS the direct comparison
            
            details = {
                "algorithm": type(csr_public_key).__name__.replace('PublicKey', ''),
                "keySize": getattr(csr_public_key, 'key_size', 0)
            }
        
        logger.debug(f"Direct key comparison: {direct_match}")
        
        # THE KEY FIX: Use fingerprint as authoritative - it's the most reliable method
        is_valid = fingerprint_match
        
        # CRITICAL DEBUG LOGGING
        logger.info(f"=== FINAL CSR VALIDATION RESULT ===")
        logger.info(f"is_valid value: {is_valid}")
        logger.info(f"fingerprint_match: {fingerprint_match}")
        logger.info(f"direct_match: {direct_match}")
        
        # Add detailed comparison results
        details.update({
            "publicKeyComparison": {
                "directMatch": direct_match,
                "fingerprintMatch": fingerprint_match
            },
            "fingerprint": {
                "csr": csr_fingerprint,
                "certificate": cert_fingerprint,
                "match": fingerprint_match
            }
        })
        
        # Add subject and SAN comparisons if there are differences
        try:
            subject_comparison = compare_subject_names(csr, certificate)
            if not subject_comparison["match"]:
                details["subjectComparison"] = subject_comparison
        except Exception as e:
            logger.warning(f"Error comparing subject names: {e}")
        
        try:
            san_comparison = compare_sans(csr, certificate)
            if not san_comparison["match"]:
                details["sanComparison"] = san_comparison
        except Exception as e:
            logger.warning(f"Error comparing SANs: {e}")
        
        # Log the final result with explanation
        if is_valid:
            logger.info("✅ CSR <-> Certificate validation: PUBLIC KEYS MATCH")
            logger.info(f"  ✓ Algorithm: {details['algorithm']}")
            logger.info(f"  ✓ Key size: {details['keySize']} bits")
            logger.info(f"  ✓ Fingerprint match: True")
            logger.info(f"  ✓ Direct comparison: {direct_match}")
        else:
            logger.warning("❌ CSR <-> Certificate validation: PUBLIC KEYS DO NOT MATCH")
            logger.warning(f"  ✗ Fingerprint match: {fingerprint_match}")
            logger.warning(f"  ✗ Direct comparison: {direct_match}")
        
        logger.info(f"About to return ValidationResult with is_valid={is_valid}")
        
        result = ValidationResult(
            is_valid=is_valid,
            validation_type="CSR <-> Certificate",
            details=details
        )
        
        logger.info(f"Created ValidationResult: is_valid={result.is_valid}")
        return result
        
    except Exception as e:
        logger.error(f"Error during CSR <-> Certificate validation: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return ValidationResult(
            is_valid=False,
            validation_type="CSR <-> Certificate",
            error=str(e)
        )