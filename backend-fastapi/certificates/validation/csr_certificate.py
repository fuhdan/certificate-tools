# backend-fastapi/certificates/validation/csr_certificate.py
# CSR <-> Certificate validation functions

import logging
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .models import ValidationResult
from .utils import compare_subject_names, compare_sans

logger = logging.getLogger(__name__)

def validate_csr_certificate_match(csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> ValidationResult:
    """Validate that CSR public key matches certificate public key using direct comparison"""
    logger.info(f"=== CSR <-> CERTIFICATE VALIDATION ===")
    logger.debug(f"CSR type: {type(csr).__name__}")
    logger.debug(f"Certificate type: {type(certificate).__name__}")
    
    try:
        # Extract public keys
        csr_public_key = csr.public_key()
        cert_public_key = certificate.public_key()
        
        logger.debug(f"CSR public key type: {type(csr_public_key).__name__}")
        logger.debug(f"Certificate public key type: {type(cert_public_key).__name__}")
        
        # SIMPLIFIED: Use direct public_numbers() comparison like the example
        if isinstance(csr_public_key, rsa.RSAPublicKey) and isinstance(cert_public_key, rsa.RSAPublicKey):
            csr_numbers = csr_public_key.public_numbers()
            cert_numbers = cert_public_key.public_numbers()
            
            # Direct comparison as shown in the example
            public_keys_match = csr_numbers == cert_numbers
            
            logger.debug(f"RSA public_numbers() comparison: {public_keys_match}")
            
            details = {
                "algorithm": "RSA",
                "keySize": csr_numbers.n.bit_length(),
                "publicKeyMatch": public_keys_match
            }
            
        elif isinstance(csr_public_key, ec.EllipticCurvePublicKey) and isinstance(cert_public_key, ec.EllipticCurvePublicKey):
            csr_numbers = csr_public_key.public_numbers()
            cert_numbers = cert_public_key.public_numbers()
            
            # Direct comparison for EC keys
            public_keys_match = csr_numbers == cert_numbers
            
            logger.debug(f"EC public_numbers() comparison: {public_keys_match}")
            
            details = {
                "algorithm": "EC",
                "curve": csr_public_key.curve.name,
                "keySize": csr_public_key.curve.key_size,
                "publicKeyMatch": public_keys_match
            }
            
        else:
            error_msg = f"Algorithm mismatch or unsupported: CSR has {type(csr_public_key).__name__}, Certificate has {type(cert_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="CSR <-> Certificate",
                error=error_msg
            )
        
        # Generate fingerprints for additional verification
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
        logger.debug(f"CSR fingerprint: {csr_fingerprint[:16]}...")
        logger.debug(f"Certificate fingerprint: {cert_fingerprint[:16]}...")
        
        # Both methods should agree
        is_valid = public_keys_match and fingerprint_match
        
        details.update({
            "fingerprint": {
                "csr": csr_fingerprint,
                "certificate": cert_fingerprint,
                "match": fingerprint_match
            }
        })
        
        # Add subject and SAN comparisons if there are differences
        subject_comparison = compare_subject_names(csr, certificate)
        if not subject_comparison["match"]:
            details["subjectComparison"] = subject_comparison
        
        san_comparison = compare_sans(csr, certificate)
        if not san_comparison["match"]:
            details["sanComparison"] = san_comparison
        
        # Add file information for display
        details.update({
            "publicKeyComparison": {
                "directMatch": public_keys_match,
                "fingerprintMatch": fingerprint_match
            }
        })
        
        if is_valid:
            logger.info("CSR <-> Certificate validation: ✅ MATCH - Public keys are identical")
        else:
            logger.warning("CSR <-> Certificate validation: ❌ NO MATCH - Public keys differ")
            if not public_keys_match:
                logger.warning("Direct public_numbers() comparison failed")
            if not fingerprint_match:
                logger.warning("Fingerprint comparison failed")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="CSR <-> Certificate",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error during CSR <-> Certificate validation: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return ValidationResult(
            is_valid=False,
            validation_type="CSR <-> Certificate",
            error=str(e)
        )