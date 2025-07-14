# backend-fastapi/certificates/validation/private_key_csr.py
# Private Key <-> CSR validation functions

import logging
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .models import ValidationResult

logger = logging.getLogger(__name__)

def validate_private_key_csr_match(private_key, csr: x509.CertificateSigningRequest) -> ValidationResult:
    """Validate that private key matches the public key in CSR"""
    logger.info(f"=== PRIVATE KEY <-> CSR VALIDATION ===")
    logger.debug(f"Private key type: {type(private_key).__name__}")
    logger.debug(f"CSR type: {type(csr).__name__}")
    
    try:
        # Extract public keys
        private_public_key = private_key.public_key()
        csr_public_key = csr.public_key()
        
        logger.debug(f"Private key's public key type: {type(private_public_key).__name__}")
        logger.debug(f"CSR's public key type: {type(csr_public_key).__name__}")
        
        # Check if both are the same algorithm type
        if type(private_public_key) != type(csr_public_key):
            error_msg = f"Algorithm mismatch: Private key has {type(private_public_key).__name__}, CSR has {type(csr_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key <-> CSR",
                error=error_msg,
                details={
                    "privateKeyAlgorithm": type(private_public_key).__name__,
                    "csrAlgorithm": type(csr_public_key).__name__
                }
            )
        
        # Validate based on key type
        if isinstance(private_public_key, rsa.RSAPublicKey):
            return validate_rsa_keys(private_public_key, csr_public_key)
        elif isinstance(private_public_key, ec.EllipticCurvePublicKey):
            return validate_ec_keys(private_public_key, csr_public_key)
        else:
            error_msg = f"Unsupported key type: {type(private_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key <-> CSR",
                error=error_msg
            )
            
    except Exception as e:
        logger.error(f"Error during private key <-> CSR validation: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> CSR",
            error=str(e)
        )

def validate_rsa_keys(private_public_key: rsa.RSAPublicKey, csr_public_key: rsa.RSAPublicKey) -> ValidationResult:
    """Validate RSA key pair using public_numbers() comparison"""
    logger.debug("=== RSA KEY VALIDATION ===")
    
    try:
        # Get public numbers for comparison - THIS IS THE REAL VALIDATION!
        private_numbers = private_public_key.public_numbers()
        csr_numbers = csr_public_key.public_numbers()
        
        logger.debug(f"Private key RSA modulus bit length: {private_numbers.n.bit_length()}")
        logger.debug(f"CSR RSA modulus bit length: {csr_numbers.n.bit_length()}")
        logger.debug(f"Private key RSA exponent: {private_numbers.e}")
        logger.debug(f"CSR RSA exponent: {csr_numbers.e}")
        
        # Compare modulus and exponent - THE ACTUAL CRYPTOGRAPHIC VALIDATION
        modulus_match = private_numbers.n == csr_numbers.n
        exponent_match = private_numbers.e == csr_numbers.e
        
        logger.debug(f"RSA modulus match: {modulus_match}")
        logger.debug(f"RSA exponent match: {exponent_match}")
        
        is_valid = modulus_match and exponent_match
        
        details = {
            "algorithm": "RSA",
            "keySize": private_numbers.n.bit_length(),
            "comparison": {
                "modulus": {
                    "privateKey": str(private_numbers.n)[:50] + "..." if len(str(private_numbers.n)) > 50 else str(private_numbers.n),
                    "csr": str(csr_numbers.n)[:50] + "..." if len(str(csr_numbers.n)) > 50 else str(csr_numbers.n),
                    "match": modulus_match,
                    "fullMatch": private_numbers.n == csr_numbers.n
                },
                "exponent": {
                    "privateKey": private_numbers.e,
                    "csr": csr_numbers.e,
                    "match": exponent_match,
                    "fullMatch": private_numbers.e == csr_numbers.e
                }
            }
        }
        
        if is_valid:
            logger.info("RSA key validation: MATCH - public_numbers() are identical")
        else:
            logger.warning("RSA key validation: NO MATCH - public_numbers() differ")
            if not modulus_match:
                logger.warning("RSA modulus (n) mismatch")
            if not exponent_match:
                logger.warning("RSA exponent (e) mismatch")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="Private Key <-> CSR",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating RSA keys: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> CSR",
            error=f"RSA validation error: {str(e)}"
        )

def validate_ec_keys(private_public_key: ec.EllipticCurvePublicKey, csr_public_key: ec.EllipticCurvePublicKey) -> ValidationResult:
    """Validate EC key pair using public_numbers() comparison"""
    logger.debug("=== EC KEY VALIDATION ===")
    
    try:
        # Get public numbers for comparison - THIS IS THE REAL VALIDATION!
        private_numbers = private_public_key.public_numbers()
        csr_numbers = csr_public_key.public_numbers()
        
        # Get curve information
        private_curve = private_public_key.curve
        csr_curve = csr_public_key.curve
        
        logger.debug(f"Private key EC curve: {private_curve.name}")
        logger.debug(f"CSR EC curve: {csr_curve.name}")
        logger.debug(f"Private key EC X coordinate: {private_numbers.x}")
        logger.debug(f"Private key EC Y coordinate: {private_numbers.y}")
        logger.debug(f"CSR EC X coordinate: {csr_numbers.x}")
        logger.debug(f"CSR EC Y coordinate: {csr_numbers.y}")
        
        # Compare curve
        curve_match = private_curve.name == csr_curve.name
        
        # Compare public point coordinates - THE ACTUAL CRYPTOGRAPHIC VALIDATION
        x_match = private_numbers.x == csr_numbers.x
        y_match = private_numbers.y == csr_numbers.y
        
        logger.debug(f"EC curve match: {curve_match}")
        logger.debug(f"EC X coordinate match: {x_match}")
        logger.debug(f"EC Y coordinate match: {y_match}")
        
        is_valid = curve_match and x_match and y_match
        
        details = {
            "algorithm": "EC",
            "curve": private_curve.name,
            "keySize": private_curve.key_size,
            "comparison": {
                "curve": {
                    "privateKey": private_curve.name,
                    "csr": csr_curve.name,
                    "match": curve_match
                },
                "publicPoint": {
                    "x": {
                        "privateKey": str(private_numbers.x)[:50] + "..." if len(str(private_numbers.x)) > 50 else str(private_numbers.x),
                        "csr": str(csr_numbers.x)[:50] + "..." if len(str(csr_numbers.x)) > 50 else str(csr_numbers.x),
                        "match": x_match,
                        "fullMatch": private_numbers.x == csr_numbers.x
                    },
                    "y": {
                        "privateKey": str(private_numbers.y)[:50] + "..." if len(str(private_numbers.y)) > 50 else str(private_numbers.y),
                        "csr": str(csr_numbers.y)[:50] + "..." if len(str(csr_numbers.y)) > 50 else str(csr_numbers.y),
                        "match": y_match,
                        "fullMatch": private_numbers.y == csr_numbers.y
                    }
                }
            }
        }
        
        if is_valid:
            logger.info("EC key validation: MATCH - public_numbers() are identical")
        else:
            logger.warning("EC key validation: NO MATCH - public_numbers() differ")
            if not curve_match:
                logger.warning("EC curve mismatch")
            if not x_match:
                logger.warning("EC X coordinate mismatch")
            if not y_match:
                logger.warning("EC Y coordinate mismatch")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="Private Key <-> CSR",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating EC keys: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> CSR",
            error=f"EC validation error: {str(e)}"
        )