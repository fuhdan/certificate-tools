# backend-fastapi/certificates/validation/private_key_cert.py
# Private Key <-> Certificate validation functions

import logging
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .models import ValidationResult

logger = logging.getLogger(__name__)

def validate_private_key_certificate_match(private_key, certificate: x509.Certificate) -> ValidationResult:
    """Validate that private key matches the public key in certificate"""
    logger.info(f"=== PRIVATE KEY <-> CERTIFICATE VALIDATION ===")
    logger.debug(f"Private key type: {type(private_key).__name__}")
    logger.debug(f"Certificate type: {type(certificate).__name__}")
    
    try:
        # Extract public keys
        private_public_key = private_key.public_key()
        cert_public_key = certificate.public_key()
        
        logger.debug(f"Private key's public key type: {type(private_public_key).__name__}")
        logger.debug(f"Certificate's public key type: {type(cert_public_key).__name__}")
        
        # Check if both are the same algorithm type
        if type(private_public_key) != type(cert_public_key):
            error_msg = f"Algorithm mismatch: Private key has {type(private_public_key).__name__}, Certificate has {type(cert_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key <-> Certificate",
                error=error_msg,
                details={
                    "privateKeyAlgorithm": type(private_public_key).__name__,
                    "certificateAlgorithm": type(cert_public_key).__name__
                }
            )
        
        # Validate based on key type
        if isinstance(private_public_key, rsa.RSAPublicKey):
            return validate_rsa_keys(private_public_key, cert_public_key)
        elif isinstance(private_public_key, ec.EllipticCurvePublicKey):
            return validate_ec_keys(private_public_key, cert_public_key)
        else:
            error_msg = f"Unsupported key type: {type(private_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key <-> Certificate",
                error=error_msg
            )
            
    except Exception as e:
        logger.error(f"Error during private key <-> certificate validation: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> Certificate",
            error=str(e)
        )

def validate_rsa_keys(private_public_key: rsa.RSAPublicKey, cert_public_key: rsa.RSAPublicKey) -> ValidationResult:
    """Validate RSA key pair using public_numbers() comparison"""
    logger.debug("=== RSA KEY VALIDATION (Private Key <-> Certificate) ===")
    
    try:
        # Get public numbers for comparison
        private_numbers = private_public_key.public_numbers()
        cert_numbers = cert_public_key.public_numbers()
        
        logger.debug(f"Private key RSA modulus bit length: {private_numbers.n.bit_length()}")
        logger.debug(f"Certificate RSA modulus bit length: {cert_numbers.n.bit_length()}")
        logger.debug(f"Private key RSA exponent: {private_numbers.e}")
        logger.debug(f"Certificate RSA exponent: {cert_numbers.e}")
        
        # Compare modulus and exponent
        modulus_match = private_numbers.n == cert_numbers.n
        exponent_match = private_numbers.e == cert_numbers.e
        
        logger.debug(f"RSA modulus match: {modulus_match}")
        logger.debug(f"RSA exponent match: {exponent_match}")
        
        is_valid = modulus_match and exponent_match
        
        details = {
            "algorithm": "RSA",
            "keySize": private_numbers.n.bit_length(),
            "comparison": {
                "modulus": {
                    "privateKey": str(private_numbers.n)[:50] + "..." if len(str(private_numbers.n)) > 50 else str(private_numbers.n),
                    "certificate": str(cert_numbers.n)[:50] + "..." if len(str(cert_numbers.n)) > 50 else str(cert_numbers.n),
                    "match": modulus_match
                },
                "exponent": {
                    "privateKey": private_numbers.e,
                    "certificate": cert_numbers.e,
                    "match": exponent_match
                }
            }
        }
        
        if is_valid:
            logger.info("RSA key validation (Private Key <-> Certificate): MATCH")
        else:
            logger.warning("RSA key validation (Private Key <-> Certificate): NO MATCH")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="Private Key <-> Certificate",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating RSA keys: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> Certificate",
            error=f"RSA validation error: {str(e)}"
        )

def validate_ec_keys(private_public_key: ec.EllipticCurvePublicKey, cert_public_key: ec.EllipticCurvePublicKey) -> ValidationResult:
    """Validate EC key pair using public_numbers() comparison"""
    logger.debug("=== EC KEY VALIDATION (Private Key <-> Certificate) ===")
    
    try:
        # Get public numbers for comparison
        private_numbers = private_public_key.public_numbers()
        cert_numbers = cert_public_key.public_numbers()
        
        # Get curve information
        private_curve = private_public_key.curve
        cert_curve = cert_public_key.curve
        
        logger.debug(f"Private key EC curve: {private_curve.name}")
        logger.debug(f"Certificate EC curve: {cert_curve.name}")
        
        # Compare curve and coordinates
        curve_match = private_curve.name == cert_curve.name
        x_match = private_numbers.x == cert_numbers.x
        y_match = private_numbers.y == cert_numbers.y
        
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
                    "certificate": cert_curve.name,
                    "match": curve_match
                },
                "publicPoint": {
                    "x": {
                        "privateKey": str(private_numbers.x)[:50] + "..." if len(str(private_numbers.x)) > 50 else str(private_numbers.x),
                        "certificate": str(cert_numbers.x)[:50] + "..." if len(str(cert_numbers.x)) > 50 else str(cert_numbers.x),
                        "match": x_match
                    },
                    "y": {
                        "privateKey": str(private_numbers.y)[:50] + "..." if len(str(private_numbers.y)) > 50 else str(private_numbers.y),
                        "certificate": str(cert_numbers.y)[:50] + "..." if len(str(cert_numbers.y)) > 50 else str(cert_numbers.y),
                        "match": y_match
                    }
                }
            }
        }
        
        if is_valid:
            logger.info("EC key validation (Private Key <-> Certificate): MATCH")
        else:
            logger.warning("EC key validation (Private Key <-> Certificate): NO MATCH")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="Private Key <-> Certificate",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating EC keys: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> Certificate",
            error=f"EC validation error: {str(e)}"
        )