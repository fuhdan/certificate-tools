# backend-fastapi/certificates/validation/validator.py
# Certificate validation functions with comprehensive debugging

import logging
from typing import Dict, Any, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

logger = logging.getLogger(__name__)

class ValidationResult:
    """Validation result container"""
    def __init__(self, is_valid: bool, validation_type: str, details: Dict[str, Any] = None, error: str = None):
        self.is_valid = is_valid
        self.validation_type = validation_type
        self.details = details or {}
        self.error = error
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "isValid": self.is_valid,
            "validationType": self.validation_type,
            "details": self.details,
            "error": self.error
        }

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
            return _validate_rsa_keys(private_public_key, csr_public_key)
        elif isinstance(private_public_key, ec.EllipticCurvePublicKey):
            return _validate_ec_keys(private_public_key, csr_public_key)
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

def _validate_rsa_keys(private_public_key: rsa.RSAPublicKey, csr_public_key: rsa.RSAPublicKey) -> ValidationResult:
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

def _validate_ec_keys(private_public_key: ec.EllipticCurvePublicKey, csr_public_key: ec.EllipticCurvePublicKey) -> ValidationResult:
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
        ).y
        
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
                        "match": x_match
                    },
                    "y": {
                        "privateKey": str(private_numbers.y)[:50] + "..." if len(str(private_numbers.y)) > 50 else str(private_numbers.y),
                        "csr": str(csr_numbers.y)[:50] + "..." if len(str(csr_numbers.y)) > 50 else str(csr_numbers.y),
                        "match": y_match
                    }
                }
            }
        }
        
        if is_valid:
            logger.info("EC key validation: MATCH")
        else:
            logger.warning("EC key validation: NO MATCH")
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

def run_validations(certificates: List[Dict[str, Any]]) -> List[ValidationResult]:
    """Run all available validations on the certificate collection"""
    logger.info(f"=== RUNNING VALIDATIONS ===")
    logger.debug(f"Total certificates to analyze: {len(certificates)}")
    
    validations = []
    
    # Find private keys, CSRs, and certificates with their crypto objects from separate storage
    from certificates.storage import CertificateStorage
    
    private_keys = []
    csrs = []
    certificates_list = []
    
    for cert in certificates:
        analysis = cert.get('analysis', {})
        cert_type = analysis.get('type', '')
        cert_id = cert.get('id')
        
        # Get crypto objects from separate storage
        crypto_objects = CertificateStorage.get_crypto_objects(cert_id)
        
        if cert_type == 'Private Key' and analysis.get('isValid') and 'private_key' in crypto_objects:
            private_keys.append({
                'cert_data': cert,
                'private_key_obj': crypto_objects['private_key']
            })
            logger.debug(f"Found private key with crypto object: {cert.get('filename')}")
        elif cert_type == 'CSR' and analysis.get('isValid') and 'csr' in crypto_objects:
            csrs.append({
                'cert_data': cert,
                'csr_obj': crypto_objects['csr']
            })
            logger.debug(f"Found CSR with crypto object: {cert.get('filename')}")
        elif 'Certificate' in cert_type and 'Chain' not in cert_type and analysis.get('isValid') and 'certificate' in crypto_objects:
            certificates_list.append({
                'cert_data': cert,
                'certificate_obj': crypto_objects['certificate']
            })
            logger.debug(f"Found certificate with crypto object: {cert.get('filename')}")
    
    logger.debug(f"Found {len(private_keys)} private keys, {len(csrs)} CSRs, and {len(certificates_list)} certificates with crypto objects")
    
    # Validate private key <-> CSR pairs
    if private_keys and csrs:
        logger.info("Running private key <-> CSR validations...")
        for pk_item in private_keys:
            for csr_item in csrs:
                try:
                    validation = validate_private_key_csr_match(
                        pk_item['private_key_obj'], 
                        csr_item['csr_obj']
                    )
                    
                    # Add file information to validation details
                    if validation.details:
                        validation.details.update({
                            "privateKeyFile": pk_item['cert_data'].get('filename'),
                            "csrFile": csr_item['cert_data'].get('filename')
                        })
                    
                    validations.append(validation)
                    logger.info(f"Validated {pk_item['cert_data'].get('filename')} <-> {csr_item['cert_data'].get('filename')}: {'MATCH' if validation.is_valid else 'NO MATCH'}")
                    
                except Exception as e:
                    logger.error(f"Error validating {pk_item['cert_data'].get('filename')} <-> {csr_item['cert_data'].get('filename')}: {e}")
                    validations.append(ValidationResult(
                        is_valid=False,
                        validation_type="Private Key <-> CSR",
                        error=str(e),
                        details={
                            "privateKeyFile": pk_item['cert_data'].get('filename'),
                            "csrFile": csr_item['cert_data'].get('filename')
                        }
                    ))
    
    # Validate CSR <-> Certificate pairs
    if csrs and certificates_list:
        logger.info("Running CSR <-> Certificate validations...")
        for csr_item in csrs:
            for cert_item in certificates_list:
                try:
                    validation = validate_csr_certificate_match(
                        csr_item['csr_obj'], 
                        cert_item['certificate_obj']
                    )
                    
                    # Add file information to validation details
                    if validation.details:
                        validation.details.update({
                            "csrFile": csr_item['cert_data'].get('filename'),
                            "certificateFile": cert_item['cert_data'].get('filename')
                        })
                    
                    validations.append(validation)
                    logger.info(f"Validated {csr_item['cert_data'].get('filename')} <-> {cert_item['cert_data'].get('filename')}: {'MATCH' if validation.is_valid else 'NO MATCH'}")
                    
                except Exception as e:
                    logger.error(f"Error validating {csr_item['cert_data'].get('filename')} <-> {cert_item['cert_data'].get('filename')}: {e}")
                    validations.append(ValidationResult(
                        is_valid=False,
                        validation_type="CSR <-> Certificate",
                        error=str(e),
                        details={
                            "csrFile": csr_item['cert_data'].get('filename'),
                            "certificateFile": cert_item['cert_data'].get('filename')
                        }
                    ))
    
    # NEW: Validate Private Key <-> Certificate pairs
    if private_keys and certificates_list:
        logger.info("Running Private Key <-> Certificate validations...")
        for pk_item in private_keys:
            for cert_item in certificates_list:
                try:
                    validation = validate_private_key_certificate_match(
                        pk_item['private_key_obj'], 
                        cert_item['certificate_obj']
                    )
                    
                    # Add file information to validation details
                    if validation.details:
                        validation.details.update({
                            "privateKeyFile": pk_item['cert_data'].get('filename'),
                            "certificateFile": cert_item['cert_data'].get('filename')
                        })
                    
                    validations.append(validation)
                    logger.info(f"Validated {pk_item['cert_data'].get('filename')} <-> {cert_item['cert_data'].get('filename')}: {'MATCH' if validation.is_valid else 'NO MATCH'}")
                    
                except Exception as e:
                    logger.error(f"Error validating {pk_item['cert_data'].get('filename')} <-> {cert_item['cert_data'].get('filename')}: {e}")
                    validations.append(ValidationResult(
                        is_valid=False,
                        validation_type="Private Key <-> Certificate",
                        error=str(e),
                        details={
                            "privateKeyFile": pk_item['cert_data'].get('filename'),
                            "certificateFile": cert_item['cert_data'].get('filename')
                        }
                    ))
    
    logger.info(f"Completed {len(validations)} validations")
    return validations

def validate_csr_certificate_match(csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> ValidationResult:
    """Validate that CSR public key matches certificate public key"""
    logger.info(f"=== CSR <-> CERTIFICATE VALIDATION ===")
    logger.debug(f"CSR type: {type(csr).__name__}")
    logger.debug(f"Certificate type: {type(certificate).__name__}")
    
    try:
        # Extract public keys
        csr_public_key = csr.public_key()
        cert_public_key = certificate.public_key()
        
        logger.debug(f"CSR public key type: {type(csr_public_key).__name__}")
        logger.debug(f"Certificate public key type: {type(cert_public_key).__name__}")
        
        # Check if both are the same algorithm type
        if type(csr_public_key) != type(cert_public_key):
            error_msg = f"Algorithm mismatch: CSR has {type(csr_public_key).__name__}, Certificate has {type(cert_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="CSR <-> Certificate",
                error=error_msg,
                details={
                    "csrAlgorithm": type(csr_public_key).__name__,
                    "certificateAlgorithm": type(cert_public_key).__name__
                }
            )
        
        # Validate based on key type
        if isinstance(csr_public_key, rsa.RSAPublicKey):
            return _validate_csr_cert_rsa_keys(csr_public_key, cert_public_key, csr, certificate)
        elif isinstance(csr_public_key, ec.EllipticCurvePublicKey):
            return _validate_csr_cert_ec_keys(csr_public_key, cert_public_key, csr, certificate)
        else:
            error_msg = f"Unsupported key type: {type(csr_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="CSR <-> Certificate",
                error=error_msg
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

def _validate_csr_cert_rsa_keys(csr_public_key: rsa.RSAPublicKey, cert_public_key: rsa.RSAPublicKey, 
                               csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> ValidationResult:
    """Validate RSA keys between CSR and certificate"""
    logger.debug("=== CSR <-> CERTIFICATE RSA KEY VALIDATION ===")
    
    try:
        # Get public numbers for comparison - THE REAL VALIDATION!
        csr_numbers = csr_public_key.public_numbers()
        cert_numbers = cert_public_key.public_numbers()
        
        logger.debug(f"CSR RSA modulus bit length: {csr_numbers.n.bit_length()}")
        logger.debug(f"Certificate RSA modulus bit length: {cert_numbers.n.bit_length()}")
        logger.debug(f"CSR RSA exponent: {csr_numbers.e}")
        logger.debug(f"Certificate RSA exponent: {cert_numbers.e}")
        
        # Compare modulus and exponent - THE ACTUAL CRYPTOGRAPHIC VALIDATION
        modulus_match = csr_numbers.n == cert_numbers.n
        exponent_match = csr_numbers.e == cert_numbers.e
        public_key_match = modulus_match and exponent_match
        
        logger.debug(f"RSA modulus match: {modulus_match}")
        logger.debug(f"RSA exponent match: {exponent_match}")
        logger.debug(f"Public key match: {public_key_match}")
        
        # Generate public key fingerprints (hash of public key)
        from cryptography.hazmat.primitives import hashes, serialization
        
        csr_pubkey_der = csr_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_pubkey_der = cert_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        import hashlib
        csr_fingerprint = hashlib.sha256(csr_pubkey_der).hexdigest()
        cert_fingerprint = hashlib.sha256(cert_pubkey_der).hexdigest()
        fingerprint_match = csr_fingerprint == cert_fingerprint
        
        logger.debug(f"CSR fingerprint: {csr_fingerprint[:16]}...")
        logger.debug(f"Certificate fingerprint: {cert_fingerprint[:16]}...")
        logger.debug(f"Fingerprint match: {fingerprint_match}")
        
        # Extract and compare subject names
        subject_comparison = _compare_subject_names(csr, certificate)
        
        # Extract and compare SANs
        san_comparison = _compare_sans(csr, certificate)
        
        is_valid = public_key_match and fingerprint_match
        
        details = {
            "algorithm": "RSA",
            "keySize": csr_numbers.n.bit_length(),
            "publicKeyComparison": {
                "modulus": {
                    "csr": str(csr_numbers.n)[:50] + "..." if len(str(csr_numbers.n)) > 50 else str(csr_numbers.n),
                    "certificate": str(cert_numbers.n)[:50] + "..." if len(str(cert_numbers.n)) > 50 else str(cert_numbers.n),
                    "match": modulus_match
                },
                "exponent": {
                    "csr": csr_numbers.e,
                    "certificate": cert_numbers.e,
                    "match": exponent_match
                }
            },
            "fingerprint": {
                "csr": csr_fingerprint,
                "certificate": cert_fingerprint,
                "match": fingerprint_match
            }
        }
        
        # Add subject comparison only if there are differences
        if not subject_comparison["match"]:
            details["subjectComparison"] = subject_comparison
        
        # Add SAN comparison only if there are differences
        if not san_comparison["match"]:
            details["sanComparison"] = san_comparison
        
        if is_valid:
            logger.info("CSR <-> Certificate RSA validation: MATCH - public keys are identical")
        else:
            logger.warning("CSR <-> Certificate RSA validation: NO MATCH - public keys differ")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="CSR <-> Certificate",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating CSR <-> Certificate RSA keys: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="CSR <-> Certificate",
            error=f"RSA validation error: {str(e)}"
        )

def _validate_csr_cert_ec_keys(csr_public_key: ec.EllipticCurvePublicKey, cert_public_key: ec.EllipticCurvePublicKey,
                              csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> ValidationResult:
    """Validate EC keys between CSR and certificate"""
    logger.debug("=== CSR <-> CERTIFICATE EC KEY VALIDATION ===")
    
    try:
        # Get public numbers for comparison - THE REAL VALIDATION!
        csr_numbers = csr_public_key.public_numbers()
        cert_numbers = cert_public_key.public_numbers()
        
        # Get curve information
        csr_curve = csr_public_key.curve
        cert_curve = cert_public_key.curve
        
        logger.debug(f"CSR EC curve: {csr_curve.name}")
        logger.debug(f"Certificate EC curve: {cert_curve.name}")
        logger.debug(f"CSR EC X coordinate: {csr_numbers.x}")
        logger.debug(f"CSR EC Y coordinate: {csr_numbers.y}")
        logger.debug(f"Certificate EC X coordinate: {cert_numbers.x}")
        logger.debug(f"Certificate EC Y coordinate: {cert_numbers.y}")
        
        # Compare curve and public point coordinates - THE ACTUAL CRYPTOGRAPHIC VALIDATION
        curve_match = csr_curve.name == cert_curve.name
        x_match = csr_numbers.x == cert_numbers.x
        y_match = csr_numbers.y == cert_numbers.y
        public_key_match = curve_match and x_match and y_match
        
        logger.debug(f"EC curve match: {curve_match}")
        logger.debug(f"EC X coordinate match: {x_match}")
        logger.debug(f"EC Y coordinate match: {y_match}")
        logger.debug(f"Public key match: {public_key_match}")
        
        # Generate public key fingerprints
        from cryptography.hazmat.primitives import serialization
        
        csr_pubkey_der = csr_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_pubkey_der = cert_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        import hashlib
        csr_fingerprint = hashlib.sha256(csr_pubkey_der).hexdigest()
        cert_fingerprint = hashlib.sha256(cert_pubkey_der).hexdigest()
        fingerprint_match = csr_fingerprint == cert_fingerprint
        
        logger.debug(f"CSR fingerprint: {csr_fingerprint[:16]}...")
        logger.debug(f"Certificate fingerprint: {cert_fingerprint[:16]}...")
        logger.debug(f"Fingerprint match: {fingerprint_match}")
        
        # Extract and compare subject names
        subject_comparison = _compare_subject_names(csr, certificate)
        
        # Extract and compare SANs
        san_comparison = _compare_sans(csr, certificate)
        
        is_valid = public_key_match and fingerprint_match
        
        details = {
            "algorithm": "EC",
            "curve": csr_curve.name,
            "keySize": csr_curve.key_size,
            "publicKeyComparison": {
                "curve": {
                    "csr": csr_curve.name,
                    "certificate": cert_curve.name,
                    "match": curve_match
                },
                "publicPoint": {
                    "x": {
                        "csr": str(csr_numbers.x)[:50] + "..." if len(str(csr_numbers.x)) > 50 else str(csr_numbers.x),
                        "certificate": str(cert_numbers.x)[:50] + "..." if len(str(cert_numbers.x)) > 50 else str(cert_numbers.x),
                        "match": x_match
                    },
                    "y": {
                        "csr": str(csr_numbers.y)[:50] + "..." if len(str(csr_numbers.y)) > 50 else str(csr_numbers.y),
                        "certificate": str(cert_numbers.y)[:50] + "..." if len(str(cert_numbers.y)) > 50 else str(cert_numbers.y),
                        "match": y_match
                    }
                }
            },
            "fingerprint": {
                "csr": csr_fingerprint,
                "certificate": cert_fingerprint,
                "match": fingerprint_match
            }
        }
        
        # Add subject comparison only if there are differences
        if not subject_comparison["match"]:
            details["subjectComparison"] = subject_comparison
        
        # Add SAN comparison only if there are differences
        if not san_comparison["match"]:
            details["sanComparison"] = san_comparison
        
        if is_valid:
            logger.info("CSR <-> Certificate EC validation: MATCH - public keys are identical")
        else:
            logger.warning("CSR <-> Certificate EC validation: NO MATCH - public keys differ")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="CSR <-> Certificate",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating CSR <-> Certificate EC keys: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="CSR <-> Certificate",
            error=f"EC validation error: {str(e)}"
        )

def _compare_subject_names(csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> Dict[str, Any]:
    """Compare subject names between CSR and certificate"""
    logger.debug("Comparing subject names...")
    
    try:
        # Extract common names
        csr_cn = None
        cert_cn = None
        
        for attribute in csr.subject:
            if attribute.oid._name == 'commonName':
                csr_cn = attribute.value
                break
        
        for attribute in certificate.subject:
            if attribute.oid._name == 'commonName':
                cert_cn = attribute.value
                break
        
        logger.debug(f"CSR CN: {csr_cn}")
        logger.debug(f"Certificate CN: {cert_cn}")
        
        cn_match = csr_cn == cert_cn
        
        return {
            "match": cn_match,
            "commonName": {
                "csr": csr_cn or "N/A",
                "certificate": cert_cn or "N/A",
                "match": cn_match
            }
        }
        
    except Exception as e:
        logger.error(f"Error comparing subject names: {e}")
        return {"match": False, "error": str(e)}

def validate_private_key_certificate_match(private_key, certificate: x509.Certificate) -> ValidationResult:
    """Validate that private key matches the certificate public key"""
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
            return _validate_private_key_cert_rsa_keys(private_public_key, cert_public_key, certificate)
        elif isinstance(private_public_key, ec.EllipticCurvePublicKey):
            return _validate_private_key_cert_ec_keys(private_public_key, cert_public_key, certificate)
        else:
            error_msg = f"Unsupported key type: {type(private_public_key).__name__}"
            logger.warning(error_msg)
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key <-> Certificate",
                error=error_msg
            )
            
    except Exception as e:
        logger.error(f"Error during Private Key <-> Certificate validation: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> Certificate",
            error=str(e)
        )

def _validate_private_key_cert_rsa_keys(private_public_key: rsa.RSAPublicKey, cert_public_key: rsa.RSAPublicKey, 
                                      certificate: x509.Certificate) -> ValidationResult:
    """Validate RSA keys between private key and certificate"""
    logger.debug("=== PRIVATE KEY <-> CERTIFICATE RSA KEY VALIDATION ===")
    
    try:
        # Get public numbers for comparison - THE REAL VALIDATION!
        private_numbers = private_public_key.public_numbers()
        cert_numbers = cert_public_key.public_numbers()
        
        logger.debug(f"Private key RSA modulus bit length: {private_numbers.n.bit_length()}")
        logger.debug(f"Certificate RSA modulus bit length: {cert_numbers.n.bit_length()}")
        logger.debug(f"Private key RSA exponent: {private_numbers.e}")
        logger.debug(f"Certificate RSA exponent: {cert_numbers.e}")
        
        # Compare modulus and exponent - THE ACTUAL CRYPTOGRAPHIC VALIDATION
        modulus_match = private_numbers.n == cert_numbers.n
        exponent_match = private_numbers.e == cert_numbers.e
        public_key_match = modulus_match and exponent_match
        
        logger.debug(f"RSA modulus match: {modulus_match}")
        logger.debug(f"RSA exponent match: {exponent_match}")
        logger.debug(f"Public key match: {public_key_match}")
        
        # Generate public key fingerprints (hash of public key)
        from cryptography.hazmat.primitives import serialization
        
        private_pubkey_der = private_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_pubkey_der = cert_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        import hashlib
        private_fingerprint = hashlib.sha256(private_pubkey_der).hexdigest()
        cert_fingerprint = hashlib.sha256(cert_pubkey_der).hexdigest()
        fingerprint_match = private_fingerprint == cert_fingerprint
        
        logger.debug(f"Private key fingerprint: {private_fingerprint[:16]}...")
        logger.debug(f"Certificate fingerprint: {cert_fingerprint[:16]}...")
        logger.debug(f"Fingerprint match: {fingerprint_match}")
        
        is_valid = public_key_match and fingerprint_match
        
        details = {
            "algorithm": "RSA",
            "keySize": private_numbers.n.bit_length(),
            "publicKeyComparison": {
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
            },
            "fingerprint": {
                "privateKey": private_fingerprint,
                "certificate": cert_fingerprint,
                "match": fingerprint_match
            }
        }
        
        if is_valid:
            logger.info("Private Key <-> Certificate RSA validation: MATCH - public keys are identical")
        else:
            logger.warning("Private Key <-> Certificate RSA validation: NO MATCH - public keys differ")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="Private Key <-> Certificate",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating Private Key <-> Certificate RSA keys: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> Certificate",
            error=f"RSA validation error: {str(e)}"
        )

def _validate_private_key_cert_ec_keys(private_public_key: ec.EllipticCurvePublicKey, cert_public_key: ec.EllipticCurvePublicKey,
                                     certificate: x509.Certificate) -> ValidationResult:
    """Validate EC keys between private key and certificate"""
    logger.debug("=== PRIVATE KEY <-> CERTIFICATE EC KEY VALIDATION ===")
    
    try:
        # Get public numbers for comparison - THE REAL VALIDATION!
        private_numbers = private_public_key.public_numbers()
        cert_numbers = cert_public_key.public_numbers()
        
        # Get curve information
        private_curve = private_public_key.curve
        cert_curve = cert_public_key.curve
        
        logger.debug(f"Private key EC curve: {private_curve.name}")
        logger.debug(f"Certificate EC curve: {cert_curve.name}")
        logger.debug(f"Private key EC X coordinate: {private_numbers.x}")
        logger.debug(f"Private key EC Y coordinate: {private_numbers.y}")
        logger.debug(f"Certificate EC X coordinate: {cert_numbers.x}")
        logger.debug(f"Certificate EC Y coordinate: {cert_numbers.y}")
        
        # Compare curve and public point coordinates - THE ACTUAL CRYPTOGRAPHIC VALIDATION
        curve_match = private_curve.name == cert_curve.name
        x_match = private_numbers.x == cert_numbers.x
        y_match = private_numbers.y == cert_numbers.y
        public_key_match = curve_match and x_match and y_match
        
        logger.debug(f"EC curve match: {curve_match}")
        logger.debug(f"EC X coordinate match: {x_match}")
        logger.debug(f"EC Y coordinate match: {y_match}")
        logger.debug(f"Public key match: {public_key_match}")
        
        # Generate public key fingerprints
        from cryptography.hazmat.primitives import serialization
        
        private_pubkey_der = private_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_pubkey_der = cert_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        import hashlib
        private_fingerprint = hashlib.sha256(private_pubkey_der).hexdigest()
        cert_fingerprint = hashlib.sha256(cert_pubkey_der).hexdigest()
        fingerprint_match = private_fingerprint == cert_fingerprint
        
        logger.debug(f"Private key fingerprint: {private_fingerprint[:16]}...")
        logger.debug(f"Certificate fingerprint: {cert_fingerprint[:16]}...")
        logger.debug(f"Fingerprint match: {fingerprint_match}")
        
        is_valid = public_key_match and fingerprint_match
        
        details = {
            "algorithm": "EC",
            "curve": private_curve.name,
            "keySize": private_curve.key_size,
            "publicKeyComparison": {
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
            },
            "fingerprint": {
                "privateKey": private_fingerprint,
                "certificate": cert_fingerprint,
                "match": fingerprint_match
            }
        }
        
        if is_valid:
            logger.info("Private Key <-> Certificate EC validation: MATCH - public keys are identical")
        else:
            logger.warning("Private Key <-> Certificate EC validation: NO MATCH - public keys differ")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="Private Key <-> Certificate",
            details=details
        )
        
    except Exception as e:
        logger.error(f"Error validating Private Key <-> Certificate EC keys: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> Certificate",
            error=f"EC validation error: {str(e)}"
        )