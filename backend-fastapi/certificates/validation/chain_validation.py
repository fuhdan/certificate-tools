# backend-fastapi/certificates/validation/chain_validation.py
# Certificate chain validation with COMPREHENSIVE cryptographic details

import logging
from typing import List, Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448
from cryptography.exceptions import InvalidSignature
from .models import ValidationResult

logger = logging.getLogger(__name__)

def validate_certificate_chain(certificates: List[Dict[str, Any]]) -> List[ValidationResult]:
    """Validate certificate chains with FULL signature verification details"""
    logger.info(f"=== COMPREHENSIVE CERTIFICATE CHAIN VALIDATION ===")
    
    validations = []
    
    # Find certificates that could form chains
    from certificates.storage import CertificateStorage
    
    cert_objects = []
    for cert in certificates:
        analysis = cert.get('analysis', {})
        cert_type = analysis.get('type', '')
        cert_id = cert.get('id')
        
        # Get crypto objects from storage
        crypto_objects = CertificateStorage.get_crypto_objects(cert_id)
        
        if 'Certificate' in cert_type and 'Chain' not in cert_type and analysis.get('isValid') and 'certificate' in crypto_objects:
            cert_obj = crypto_objects['certificate']
            is_ca = _is_ca_certificate(cert_obj)
            
            cert_info = {
                'cert_data': cert,
                'certificate_obj': cert_obj,
                'is_ca': is_ca,
                'subject': _get_subject_cn(cert_obj),
                'issuer': _get_issuer_cn(cert_obj),
                'filename': cert.get('filename'),
                'serial_number': str(cert_obj.serial_number),
                'signature_algorithm': cert_obj.signature_algorithm_oid._name,
                'public_key_algorithm': _get_public_key_algorithm(cert_obj.public_key()),
                'key_size': _get_key_size(cert_obj.public_key()),
                'not_before': cert_obj.not_valid_before_utc.isoformat(),
                'not_after': cert_obj.not_valid_after_utc.isoformat()
            }
            cert_objects.append(cert_info)
    
    logger.debug(f"Found {len(cert_objects)} certificates for chain validation")
    
    # Build and validate chains
    if len(cert_objects) >= 2:
        chains = _build_certificate_chains(cert_objects)
        
        for chain in chains:
            validation = _validate_single_chain_detailed(chain)
            validations.append(validation)
    
    return validations

def _build_certificate_chains(cert_objects: List[Dict]) -> List[List[Dict]]:
    """Build possible certificate chains"""
    logger.debug("Building certificate chains...")
    
    chains = []
    
    # Find end-entity certificates (not CA)
    end_entities = [c for c in cert_objects if not c['is_ca']]
    
    # Find CA certificates
    cas = [c for c in cert_objects if c['is_ca']]
    
    logger.debug(f"Found {len(end_entities)} end-entity certificates and {len(cas)} CA certificates")
    
    # For each end-entity, try to find its issuing CA
    for end_entity in end_entities:
        logger.debug(f"Looking for issuer of: {end_entity['subject']} (issued by: {end_entity['issuer']})")
        
        for ca in cas:
            logger.debug(f"  Checking CA: {ca['subject']}")
            
            # Check if this CA could be the issuer
            if end_entity['issuer'] == ca['subject']:
                logger.debug(f"  ✓ Found issuer match: {end_entity['subject']} → {ca['subject']}")
                chains.append([end_entity, ca])
            else:
                logger.debug(f"  ✗ No match: '{end_entity['issuer']}' != '{ca['subject']}'")
    
    logger.debug(f"Built {len(chains)} possible certificate chains")
    return chains

def _validate_single_chain_detailed(chain: List[Dict]) -> ValidationResult:
    """Validate a single certificate chain with COMPREHENSIVE cryptographic details"""
    logger.debug(f"=== DETAILED CHAIN VALIDATION ===")
    
    if len(chain) < 2:
        return ValidationResult(
            is_valid=False,
            validation_type="Certificate Chain",
            error="Chain must have at least 2 certificates"
        )
    
    end_entity = chain[0]
    issuing_ca = chain[1]
    
    logger.info(f"Validating chain: {end_entity['filename']} → {issuing_ca['filename']}")
    
    try:
        # Perform comprehensive signature verification
        signature_result = _verify_certificate_signature_detailed(
            end_entity['certificate_obj'], 
            issuing_ca['certificate_obj']
        )
        
        # Check name chaining
        name_chain_valid = end_entity['issuer'] == issuing_ca['subject']
        
        # Extract certificate fingerprints
        ee_fingerprint = _get_certificate_fingerprint(end_entity['certificate_obj'])
        ca_fingerprint = _get_certificate_fingerprint(issuing_ca['certificate_obj'])
        
        # Extract key identifiers if available
        ee_ski = _get_subject_key_identifier(end_entity['certificate_obj'])
        ee_aki = _get_authority_key_identifier(end_entity['certificate_obj'])
        ca_ski = _get_subject_key_identifier(issuing_ca['certificate_obj'])
        ca_aki = _get_authority_key_identifier(issuing_ca['certificate_obj'])
        
        # Build comprehensive validation details
        validation_details = {
            "signatureVerification": signature_result,
            "nameChaining": {
                "valid": name_chain_valid,
                "endEntityIssuer": end_entity['issuer'],
                "caSubject": issuing_ca['subject'],
                "match": end_entity['issuer'] == issuing_ca['subject']
            },
            "certificates": [
                {
                    "filename": end_entity['filename'],
                    "subject": end_entity['subject'],
                    "issuer": end_entity['issuer'],
                    "serialNumber": end_entity['serial_number'],
                    "fingerprint": ee_fingerprint,
                    "isCA": end_entity['is_ca'],
                    "signatureAlgorithm": end_entity['signature_algorithm'],
                    "publicKeyAlgorithm": end_entity['public_key_algorithm'],
                    "keySize": end_entity['key_size'],
                    "notBefore": end_entity['not_before'],
                    "notAfter": end_entity['not_after']
                },
                {
                    "filename": issuing_ca['filename'],
                    "subject": issuing_ca['subject'],
                    "issuer": issuing_ca['issuer'],
                    "serialNumber": issuing_ca['serial_number'],
                    "fingerprint": ca_fingerprint,
                    "isCA": issuing_ca['is_ca'],
                    "signatureAlgorithm": issuing_ca['signature_algorithm'],
                    "publicKeyAlgorithm": issuing_ca['public_key_algorithm'],
                    "keySize": issuing_ca['key_size'],
                    "notBefore": issuing_ca['not_before'],
                    "notAfter": issuing_ca['not_after']
                }
            ],
            "keyIdentifiers": {
                "endEntity": {
                    "subjectKeyId": ee_ski,
                    "authorityKeyId": ee_aki
                },
                "issuingCA": {
                    "subjectKeyId": ca_ski,
                    "authorityKeyId": ca_aki
                },
                "keyIdMatch": ee_aki == ca_ski if (ee_aki and ca_ski) else None
            },
            "fingerprints": {
                "endEntity": ee_fingerprint,
                "issuingCA": ca_fingerprint
            },
            "validationSteps": [
                {
                    "step": "Digital Signature Verification",
                    "result": signature_result['verified'],
                    "details": f"Verified {end_entity['subject']} signature using {issuing_ca['subject']} public key"
                },
                {
                    "step": "Certificate Name Chaining",
                    "result": name_chain_valid,
                    "details": f"End entity issuer '{end_entity['issuer']}' {'matches' if name_chain_valid else 'does not match'} CA subject '{issuing_ca['subject']}'"
                },
                {
                    "step": "Key Identifier Matching",
                    "result": ee_aki == ca_ski if (ee_aki and ca_ski) else None,
                    "details": f"Authority Key ID matching: {ee_aki == ca_ski if (ee_aki and ca_ski) else 'Key IDs not available'}"
                }
            ],
            "files": [end_entity['filename'], issuing_ca['filename']]
        }
        
        # Overall validation result
        is_valid = signature_result['verified'] and name_chain_valid
        
        # Log detailed results
        if is_valid:
            logger.info(f"✅ Certificate chain VALID: {end_entity['filename']} → {issuing_ca['filename']}")
            logger.info(f"  ✓ Signature verification: PASSED")
            logger.info(f"  ✓ Name chaining: PASSED")
            if ee_aki and ca_ski:
                logger.info(f"  ✓ Key ID matching: {'PASSED' if ee_aki == ca_ski else 'FAILED'}")
        else:
            logger.warning(f"❌ Certificate chain INVALID: {end_entity['filename']} → {issuing_ca['filename']}")
            if not signature_result['verified']:
                logger.warning(f"  ✗ Signature verification: FAILED - {signature_result.get('error', 'Unknown error')}")
            if not name_chain_valid:
                logger.warning(f"  ✗ Name chaining: FAILED - '{end_entity['issuer']}' != '{issuing_ca['subject']}'")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="Certificate Chain",
            details=validation_details
        )
        
    except Exception as e:
        logger.error(f"Error validating certificate chain: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return ValidationResult(
            is_valid=False,
            validation_type="Certificate Chain",
            error=str(e),
            details={
                "endEntityFile": end_entity['filename'],
                "issuingCAFile": issuing_ca['filename'],
                "error": str(e)
            }
        )

def _verify_certificate_signature_detailed(cert: x509.Certificate, issuer_cert: x509.Certificate) -> Dict[str, Any]:
    """Verify certificate signature with detailed cryptographic results"""
    logger.debug(f"Verifying signature: {_get_subject_cn(cert)} signed by {_get_subject_cn(issuer_cert)}")
    
    result = {
        "verified": False,
        "algorithm": cert.signature_algorithm_oid._name,
        "algorithmOID": cert.signature_algorithm_oid.dotted_string,
        "issuerPublicKeyAlgorithm": _get_public_key_algorithm(issuer_cert.public_key()),
        "issuerKeySize": _get_key_size(issuer_cert.public_key()),
        "signatureLength": len(cert.signature),
        "error": None
    }
    
    try:
        # Get the issuer's public key
        issuer_public_key = issuer_cert.public_key()
        signature = cert.signature
        tbs_certificate_bytes = cert.tbs_certificate_bytes
        signature_algorithm = cert.signature_algorithm_oid
        
        logger.debug(f"Signature algorithm: {signature_algorithm._name}")
        logger.debug(f"Issuer public key: {_get_public_key_algorithm(issuer_public_key)} ({_get_key_size(issuer_public_key)} bits)")
        logger.debug(f"Signature length: {len(signature)} bytes")
        
        # Perform signature verification based on algorithm type
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            _verify_rsa_signature(issuer_public_key, signature, tbs_certificate_bytes, signature_algorithm)
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            _verify_ec_signature(issuer_public_key, signature, tbs_certificate_bytes, signature_algorithm)
        elif isinstance(issuer_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            _verify_ed_signature(issuer_public_key, signature, tbs_certificate_bytes)
        else:
            raise ValueError(f"Unsupported public key type: {type(issuer_public_key)}")
        
        result["verified"] = True
        logger.debug(f"✅ Signature verification PASSED")
        
    except InvalidSignature:
        result["error"] = "Invalid signature - cryptographic verification failed"
        logger.debug(f"❌ Signature verification FAILED: Invalid signature")
    except Exception as e:
        result["error"] = f"Signature verification error: {str(e)}"
        logger.debug(f"❌ Signature verification FAILED: {str(e)}")
    
    return result

def _verify_rsa_signature(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes, sig_algorithm: x509.ObjectIdentifier):
    """Verify RSA signature with appropriate padding and hash algorithm"""
    # Determine hash algorithm and padding from signature algorithm OID
    if sig_algorithm._name in ['sha1WithRSAEncryption', 'rsaWithSHA1']:
        hash_alg = hashes.SHA1()
    elif sig_algorithm._name in ['sha256WithRSAEncryption', 'rsaWithSHA256']:
        hash_alg = hashes.SHA256()
    elif sig_algorithm._name in ['sha384WithRSAEncryption', 'rsaWithSHA384']:
        hash_alg = hashes.SHA384()
    elif sig_algorithm._name in ['sha512WithRSAEncryption', 'rsaWithSHA512']:
        hash_alg = hashes.SHA512()
    elif sig_algorithm._name == 'rsassaPss':
        # PSS padding - more complex, use SHA256 as default
        hash_alg = hashes.SHA256()
        public_key.verify(signature, data, padding.PSS(
            mgf=padding.MGF1(hash_alg),
            salt_length=padding.PSS.MAX_LENGTH
        ), hash_alg)
        return
    else:
        raise ValueError(f"Unsupported RSA signature algorithm: {sig_algorithm._name}")
    
    # PKCS1v15 padding for standard RSA signatures
    public_key.verify(signature, data, padding.PKCS1v15(), hash_alg)

def _verify_ec_signature(public_key: ec.EllipticCurvePublicKey, signature: bytes, data: bytes, sig_algorithm: x509.ObjectIdentifier):
    """Verify ECDSA signature with appropriate hash algorithm"""
    # Determine hash algorithm from signature algorithm OID
    if sig_algorithm._name in ['ecdsa-with-SHA1']:
        hash_alg = hashes.SHA1()
    elif sig_algorithm._name in ['ecdsa-with-SHA256']:
        hash_alg = hashes.SHA256()
    elif sig_algorithm._name in ['ecdsa-with-SHA384']:
        hash_alg = hashes.SHA384()
    elif sig_algorithm._name in ['ecdsa-with-SHA512']:
        hash_alg = hashes.SHA512()
    else:
        # Default to SHA256 for unknown ECDSA algorithms
        hash_alg = hashes.SHA256()
    
    public_key.verify(signature, data, ec.ECDSA(hash_alg))

def _verify_ed_signature(public_key, signature: bytes, data: bytes):
    """Verify EdDSA signature (Ed25519/Ed448)"""
    # EdDSA signatures don't use separate hash algorithms
    public_key.verify(signature, data)

# Helper functions
def _is_ca_certificate(cert: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate"""
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        return basic_constraints.value.ca
    except x509.ExtensionNotFound:
        return False

def _get_subject_cn(cert: x509.Certificate) -> str:
    """Extract Common Name from certificate subject"""
    try:
        for attribute in cert.subject:
            if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                return attribute.value
        return str(cert.subject)
    except Exception:
        return "Unknown Subject"

def _get_issuer_cn(cert: x509.Certificate) -> str:
    """Extract Common Name from certificate issuer"""
    try:
        for attribute in cert.issuer:
            if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                return attribute.value
        return str(cert.issuer)
    except Exception:
        return "Unknown Issuer"

def _get_public_key_algorithm(public_key) -> str:
    """Get public key algorithm name"""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC ({public_key.curve.name})"
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    else:
        return str(type(public_key).__name__)

def _get_key_size(public_key) -> int:
    """Get public key size in bits"""
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.curve.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return 256  # Ed25519 is always 256-bit
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return 448  # Ed448 is always 448-bit
    else:
        return 0

def _get_subject_key_identifier(cert: x509.Certificate) -> Optional[str]:
    """Extract Subject Key Identifier from certificate"""
    try:
        ski_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        return ski_ext.value.digest.hex().upper()
    except x509.ExtensionNotFound:
        return None
    except Exception as e:
        logger.debug(f"Error extracting Subject Key Identifier: {e}")
        return None

def _get_authority_key_identifier(cert: x509.Certificate) -> Optional[str]:
    """Extract Authority Key Identifier from certificate"""
    try:
        aki_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        if aki_ext.value.key_identifier:
            return aki_ext.value.key_identifier.hex().upper()
        return None
    except x509.ExtensionNotFound:
        return None
    except Exception as e:
        logger.debug(f"Error extracting Authority Key Identifier: {e}")
        return None

def _get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA256 fingerprint of certificate"""
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex().upper()