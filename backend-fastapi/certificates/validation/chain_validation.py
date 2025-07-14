# certificates/validation/chain_validation.py
# Certificate chain validation with COMPREHENSIVE details

import logging
from typing import List, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
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
    """Validate a single certificate chain with COMPREHENSIVE details"""
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
        # Perform signature verification
        signature_result = _verify_certificate_signature_detailed(
            end_entity['certificate_obj'], 
            issuing_ca['certificate_obj']
        )
        
        # Extract fingerprints for comparison
        ee_fingerprint = _get_certificate_fingerprint(end_entity['certificate_obj'])
        ca_fingerprint = _get_certificate_fingerprint(issuing_ca['certificate_obj'])
        
        # Extract key identifiers if available
        ee_ski = _get_subject_key_identifier(end_entity['certificate_obj'])
        ca_ski = _get_subject_key_identifier(issuing_ca['certificate_obj'])
        ee_aki = _get_authority_key_identifier(end_entity['certificate_obj'])
        
        # Check key identifier matching
        key_id_match = False
        if ee_aki and ca_ski:
            key_id_match = ee_aki == ca_ski
            logger.debug(f"Key identifier match: {key_id_match}")
        
        validation_details = {
            "chainDescription": f"{end_entity['subject']} → {issuing_ca['subject']}",
            "endEntityCertificate": {
                "filename": end_entity['filename'],
                "subject": end_entity['subject'],
                "issuer": end_entity['issuer'],
                "serialNumber": end_entity['serial_number'],
                "fingerprint": ee_fingerprint,
                "subjectKeyIdentifier": ee_ski,
                "authorityKeyIdentifier": ee_aki,
                "validFrom": end_entity['not_before'],
                "validUntil": end_entity['not_after'],
                "publicKeyAlgorithm": end_entity['public_key_algorithm'],
                "keySize": end_entity['key_size']
            },
            "issuingCA": {
                "filename": issuing_ca['filename'],
                "subject": issuing_ca['subject'],
                "issuer": issuing_ca['issuer'],
                "serialNumber": issuing_ca['serial_number'],
                "fingerprint": ca_fingerprint,
                "subjectKeyIdentifier": ca_ski,
                "validFrom": issuing_ca['not_before'],
                "validUntil": issuing_ca['not_after'],
                "publicKeyAlgorithm": issuing_ca['public_key_algorithm'],
                "keySize": issuing_ca['key_size'],
                "isSelfSigned": issuing_ca['subject'] == issuing_ca['issuer']
            },
            "signatureVerification": signature_result,
            "nameChaining": {
                "issuerFieldMatches": end_entity['issuer'] == issuing_ca['subject'],
                "endEntityIssuer": end_entity['issuer'],
                "caSubject": issuing_ca['subject']
            },
            "keyIdentifierChaining": {
                "authorityKeyIdMatches": key_id_match,
                "endEntityAKI": ee_aki,
                "caSubjectKeyId": ca_ski
            } if ee_aki and ca_ski else None,
            "certificateFiles": [end_entity['filename'], issuing_ca['filename']]
        }
        
        # Overall validation result
        is_valid = (signature_result['verified'] and 
                   end_entity['issuer'] == issuing_ca['subject'])
        
        if is_valid:
            logger.info(f"✅ Certificate chain VALID: {end_entity['filename']} → {issuing_ca['filename']}")
        else:
            logger.warning(f"❌ Certificate chain INVALID: {end_entity['filename']} → {issuing_ca['filename']}")
            if not signature_result['verified']:
                logger.warning(f"  - Signature verification failed")
            if end_entity['issuer'] != issuing_ca['subject']:
                logger.warning(f"  - Name chaining failed: '{end_entity['issuer']}' != '{issuing_ca['subject']}'")
        
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
                "issuingCAFile": issuing_ca['filename']
            }
        )

def _verify_certificate_signature_detailed(cert: x509.Certificate, issuer_cert: x509.Certificate) -> Dict[str, Any]:
    """Verify certificate signature with detailed results"""
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
        
        logger.debug(f"Signature algorithm: {result['algorithm']} ({result['algorithmOID']})")
        logger.debug(f"Issuer public key: {result['issuerPublicKeyAlgorithm']} {result['issuerKeySize']} bits")
        logger.debug(f"Signature length: {result['signatureLength']} bytes")
        
        # Verify signature based on algorithm
        if signature_algorithm.dotted_string == "1.2.840.113549.1.1.11":  # SHA256withRSA
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(signature, tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
                result["verified"] = True
                result["hashAlgorithm"] = "SHA256"
                logger.debug("RSA-SHA256 signature verification: SUCCESS")
            else:
                result["error"] = f"Algorithm mismatch: RSA signature but {type(issuer_public_key).__name__} public key"
                
        elif signature_algorithm.dotted_string == "1.2.840.113549.1.1.5":  # SHA1withRSA
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(signature, tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA1())
                result["verified"] = True
                result["hashAlgorithm"] = "SHA1"
                logger.debug("RSA-SHA1 signature verification: SUCCESS")
            else:
                result["error"] = f"Algorithm mismatch: RSA signature but {type(issuer_public_key).__name__} public key"
                
        elif signature_algorithm.dotted_string == "1.2.840.10045.4.3.2":  # ECDSA with SHA256
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(signature, tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
                result["verified"] = True
                result["hashAlgorithm"] = "SHA256"
                result["curve"] = issuer_public_key.curve.name
                logger.debug("ECDSA-SHA256 signature verification: SUCCESS")
            else:
                result["error"] = f"Algorithm mismatch: ECDSA signature but {type(issuer_public_key).__name__} public key"
        else:
            result["error"] = f"Unsupported signature algorithm: {signature_algorithm.dotted_string}"
            logger.warning(f"Unsupported signature algorithm: {signature_algorithm.dotted_string}")
        
    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"Signature verification failed: {e}")
    
    return result

def _get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA256 fingerprint of certificate"""
    from cryptography.hazmat.primitives import serialization
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    import hashlib
    return hashlib.sha256(cert_der).hexdigest()

def _get_subject_key_identifier(cert: x509.Certificate) -> str:
    """Extract Subject Key Identifier extension"""
    try:
        ski_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        return ski_ext.value.digest.hex()
    except x509.ExtensionNotFound:
        return None

def _get_authority_key_identifier(cert: x509.Certificate) -> str:
    """Extract Authority Key Identifier extension"""
    try:
        aki_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        if aki_ext.value.key_identifier:
            return aki_ext.value.key_identifier.hex()
        return None
    except x509.ExtensionNotFound:
        return None

def _is_ca_certificate(cert: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate"""
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
        return basic_constraints.ca
    except x509.ExtensionNotFound:
        return False

def _get_subject_cn(cert: x509.Certificate) -> str:
    """Extract subject common name"""
    try:
        for attribute in cert.subject:
            if attribute.oid._name == 'commonName':
                return attribute.value
        return "Unknown"
    except Exception:
        return "Unknown"

def _get_issuer_cn(cert: x509.Certificate) -> str:
    """Extract issuer common name"""
    try:
        for attribute in cert.issuer:
            if attribute.oid._name == 'commonName':
                return attribute.value
        return "Unknown"
    except Exception:
        return "Unknown"

def _get_public_key_algorithm(public_key) -> str:
    """Get public key algorithm name"""
    return type(public_key).__name__.replace('PublicKey', '')

def _get_key_size(public_key) -> int:
    """Get public key size"""
    try:
        if hasattr(public_key, 'key_size'):
            return public_key.key_size
        return 0
    except:
        return 0