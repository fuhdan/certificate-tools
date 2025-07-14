# backend-fastapi/certificates/validation/chain_validation.py
# Certificate chain validation functions

import logging
from typing import List, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .models import ValidationResult

logger = logging.getLogger(__name__)

def validate_certificate_chain(certificates: List[Dict[str, Any]]) -> List[ValidationResult]:
    """Validate certificate chains - signature verification and hierarchy"""
    logger.info(f"=== CERTIFICATE CHAIN VALIDATION ===")
    
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
            cert_objects.append({
                'cert_data': cert,
                'certificate_obj': crypto_objects['certificate'],
                'is_ca': _is_ca_certificate(crypto_objects['certificate']),
                'subject': _get_subject_cn(crypto_objects['certificate']),
                'issuer': _get_issuer_cn(crypto_objects['certificate'])
            })
    
    logger.debug(f"Found {len(cert_objects)} certificates for chain validation")
    
    # Try to build and validate chains
    if len(cert_objects) >= 2:
        chains = _build_certificate_chains(cert_objects)
        
        for chain in chains:
            validation = _validate_single_chain(chain)
            validations.append(validation)
    
    return validations

def _is_ca_certificate(cert: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate"""
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
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

def _build_certificate_chains(cert_objects: List[Dict]) -> List[List[Dict]]:
    """Build possible certificate chains from available certificates"""
    logger.debug("Building certificate chains...")
    
    chains = []
    
    # Find root certificates (self-signed)
    roots = [c for c in cert_objects if c['subject'] == c['issuer']]
    
    # Find end-entity certificates (not CA)
    end_entities = [c for c in cert_objects if not c['is_ca']]
    
    logger.debug(f"Found {len(roots)} root CAs and {len(end_entities)} end-entity certificates")
    
    # Try to build chains from end-entity to root
    for end_entity in end_entities:
        for root in roots:
            chain = _build_chain_recursive(end_entity, root, cert_objects, [])
            if chain and len(chain) >= 2:
                chains.append(chain)
    
    logger.debug(f"Built {len(chains)} possible certificate chains")
    return chains

def _build_chain_recursive(current_cert: Dict, target_root: Dict, all_certs: List[Dict], current_chain: List[Dict]) -> List[Dict]:
    """Recursively build certificate chain"""
    
    # Add current certificate to chain
    new_chain = current_chain + [current_cert]
    
    # If we reached the target root, return the chain
    if current_cert['subject'] == target_root['subject']:
        return new_chain
    
    # If chain is getting too long, stop
    if len(new_chain) > 5:
        return []
    
    # Find the issuer of current certificate
    issuer_cn = current_cert['issuer']
    
    # Look for a certificate that could be the issuer
    for cert in all_certs:
        if cert['subject'] == issuer_cn and cert not in new_chain:
            # Found potential issuer, continue building
            result = _build_chain_recursive(cert, target_root, all_certs, new_chain)
            if result:
                return result
    
    return []

def _validate_single_chain(chain: List[Dict]) -> ValidationResult:
    """Validate a single certificate chain"""
    logger.debug(f"Validating chain with {len(chain)} certificates")
    
    chain_description = " -> ".join([cert['subject'] for cert in chain])
    logger.debug(f"Chain: {chain_description}")
    
    try:
        is_valid = True
        validation_details = {
            "chainLength": len(chain),
            "certificates": [],
            "signatureValidations": []
        }
        
        # Validate each certificate in the chain
        for i, cert_info in enumerate(chain):
            cert = cert_info['certificate_obj']
            
            cert_details = {
                "position": i,
                "subject": cert_info['subject'],
                "issuer": cert_info['issuer'],
                "isCA": cert_info['is_ca'],
                "filename": cert_info['cert_data'].get('filename')
            }
            validation_details["certificates"].append(cert_details)
            
            # Validate signature (except for root certificate)
            if i < len(chain) - 1:
                issuer_cert = chain[i + 1]['certificate_obj']
                signature_valid = _verify_certificate_signature(cert, issuer_cert)
                
                signature_validation = {
                    "certificateSubject": cert_info['subject'],
                    "issuerSubject": chain[i + 1]['subject'],
                    "signatureValid": signature_valid
                }
                validation_details["signatureValidations"].append(signature_validation)
                
                if not signature_valid:
                    is_valid = False
                    logger.warning(f"Invalid signature: {cert_info['subject']} not signed by {chain[i + 1]['subject']}")
        
        # Add file information
        validation_details.update({
            "certificateFiles": [cert['cert_data'].get('filename') for cert in chain]
        })
        
        if is_valid:
            logger.info(f"✅ Certificate chain validation: VALID - {chain_description}")
        else:
            logger.warning(f"❌ Certificate chain validation: INVALID - {chain_description}")
        
        return ValidationResult(
            is_valid=is_valid,
            validation_type="Certificate Chain",
            details=validation_details
        )
        
    except Exception as e:
        logger.error(f"Error validating certificate chain: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Certificate Chain",
            error=str(e),
            details={
                "chainLength": len(chain),
                "certificateFiles": [cert['cert_data'].get('filename') for cert in chain]
            }
        )

def _verify_certificate_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Verify that cert was signed by issuer_cert"""
    logger.debug(f"Verifying signature: {_get_subject_cn(cert)} signed by {_get_subject_cn(issuer_cert)}")
    
    try:
        # Get the issuer's public key
        issuer_public_key = issuer_cert.public_key()
        
        # Extract signature and signed data from certificate
        signature = cert.signature
        tbs_certificate_bytes = cert.tbs_certificate_bytes
        
        # Get signature algorithm
        signature_algorithm = cert.signature_algorithm_oid
        
        # Verify signature based on algorithm
        if signature_algorithm.dotted_string == "1.2.840.113549.1.1.11":  # SHA256withRSA
            from cryptography.hazmat.primitives.asymmetric import rsa
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    signature,
                    tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                logger.debug("RSA signature verification successful")
                return True
        elif signature_algorithm.dotted_string == "1.2.840.10045.4.3.2":  # ECDSA with SHA256
            from cryptography.hazmat.primitives.asymmetric import ec
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    signature,
                    tbs_certificate_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
                logger.debug("ECDSA signature verification successful")
                return True
        
        logger.warning(f"Unsupported signature algorithm: {signature_algorithm.dotted_string}")
        return False
        
    except Exception as e:
        logger.debug(f"Signature verification failed: {e}")
        return False