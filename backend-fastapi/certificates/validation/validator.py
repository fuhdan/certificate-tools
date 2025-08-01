# backend-fastapi/certificates/validation/validator.py
# Updated validator for unified PEM storage

import logging
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.x509 import oid

from .models import ValidationResult
from .private_key_csr import validate_private_key_csr_match
from .csr_certificate import validate_csr_certificate_match
from .private_key_cert import validate_private_key_certificate_match
from .chain_validation import validate_certificate_chain

logger = logging.getLogger(__name__)

def run_validations(certificates: List, session_id: str) -> List[ValidationResult]:
    """
    Run intelligent validations on certificates from unified storage
    
    Args:
        certificates: List of UnifiedCertificateModel objects from CertificateStorage.get_all()
        session_id: Session identifier for logging
    
    Returns:
        List of ValidationResult objects
    """
    logger.info(f"[{session_id}] === RUNNING UNIFIED STORAGE VALIDATIONS ===")
    logger.debug(f"[{session_id}] Total certificates to analyze: {len(certificates)}")
    
    validations = []
    
    # Categorize certificates by type using pre-computed info
    private_keys = []
    csrs = []
    end_entity_certs = []
    ca_certs = []
    
    for cert in certificates:
        cert_id = cert.id
        filename = cert.filename
        
        logger.debug(f"[{session_id}] Processing {filename} - ID: {cert_id}")
        
        # Categorize based on content flags and pre-computed info
        if cert.has_private_key and not cert.has_certificate and not cert.has_csr:
            # Pure private key
            private_keys.append({
                'cert_id': cert_id,
                'filename': filename,
                'cert_model': cert
            })
            logger.debug(f"[{session_id}] Categorized as Private Key: {filename}")
            
        elif cert.has_csr and not cert.has_certificate:
            # Pure CSR
            csrs.append({
                'cert_id': cert_id,
                'filename': filename,
                'cert_model': cert
            })
            logger.debug(f"[{session_id}] Categorized as CSR: {filename}")
            
        elif cert.has_certificate:
            # Certificate (may also have private key)
            if cert.certificate_info and cert.certificate_info.is_ca:
                ca_certs.append({
                    'cert_id': cert_id,
                    'filename': filename,
                    'cert_model': cert
                })
                logger.debug(f"[{session_id}] Categorized as CA Certificate: {filename}")
            else:
                end_entity_certs.append({
                    'cert_id': cert_id,
                    'filename': filename,
                    'cert_model': cert
                })
                logger.debug(f"[{session_id}] Categorized as End Entity Certificate: {filename}")
    
    logger.info(f"[{session_id}] Certificate categorization:")
    logger.info(f"[{session_id}]   Private Keys: {len(private_keys)}")
    logger.info(f"[{session_id}]   CSRs: {len(csrs)}")
    logger.info(f"[{session_id}]   End Entity Certs: {len(end_entity_certs)}")
    logger.info(f"[{session_id}]   CA Certs: {len(ca_certs)}")
    
    # Run validation checks
    
    # 1. Private Key ↔ CSR matching
    if private_keys and csrs:
        logger.debug(f"[{session_id}] Running Private Key ↔ CSR validations...")
        for pk_item in private_keys:
            for csr_item in csrs:
                validation = _validate_private_key_csr_unified(pk_item, csr_item, session_id)
                validations.append(validation)
    
    # 2. CSR ↔ End-Entity Certificate matching
    if csrs and end_entity_certs:
        logger.debug(f"[{session_id}] Running CSR ↔ End-Entity Certificate validations...")
        for csr_item in csrs:
            for cert_item in end_entity_certs:
                validation = _validate_csr_certificate_unified(csr_item, cert_item, session_id)
                validations.append(validation)
    
    # 3. Private Key ↔ End-Entity Certificate matching
    if private_keys and end_entity_certs:
        logger.debug(f"[{session_id}] Running Private Key ↔ End-Entity Certificate validations...")
        for pk_item in private_keys:
            for cert_item in end_entity_certs:
                validation = _validate_private_key_certificate_unified(pk_item, cert_item, session_id)
                validations.append(validation)
    
    # 4. Internal certificate validations (certificate with bundled private key)
    for cert_item in end_entity_certs:
        if cert_item['cert_model'].has_private_key:
            logger.debug(f"[{session_id}] Running internal validation for {cert_item['filename']}")
            validation = _validate_internal_cert_key_match(cert_item, session_id)
            validations.append(validation)
    
    # 5. Certificate Chain Validation
    all_cert_items = end_entity_certs + ca_certs
    if len(all_cert_items) >= 2:
        logger.debug(f"[{session_id}] Running Certificate Chain validations...")
        try:
            chain_validations = _validate_certificate_chain_unified(all_cert_items, session_id)
            validations.extend(chain_validations)
            logger.info(f"[{session_id}] Completed {len(chain_validations)} certificate chain validations")
        except Exception as e:
            logger.error(f"[{session_id}] Error during certificate chain validation: {e}")
            validations.append(ValidationResult(
                is_valid=False,
                validation_type="Certificate Chain",
                description="Failed to validate certificate chain",
                certificate_1="Multiple certificates",
                certificate_2="",
                error=str(e)
            ))
    
    # Log validation summary
    passed_count = sum(1 for v in validations if v.is_valid)
    failed_count = len(validations) - passed_count
    logger.info(f"[{session_id}] Validation complete: {passed_count} passed, {failed_count} failed ({len(validations)} total)")
    
    return validations

def _validate_private_key_csr_unified(pk_item: Dict, csr_item: Dict, session_id: str) -> ValidationResult:
    """Validate private key matches CSR using unified storage"""
    from certificates.storage import CryptoObjectAccess
    
    logger.debug(f"[{session_id}] Validating Private Key ↔ CSR: {pk_item['filename']} ↔ {csr_item['filename']}")
    
    try:
        # Get crypto objects from unified storage
        private_key = CryptoObjectAccess.get_private_key(pk_item['cert_id'], session_id)
        csr = CryptoObjectAccess.get_csr(csr_item['cert_id'], session_id)
        
        if not private_key:
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key ↔ CSR",
                description=f"Failed to load private key from {pk_item['filename']}",
                certificate_1=pk_item['filename'],
                certificate_2=csr_item['filename'],
                error="Could not load private key"
            )
        
        if not csr:
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key ↔ CSR",
                description=f"Failed to load CSR from {csr_item['filename']}",
                certificate_1=pk_item['filename'],
                certificate_2=csr_item['filename'],
                error="Could not load CSR"
            )
        
        # Perform the actual validation
        result = validate_private_key_csr_match(private_key, csr)
        
        # Update result with file information
        result.certificate_1 = pk_item['filename']
        result.certificate_2 = csr_item['filename']
        result.description = f"Private key in {pk_item['filename']} {'matches' if result.is_valid else 'does not match'} CSR in {csr_item['filename']}"
        
        return result
        
    except Exception as e:
        logger.error(f"[{session_id}] Error validating private key ↔ CSR: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key ↔ CSR",
            description=f"Validation failed for {pk_item['filename']} ↔ {csr_item['filename']}",
            certificate_1=pk_item['filename'],
            certificate_2=csr_item['filename'],
            error=str(e)
        )

def _validate_csr_certificate_unified(csr_item: Dict, cert_item: Dict, session_id: str) -> ValidationResult:
    """Validate CSR matches certificate using unified storage"""
    from certificates.storage import CryptoObjectAccess
    
    logger.debug(f"[{session_id}] Validating CSR ↔ Certificate: {csr_item['filename']} ↔ {cert_item['filename']}")
    
    try:
        # Get crypto objects from unified storage
        csr = CryptoObjectAccess.get_csr(csr_item['cert_id'], session_id)
        certificate = CryptoObjectAccess.get_certificate(cert_item['cert_id'], session_id)
        
        if not csr:
            return ValidationResult(
                is_valid=False,
                validation_type="CSR ↔ Certificate",
                description=f"Failed to load CSR from {csr_item['filename']}",
                certificate_1=csr_item['filename'],
                certificate_2=cert_item['filename'],
                error="Could not load CSR"
            )
        
        if not certificate:
            return ValidationResult(
                is_valid=False,
                validation_type="CSR ↔ Certificate",
                description=f"Failed to load certificate from {cert_item['filename']}",
                certificate_1=csr_item['filename'],
                certificate_2=cert_item['filename'],
                error="Could not load certificate"
            )
        
        # Perform the actual validation
        result = validate_csr_certificate_match(csr, certificate)
        
        # Update result with file information
        result.certificate_1 = csr_item['filename']
        result.certificate_2 = cert_item['filename']
        result.description = f"CSR in {csr_item['filename']} {'matches' if result.is_valid else 'does not match'} certificate in {cert_item['filename']}"
        
        return result
        
    except Exception as e:
        logger.error(f"[{session_id}] Error validating CSR ↔ certificate: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="CSR ↔ Certificate",
            description=f"Validation failed for {csr_item['filename']} ↔ {cert_item['filename']}",
            certificate_1=csr_item['filename'],
            certificate_2=cert_item['filename'],
            error=str(e)
        )

def _validate_private_key_certificate_unified(pk_item: Dict, cert_item: Dict, session_id: str) -> ValidationResult:
    """Validate private key matches certificate using unified storage"""
    from certificates.storage import CryptoObjectAccess
    
    logger.debug(f"[{session_id}] Validating Private Key ↔ Certificate: {pk_item['filename']} ↔ {cert_item['filename']}")
    
    try:
        # Get crypto objects from unified storage
        private_key = CryptoObjectAccess.get_private_key(pk_item['cert_id'], session_id)
        certificate = CryptoObjectAccess.get_certificate(cert_item['cert_id'], session_id)
        
        if not private_key:
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key ↔ Certificate",
                description=f"Failed to load private key from {pk_item['filename']}",
                certificate_1=pk_item['filename'],
                certificate_2=cert_item['filename'],
                error="Could not load private key"
            )
        
        if not certificate:
            return ValidationResult(
                is_valid=False,
                validation_type="Private Key ↔ Certificate",
                description=f"Failed to load certificate from {cert_item['filename']}",
                certificate_1=pk_item['filename'],
                certificate_2=cert_item['filename'],
                error="Could not load certificate"
            )
        
        # Perform the actual validation
        result = validate_private_key_certificate_match(private_key, certificate)
        
        # Update result with file information
        result.certificate_1 = pk_item['filename']
        result.certificate_2 = cert_item['filename']
        result.description = f"Private key in {pk_item['filename']} {'matches' if result.is_valid else 'does not match'} certificate in {cert_item['filename']}"
        
        return result
        
    except Exception as e:
        logger.error(f"[{session_id}] Error validating private key ↔ certificate: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key ↔ Certificate",
            description=f"Validation failed for {pk_item['filename']} ↔ {cert_item['filename']}",
            certificate_1=pk_item['filename'],
            certificate_2=cert_item['filename'],
            error=str(e)
        )

def _validate_internal_cert_key_match(cert_item: Dict, session_id: str) -> ValidationResult:
    """Validate certificate with bundled private key (e.g., from PKCS12)"""
    from certificates.storage import CryptoObjectAccess
    
    logger.debug(f"[{session_id}] Validating internal cert+key match: {cert_item['filename']}")
    
    try:
        # Get both crypto objects from the same certificate
        certificate = CryptoObjectAccess.get_certificate(cert_item['cert_id'], session_id)
        private_key = CryptoObjectAccess.get_private_key(cert_item['cert_id'], session_id)
        
        if not certificate or not private_key:
            return ValidationResult(
                is_valid=False,
                validation_type="Internal Certificate + Private Key",
                description=f"Failed to load bundled certificate and private key from {cert_item['filename']}",
                certificate_1=cert_item['filename'],
                certificate_2="",
                error="Could not load certificate or private key"
            )
        
        # Perform the actual validation
        result = validate_private_key_certificate_match(private_key, certificate)
        
        # Update result with file information
        result.certificate_1 = cert_item['filename']
        result.certificate_2 = ""
        result.description = f"Bundled private key and certificate in {cert_item['filename']} {'match' if result.is_valid else 'do not match'}"
        result.validation_type = "Internal Certificate + Private Key"
        
        return result
        
    except Exception as e:
        logger.error(f"[{session_id}] Error validating internal cert+key: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Internal Certificate + Private Key",
            description=f"Internal validation failed for {cert_item['filename']}",
            certificate_1=cert_item['filename'],
            certificate_2="",
            error=str(e)
        )

def _validate_certificate_chain_unified(cert_items: List[Dict], session_id: str) -> List[ValidationResult]:
    """Validate certificate chain using unified storage"""
    from certificates.storage import CryptoObjectAccess
    
    logger.debug(f"[{session_id}] Validating certificate chain with {len(cert_items)} certificates")
    
    try:
        # Get all certificate crypto objects
        certificates = []
        for cert_item in cert_items:
            cert = CryptoObjectAccess.get_certificate(cert_item['cert_id'], session_id)
            if cert:
                certificates.append(cert)
        
        if len(certificates) < 2:
            return [ValidationResult(
                is_valid=False,
                validation_type="Certificate Chain",
                description=f"Need at least 2 certificates, found {len(certificates)}",
                certificate_1="Multiple certificates",
                certificate_2="",
                error="Insufficient certificates for chain validation"
            )]
        
        # Perform chain validation
        chain_validations = validate_certificate_chain(certificates, session_id)
        
        # Update results with more descriptive information
        for validation in chain_validations:
            if not validation.certificate_1:
                validation.certificate_1 = "Certificate Chain"
            if not validation.certificate_2:
                validation.certificate_2 = ""
        
        return chain_validations
        
    except Exception as e:
        logger.error(f"[{session_id}] Error validating certificate chain: {e}")
        return [ValidationResult(
            is_valid=False,
            validation_type="Certificate Chain",
            description="Failed to validate certificate chain",
            certificate_1="Multiple certificates",
            certificate_2="",
            error=str(e)
        )]

# Backward compatibility functions

class CertificateValidator:
    """Session-aware certificate validator for unified storage"""
    
    @staticmethod
    def validate_all_certificates(session_id: str) -> List[Dict[str, Any]]:
        """Run validation checks for all certificates in session"""
        from certificates.storage import CertificateStorage
        certificates = CertificateStorage.get_all(session_id)
        validations = run_validations(certificates, session_id)
        return [validation.to_dict() for validation in validations]