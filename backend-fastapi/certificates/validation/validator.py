# backend-fastapi/certificates/validation/validator.py
# Main validation orchestrator - coordinates all validation types

import logging
from typing import Dict, Any, List
from .models import ValidationResult
from .private_key_csr import validate_private_key_csr_match
from .csr_certificate import validate_csr_certificate_match
from .private_key_cert import validate_private_key_certificate_match
from .chain_validation import validate_certificate_chain

logger = logging.getLogger(__name__)

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
    
    # 1. Validate private key <-> CSR pairs
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
    
    # 2. Validate CSR <-> Certificate pairs
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
    
    # 3. Validate Private Key <-> Certificate pairs
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
    
    # 4. NEW: Validate Certificate Chains
    if len(certificates_list) >= 2:
        logger.info("Running Certificate Chain validations...")
        try:
            chain_validations = validate_certificate_chain(certificates)
            validations.extend(chain_validations)
            logger.info(f"Completed {len(chain_validations)} certificate chain validations")
        except Exception as e:
            logger.error(f"Error during certificate chain validation: {e}")
            validations.append(ValidationResult(
                is_valid=False,
                validation_type="Certificate Chain",
                error=str(e)
            ))
    
    logger.info(f"Completed {len(validations)} total validations")
    return validations