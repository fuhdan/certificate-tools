# backend-fastapi/certificates/validation/validator.py
# FIXED validation orchestrator - now with session support and proper PKCS7 chain support

import logging
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.x509 import oid
from config import settings
from .models import ValidationResult
from .private_key_csr import validate_private_key_csr_match
from .csr_certificate import validate_csr_certificate_match
from .private_key_cert import validate_private_key_certificate_match
from .chain_validation import validate_certificate_chain

logger = logging.getLogger(__name__)

def run_validations(certificates: List[Dict[str, Any]]) -> List[ValidationResult]:
    """Run INTELLIGENT validations - works with certificates data independently of sessions"""
    logger.info(f"=== RUNNING INTELLIGENT VALIDATIONS ===")
    logger.debug(f"Total certificates to analyze: {len(certificates)}")
    
    validations = []
    
    # Find private keys, CSRs, and certificates with their crypto objects
    from certificates.storage import CertificateStorage
    
    private_keys = []
    csrs = []
    end_entity_certs = []
    ca_certs = []
    pkcs7_chains = []
    
    for cert in certificates:
        analysis = cert.get('analysis', {})
        cert_type = analysis.get('type', '')
        cert_id = cert.get('id')
        filename = cert.get('filename', 'NO_FILENAME')
        
        # Skip if cert_id is None
        if cert_id is None:
            logger.warning(f"Skipping certificate with no ID: {filename}")
            continue
        
        # Get crypto objects from separate storage - NO SESSION DEPENDENCY
        # The certificates passed to validation should already contain everything needed
        # If crypto objects are not accessible, skip crypto-based validation for that cert
        try:
            # We'll make this work without session dependency by using a default approach
            # The router calling this should ensure the certificates come from the right session
            crypto_objects = {}
            
            # Check if crypto objects are embedded in the certificate data
            if 'crypto_objects' in cert:
                crypto_objects = cert['crypto_objects']
            else:
                # Try to get from storage using default session (the router handles session routing)
                try:
                    crypto_objects = CertificateStorage.get_crypto_objects(cert_id, settings.DEFAULT_SESSION_ID)
                except:
                    # If that fails, validation will just skip crypto-based checks for this cert
                    logger.debug(f"Could not get crypto objects for cert {cert_id} - skipping crypto validation")
                    continue
                    
        except Exception as e:
            logger.warning(f"Error getting crypto objects for {filename}: {e}")
            continue
        
        if cert_type == 'Private Key' and analysis.get('isValid') and 'private_key' in crypto_objects:
            private_keys.append({
                'cert_data': cert,
                'private_key_obj': crypto_objects['private_key']
            })
            logger.info(f"✓ Found private key: {filename}")
            
        elif cert_type == 'CSR' and analysis.get('isValid') and 'csr' in crypto_objects:
            csrs.append({
                'cert_data': cert,
                'csr_obj': crypto_objects['csr']
            })
            logger.info(f"✓ Found CSR: {filename}")
            
        # FIXED: Detect ALL certificate types including "CA Certificate"
        elif ('Certificate' in cert_type and 'Chain' not in cert_type and 
              analysis.get('isValid') and 'certificate' in crypto_objects):
            
            # Single certificate - determine if CA or end-entity
            details = analysis.get('details', {})
            is_ca = details.get('extensions', {}).get('basicConstraints', {}).get('isCA', False)
            
            cert_info = {
                'cert_data': cert,
                'certificate_obj': crypto_objects['certificate'],
                'is_ca': is_ca,
                'filename': filename
            }
            
            if is_ca:
                ca_certs.append(cert_info)
                logger.info(f"✓ Found CA certificate: {filename}")
            else:
                end_entity_certs.append(cert_info)
                logger.info(f"✓ Found end-entity certificate: {filename}")
        
        # Handle explicit certificate chains
        elif ('Certificate Chain' in cert_type and analysis.get('isValid')):
            main_cert = crypto_objects.get('certificate')
            additional_certs = crypto_objects.get('additional_certificates', [])
            
            if main_cert or additional_certs:
                all_chain_certs = []
                if main_cert:
                    all_chain_certs.append(main_cert)
                if additional_certs:
                    all_chain_certs.extend(additional_certs)
                
                pkcs7_chains.append({
                    'cert_data': cert,
                    'certificates': all_chain_certs,
                    'filename': filename,
                    'chain_type': 'Certificate Chain'
                })
                logger.info(f"✓ Found Certificate Chain: {filename} ({len(all_chain_certs)} certificates)")
    
    logger.info(f"VALIDATION CANDIDATES:")
    logger.info(f"  Private Keys: {len(private_keys)}")
    logger.info(f"  CSRs: {len(csrs)}")
    logger.info(f"  End-Entity Certificates: {len(end_entity_certs)}")
    logger.info(f"  CA Certificates: {len(ca_certs)}")
    logger.info(f"  PKCS7/Certificate Chains: {len(pkcs7_chains)}")
    
    # 1. INTELLIGENT: Private Key ↔ CSR (only if both exist)
    if private_keys and csrs:
        logger.info("Running Private Key ↔ CSR validations...")
        for pk_item in private_keys:
            for csr_item in csrs:
                validation = _validate_private_key_csr(pk_item, csr_item)
                validations.append(validation)
    
    # 2. INTELLIGENT: CSR ↔ End-Entity Certificate (only end-entity certs)
    if csrs and end_entity_certs:
        logger.info("Running CSR ↔ End-Entity Certificate validations...")
        for csr_item in csrs:
            for cert_item in end_entity_certs:
                validation = _validate_csr_certificate(csr_item, cert_item)
                validations.append(validation)
    
    # 3. INTELLIGENT: Private Key ↔ End-Entity Certificate (only end-entity certs)
    if private_keys and end_entity_certs:
        logger.info("Running Private Key ↔ End-Entity Certificate validations...")
        for pk_item in private_keys:
            for cert_item in end_entity_certs:
                validation = _validate_private_key_certificate(pk_item, cert_item)
                validations.append(validation)
    
    # 4. FIXED: Certificate Chain Validation (individual certificates)
    all_certs = end_entity_certs + ca_certs
    if len(all_certs) >= 2:
        logger.info("Running Certificate Chain validations...")
        try:
            # Convert to the format expected by validate_certificate_chain
            cert_list = []
            for cert_info in all_certs:
                cert_list.append(cert_info['cert_data'])
            
            chain_validations = validate_certificate_chain(cert_list)
            validations.extend(chain_validations)
            logger.info(f"Completed {len(chain_validations)} certificate chain validations")
        except Exception as e:
            logger.error(f"Error during certificate chain validation: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            validations.append(ValidationResult(
                is_valid=False,
                validation_type="Certificate Chain",
                error=str(e)
            ))
    
    # 5. FIXED: PKCS7/Certificate Chain Validation
    if pkcs7_chains:
        logger.info("Running PKCS7/Certificate Chain validations...")
        for chain_item in pkcs7_chains:
            try:
                chain_validations = _validate_pkcs7_chain(chain_item)
                validations.extend(chain_validations)
                logger.info(f"Completed {chain_item['chain_type']} validation for {chain_item['filename']}")
            except Exception as e:
                logger.error(f"Error during {chain_item['chain_type']} validation: {e}")
                import traceback
                logger.error(f"Full traceback: {traceback.format_exc()}")
                validations.append(ValidationResult(
                    is_valid=False,
                    validation_type=f"{chain_item['chain_type']} Validation",
                    error=str(e),
                    details={"filename": chain_item['filename']}
                ))
    
    logger.info(f"Completed {len(validations)} INTELLIGENT validations")
    return validations

def _validate_private_key_csr(pk_item: Dict, csr_item: Dict) -> ValidationResult:
    """Validate private key against CSR with proper error handling"""
    try:
        validation = validate_private_key_csr_match(
            pk_item['private_key_obj'], 
            csr_item['csr_obj']
        )
        
        # Add file information
        if validation.details:
            validation.details.update({
                "privateKeyFile": pk_item['cert_data'].get('filename'),
                "csrFile": csr_item['cert_data'].get('filename')
            })
        
        logger.info(f"Private Key ↔ CSR: {pk_item['cert_data'].get('filename')} ↔ {csr_item['cert_data'].get('filename')}: {'MATCH' if validation.is_valid else 'NO MATCH'}")
        return validation
        
    except Exception as e:
        logger.error(f"Error validating Private Key ↔ CSR: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> CSR",
            error=str(e),
            details={
                "privateKeyFile": pk_item['cert_data'].get('filename'),
                "csrFile": csr_item['cert_data'].get('filename')
            }
        )

def _validate_csr_certificate(csr_item: Dict, cert_item: Dict) -> ValidationResult:
    """Validate CSR against certificate with proper error handling"""
    try:
        validation = validate_csr_certificate_match(
            csr_item['csr_obj'], 
            cert_item['certificate_obj']
        )
        
        # Add file information
        if validation.details:
            validation.details.update({
                "csrFile": csr_item['cert_data'].get('filename'),
                "certificateFile": cert_item['cert_data'].get('filename')
            })
        
        logger.info(f"CSR ↔ Certificate: {csr_item['cert_data'].get('filename')} ↔ {cert_item['cert_data'].get('filename')}: {'MATCH' if validation.is_valid else 'NO MATCH'}")
        return validation
        
    except Exception as e:
        logger.error(f"Error validating CSR ↔ Certificate: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="CSR <-> Certificate",
            error=str(e),
            details={
                "csrFile": csr_item['cert_data'].get('filename'),
                "certificateFile": cert_item['cert_data'].get('filename')
            }
        )

def _validate_private_key_certificate(pk_item: Dict, cert_item: Dict) -> ValidationResult:
    """Validate private key against certificate with proper error handling"""
    try:
        validation = validate_private_key_certificate_match(
            pk_item['private_key_obj'], 
            cert_item['certificate_obj']
        )
        
        # Add file information
        if validation.details:
            validation.details.update({
                "privateKeyFile": pk_item['cert_data'].get('filename'),
                "certificateFile": cert_item['cert_data'].get('filename')
            })
        
        logger.info(f"Private Key ↔ Certificate: {pk_item['cert_data'].get('filename')} ↔ {cert_item['cert_data'].get('filename')}: {'MATCH' if validation.is_valid else 'NO MATCH'}")
        return validation
        
    except Exception as e:
        logger.error(f"Error validating Private Key ↔ Certificate: {e}")
        return ValidationResult(
            is_valid=False,
            validation_type="Private Key <-> Certificate",
            error=str(e),
            details={
                "privateKeyFile": pk_item['cert_data'].get('filename'),
                "certificateFile": cert_item['cert_data'].get('filename')
            }
        )

def _validate_pkcs7_chain(chain_item: Dict) -> List[ValidationResult]:
    """Validate PKCS7/Certificate chain with detailed analysis"""
    logger.info(f"=== {chain_item['chain_type'].upper()} VALIDATION ===")
    
    filename = chain_item['filename']
    certificates = chain_item['certificates']
    chain_type = chain_item['chain_type']
    
    logger.info(f"Validating {chain_type}: {filename} ({len(certificates)} certificates)")
    
    validations = []
    
    if len(certificates) < 2:
        logger.warning(f"{chain_type} has only {len(certificates)} certificate(s) - cannot validate chain")
        return [ValidationResult(
            is_valid=False,
            validation_type=f"{chain_type} Validation",
            error=f"Chain must have at least 2 certificates, found {len(certificates)}",
            details={"filename": filename, "certificateCount": len(certificates)}
        )]
    
    # Analyze the certificate chain structure
    cert_info = []
    for i, cert in enumerate(certificates):
        info = {
            'index': i,
            'certificate': cert,
            'subject': _get_subject_cn(cert),
            'issuer': _get_issuer_cn(cert),
            'is_ca': _is_ca_certificate(cert),
            'serial': str(cert.serial_number),
            'fingerprint': _get_certificate_fingerprint(cert)
        }
        cert_info.append(info)
        logger.debug(f"Cert {i}: {info['subject']} (issued by: {info['issuer']}, CA: {info['is_ca']})")
    
    # Try to determine the correct chain order (end-entity → intermediate → root)
    ordered_chain = _order_certificates(cert_info)
    
    if not ordered_chain:
        logger.warning("Could not determine certificate chain order")
        return [ValidationResult(
            is_valid=False,
            validation_type=f"{chain_type} Validation",
            error="Could not determine certificate chain order",
            details={
                "filename": filename,
                "certificates": [{"subject": info['subject'], "issuer": info['issuer']} for info in cert_info]
            }
        )]
    
    # Validate each link in the chain
    for i in range(len(ordered_chain) - 1):
        child_cert_info = ordered_chain[i]
        parent_cert_info = ordered_chain[i + 1]
        
        child_cert = child_cert_info['certificate']
        parent_cert = parent_cert_info['certificate']
        
        logger.info(f"Validating chain link: {child_cert_info['subject']} → {parent_cert_info['subject']}")
        
        # Verify signature
        signature_result = _verify_certificate_signature_detailed(child_cert, parent_cert)
        
        # Check name chaining
        name_chain_valid = child_cert_info['issuer'] == parent_cert_info['subject']
        
        # Overall link validity
        link_valid = signature_result['verified'] and name_chain_valid
        
        validation = ValidationResult(
            is_valid=link_valid,
            validation_type=f"{chain_type} Validation",
            details={
                "filename": filename,
                "chainPosition": f"Link {i+1} of {len(ordered_chain)-1}",
                "childCertificate": {
                    "subject": child_cert_info['subject'],
                    "issuer": child_cert_info['issuer'],
                    "serial": child_cert_info['serial'],
                    "fingerprint": child_cert_info['fingerprint'],
                    "isCA": child_cert_info['is_ca']
                },
                "parentCertificate": {
                    "subject": parent_cert_info['subject'],
                    "issuer": parent_cert_info['issuer'],
                    "serial": parent_cert_info['serial'],
                    "fingerprint": parent_cert_info['fingerprint'],
                    "isCA": parent_cert_info['is_ca'],
                    "isSelfSigned": parent_cert_info['subject'] == parent_cert_info['issuer']
                },
                "signatureVerification": signature_result,
                "nameChaining": {
                    "valid": name_chain_valid,
                    "childIssuer": child_cert_info['issuer'],
                    "parentSubject": parent_cert_info['subject']
                },
                "chainDescription": f"{child_cert_info['subject']} → {parent_cert_info['subject']}"
            }
        )
        
        validations.append(validation)
        
        if link_valid:
            logger.info(f"✅ Chain link VALID: {child_cert_info['subject']} → {parent_cert_info['subject']}")
        else:
            logger.warning(f"❌ Chain link INVALID: {child_cert_info['subject']} → {parent_cert_info['subject']}")
            if not signature_result['verified']:
                logger.warning(f"  - Signature verification failed")
            if not name_chain_valid:
                logger.warning(f"  - Name chaining failed")
    
    return validations

# FIXED helper functions - removed is_issuer parameter
def _get_subject_cn(cert):
    """Extract subject common name"""
    try:
        for attribute in cert.subject:
            if attribute.oid == oid.NameOID.COMMON_NAME:
                return attribute.value
        return "Unknown"
    except Exception:
        return "Unknown"

def _get_issuer_cn(cert):
    """Extract issuer common name"""
    try:
        for attribute in cert.issuer:
            if attribute.oid == oid.NameOID.COMMON_NAME:
                return attribute.value
        return "Unknown"
    except Exception:
        return "Unknown"

def _is_ca_certificate(cert):
    """Check if certificate is a CA certificate"""
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(oid.ExtensionOID.BASIC_CONSTRAINTS).value
        return basic_constraints.ca
    except:
        return False

def _get_certificate_fingerprint(cert):
    """Get SHA256 fingerprint of certificate"""
    from cryptography.hazmat.primitives import serialization
    import hashlib
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(cert_der).hexdigest()

def _verify_certificate_signature_detailed(cert, issuer_cert):
    """Verify certificate signature with detailed results"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    
    result = {
        "verified": False,
        "algorithm": cert.signature_algorithm_oid._name,
        "algorithmOID": cert.signature_algorithm_oid.dotted_string,
        "issuerPublicKeyAlgorithm": type(issuer_cert.public_key()).__name__.replace('PublicKey', ''),
        "error": None
    }
    
    try:
        issuer_public_key = issuer_cert.public_key()
        signature = cert.signature
        tbs_certificate_bytes = cert.tbs_certificate_bytes
        signature_algorithm = cert.signature_algorithm_oid
        
        # Verify signature based on algorithm
        if signature_algorithm.dotted_string == "1.2.840.113549.1.1.11":  # SHA256withRSA
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(signature, tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
                result["verified"] = True
                result["hashAlgorithm"] = "SHA256"
        elif signature_algorithm.dotted_string == "1.2.840.10045.4.3.2":  # ECDSA with SHA256
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(signature, tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
                result["verified"] = True
                result["hashAlgorithm"] = "SHA256"
        else:
            result["error"] = f"Unsupported signature algorithm: {signature_algorithm.dotted_string}"
        
    except Exception as e:
        result["error"] = str(e)
    
    return result

def _order_certificates(cert_info: List[Dict]) -> List[Dict]:
    """Order certificates in a logical chain (end-entity → intermediate → root)"""
    logger.debug("Ordering certificates...")
    
    # Find the end-entity certificate (not CA)
    end_entities = [info for info in cert_info if not info['is_ca']]
    cas = [info for info in cert_info if info['is_ca']]
    
    logger.debug(f"Found {len(end_entities)} end-entity certs and {len(cas)} CA certs")
    
    if len(end_entities) != 1:
        logger.warning(f"Expected 1 end-entity certificate, found {len(end_entities)}")
        if len(end_entities) == 0:
            # If no clear end-entity, try to find the leaf certificate
            # Look for certificate that is not an issuer of any other cert
            potential_leaves = []
            for cert in cert_info:
                is_issuer = any(other['issuer'] == cert['subject'] for other in cert_info if other != cert)
                if not is_issuer:
                    potential_leaves.append(cert)
            
            if len(potential_leaves) == 1:
                logger.info(f"Found leaf certificate by issuer analysis: {potential_leaves[0]['subject']}")
                end_entities = potential_leaves
                cas = [info for info in cert_info if info not in end_entities]
            else:
                return []
        else:
            return []
    
    # Start with the end-entity certificate
    ordered = [end_entities[0]]
    remaining_cas = cas.copy()
    
    current = end_entities[0]
    
    # Build the chain by following issuer → subject relationships
    while remaining_cas and current['issuer'] != current['subject']:  # Not self-signed
        # Find the issuer of the current certificate
        next_cert = None
        for ca in remaining_cas:
            if ca['subject'] == current['issuer']:
                next_cert = ca
                break
        
        if next_cert:
            ordered.append(next_cert)
            remaining_cas.remove(next_cert)
            current = next_cert
            logger.debug(f"Added to chain: {next_cert['subject']}")
        else:
            logger.warning(f"Could not find issuer '{current['issuer']}' for certificate '{current['subject']}'")
            break
    
    logger.info(f"Ordered chain: {' → '.join([cert['subject'] for cert in ordered])}")
    return ordered