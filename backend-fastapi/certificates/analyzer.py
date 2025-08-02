# backend-fastapi/certificates/analyzer.py
# Enhanced analyzer with smart chain management and comprehensive format support

import hashlib
import logging
import uuid
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from .extractors.certificate import extract_certificate_metadata
from .extractors.csr import extract_csr_metadata
from .extractors.private_key import extract_private_key_metadata

from .storage.session_pki_storage import (
    session_pki_storage, 
    PKIComponentType,
    process_pkcs12_bundle
)

logger = logging.getLogger(__name__)

def get_file_format(filename: str) -> str:
    """Determine file format from filename"""
    extension = filename.split('.')[-1].lower()
    format_map = {
        'pem': 'PEM',
        'crt': 'PEM', 
        'cer': 'PEM',
        'der': 'DER',
        'p12': 'PKCS12',
        'pfx': 'PKCS12',
        'p7b': 'PKCS7',
        'p7c': 'PKCS7',
        'p7s': 'PKCS7',
        'spc': 'PKCS7',
        'jks': 'JKS',
        'key': 'Private Key',
        'csr': 'CSR',
        'p8': 'DER',
        'pk8': 'DER'
    }
    detected_format = format_map.get(extension, extension.upper())
    logger.debug(f"File format detection: {filename} -> {detected_format}")
    return detected_format

def analyze_uploaded_certificate(file_content: bytes, filename: str, password: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Main certificate analysis function with enhanced chain management
    Returns: analysis results with component IDs
    """
    logger.debug(f"=== SESSION-BASED PKI ANALYSIS START ===")
    logger.debug(f"File: {filename}")
    logger.debug(f"Size: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"Session ID: {session_id}")
    
    if not session_id:
        raise ValueError("Session ID is required for PKI analysis")
    
    # Detect file format
    file_format = get_file_format(filename)
    logger.debug(f"Detected format: {file_format}")
    
    component_ids = []
    analysis_result = {
        "success": True,
        "filename": filename,
        "format": file_format,
        "session_id": session_id,
        "component_ids": [],
        "components_created": 0,
        "message": ""
    }
    
    try:
        # Process based on file format with enhanced chain management
        if file_format == 'PKCS12':
            component_ids = _process_pkcs12_file(file_content, filename, password, session_id)
            analysis_result["message"] = f"PKCS12 bundle processed: {len(component_ids)} components extracted"
            
        elif file_format == 'PKCS7':
            component_ids = _process_pkcs7_file(file_content, filename, password, session_id)
            analysis_result["message"] = f"PKCS7 bundle processed: {len(component_ids)} components extracted"
            
        elif file_format in ['PEM', 'CRT', 'CER']:
            component_ids = _process_pem_file(file_content, filename, session_id)
            analysis_result["message"] = f"PEM file processed: {len(component_ids)} components extracted"
            
        elif file_format == 'DER':
            component_ids = _process_der_file(file_content, filename, session_id, password)
            analysis_result["message"] = f"DER file processed: {len(component_ids)} components extracted"
            
        elif file_format == 'CSR':
            component_ids = _process_csr_file(file_content, filename, session_id)
            analysis_result["message"] = f"CSR file processed: {len(component_ids)} components extracted"
            
        else:
            raise ValueError(f"Unsupported file format: {file_format}")
        
        analysis_result["component_ids"] = component_ids
        analysis_result["components_created"] = len(component_ids)
        
        logger.info(f"[{session_id}] Successfully processed {filename}: {len(component_ids)} components")
        
    except Exception as e:
        logger.error(f"[{session_id}] Analysis failed for {filename}: {e}")
        analysis_result["success"] = False
        analysis_result["message"] = f"Analysis failed: {str(e)}"
        raise
    
    logger.debug(f"=== SESSION-BASED PKI ANALYSIS COMPLETE ===")
    return analysis_result

def _process_pkcs12_file(file_content: bytes, filename: str, password: Optional[str], session_id: str) -> List[str]:
    """Process PKCS12 file with enhanced chain management"""
    logger.debug("Processing PKCS12 file")
    
    from cryptography.hazmat.primitives.serialization import pkcs12
    
    try:
        # Try without password first
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(file_content, password=None)
        logger.debug("PKCS12 loaded without password")
    except Exception:
        # Try with password
        if not password:
            raise ValueError("Password required for PKCS12 file")
        
        try:
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                file_content, 
                password=password.encode()
            )
            logger.debug("PKCS12 loaded with password")
        except Exception as e:
            raise ValueError(f"Failed to decrypt PKCS12 file: {e}")
    
    # Use enhanced session-based processing with chain management
    component_ids = process_pkcs12_bundle(session_id, filename, cert, private_key, additional_certs)
    
    logger.info(f"PKCS12 processing complete: {len(component_ids)} components stored")
    return component_ids

def _process_pkcs7_file(file_content: bytes, filename: str, password: Optional[str], session_id: str) -> List[str]:
    """Process PKCS7 file with enhanced chain management"""
    logger.debug("Processing PKCS7 file")
    
    # Try PEM format first
    try:
        content_str = file_content.decode('utf-8')
        if '-----BEGIN PKCS7-----' in content_str:
            return _process_pkcs7_pem(content_str, filename, session_id)
        elif '-----BEGIN CERTIFICATE-----' in content_str:
            # Multiple certificates in PEM format - treat as chain
            return _process_pem_certificate_chain(file_content, filename, session_id)
    except UnicodeDecodeError:
        pass
    
    # Try DER format
    return _process_pkcs7_der(file_content, filename, session_id)

def _process_pkcs7_pem(content_str: str, filename: str, session_id: str) -> List[str]:
    """Process PEM PKCS7 content"""
    import re
    import base64
    
    # Extract PKCS7 content
    pkcs7_match = re.search(
        r'-----BEGIN PKCS7-----\s*(.*?)\s*-----END PKCS7-----',
        content_str,
        re.DOTALL
    )
    
    if not pkcs7_match:
        raise ValueError("No PKCS7 content found in PEM file")
    
    pkcs7_b64 = pkcs7_match.group(1)
    pkcs7_der = base64.b64decode(''.join(pkcs7_b64.split()))
    
    return _process_pkcs7_der(pkcs7_der, filename, session_id)

def _process_pkcs7_der(file_content: bytes, filename: str, session_id: str) -> List[str]:
    """Process DER PKCS7 content with chain management"""
    from cryptography.hazmat.primitives.serialization import pkcs7
    
    try:
        # Load PKCS7 structure
        pkcs7_certs = pkcs7.load_der_pkcs7_certificates(file_content)
        logger.debug(f"PKCS7 loaded: {len(pkcs7_certs)} certificates")
        
        if not pkcs7_certs:
            raise ValueError("No certificates found in PKCS7 file")
        
        # Prepare components data for chain processing
        components_data = []
        
        # Extract certificate metadata for chain analysis
        all_certs = []
        for cert in pkcs7_certs:
            all_certs.append({
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'is_ca': _is_ca_certificate(cert),
                'is_self_signed': cert.subject == cert.issuer,
                'cert_obj': cert
            })
        
        # Determine PKI roles for all certificates
        cert_roles = _determine_pki_roles(all_certs)
        
        # Create components data with proper roles
        for cert in pkcs7_certs:
            cert_metadata = extract_certificate_metadata(cert)
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            cert_subject = cert.subject.rfc4514_string()
            cert_type = cert_roles.get(cert_subject, PKIComponentType.INTERMEDIATE_CA)
            
            components_data.append({
                'type': cert_type,
                'content': cert_pem,
                'metadata': cert_metadata
            })
        
        # Process as a chain to handle duplicates and conflicts
        component_ids = session_pki_storage.process_chain_upload(session_id, filename, components_data)
        
        # Log issuing CA identification
        issuing_ca = None
        for cert_info in all_certs:
            cert_subject = cert_info['subject']
            if cert_roles.get(cert_subject) == PKIComponentType.ISSUING_CA:
                issuing_ca = cert_subject
                break
        
        if issuing_ca:
            logger.debug("Identifying issuing CA in certificate chain")
            logger.info(f"Identified issuing CA: {issuing_ca}")
        
        return component_ids
        
    except Exception as e:
        raise ValueError(f"Failed to process PKCS7 file: {e}")

def _process_pem_certificate_chain(file_content: bytes, filename: str, session_id: str) -> List[str]:
    """Process multiple certificates in PEM format as a chain"""
    logger.debug("Processing PEM certificate chain")
    
    try:
        content_str = file_content.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("File is not valid PEM format")
    
    # Extract all certificates
    cert_pattern = r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
    cert_matches = re.findall(cert_pattern, content_str, re.DOTALL)
    
    if not cert_matches:
        raise ValueError("No certificates found in PEM file")
    
    # Parse certificates and prepare for chain processing
    certificates = []
    components_data = []
    
    for cert_pem in cert_matches:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        certificates.append({
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'is_ca': _is_ca_certificate(cert),
            'is_self_signed': cert.subject == cert.issuer,
            'cert_obj': cert
        })
    
    # Determine PKI roles
    cert_roles = _determine_pki_roles(certificates)
    
    # Create components data
    for i, cert_pem in enumerate(cert_matches):
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cert_metadata = extract_certificate_metadata(cert)
        cert_subject = cert.subject.rfc4514_string()
        cert_type = cert_roles.get(cert_subject, PKIComponentType.INTERMEDIATE_CA)
        
        components_data.append({
            'type': cert_type,
            'content': cert_pem,
            'metadata': cert_metadata
        })
    
    # Process as a chain
    return session_pki_storage.process_chain_upload(session_id, filename, components_data)

def _process_pem_file(file_content: bytes, filename: str, session_id: str) -> List[str]:
    """Process PEM file (could contain multiple certificates, keys, CSRs)"""
    logger.debug("Processing PEM file")
    
    try:
        content_str = file_content.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("File is not valid PEM format")
    
    component_ids = []
    
    # Check if this is a multi-certificate chain
    cert_pattern = r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
    cert_matches = re.findall(cert_pattern, content_str, re.DOTALL)
    
    if len(cert_matches) > 1:
        # Multiple certificates - process as chain
        return _process_pem_certificate_chain(file_content, filename, session_id)
    
    # Single certificate processing
    for cert_pem in cert_matches:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Determine certificate type
        is_ca = _is_ca_certificate(cert)
        is_self_signed = cert.subject == cert.issuer
        
        if is_ca:
            if is_self_signed:
                cert_type = PKIComponentType.ROOT_CA
            else:
                cert_type = PKIComponentType.INTERMEDIATE_CA
        else:
            cert_type = PKIComponentType.CERTIFICATE
        
        cert_metadata = extract_certificate_metadata(cert)
        
        component_id = session_pki_storage.add_component(
            session_id, cert_type, cert_pem, filename, cert_metadata
        )
        component_ids.append(component_id)
    
    # Look for private keys
    key_patterns = [
        r'-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----',
        r'-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----',
        r'-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----'
    ]
    
    for pattern in key_patterns:
        key_matches = re.findall(pattern, content_str, re.DOTALL)
        for key_pem in key_matches:
            private_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
            
            key_metadata = extract_private_key_metadata(private_key, is_encrypted=False)
            
            component_id = session_pki_storage.add_component(
                session_id, PKIComponentType.PRIVATE_KEY, key_pem, filename, key_metadata
            )
            component_ids.append(component_id)
    
    # Look for CSRs
    csr_pattern = r'-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----'
    csr_matches = re.findall(csr_pattern, content_str, re.DOTALL)
    
    for csr_pem in csr_matches:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        
        csr_metadata = extract_csr_metadata(csr)
        
        component_id = session_pki_storage.add_component(
            session_id, PKIComponentType.CSR, csr_pem, filename, csr_metadata
        )
        component_ids.append(component_id)
    
    if not component_ids:
        raise ValueError("No valid certificates, keys, or CSRs found in PEM file")
    
    return component_ids

def _process_der_file(file_content: bytes, filename: str, session_id: str, password: Optional[str] = None) -> List[str]:
    """Process DER file (certificate, private key, or CSR)"""
    logger.debug("Processing DER file")
    
    component_ids = []
    errors = []
    
    # Try to load as certificate first
    try:
        cert = x509.load_der_x509_certificate(file_content)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        is_ca = _is_ca_certificate(cert)
        is_self_signed = cert.subject == cert.issuer
        
        if is_ca:
            if is_self_signed:
                cert_type = PKIComponentType.ROOT_CA
            else:
                cert_type = PKIComponentType.INTERMEDIATE_CA
        else:
            cert_type = PKIComponentType.CERTIFICATE
        
        cert_metadata = extract_certificate_metadata(cert)
        
        component_id = session_pki_storage.add_component(
            session_id, cert_type, cert_pem, filename, cert_metadata
        )
        component_ids.append(component_id)
        
        return component_ids
        
    except Exception as cert_error:
        logger.debug(f"DER certificate parsing failed: {cert_error}")
        errors.append(f"Certificate: {cert_error}")
    
    # Try to load as CSR second
    try:
        csr = x509.load_der_x509_csr(file_content)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        csr_metadata = extract_csr_metadata(csr)
        
        component_id = session_pki_storage.add_component(
            session_id, PKIComponentType.CSR, csr_pem, filename, csr_metadata
        )
        component_ids.append(component_id)
        
        return component_ids
        
    except Exception as csr_error:
        logger.debug(f"DER CSR parsing failed: {csr_error}")
        errors.append(f"CSR: {csr_error}")
    
    # Try to load as private key third
    try:
        # First try without password for unencrypted keys
        try:
            private_key = serialization.load_der_private_key(file_content, password=None)
            logger.debug("Successfully loaded unencrypted DER private key")
        except Exception as unencrypted_error:
            # Check if it's an encryption-related error
            error_str = str(unencrypted_error).lower()
            if any(keyword in error_str for keyword in ['encrypted', 'password', 'decrypt', 'bad decrypt']):
                if password is None:
                    logger.debug("Encrypted DER private key detected but no password provided")
                    raise ValueError("Password was not given but private key is encrypted")
                else:
                    logger.debug(f"Attempting to decrypt DER private key with provided password")
                    # Try with provided password
                    password_bytes = password.encode('utf-8') if isinstance(password, str) else password
                    private_key = serialization.load_der_private_key(file_content, password=password_bytes)
                    logger.debug("Successfully decrypted DER private key with password")
            else:
                # Not encryption-related, re-raise the original error
                raise unencrypted_error
        
        # Convert to PEM for storage
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        key_metadata = extract_private_key_metadata(private_key, is_encrypted=(password is not None))
        
        component_id = session_pki_storage.add_component(
            session_id, PKIComponentType.PRIVATE_KEY, key_pem, filename, key_metadata
        )
        component_ids.append(component_id)
        
        return component_ids
        
    except Exception as key_error:
        logger.debug(f"DER private key parsing failed: {key_error}")
        errors.append(f"Private Key: {key_error}")

    # If all parsing attempts failed, provide detailed error
    error_details = "; ".join(errors)
    raise ValueError(f"DER file does not contain a valid certificate, CSR, or private key. Errors: {error_details}")

def _process_csr_file(file_content: bytes, filename: str, session_id: str) -> List[str]:
    """Process CSR file"""
    logger.debug("Processing CSR file")
    
    try:
        # Try PEM first
        content_str = file_content.decode('utf-8')
        csr = x509.load_pem_x509_csr(content_str.encode())
        csr_pem = content_str
    except Exception:
        try:
            # Try DER
            csr = x509.load_der_x509_csr(file_content)
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to load CSR: {e}")
    
    csr_metadata = extract_csr_metadata(csr)
    
    component_id = session_pki_storage.add_component(
        session_id, PKIComponentType.CSR, csr_pem, filename, csr_metadata
    )
    
    return [component_id]

def _determine_pki_roles(certificates: List[Dict[str, Any]]) -> Dict[str, PKIComponentType]:
    """Determine PKI roles for certificates in a chain"""
    cert_roles = {}
    
    # Find end-entity certificate (non-CA)
    end_entity = None
    for cert in certificates:
        if not cert.get('is_ca', False):
            end_entity = cert
            break
    
    if not end_entity:
        # No end-entity found, classify all as CAs based on hierarchy
        for cert in certificates:
            if cert.get('is_self_signed', False):
                cert_roles[cert['subject']] = PKIComponentType.ROOT_CA
            else:
                cert_roles[cert['subject']] = PKIComponentType.INTERMEDIATE_CA
        return cert_roles
    
    # Classify end-entity certificate
    cert_roles[end_entity['subject']] = PKIComponentType.CERTIFICATE
    logger.info(f"FOUND END-ENTITY: {end_entity['subject']}")
    logger.info(f"CLASSIFIED END-ENTITY: {end_entity['subject']}")
    
    # Find issuing CA (directly signed the end-entity)
    issuing_ca_subject = end_entity.get('issuer')
    logger.debug(f"Looking for issuing CA with subject: {issuing_ca_subject}")
    
    for cert in certificates:
        if not cert.get('is_ca', False):
            continue  # Skip non-CA certificates
        
        if cert['subject'] == issuing_ca_subject:
            # This CA signed the end-entity certificate
            cert_roles[cert['subject']] = PKIComponentType.ISSUING_CA
            logger.info(f"CLASSIFIED ISSUING CA: {cert['subject']}")
        elif cert.get('is_self_signed', False):
            # Self-signed CA is root CA
            cert_roles[cert['subject']] = PKIComponentType.ROOT_CA
            logger.info(f"CLASSIFIED ROOT CA: {cert['subject']}")
        else:
            # Other CAs are intermediate CAs
            cert_roles[cert['subject']] = PKIComponentType.INTERMEDIATE_CA
            logger.info(f"CLASSIFIED INTERMEDIATE CA: {cert['subject']}")
    
    logger.info(f"PKI Chain roles identified: {cert_roles}")
    return cert_roles

# Helper functions
def _is_ca_certificate(cert) -> bool:
    """Check if certificate is a CA certificate"""
    try:
        from cryptography.x509.oid import ExtensionOID
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        return basic_constraints.ca
    except x509.ExtensionNotFound:
        return False

def _get_cert_fingerprint(cert) -> str:
    """Get certificate SHA256 fingerprint"""
    return cert.fingerprint(hashes.SHA256()).hex().upper()

def _get_public_key_fingerprint(private_key) -> str:
    """Get public key fingerprint from private key"""
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_bytes).hexdigest().upper()

def _get_public_key_fingerprint_from_csr(csr) -> str:
    """Get public key fingerprint from CSR"""
    public_key = csr.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_bytes).hexdigest().upper()