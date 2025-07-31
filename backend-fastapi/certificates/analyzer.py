# backend-fastapi/certificates/analyzer.py
# Updated analyzer to use session-based PKI storage

import hashlib
import logging
import uuid
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes

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
        'p8': 'PKCS8',
        'pk8': 'PKCS8'
    }
    detected_format = format_map.get(extension, extension.upper())
    logger.debug(f"File format detection: {filename} -> {detected_format}")
    return detected_format

def analyze_uploaded_certificate(file_content: bytes, filename: str, password: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Main certificate analysis function - processes file and stores components in session
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
        # Process based on file format
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
            component_ids = _process_der_file(file_content, filename, session_id)
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
    """Process PKCS12 file and store components"""
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
    
    # Use the new session-based processing
    component_ids = process_pkcs12_bundle(session_id, filename, cert, private_key, additional_certs)
    
    logger.info(f"PKCS12 processing complete: {len(component_ids)} components stored")
    return component_ids

def _process_pkcs7_file(file_content: bytes, filename: str, password: Optional[str], session_id: str) -> List[str]:
    """Process PKCS7 file and store components"""
    logger.debug("Processing PKCS7 file")
    
    # Try PEM format first
    try:
        content_str = file_content.decode('utf-8')
        if '-----BEGIN PKCS7-----' in content_str:
            return _process_pkcs7_pem(content_str, filename, session_id)
        elif '-----BEGIN CERTIFICATE-----' in content_str:
            # Multiple certificates in PEM format
            return _process_pem_file(file_content, filename, session_id)
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
    """Process DER PKCS7 content"""
    from cryptography.hazmat.primitives.serialization import pkcs7
    
    try:
        # Load PKCS7 structure
        pkcs7_data = pkcs7.load_der_pkcs7_certificates(file_content)
        logger.debug(f"PKCS7 loaded: {len(pkcs7_data)} certificates")
        
        component_ids = []
        
        # Process each certificate
        for i, cert in enumerate(pkcs7_data):
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            # Determine certificate type based on CA status
            is_ca = _is_ca_certificate(cert)
            is_self_signed = cert.subject == cert.issuer
            
            if is_ca:
                if is_self_signed:
                    cert_type = PKIComponentType.ROOT_CA
                else:
                    cert_type = PKIComponentType.INTERMEDIATE_CA
            else:
                cert_type = PKIComponentType.CERTIFICATE
            
            # Create metadata
            cert_metadata = {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'is_ca': is_ca,
                'is_self_signed': is_self_signed,
                'fingerprint_sha256': _get_cert_fingerprint(cert)
            }
            
            # Store component
            component_id = session_pki_storage.add_component(
                session_id, cert_type, cert_pem, filename, cert_metadata
            )
            component_ids.append(component_id)
        
        # If we have multiple CA certificates, identify the issuing CA
        if len([c for c in pkcs7_data if _is_ca_certificate(c)]) > 1:
            component_ids = _identify_issuing_ca_in_chain(session_id, component_ids)
        
        return component_ids
        
    except Exception as e:
        raise ValueError(f"Failed to process PKCS7 file: {e}")

def _process_pem_file(file_content: bytes, filename: str, session_id: str) -> List[str]:
    """Process PEM file (could contain multiple certificates, keys, CSRs)"""
    logger.debug("Processing PEM file")
    
    try:
        content_str = file_content.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("File is not valid PEM format")
    
    component_ids = []
    
    # Look for certificates
    cert_pattern = r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
    cert_matches = re.findall(cert_pattern, content_str, re.DOTALL)
    
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
        
        cert_metadata = {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'serial_number': str(cert.serial_number),
            'is_ca': is_ca,
            'is_self_signed': is_self_signed,
            'fingerprint_sha256': _get_cert_fingerprint(cert)
        }
        
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
            
            key_metadata = {
                'algorithm': type(private_key).__name__.replace('PrivateKey', ''),
                'key_size': getattr(private_key, 'key_size', None),
                'is_encrypted': False,
                'public_key_fingerprint': _get_public_key_fingerprint(private_key)
            }
            
            component_id = session_pki_storage.add_component(
                session_id, PKIComponentType.PRIVATE_KEY, key_pem, filename, key_metadata
            )
            component_ids.append(component_id)
    
    # Look for CSRs
    csr_pattern = r'-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----'
    csr_matches = re.findall(csr_pattern, content_str, re.DOTALL)
    
    for csr_pem in csr_matches:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        
        csr_metadata = {
            'subject': csr.subject.rfc4514_string(),
            'signature_algorithm': csr.signature_algorithm_oid._name,
            'public_key_algorithm': type(csr.public_key()).__name__.replace('PublicKey', ''),
            'public_key_size': getattr(csr.public_key(), 'key_size', None),
            'public_key_fingerprint': _get_public_key_fingerprint_from_csr(csr)
        }
        
        component_id = session_pki_storage.add_component(
            session_id, PKIComponentType.CSR, csr_pem, filename, csr_metadata
        )
        component_ids.append(component_id)
    
    if not component_ids:
        raise ValueError("No valid certificates, keys, or CSRs found in PEM file")
    
    return component_ids

def _process_der_file(file_content: bytes, filename: str, session_id: str) -> List[str]:
    """Process DER file (single certificate or key)"""
    logger.debug("Processing DER file")
    
    component_ids = []
    
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
        
        cert_metadata = {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'serial_number': str(cert.serial_number),
            'is_ca': is_ca,
            'is_self_signed': is_self_signed,
            'fingerprint_sha256': _get_cert_fingerprint(cert)
        }
        
        component_id = session_pki_storage.add_component(
            session_id, cert_type, cert_pem, filename, cert_metadata
        )
        component_ids.append(component_id)
        
        return component_ids
        
    except Exception:
        pass
    
    # Try to load as private key
    try:
        private_key = serialization.load_der_private_key(file_content, password=None)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        key_metadata = {
            'algorithm': type(private_key).__name__.replace('PrivateKey', ''),
            'key_size': getattr(private_key, 'key_size', None),
            'is_encrypted': False,
            'public_key_fingerprint': _get_public_key_fingerprint(private_key)
        }
        
        component_id = session_pki_storage.add_component(
            session_id, PKIComponentType.PRIVATE_KEY, key_pem, filename, key_metadata
        )
        component_ids.append(component_id)
        
        return component_ids
        
    except Exception:
        pass
    
    raise ValueError("DER file does not contain a valid certificate or private key")

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
    
    csr_metadata = {
        'subject': csr.subject.rfc4514_string(),
        'signature_algorithm': csr.signature_algorithm_oid._name,
        'public_key_algorithm': type(csr.public_key()).__name__.replace('PublicKey', ''),
        'public_key_size': getattr(csr.public_key(), 'key_size', None),
        'public_key_fingerprint': _get_public_key_fingerprint_from_csr(csr)
    }
    
    component_id = session_pki_storage.add_component(
        session_id, PKIComponentType.CSR, csr_pem, filename, csr_metadata
    )
    
    return [component_id]

def _identify_issuing_ca_in_chain(session_id: str, component_ids: List[str]) -> List[str]:
    """Identify and update the issuing CA in a certificate chain"""
    logger.debug("Identifying issuing CA in certificate chain")
    
    # Get session components
    session = session_pki_storage.get_or_create_session(session_id)
    
    # Find end-entity certificate
    end_entity_cert = None
    for comp_id in component_ids:
        component = session.components.get(comp_id)
        if component and component.type == PKIComponentType.CERTIFICATE:
            end_entity_cert = component
            break
    
    if not end_entity_cert:
        logger.debug("No end-entity certificate found, cannot identify issuing CA")
        return component_ids
    
    # Find the CA that issued the end-entity certificate
    end_entity_issuer = end_entity_cert.metadata.get('issuer')
    
    for comp_id in component_ids:
        component = session.components.get(comp_id)
        if (component and 
            component.type == PKIComponentType.INTERMEDIATE_CA and
            component.metadata.get('subject') == end_entity_issuer):
            
            # This is the issuing CA - update its type
            component.type = PKIComponentType.ISSUING_CA
            component.order = PKIComponentType.ISSUING_CA.order
            
            logger.info(f"Identified issuing CA: {component.metadata.get('subject')}")
            break
    
    return component_ids

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