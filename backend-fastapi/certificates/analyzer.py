# backend-fastapi/certificates/analyzer.py
# Updated analyzer to use unified PEM storage model

import hashlib
import logging
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .storage.unified_storage import (
    UnifiedCertificateData, 
    unified_storage,
    create_certificate_info,
    create_private_key_info,
    create_csr_info
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

def analyze_uploaded_certificate(file_content: bytes, filename: str, password: Optional[str] = None, session_id: Optional[str] = None) -> str:
    """
    Main certificate analysis function - creates UnifiedCertificateData and stores it
    Returns: certificate ID for retrieval
    """
    logger.debug(f"=== UNIFIED CERTIFICATE ANALYSIS START ===")
    logger.debug(f"File: {filename}")
    logger.debug(f"Size: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    
    # Generate unique certificate ID
    cert_id = str(uuid.uuid4())
    
    # Create base unified certificate data
    unified_cert = UnifiedCertificateData(
        id=cert_id,
        filename=filename,
        original_format=get_file_format(filename),
        uploaded_at=datetime.utcnow().isoformat(),
        file_size=len(file_content),
        file_hash=hashlib.sha256(file_content).hexdigest(),
        content_hash="",  # Will be set after content analysis
        requires_password=False,
        used_password=bool(password)
    )
    
    try:
        # Determine format and parse accordingly
        original_format = unified_cert.original_format
        
        if original_format in ['PKCS12']:
            _parse_pkcs12_content(file_content, password, unified_cert)
        elif original_format in ['PKCS7', 'P7B', 'P7C']:
            _parse_pkcs7_content(file_content, password, unified_cert)
        elif original_format in ['DER', 'PKCS8']:
            _parse_der_content(file_content, password, unified_cert)
        else:
            # Try PEM format (most common)
            _parse_pem_content(file_content, password, unified_cert)
        
        # Generate content hash from PEM content
        unified_cert.content_hash = _generate_content_hash(unified_cert)
        
        # Mark as valid if we have any content
        unified_cert.is_valid = any([
            unified_cert.certificate_pem,
            unified_cert.private_key_pem,
            unified_cert.csr_pem,
            unified_cert.additional_certificates_pem
        ])
        
        logger.debug(f"Analysis complete: valid={unified_cert.is_valid}")
        
    except Exception as e:
        logger.error(f"Certificate analysis failed: {e}")
        unified_cert.is_valid = False
        unified_cert.validation_errors.append(str(e))
    
    # Store in unified storage
    if session_id:
        unified_storage.store_certificate(unified_cert, session_id)
        logger.debug(f"Stored certificate {cert_id} in session {session_id}")
    else:
        logger.warning(f"No session_id provided, certificate {cert_id} not stored")
    
    return cert_id

def _parse_pem_content(file_content: bytes, password: Optional[str], unified_cert: UnifiedCertificateData):
    """Parse PEM format content and populate unified certificate data"""
    logger.debug("Parsing PEM content")
    
    try:
        content_str = file_content.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("File is not valid PEM format (not UTF-8)")
    
    if '-----BEGIN' not in content_str:
        raise ValueError("No PEM markers found in file")
    
    # Extract all PEM objects
    import re
    pem_objects = re.findall(r'-----BEGIN ([A-Z\s]+)-----.*?-----END \1-----', content_str, re.DOTALL)
    
    for match in re.finditer(r'-----BEGIN ([A-Z\s]+)-----.*?-----END \1-----', content_str, re.DOTALL):
        pem_object = match.group(0)
        object_type = match.group(1)
        
        try:
            if 'CERTIFICATE' in object_type and 'REQUEST' not in object_type:
                # X.509 Certificate
                cert = x509.load_pem_x509_certificate(pem_object.encode())
                
                if unified_cert.certificate_pem is None:
                    # Main certificate
                    unified_cert.certificate_pem = pem_object
                    unified_cert.certificate_info = create_certificate_info(cert)
                    logger.debug("Stored main certificate")
                else:
                    # Additional certificate
                    unified_cert.additional_certificates_pem.append(pem_object)
                    unified_cert.additional_certificates_info.append(create_certificate_info(cert))
                    logger.debug("Stored additional certificate")
                    
            elif 'PRIVATE KEY' in object_type:
                # Private Key
                try:
                    if 'ENCRYPTED' in object_type:
                        if not password:
                            unified_cert.requires_password = True
                            raise ValueError("Password required for encrypted private key")
                        private_key = serialization.load_pem_private_key(
                            pem_object.encode(), 
                            password=password.encode() if password else None
                        )
                        is_encrypted = True
                    else:
                        private_key = serialization.load_pem_private_key(
                            pem_object.encode(), 
                            password=None
                        )
                        is_encrypted = False
                    
                    unified_cert.private_key_pem = pem_object
                    unified_cert.private_key_info = create_private_key_info(private_key, is_encrypted)
                    logger.debug("Stored private key")
                    
                except Exception as e:
                    if "password" in str(e).lower():
                        unified_cert.requires_password = True
                    raise e
                    
            elif 'CERTIFICATE REQUEST' in object_type:
                # CSR
                csr = x509.load_pem_x509_csr(pem_object.encode())
                unified_cert.csr_pem = pem_object
                unified_cert.csr_info = create_csr_info(csr)
                logger.debug("Stored CSR")
                
        except Exception as e:
            logger.warning(f"Failed to parse PEM object {object_type}: {e}")
            unified_cert.validation_errors.append(f"Failed to parse {object_type}: {str(e)}")

def _parse_pkcs12_content(file_content: bytes, password: Optional[str], unified_cert: UnifiedCertificateData):
    """Parse PKCS12 content and populate unified certificate data"""
    logger.debug("Parsing PKCS12 content")
    
    from cryptography.hazmat.primitives.serialization import pkcs12
    
    try:
        # Try without password first
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(file_content, password=None)
        logger.debug("PKCS12 loaded without password")
    except Exception:
        # Try with password
        if not password:
            unified_cert.requires_password = True
            raise ValueError("Password required for PKCS12 file")
        
        try:
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                file_content, 
                password=password.encode()
            )
            logger.debug("PKCS12 loaded with password")
        except Exception as e:
            raise ValueError(f"Failed to decrypt PKCS12 file: {e}")
    
    # Convert crypto objects to PEM and store
    if cert:
        unified_cert.certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        unified_cert.certificate_info = create_certificate_info(cert)
        logger.debug("Stored PKCS12 certificate")
    
    if private_key:
        unified_cert.private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        unified_cert.private_key_info = create_private_key_info(private_key, is_encrypted=bool(password))
        logger.debug("Stored PKCS12 private key")
    
    if additional_certs:
        for additional_cert in additional_certs:
            pem_cert = additional_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            unified_cert.additional_certificates_pem.append(pem_cert)
            unified_cert.additional_certificates_info.append(create_certificate_info(additional_cert))
        logger.debug(f"Stored {len(additional_certs)} additional PKCS12 certificates")

def _parse_pkcs7_content(file_content: bytes, password: Optional[str], unified_cert: UnifiedCertificateData):
    """Parse PKCS7 content and populate unified certificate data"""
    logger.debug("Parsing PKCS7 content")
    
    # Try PEM format first
    try:
        content_str = file_content.decode('utf-8')
        if '-----BEGIN PKCS7-----' in content_str:
            _parse_pkcs7_pem(content_str, unified_cert)
            return
        elif '-----BEGIN CERTIFICATE-----' in content_str:
            # Multiple certificates in PEM format
            _parse_pem_content(file_content, password, unified_cert)
            return
    except UnicodeDecodeError:
        pass
    
    # Try DER format
    _parse_pkcs7_der(file_content, unified_cert)

def _parse_pkcs7_pem(content_str: str, unified_cert: UnifiedCertificateData):
    """Parse PEM PKCS7 content"""
    import re
    import base64
    
    pkcs7_match = re.search(
        r'-----BEGIN PKCS7-----\s*(.*?)\s*-----END PKCS7-----',
        content_str,
        re.DOTALL
    )
    
    if pkcs7_match:
        pkcs7_b64 = pkcs7_match.group(1).replace('\n', '').replace('\r', '').replace(' ', '')
        pkcs7_der = base64.b64decode(pkcs7_b64)
        _parse_pkcs7_der(pkcs7_der, unified_cert)

def _parse_pkcs7_der(der_content: bytes, unified_cert: UnifiedCertificateData):
    """Parse DER PKCS7 content"""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        
        # Try to load PKCS7 data
        pkcs7_data = pkcs7.load_der_pkcs7_certificates(der_content)
        
        # Convert certificates to PEM
        for i, cert in enumerate(pkcs7_data):
            pem_cert = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            if i == 0:
                # First certificate is main certificate
                unified_cert.certificate_pem = pem_cert
                unified_cert.certificate_info = create_certificate_info(cert)
            else:
                # Additional certificates
                unified_cert.additional_certificates_pem.append(pem_cert)
                unified_cert.additional_certificates_info.append(create_certificate_info(cert))
        
        logger.debug(f"Stored {len(pkcs7_data)} certificates from PKCS7")
        
    except Exception as e:
        logger.error(f"Failed to parse PKCS7 DER: {e}")
        raise ValueError(f"Invalid PKCS7 format: {e}")

def _parse_der_content(file_content: bytes, password: Optional[str], unified_cert: UnifiedCertificateData):
    """Parse DER format content"""
    logger.debug("Parsing DER content")
    
    # Try different DER types
    parsers = [
        ("Certificate", lambda: x509.load_der_x509_certificate(file_content)),
        ("CSR", lambda: x509.load_der_x509_csr(file_content)),
        ("Private Key", lambda: serialization.load_der_private_key(file_content, password=password.encode() if password else None))
    ]
    
    for content_type, parser in parsers:
        try:
            obj = parser()
            
            if content_type == "Certificate":
                unified_cert.certificate_pem = obj.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                unified_cert.certificate_info = create_certificate_info(obj)
                logger.debug("Stored DER certificate")
                return
                
            elif content_type == "CSR":
                unified_cert.csr_pem = obj.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                unified_cert.csr_info = create_csr_info(obj)
                logger.debug("Stored DER CSR")
                return
                
            elif content_type == "Private Key":
                unified_cert.private_key_pem = obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                unified_cert.private_key_info = create_private_key_info(obj, is_encrypted=bool(password))
                logger.debug("Stored DER private key")
                return
                
        except Exception as e:
            logger.debug(f"Not a {content_type}: {e}")
            if "password" in str(e).lower():
                unified_cert.requires_password = True
    
    raise ValueError("Unable to parse DER content as any known type")

def _generate_content_hash(unified_cert: UnifiedCertificateData) -> str:
    """Generate content hash from PEM content for deduplication"""
    content_parts = []
    
    if unified_cert.certificate_pem:
        content_parts.append(unified_cert.certificate_pem)
    if unified_cert.private_key_pem:
        content_parts.append(unified_cert.private_key_pem)
    if unified_cert.csr_pem:
        content_parts.append(unified_cert.csr_pem)
    if unified_cert.additional_certificates_pem:
        content_parts.extend(unified_cert.additional_certificates_pem)
    
    combined_content = ''.join(sorted(content_parts))
    return hashlib.sha256(combined_content.encode()).hexdigest()

# Backward compatibility functions for existing API

def get_certificate_by_id(cert_id: str, session_id: str) -> Optional[UnifiedCertificateData]:
    """Get certificate by ID from unified storage"""
    return unified_storage.get_certificate(cert_id, session_id)

def get_all_certificates(session_id: str) -> List[UnifiedCertificateData]:
    """Get all certificates for session from unified storage"""
    return unified_storage.get_all_certificates(session_id)

def remove_certificate(cert_id: str, session_id: str) -> bool:
    """Remove certificate from unified storage"""
    return unified_storage.remove_certificate(cert_id, session_id)

def clear_session(session_id: str):
    """Clear session from unified storage"""
    unified_storage.clear_session(session_id)