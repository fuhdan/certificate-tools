# backend-fastapi/certificates/storage/unified_storage.py
# Complete rewrite - unified storage model with proper serialization

import logging
import hashlib
from typing import Dict, Any, List, Optional, Union, cast
from dataclasses import dataclass, asdict, field
from datetime import datetime
from cryptography import x509
from cryptography.x509 import oid
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

logger = logging.getLogger(__name__)

@dataclass
class CertificateInfo:
    """Pre-computed certificate information"""
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: Optional[int]
    is_ca: bool
    is_self_signed: bool
    fingerprint_sha1: str
    fingerprint_sha256: str
    extensions: Dict[str, Any]

@dataclass
class PrivateKeyInfo:
    """Pre-computed private key information"""
    algorithm: str
    key_size: Optional[int]
    is_encrypted: bool
    public_key_fingerprint: str  # Links to certificate

@dataclass
class CSRInfo:
    """Pre-computed CSR information"""
    subject: str
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: Optional[int]
    public_key_fingerprint: str
    extensions: Dict[str, Any]

@dataclass
class UnifiedCertificateData:
    """Unified certificate data structure - everything stored as PEM with pre-computed values"""
    
    # Identity
    id: str
    filename: str
    original_format: str  # PKCS12, PKCS7, PEM, DER
    uploaded_at: str
    
    # File metadata
    file_size: int
    file_hash: str  # SHA256 of original file
    content_hash: str  # SHA256 of normalized content
    
    # PEM Content (always stored as PEM regardless of input format)
    certificate_pem: Optional[str] = None
    private_key_pem: Optional[str] = None
    csr_pem: Optional[str] = None
    additional_certificates_pem: List[str] = field(default_factory=list)
    
    # Pre-computed Information (ready for display/validation)
    certificate_info: Optional[CertificateInfo] = None
    private_key_info: Optional[PrivateKeyInfo] = None
    csr_info: Optional[CSRInfo] = None
    additional_certificates_info: List[CertificateInfo] = field(default_factory=list)
    
    # Validation State
    is_valid: bool = False
    validation_errors: List[str] = field(default_factory=list)
    requires_password: bool = False
    used_password: bool = False

class UnifiedStorageManager:
    """Manages unified certificate storage with PEM format and pre-computed values"""
    
    def __init__(self):
        self._storage: Dict[str, Dict[str, UnifiedCertificateData]] = {}  # session_id -> cert_id -> data
        self._session_metadata: Dict[str, Dict[str, Any]] = {}  # session_id -> metadata
        
    def store_certificate(self, cert_data: UnifiedCertificateData, session_id: str) -> str:
        """Store unified certificate data"""
        logger.debug(f"[{session_id}] Storing unified certificate: {cert_data.filename}")
        
        if session_id not in self._storage:
            self._storage[session_id] = {}
            self._session_metadata[session_id] = {
                'created_at': datetime.utcnow().isoformat(),
                'last_updated': datetime.utcnow().isoformat(),
                'certificate_count': 0
            }
        
        self._storage[session_id][cert_data.id] = cert_data
        self._session_metadata[session_id]['certificate_count'] = len(self._storage[session_id])
        self._session_metadata[session_id]['last_updated'] = datetime.utcnow().isoformat()
        
        logger.debug(f"[{session_id}] Stored certificate {cert_data.id}. Session now has {len(self._storage[session_id])} certificates")
        return cert_data.id
    
    def get_certificate(self, cert_id: str, session_id: str) -> Optional[UnifiedCertificateData]:
        """Get certificate by ID"""
        return self._storage.get(session_id, {}).get(cert_id)
    
    def get_all_certificates(self, session_id: str) -> List[UnifiedCertificateData]:
        """Get all certificates for session"""
        return list(self._storage.get(session_id, {}).values())
    
    def remove_certificate(self, cert_id: str, session_id: str) -> bool:
        """Remove certificate"""
        if session_id in self._storage and cert_id in self._storage[session_id]:
            del self._storage[session_id][cert_id]
            self._session_metadata[session_id]['certificate_count'] = len(self._storage[session_id])
            self._session_metadata[session_id]['last_updated'] = datetime.utcnow().isoformat()
            logger.debug(f"[{session_id}] Removed certificate {cert_id}")
            return True
        return False
    
    def clear_session(self, session_id: str):
        """Clear all certificates for session"""
        if session_id in self._storage:
            count = len(self._storage[session_id])
            del self._storage[session_id]
            del self._session_metadata[session_id]
            logger.debug(f"[{session_id}] Cleared session with {count} certificates")
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get session summary"""
        if session_id not in self._storage:
            return {'exists': False}
        
        certificates = self._storage[session_id]
        metadata = self._session_metadata[session_id]
        
        summary = {
            'exists': True,
            'certificate_count': len(certificates),
            'created_at': metadata['created_at'],
            'last_updated': metadata['last_updated'],
            'certificates': []
        }
        
        for cert_data in certificates.values():
            cert_summary = {
                'id': cert_data.id,
                'filename': cert_data.filename,
                'original_format': cert_data.original_format,
                'is_valid': cert_data.is_valid,
                'has_certificate': cert_data.certificate_pem is not None,
                'has_private_key': cert_data.private_key_pem is not None,
                'has_csr': cert_data.csr_pem is not None,
                'additional_certs_count': len(cert_data.additional_certificates_pem),
                'uploaded_at': cert_data.uploaded_at
            }
            
            if cert_data.certificate_info:
                cert_summary['subject'] = cert_data.certificate_info.subject
                cert_summary['issuer'] = cert_data.certificate_info.issuer
                cert_summary['not_valid_after'] = cert_data.certificate_info.not_valid_after
                cert_summary['is_ca'] = cert_data.certificate_info.is_ca
            
            summary['certificates'].append(cert_summary)
        
        return summary

# Utility functions for creating pre-computed information

def create_certificate_info(cert: x509.Certificate) -> CertificateInfo:
    """Create pre-computed certificate information from cryptography certificate object"""
    
    # Basic info
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    is_self_signed = subject == issuer
    
    # Public key info
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
        public_key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_algorithm = "EC"
        public_key_size = public_key.curve.key_size
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key_algorithm = "EdDSA"
        public_key_size = None
    else:
        public_key_algorithm = "Unknown"
        public_key_size = None
    
    # Fingerprints
    fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
    
    # Extensions - FIXED IP ADDRESS SERIALIZATION
    extensions = {}
    is_ca = False
    
    try:
        # Basic Constraints
        basic_constraints = cert.extensions.get_extension_for_oid(oid.ExtensionOID.BASIC_CONSTRAINTS)
        basic_constraints_value = cast(x509.BasicConstraints, basic_constraints.value)
        is_ca = basic_constraints_value.ca
        extensions['basic_constraints'] = {
            'ca': basic_constraints_value.ca,
            'path_length': basic_constraints_value.path_length
        }
    except x509.ExtensionNotFound:
        pass
    
    try:
        # Key Usage
        key_usage = cert.extensions.get_extension_for_oid(oid.ExtensionOID.KEY_USAGE)
        key_usage_value = cast(x509.KeyUsage, key_usage.value)
        extensions['key_usage'] = {
            'digital_signature': key_usage_value.digital_signature,
            'key_encipherment': key_usage_value.key_encipherment,
            'key_agreement': key_usage_value.key_agreement,
            'key_cert_sign': key_usage_value.key_cert_sign,
            'crl_sign': key_usage_value.crl_sign,
            'content_commitment': key_usage_value.content_commitment,
            'data_encipherment': key_usage_value.data_encipherment,
            'encipher_only': key_usage_value.encipher_only if key_usage_value.key_agreement else False,
            'decipher_only': key_usage_value.decipher_only if key_usage_value.key_agreement else False,
        }
    except x509.ExtensionNotFound:
        pass
    
    try:
        # Extended Key Usage
        ext_key_usage = cert.extensions.get_extension_for_oid(oid.ExtensionOID.EXTENDED_KEY_USAGE)
        ext_key_usage_value = cast(x509.ExtendedKeyUsage, ext_key_usage.value)
        extensions['extended_key_usage'] = [usage._name for usage in ext_key_usage_value]
    except x509.ExtensionNotFound:
        pass
    
    try:
        # Subject Alternative Name - CRITICAL FIX FOR IP ADDRESS SERIALIZATION
        san = cert.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_value = cast(x509.SubjectAlternativeName, san.value)
        san_list = []
        
        for name in san_value:
            if isinstance(name, x509.DNSName):
                san_list.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                # CRITICAL FIX: Convert IPv4Address/IPv6Address to string
                san_list.append(f"IP:{str(name.value)}")
            elif isinstance(name, x509.RFC822Name):
                san_list.append(f"Email:{name.value}")
            elif isinstance(name, x509.UniformResourceIdentifier):
                san_list.append(f"URI:{name.value}")
            elif isinstance(name, x509.DirectoryName):
                san_list.append(f"DirName:{name.value.rfc4514_string()}")
            elif isinstance(name, x509.RegisteredID):
                san_list.append(f"RegisteredID:{name.value.dotted_string}")
            elif isinstance(name, x509.OtherName):
                san_list.append(f"OtherName:{str(name.value)}")
            else:
                san_list.append(f"Other:{str(name)}")
                
        extensions['subject_alt_name'] = san_list
    except x509.ExtensionNotFound:
        pass
    
    try:
        # Authority Key Identifier
        aki = cert.extensions.get_extension_for_oid(oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        aki_value = cast(x509.AuthorityKeyIdentifier, aki.value)
        extensions['authority_key_identifier'] = {
            'key_identifier': aki_value.key_identifier.hex().upper() if aki_value.key_identifier else None,
            'authority_cert_issuer': str(aki_value.authority_cert_issuer) if aki_value.authority_cert_issuer else None,
            'authority_cert_serial_number': str(aki_value.authority_cert_serial_number) if aki_value.authority_cert_serial_number else None
        }
    except x509.ExtensionNotFound:
        pass
    
    try:
        # Subject Key Identifier
        ski = cert.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        ski_value = cast(x509.SubjectKeyIdentifier, ski.value)
        extensions['subject_key_identifier'] = ski_value.key_identifier.hex().upper()
    except x509.ExtensionNotFound:
        pass
    
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        serial_number=str(cert.serial_number),
        not_valid_before=cert.not_valid_before.isoformat(),
        not_valid_after=cert.not_valid_after.isoformat(),
        signature_algorithm=cert.signature_algorithm_oid._name,
        public_key_algorithm=public_key_algorithm,
        public_key_size=public_key_size,
        is_ca=is_ca,
        is_self_signed=is_self_signed,
        fingerprint_sha1=fingerprint_sha1,
        fingerprint_sha256=fingerprint_sha256,
        extensions=extensions
    )

def create_private_key_info(private_key, is_encrypted: bool = False) -> PrivateKeyInfo:
    """Create pre-computed private key information"""
    
    if isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = "RSA"
        key_size = private_key.key_size
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = "EC"
        key_size = private_key.curve.key_size
    elif isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        algorithm = "EdDSA"
        key_size = None
    else:
        algorithm = "Unknown"
        key_size = None
    
    # Create public key fingerprint for matching
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_fingerprint = hashlib.sha256(public_key_der).hexdigest().upper()
    
    return PrivateKeyInfo(
        algorithm=algorithm,
        key_size=key_size,
        is_encrypted=is_encrypted,
        public_key_fingerprint=public_key_fingerprint
    )

def create_csr_info(csr: x509.CertificateSigningRequest) -> CSRInfo:
    """Create pre-computed CSR information"""
    
    # Public key info
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
        public_key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_algorithm = "EC"
        public_key_size = public_key.curve.key_size
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key_algorithm = "EdDSA"
        public_key_size = None
    else:
        public_key_algorithm = "Unknown"
        public_key_size = None
    
    # Public key fingerprint
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_fingerprint = hashlib.sha256(public_key_der).hexdigest().upper()
    
    # Extensions - FIXED IP ADDRESS SERIALIZATION
    extensions = {}
    
    try:
        # Subject Alternative Name
        san = csr.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_value = cast(x509.SubjectAlternativeName, san.value)
        san_list = []
        
        for name in san_value:
            if isinstance(name, x509.DNSName):
                san_list.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                # CRITICAL FIX: Convert IPv4Address/IPv6Address to string
                san_list.append(f"IP:{str(name.value)}")
            elif isinstance(name, x509.RFC822Name):
                san_list.append(f"Email:{name.value}")
            elif isinstance(name, x509.UniformResourceIdentifier):
                san_list.append(f"URI:{name.value}")
            elif isinstance(name, x509.DirectoryName):
                san_list.append(f"DirName:{name.value.rfc4514_string()}")
            elif isinstance(name, x509.RegisteredID):
                san_list.append(f"RegisteredID:{name.value.dotted_string}")
            elif isinstance(name, x509.OtherName):
                san_list.append(f"OtherName:{str(name.value)}")
            else:
                san_list.append(f"Other:{str(name)}")
                
        extensions['subject_alt_name'] = san_list
    except x509.ExtensionNotFound:
        pass
    
    try:
        # Basic Constraints (if present in CSR)
        basic_constraints = csr.extensions.get_extension_for_oid(oid.ExtensionOID.BASIC_CONSTRAINTS)
        basic_constraints_value = cast(x509.BasicConstraints, basic_constraints.value)
        extensions['basic_constraints'] = {
            'ca': basic_constraints_value.ca,
            'path_length': basic_constraints_value.path_length
        }
    except x509.ExtensionNotFound:
        pass
    
    try:
        # Key Usage (if present in CSR)
        key_usage = csr.extensions.get_extension_for_oid(oid.ExtensionOID.KEY_USAGE)
        key_usage_value = cast(x509.KeyUsage, key_usage.value)
        extensions['key_usage'] = {
            'digital_signature': key_usage_value.digital_signature,
            'key_encipherment': key_usage_value.key_encipherment,
            'key_agreement': key_usage_value.key_agreement,
            'key_cert_sign': key_usage_value.key_cert_sign,
            'crl_sign': key_usage_value.crl_sign,
            'content_commitment': key_usage_value.content_commitment,
            'data_encipherment': key_usage_value.data_encipherment,
            'encipher_only': key_usage_value.encipher_only if key_usage_value.key_agreement else False,
            'decipher_only': key_usage_value.decipher_only if key_usage_value.key_agreement else False,
        }
    except x509.ExtensionNotFound:
        pass
    
    try:
        # Extended Key Usage (if present in CSR)
        ext_key_usage = csr.extensions.get_extension_for_oid(oid.ExtensionOID.EXTENDED_KEY_USAGE)
        ext_key_usage_value = cast(x509.ExtendedKeyUsage, ext_key_usage.value)
        extensions['extended_key_usage'] = [usage._name for usage in ext_key_usage_value]
    except x509.ExtensionNotFound:
        pass
    
    return CSRInfo(
        subject=csr.subject.rfc4514_string(),
        signature_algorithm=csr.signature_algorithm_oid._name,
        public_key_algorithm=public_key_algorithm,
        public_key_size=public_key_size,
        public_key_fingerprint=public_key_fingerprint,
        extensions=extensions
    )

# Global instance
unified_storage = UnifiedStorageManager()