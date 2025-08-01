# backend-fastapi/certificates/storage/session_pki_storage.py
# New session-based PKI component storage

import logging
import uuid
import hashlib
import re
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from ..extractors.certificate import extract_certificate_metadata
from ..extractors.private_key import extract_private_key_metadata

logger = logging.getLogger(__name__)

class PKIComponentType(Enum):
    """PKI Component Types with explicit ordering"""
    PRIVATE_KEY = ("PrivateKey", 1)
    CSR = ("CSR", 2) 
    CERTIFICATE = ("Certificate", 3)
    ISSUING_CA = ("IssuingCA", 4)
    INTERMEDIATE_CA = ("IntermediateCA", 5)
    ROOT_CA = ("RootCA", 6)
    
    def __init__(self, type_name: str, order: int):
        self.type_name = type_name
        self.order = order

@dataclass
class PKIComponent:
    """Individual PKI component (certificate, key, CSR, etc.)"""
    id: str
    type: PKIComponentType
    order: int
    content: str  # PEM content
    filename: str  # Source filename
    uploaded_at: str
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response"""
        return {
            "id": self.id,
            "type": self.type.type_name,
            "order": self.order,
            "content": self.content,
            "filename": self.filename, 
            "uploaded_at": self.uploaded_at,
            "metadata": self.metadata
        }

@dataclass 
class PKISession:
    """Complete PKI session containing all components"""
    session_id: str
    created_at: str
    last_updated: str
    components: Dict[str, PKIComponent]  # component_id -> PKIComponent
    
    def add_component(self, component: PKIComponent) -> str:
        """Add component to session"""
        self.components[component.id] = component
        self.last_updated = datetime.utcnow().isoformat()
        return component.id
    
    def remove_component(self, component_id: str) -> bool:
        """Remove component from session"""
        if component_id in self.components:
            del self.components[component_id]
            self.last_updated = datetime.utcnow().isoformat()
            return True
        return False
    
    def get_components_by_type(self, component_type: PKIComponentType) -> List[PKIComponent]:
        """Get all components of specific type"""
        return [comp for comp in self.components.values() if comp.type == component_type]
    
    def get_ordered_components(self) -> List[PKIComponent]:
        """Get all components in PKI hierarchy order"""
        return sorted(self.components.values(), key=lambda c: c.order)
    
    def replace_component(self, old_component_id: str, new_component: PKIComponent) -> bool:
        """Replace an existing component with a new one"""
        if old_component_id in self.components:
            # Keep the same ID but update content
            new_component.id = old_component_id
            self.components[old_component_id] = new_component
            self.last_updated = datetime.utcnow().isoformat()
            return True
        return False

class SessionPKIStorage:
    """Session-based PKI storage manager"""
    
    def __init__(self):
        self._sessions: Dict[str, PKISession] = {}
    
    def get_or_create_session(self, session_id: str) -> PKISession:
        """Get existing session or create new one"""
        if session_id not in self._sessions:
            self._sessions[session_id] = PKISession(
                session_id=session_id,
                created_at=datetime.utcnow().isoformat(),
                last_updated=datetime.utcnow().isoformat(),
                components={}
            )
            logger.info(f"Created new PKI session: {session_id}")
        return self._sessions[session_id]
    
    def add_component(self, session_id: str, component_type: PKIComponentType, 
                     content: str, filename: str, metadata: Dict[str, Any]) -> str:
        """Add PKI component to session with duplicate detection"""
        session = self.get_or_create_session(session_id)
        
        # Check for duplicates based on component type and fingerprint
        existing_component_id = self._find_duplicate_component(session, component_type, metadata)
        
        if existing_component_id:
            # Replace existing component
            logger.info(f"Found duplicate {component_type.type_name}, replacing existing component")
            
            new_component = PKIComponent(
                id=existing_component_id,  # Keep existing ID
                type=component_type,
                order=component_type.order,
                content=content,
                filename=filename,
                uploaded_at=datetime.utcnow().isoformat(),
                metadata=metadata
            )
            
            session.replace_component(existing_component_id, new_component)
            logger.info(f"Replaced {component_type.type_name} in session {session_id}: {filename}")
            return existing_component_id
        else:
            # Add new component (original logic)
            component_id = str(uuid.uuid4())
            component = PKIComponent(
                id=component_id,
                type=component_type,
                order=component_type.order,
                content=content,
                filename=filename,
                uploaded_at=datetime.utcnow().isoformat(),
                metadata=metadata
            )
            
            session.add_component(component)
            logger.info(f"Added {component_type.type_name} to session {session_id}: {filename}")
            return component_id
    
    def _find_duplicate_component(self, session: PKISession, component_type: PKIComponentType, 
                                 metadata: Dict[str, Any]) -> Optional[str]:
        """Find duplicate component in session based on type and fingerprint"""
        
        # Only check for duplicates on specific component types
        if component_type not in [PKIComponentType.CSR, PKIComponentType.PRIVATE_KEY]:
            return None
        
        # Get the fingerprint from metadata
        if component_type == PKIComponentType.CSR:
            new_fingerprint = metadata.get('public_key_fingerprint')
        elif component_type == PKIComponentType.PRIVATE_KEY:
            new_fingerprint = metadata.get('public_key_fingerprint')
        else:
            return None
        
        if not new_fingerprint:
            return None
        
        # Search for existing component with same type and fingerprint
        for component in session.components.values():
            if component.type == component_type:
                existing_fingerprint = component.metadata.get('public_key_fingerprint')
                if existing_fingerprint == new_fingerprint:
                    logger.debug(f"Duplicate {component_type.type_name} detected: {new_fingerprint[:16]}...")
                    return component.id
        
        return None
    
    def get_session_components(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all components for session as API response format"""
        if session_id not in self._sessions:
            return []
        
        session = self._sessions[session_id]
        components = session.get_ordered_components()
        return [comp.to_dict() for comp in components]
    
    def clear_session(self, session_id: str) -> bool:
        """Clear all components from session"""
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info(f"Cleared PKI session: {session_id}")
            return True
        return False
    
    def identify_certificate_chain_roles(self, certificates: List[Dict[str, Any]]) -> Dict[str, PKIComponentType]:
        """Analyze certificate chain to identify roles (Issuing CA vs Intermediate CA)"""
        cert_roles = {}
        
        # Find the end-entity certificate (non-CA certificate)
        end_entity = None
        for cert in certificates:
            if not cert.get('is_ca', False):
                end_entity = cert
                break
        
        if not end_entity:
            logger.warning("No end-entity certificate found in chain")
            # All are CAs, use self-signed status to determine roles
            for cert in certificates:
                if cert.get('is_self_signed', False):
                    cert_roles[cert['subject']] = PKIComponentType.ROOT_CA
                else:
                    cert_roles[cert['subject']] = PKIComponentType.INTERMEDIATE_CA
            return cert_roles
        
        # Find the issuing CA (certificate that signed the end-entity)
        issuing_ca_subject = end_entity.get('issuer')
        cert_roles[end_entity['subject']] = PKIComponentType.CERTIFICATE
        
        for cert in certificates:
            if not cert.get('is_ca', False):
                continue
                
            if cert['subject'] == issuing_ca_subject:
                # This CA signed the end-entity certificate
                cert_roles[cert['subject']] = PKIComponentType.ISSUING_CA
            elif cert.get('is_self_signed', False):
                # Self-signed CA is root CA
                cert_roles[cert['subject']] = PKIComponentType.ROOT_CA
            else:
                # Other CAs are intermediate CAs
                cert_roles[cert['subject']] = PKIComponentType.INTERMEDIATE_CA
        
        logger.info(f"Certificate chain roles identified: {cert_roles}")
        return cert_roles

# Global instance
session_pki_storage = SessionPKIStorage()

def process_pkcs12_bundle(session_id: str, filename: str, cert, private_key, additional_certs) -> List[str]:
    """Process PKCS12 bundle and store components separately"""
    component_ids = []
    
    # Extract certificate metadata for chain analysis
    all_certs = []
    if cert:
        all_certs.append({
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(), 
            'is_ca': _is_ca_certificate(cert),
            'is_self_signed': cert.subject == cert.issuer
        })
    
    for add_cert in (additional_certs or []):
        all_certs.append({
            'subject': add_cert.subject.rfc4514_string(),
            'issuer': add_cert.issuer.rfc4514_string(),
            'is_ca': _is_ca_certificate(add_cert), 
            'is_self_signed': add_cert.subject == add_cert.issuer
        })
    
    # Analyze certificate chain roles
    cert_roles = session_pki_storage.identify_certificate_chain_roles(all_certs)
    
    # Store private key if present
    if private_key:
        from cryptography.hazmat.primitives import serialization
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        key_metadata = extract_private_key_metadata(private_key, is_encrypted=False)
        
        component_id = session_pki_storage.add_component(
            session_id, PKIComponentType.PRIVATE_KEY, key_pem, filename, key_metadata
        )
        component_ids.append(component_id)
    
    # Store main certificate if present  
    if cert:
        from cryptography.hazmat.primitives import serialization
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        cert_subject = cert.subject.rfc4514_string()
        cert_type = cert_roles.get(cert_subject, PKIComponentType.CERTIFICATE)
        
        cert_metadata = extract_certificate_metadata(cert)
        
        component_id = session_pki_storage.add_component(
            session_id, cert_type, cert_pem, filename, cert_metadata
        )
        component_ids.append(component_id)
    
    # Store additional certificates
    for add_cert in (additional_certs or []):
        from cryptography.hazmat.primitives import serialization
        cert_pem = add_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        cert_subject = add_cert.subject.rfc4514_string()
        cert_type = cert_roles.get(cert_subject, PKIComponentType.INTERMEDIATE_CA)
        
        cert_metadata = extract_certificate_metadata(cert)
        
        component_id = session_pki_storage.add_component(
            session_id, cert_type, cert_pem, filename, cert_metadata
        )
        component_ids.append(component_id)
    
    logger.info(f"Processed PKCS12 bundle {filename}: {len(component_ids)} components stored")
    return component_ids

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
    from cryptography.hazmat.primitives import hashes
    return cert.fingerprint(hashes.SHA256()).hex().upper()

def _get_public_key_fingerprint(private_key) -> str:
    """Get public key fingerprint from private key"""
    from cryptography.hazmat.primitives import hashes, serialization
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_bytes).hexdigest().upper()