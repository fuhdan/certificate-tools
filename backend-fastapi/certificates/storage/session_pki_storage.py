# backend-fastapi/certificates/storage/session_pki_storage.py
# Complete PKI session storage with smart deduplication and all existing features preserved

import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class PKIComponentType(Enum):
    """PKI component types with ordering for hierarchy"""
    PRIVATE_KEY = ("PrivateKey", 1)
    CSR = ("CSR", 2)
    CERTIFICATE = ("Certificate", 3)  # End entity certificate
    ISSUING_CA = ("IssuingCA", 4)     # CA that directly signed the certificate
    INTERMEDIATE_CA = ("IntermediateCA", 5)  # Intermediate CAs in chain
    ROOT_CA = ("RootCA", 6)           # Root CA (self-signed)
    
    def __init__(self, type_name: str, order: int):
        self.type_name = type_name
        self.order = order

@dataclass
class PKIComponent:
    """PKI component with enhanced metadata"""
    id: str
    type: PKIComponentType
    order: int
    content: str  # PEM content
    filename: str  # Source filename
    uploaded_at: str
    metadata: Dict[str, Any]
    chain_id: Optional[str] = None  # Links components from same upload
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response"""
        return {
            "id": self.id,
            "type": self.type.type_name,
            "order": self.order,
            "content": self.content,
            "filename": self.filename, 
            "uploaded_at": self.uploaded_at,
            "metadata": self.metadata,
            "chain_id": self.chain_id
        }

@dataclass 
class PKISession:
    """Complete PKI session containing all components with enhanced chain management"""
    session_id: str
    created_at: str
    last_updated: str
    components: Dict[str, PKIComponent] = field(default_factory=dict)  # component_id -> PKIComponent
    chains: Dict[str, Set[str]] = field(default_factory=dict)  # chain_id -> set of component_ids
    
    def add_component(self, component: PKIComponent) -> str:
        """Add component to session"""
        self.components[component.id] = component
        self.last_updated = datetime.utcnow().isoformat()
        
        # Track chain membership
        if component.chain_id:
            if component.chain_id not in self.chains:
                self.chains[component.chain_id] = set()
            self.chains[component.chain_id].add(component.id)
        
        return component.id
    
    def remove_component(self, component_id: str) -> bool:
        """Remove component from session"""
        if component_id in self.components:
            component = self.components[component_id]
            
            # Remove from chain tracking
            if component.chain_id and component.chain_id in self.chains:
                self.chains[component.chain_id].discard(component_id)
                if not self.chains[component.chain_id]:
                    del self.chains[component.chain_id]
            
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
            old_component = self.components[old_component_id]
            
            # Remove from old chain
            if old_component.chain_id and old_component.chain_id in self.chains:
                self.chains[old_component.chain_id].discard(old_component_id)
                if not self.chains[old_component.chain_id]:
                    del self.chains[old_component.chain_id]
            
            # Keep the same ID but update content
            new_component.id = old_component_id
            self.components[old_component_id] = new_component
            self.last_updated = datetime.utcnow().isoformat()
            
            # Add to new chain
            if new_component.chain_id:
                if new_component.chain_id not in self.chains:
                    self.chains[new_component.chain_id] = set()
                self.chains[new_component.chain_id].add(old_component_id)
            
            return True
        return False

    def remove_chain(self, chain_id: str) -> int:
        """Remove entire chain from session"""
        if chain_id not in self.chains:
            return 0
        
        component_ids = list(self.chains[chain_id])
        removed_count = 0
        
        for component_id in component_ids:
            if self.remove_component(component_id):
                removed_count += 1
        
        return removed_count

    def clear_all(self):
        """Clear all components and chains"""
        self.components.clear()
        self.chains.clear()
        self.last_updated = datetime.utcnow().isoformat()

    def is_expired(self, max_age_hours: int = 24) -> bool:
        """Check if session has expired"""
        try:
            last_update = datetime.fromisoformat(self.last_updated)
            age_hours = (datetime.utcnow() - last_update).total_seconds() / 3600
            return age_hours > max_age_hours
        except (ValueError, TypeError):
            # If we can't parse the timestamp, consider it expired for safety
            return True

class SessionPKIStorage:
    """Enhanced session-based PKI storage manager with smart deduplication and all existing features"""
    
    def __init__(self):
        self._sessions: Dict[str, PKISession] = {}
    
    def get_or_create_session(self, session_id: str) -> PKISession:
        """Get existing session or create new one"""
        if session_id not in self._sessions:
            self._sessions[session_id] = PKISession(
                session_id=session_id,
                created_at=datetime.utcnow().isoformat(),
                last_updated=datetime.utcnow().isoformat()
            )
            logger.info(f"Created new PKI session: {session_id}")
        return self._sessions[session_id]
    
    def add_component(self, session_id: str, component_type: PKIComponentType, 
                     content: str, filename: str, metadata: Dict[str, Any],
                     chain_id: Optional[str] = None) -> str:
        """Add PKI component with enhanced deduplication and chain management"""
        session = self.get_or_create_session(session_id)
        
        # Enhanced duplicate detection for all component types
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
                metadata=metadata,
                chain_id=chain_id
            )
            
            session.replace_component(existing_component_id, new_component)
            logger.info(f"Replaced {component_type.type_name} in session {session_id}: {filename}")
            return existing_component_id
        
        # Check for chain conflicts
        conflicting_chain_id = self._find_chain_conflict(session, component_type, metadata)
        if conflicting_chain_id:
            logger.info(f"Removing conflicting chain {conflicting_chain_id} for new {component_type.type_name}")
            removed_count = session.remove_chain(conflicting_chain_id)
            logger.info(f"Removed {removed_count} components from conflicting chain")
        
        # Add new component (original logic preserved)
        component_id = str(uuid.uuid4())
        component = PKIComponent(
            id=component_id,
            type=component_type,
            order=component_type.order,
            content=content,
            filename=filename,
            uploaded_at=datetime.utcnow().isoformat(),
            metadata=metadata,
            chain_id=chain_id
        )
        
        session.add_component(component)
        logger.info(f"Added {component_type.type_name} to session {session_id}: {filename}")
        return component_id
    
    def _find_duplicate_component(self, session: PKISession, component_type: PKIComponentType, 
                             metadata: Dict[str, Any]) -> Optional[str]:
        """Find duplicate component in session based on type and fingerprint"""
        
        # FIXED: Expand duplicate detection to include all single-instance component types
        # Only allow ONE instance of these component types per session
        unique_component_types = [
            PKIComponentType.CSR,            # ✅ Only one CSR per session (any CSR replaces existing)
            PKIComponentType.PRIVATE_KEY,    # ✅ Only one Private Key per session
            PKIComponentType.CERTIFICATE,    # ✅ Only one end-entity Certificate per session
            PKIComponentType.ISSUING_CA,     # ✅ Only one Issuing CA per session (one cert = one issuer)
            PKIComponentType.ROOT_CA         # ✅ Only one Root CA per session
        ]
        
        if component_type not in unique_component_types:
            return None
        
        # Get the fingerprint from metadata using consistent field name
        if component_type in [PKIComponentType.CSR, PKIComponentType.PRIVATE_KEY]:
            new_fingerprint = metadata.get('sha256_fingerprint')
        elif component_type in [PKIComponentType.ROOT_CA, PKIComponentType.CERTIFICATE, PKIComponentType.ISSUING_CA]:
            new_fingerprint = metadata.get('fingerprint_sha256')
        else:
            return None
        
        if not new_fingerprint:
            logger.warning(f"No fingerprint found for {component_type.type_name} duplicate detection")
            return None
        
        # For all single-instance component types: replace ANY existing component of the same type
        # Each PKI session should have exactly ONE of each of these components
        logger.debug(f"Checking for existing {component_type.type_name} to replace...")
        for component in session.components.values():
            if component.type == component_type:
                if component_type in [PKIComponentType.CSR, PKIComponentType.PRIVATE_KEY]:
                    existing_fingerprint = component.metadata.get('sha256_fingerprint')
                else:
                    existing_fingerprint = component.metadata.get('fingerprint_sha256')
                logger.info(f"Found existing {component_type.type_name} (fingerprint: {existing_fingerprint[:16] if existing_fingerprint else 'NONE'}...)")
                logger.info(f"Replacing with new {component_type.type_name} (fingerprint: {new_fingerprint[:16] if new_fingerprint else 'NONE'}...)")
                return component.id
        
        return None
    
    def _find_chain_conflict(self, session: PKISession, component_type: PKIComponentType,
                           metadata: Dict[str, Any]) -> Optional[str]:
        """Find conflicting chain that should be replaced"""
        
        subject = metadata.get('subject')
        
        # Only check for CA certificate conflicts
        if component_type not in [PKIComponentType.ISSUING_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ROOT_CA]:
            return None
        
        for component in session.components.values():
            existing_subject = component.metadata.get('subject')
            
            # Same CA subject in different chain
            if (component.type in [PKIComponentType.ISSUING_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ROOT_CA] and
                subject and existing_subject == subject and
                component.chain_id):  # Must be part of a chain
                return component.chain_id
        
        return None
    
    def process_chain_upload(self, session_id: str, filename: str, components_data: List[Dict[str, Any]]) -> List[str]:
        """Process a complete certificate chain upload (PKCS12/PKCS7)"""
        chain_id = str(uuid.uuid4())
        component_ids = []
        
        logger.info(f"Processing chain upload: {filename} with {len(components_data)} components")
        
        # Check for conflicting chains and remove them first
        session = self.get_or_create_session(session_id)
        conflicting_chains = set()
        
        for comp_data in components_data:
            metadata = comp_data['metadata']
            component_type = comp_data['type']
            
            conflicting_chain_id = self._find_chain_conflict(session, component_type, metadata)
            if conflicting_chain_id:
                conflicting_chains.add(conflicting_chain_id)
        
        # Remove all conflicting chains before adding new one
        total_removed = 0
        for conflicting_chain_id in conflicting_chains:
            removed_count = session.remove_chain(conflicting_chain_id)
            total_removed += removed_count
            logger.info(f"Removed {removed_count} components from conflicting chain {conflicting_chain_id}")
        
        if total_removed > 0:
            logger.info(f"Total removed {total_removed} components from {len(conflicting_chains)} conflicting chains")
        
        # Add all components with the same chain_id
        for comp_data in components_data:
            component_id = self.add_component(
                session_id=session_id,
                component_type=comp_data['type'],
                content=comp_data['content'],
                filename=filename,
                metadata=comp_data['metadata'],
                chain_id=chain_id
            )
            component_ids.append(component_id)
        
        logger.info(f"Added {len(component_ids)} components as chain {chain_id}")
        return component_ids
    
    def get_session_components(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all components for session as API response format"""
        if session_id not in self._sessions:
            return []
        
        session = self._sessions[session_id]
        
        # Sort components by type order for consistent display
        sorted_components = sorted(session.components.values(), key=lambda c: c.order)
        
        return [component.to_dict() for component in sorted_components]
    
    def clear_session(self, session_id: str) -> bool:
        """Clear all components from session"""
        if session_id in self._sessions:
            self._sessions[session_id].clear_all()
            logger.info(f"Cleared PKI session: {session_id}")
            return True
        return False
    
    def get_chain_summary(self, session_id: str) -> Dict[str, Any]:
        """Get summary of PKI chains in session"""
        if session_id not in self._sessions:
            return {"chains": {}, "orphaned_components": [], "total_components": 0}
        
        session = self._sessions[session_id]
        
        chain_summary = {}
        orphaned_components = []
        
        # Summarize chains
        for chain_id, component_ids in session.chains.items():
            chain_components = []
            for comp_id in component_ids:
                if comp_id in session.components:
                    comp = session.components[comp_id]
                    chain_components.append({
                        "id": comp.id,
                        "type": comp.type.type_name,
                        "filename": comp.filename
                    })
            
            chain_summary[chain_id] = {
                "component_count": len(chain_components),
                "components": chain_components
            }
        
        # Find orphaned components (no chain_id)
        for component in session.components.values():
            if not component.chain_id:
                orphaned_components.append({
                    "id": component.id,
                    "type": component.type.type_name,
                    "filename": component.filename
                })
        
        return {
            "chains": chain_summary,
            "orphaned_components": orphaned_components,
            "total_components": len(session.components)
        }

    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up expired sessions - preserve existing functionality"""
        expired_sessions = []
        
        for session_id, session in self._sessions.items():
            if session.is_expired(max_age_hours):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self._sessions[session_id]
            logger.info(f"Cleaned up expired session: {session_id}")
        
        return len(expired_sessions)

    def get_session_count(self) -> int:
        """Get total number of active sessions"""
        return len(self._sessions)

    def get_component_count(self, session_id: str) -> Dict[str, int]:
        """Get component count by type for session"""
        if session_id not in self._sessions:
            return {}
        
        session = self._sessions[session_id]
        component_counts = {}
        
        for component in session.components.values():
            type_name = component.type.type_name
            component_counts[type_name] = component_counts.get(type_name, 0) + 1
        
        return component_counts

    def has_component_type(self, session_id: str, component_type: PKIComponentType) -> bool:
        """Check if session has component of specific type"""
        if session_id not in self._sessions:
            return False
        
        session = self._sessions[session_id]
        return any(comp.type == component_type for comp in session.components.values())

    def get_component_by_id(self, session_id: str, component_id: str) -> Optional[PKIComponent]:
        """Get specific component by ID"""
        if session_id not in self._sessions:
            return None
        
        session = self._sessions[session_id]
        return session.components.get(component_id)

# Global instance
session_pki_storage = SessionPKIStorage()

def process_pkcs12_bundle(session_id: str, filename: str, cert, private_key, additional_certs) -> List[str]:
    """Process PKCS12 bundle with enhanced chain management"""
    # Import extractors at runtime to avoid circular imports
    try:
        from ..extractors.certificate import extract_certificate_metadata
        from ..extractors.private_key import extract_private_key_metadata
    except ImportError:
        # Fallback import paths
        from certificates.extractors.certificate import extract_certificate_metadata
        from certificates.extractors.private_key import extract_private_key_metadata
    
    from cryptography.hazmat.primitives import serialization
    
    logger.debug(f"=== PKCS12 BUNDLE PROCESSING ===")
    logger.debug(f"Session: {session_id}")
    logger.debug(f"Filename: {filename}")
    logger.debug(f"Main cert: {'YES' if cert else 'NO'}")
    logger.debug(f"Private key: {'YES' if private_key else 'NO'}")
    logger.debug(f"Additional certs: {len(additional_certs) if additional_certs else 0}")
    
    # Prepare all components data
    components_data = []
    
    # Extract certificate metadata for chain analysis
    all_certs = []
    if cert:
        all_certs.append({
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'is_ca': _is_ca_certificate(cert),
            'is_self_signed': cert.subject == cert.issuer,
            'cert_obj': cert
        })
    
    for add_cert in additional_certs or []:
        all_certs.append({
            'subject': add_cert.subject.rfc4514_string(),
            'issuer': add_cert.issuer.rfc4514_string(),
            'is_ca': _is_ca_certificate(add_cert),
            'is_self_signed': add_cert.subject == add_cert.issuer,
            'cert_obj': add_cert
        })
    
    # Determine PKI roles
    cert_roles = _determine_pki_roles(all_certs)
    logger.info(f"PKI Chain roles identified: {cert_roles}")
    
    # Add private key if present
    if private_key:
        key_metadata = extract_private_key_metadata(private_key)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        components_data.append({
            'type': PKIComponentType.PRIVATE_KEY,
            'content': key_pem,
            'metadata': key_metadata
        })
        logger.info(f"Stored private key: will be assigned new ID")
    
    # Add main certificate
    if cert:
        cert_metadata = extract_certificate_metadata(cert)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        cert_subject = cert.subject.rfc4514_string()
        cert_type = cert_roles.get(cert_subject, PKIComponentType.CERTIFICATE)
        
        components_data.append({
            'type': cert_type,
            'content': cert_pem,
            'metadata': cert_metadata
        })
        logger.info(f"Stored main certificate: {cert_subject} as {cert_type.type_name}")
    
    # Add additional certificates
    for i, add_cert in enumerate(additional_certs or []):
        cert_metadata = extract_certificate_metadata(add_cert)
        cert_pem = add_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        cert_subject = add_cert.subject.rfc4514_string()
        cert_type = cert_roles.get(cert_subject, PKIComponentType.INTERMEDIATE_CA)
        
        components_data.append({
            'type': cert_type,
            'content': cert_pem,
            'metadata': cert_metadata
        })
        logger.info(f"Stored additional certificate [{i}]: {cert_subject} as {cert_type.type_name}")
    
    # Process as a chain to handle duplicates and conflicts
    component_ids = session_pki_storage.process_chain_upload(session_id, filename, components_data)
    
    logger.info(f"Processed PKCS12 bundle {filename}: {len(component_ids)} components stored")
    return component_ids

def _determine_pki_roles(certificates: List[Dict[str, Any]]) -> Dict[str, PKIComponentType]:
    """Determine PKI roles for certificates in a chain"""
    cert_roles = {}
    
    logger.debug(f"=== PKI CHAIN ROLE IDENTIFICATION ===")
    logger.debug(f"Analyzing {len(certificates)} certificates")
    
    for i, cert in enumerate(certificates):
        logger.debug(f"  Cert [{i}]: Subject={cert['subject']}")
        logger.debug(f"            Issuer={cert['issuer']}")
        logger.debug(f"            Is CA={cert['is_ca']}")
        logger.debug(f"            Self-signed={cert['is_self_signed']}")
    
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
                logger.info(f"CLASSIFIED ROOT CA: {cert['subject']}")
            else:
                cert_roles[cert['subject']] = PKIComponentType.INTERMEDIATE_CA
                logger.info(f"CLASSIFIED INTERMEDIATE CA: {cert['subject']}")
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

def _is_ca_certificate(cert) -> bool:
    """Check if certificate is a CA certificate"""
    try:
        from cryptography.x509.oid import ExtensionOID
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        return basic_constraints.ca
    except:
        return False

def _get_cert_fingerprint(cert) -> str:
    """Get certificate SHA256 fingerprint"""
    from cryptography.hazmat.primitives import hashes
    return cert.fingerprint(hashes.SHA256()).hex().upper()

def _get_public_key_fingerprint(private_key) -> str:
    """Get public key fingerprint from private key - FIXED: Use DER encoding"""
    from cryptography.hazmat.primitives import hashes, serialization
    import hashlib
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,  # FIXED: Use DER for consistency
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_key_der).hexdigest().upper()