# backend-fastapi/services/download_service.py
# Unified download service - consolidates Apache, IIS, and advanced downloads

import logging
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from pydantic import BaseModel, Field

from certificates.storage.session_pki_storage import session_pki_storage, PKIComponentType
from services.secure_zip_creator import secure_zip_creator, SecureZipCreatorError
from services.instruction_generator import InstructionGenerator
from services.file_naming_service import get_standard_filename
from services.format_converter import format_converter

logger = logging.getLogger(__name__)

class BundleType(str, Enum):
    """Supported bundle types"""
    APACHE = "apache"
    IIS = "iis"
    NGINX = "nginx"
    CUSTOM = "custom"

class BundleConfig(BaseModel):
    """Configuration for bundle generation"""
    bundle_type: BundleType
    format_selections: Dict[str, str] = Field(default_factory=dict)
    component_selection: List[str] = Field(default_factory=list)  # empty = all components
    
class DownloadService:
    """Unified service for all download operations"""
    
    def __init__(self):
        self.instruction_generator = InstructionGenerator()
    
    async def create_bundle(
        self, 
        session_id: str, 
        config: BundleConfig,
        include_instructions: bool = True
    ) -> Tuple[bytes, str, Optional[str]]:
        """
        Create download bundle based on configuration
        
        Args:
            session_id: Session identifier
            config: Bundle configuration
            include_instructions: Whether to include installation instructions
            
        Returns:
            Tuple of (zip_data, zip_password, bundle_password)
        """
        logger.info(f"Creating {config.bundle_type} bundle for session: {session_id}")
        
        # Get session from PKI storage
        session = session_pki_storage.get_or_create_session(session_id)
        
        if not session.components:
            raise ValueError("No PKI components found in session")
        
        # Find primary certificate
        primary_cert = self._find_primary_certificate(session)
        if not primary_cert:
            raise ValueError("No end-entity certificate found")
        
        # Extract certificate data based on bundle type
        certificate_data = self._extract_certificate_data(
            primary_cert, session, session_id, config.bundle_type
        )
        
        # Prepare download package
        files = {}
        bundle_password = None

        logger.debug(f"Preparing bundle of type: {config.bundle_type}")
        
        if config.bundle_type in [BundleType.APACHE, BundleType.NGINX]:
            logger.debug("Taking Apache/Nginx path")
            files, selected_components = self._prepare_apache_nginx_bundle(
                certificate_data, session, config, include_instructions
            )
        elif config.bundle_type == BundleType.IIS:
            logger.debug("Taking IIS path")
            files, selected_components, bundle_password = self._prepare_p12_bundle(
                certificate_data, session, config, include_instructions
            )
        elif config.bundle_type == BundleType.CUSTOM:
            files, selected_components = self._prepare_custom_bundle(
                session, config, include_instructions
            )
        else:
            raise ValueError(f"Unsupported bundle type: {config.bundle_type}")
        
        # Create ZIP bundle
        zip_data, zip_password = self._create_zip_bundle(
            files, session_id, config.bundle_type, selected_components, bundle_password
        )
        
        logger.info(f"Bundle created successfully for session: {session_id}")
        return zip_data, zip_password, bundle_password
    
    def _find_primary_certificate(self, session):
        """Find primary end-entity certificate"""
        for component in session.components.values():
            if component.type == PKIComponentType.CERTIFICATE:
                return component
        return None
    
    def _extract_certificate_data(self, primary_cert, session, session_id, bundle_type):
        """Extract certificate data based on bundle type requirements"""
        logger.debug(f"Extracting certificate data for {bundle_type} bundle")
        
        certificate_pem = primary_cert.content
        if not certificate_pem:
            raise ValueError("Certificate PEM not found")
        
        # Find private key component
        private_key_pem = None
        for component in session.components.values():
            if component.type == PKIComponentType.PRIVATE_KEY:
                private_key_pem = component.content
                break
        
        # Private key is required for IIS, optional for others
        if bundle_type == BundleType.IIS and not private_key_pem:
            raise ValueError("No private key found. IIS requires a private key for PKCS#12 bundle.")
        
        # Build CA bundle from CA components
        ca_bundle_parts = []
        for component in session.components.values():
            if component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
                if component.id != primary_cert.id:
                    ca_bundle_parts.append(component.content)
        
        ca_bundle = '\n'.join(ca_bundle_parts) if ca_bundle_parts else None
        
        # Extract metadata from certificate component
        cert_metadata = primary_cert.metadata or {}
        domain_name = self._extract_domain_name_from_metadata(cert_metadata)
        
        return {
            'certificate': certificate_pem,
            'private_key': private_key_pem,
            'ca_bundle': ca_bundle,
            'domain_name': domain_name,
            'subject': cert_metadata.get('subject', ''),
            'issuer': cert_metadata.get('issuer', ''),
            'expiry_date': cert_metadata.get('not_valid_after', ''),
            'filename': primary_cert.filename
        }
    
    def _prepare_apache_nginx_bundle(self, certificate_data, session, config, include_instructions):
        """Prepare Apache/Nginx bundle with separate files"""
        files = {}
        
        # Add certificate files with standardized names
        files['certificate.crt'] = certificate_data['certificate']
        
        if certificate_data['private_key']:
            files['private-key.pem'] = certificate_data['private_key']
        
        if certificate_data['ca_bundle']:
            files['ca-bundle.crt'] = certificate_data['ca_bundle']
        
        # Initialize guides as empty strings
        apache_guide = ''
        nginx_guide = ''
        
        # Add instructions if requested
        if include_instructions:
            if config.bundle_type == BundleType.APACHE:
                apache_guide = self.instruction_generator.generate_instructions(
                    'apache', certificate_data
                )
                if apache_guide:
                    files['APACHE_INSTALLATION_GUIDE.txt'] = apache_guide
                else:
                    apache_guide = ''  # Ensure it's empty string, not None
            
            if config.bundle_type == BundleType.NGINX:
                nginx_guide = self.instruction_generator.generate_instructions(
                    'nginx', certificate_data
                )
                if nginx_guide:
                    files['NGINX_INSTALLATION_GUIDE.txt'] = nginx_guide
                else:
                    nginx_guide = ''  # Ensure it's empty string, not None
            
            # For Apache bundles, also generate nginx guide
            if config.bundle_type == BundleType.APACHE:
                nginx_guide = self.instruction_generator.generate_instructions(
                    'nginx', certificate_data
                )
                if nginx_guide:
                    files['NGINX_INSTALLATION_GUIDE.txt'] = nginx_guide
                else:
                    nginx_guide = ''  # Ensure it's empty string, not None
        
        # Get selected components for manifest
        selected_components = list(session.components.values())
        
        return files, selected_components
    
    def _prepare_p12_bundle(self, certificate_data, session, config, include_instructions):
        """Prepare PKCS#12 bundle (used for IIS and advanced downloads)"""
        files = {}
        
        # Generate PKCS#12 password
        bundle_password = secure_zip_creator.generate_secure_password()

        logger.debug(f"Creating PKCS#12 with cert: {bool(certificate_data['certificate'])}, key: {bool(certificate_data['private_key'])}")
        
        # Create PKCS#12 bundle
        p12_bundle = self._create_pkcs12_bundle(
            certificate_data['certificate'],
            certificate_data['private_key'],
            certificate_data['ca_bundle'],
            bundle_password
        )
        logger.debug(f"PKCS#12 bundle created successfully, size: {len(p12_bundle)}")
        
        # Choose filename extension based on whether IIS instructions are included
        if config.bundle_type == BundleType.IIS and include_instructions:
            # Use Windows .pfx extension when IIS instructions are included
            p12_filename = get_standard_filename(PKIComponentType.CERTIFICATE, "PFX")
        else:
            # Use OpenSSL .p12 extension by default
            p12_filename = get_standard_filename(PKIComponentType.CERTIFICATE, "PKCS12")
        
        files[p12_filename] = p12_bundle

        logger.debug(f"P12 bundle files created: {list(files.keys())}")
        
        # Add instructions if requested
        if include_instructions:
            # Update certificate data with PKCS#12 filename for instructions
            certificate_data['filenames'] = {'pkcs12': p12_filename}
            
            iis_guide = self.instruction_generator.generate_instructions(
                'iis', certificate_data
            )
            if iis_guide:
                files['IIS_INSTALLATION_GUIDE.txt'] = iis_guide
        
        # Get selected components for manifest
        selected_components = list(session.components.values())
        
        return files, selected_components, bundle_password
    
    def _prepare_custom_bundle(self, session, config, include_instructions):
        """Prepare custom bundle with selected components and formats"""
        files = {}
        selected_components = []
        
        # Determine which components to include
        if config.component_selection:
            # Use specified components
            component_ids = config.component_selection
        else:
            # Use all components
            component_ids = list(session.components.keys())
        
        # Process each selected component
        for component_id in component_ids:
            if component_id not in session.components:
                continue
                
            component = session.components[component_id]
            selected_components.append(component)
            
            # Get format selection for this component
            format_key = f"{component.type.type_name.lower()}_{component_id}"
            selected_format = config.format_selections.get(format_key, 'pem')
            
            # Use standardized filename
            standard_filename = get_standard_filename(component.type, selected_format)
            
            # Convert content to requested format
            try:
                if component.type.type_name == 'PrivateKey':
                    # Use bundle_password for private key encryption if specified
                    converted_content = format_converter.convert_private_key(
                        component.content, selected_format, password=None
                    )
                else:
                    converted_content = format_converter.convert_certificate(
                        component.content, selected_format
                    )
                
                files[standard_filename] = converted_content
                
            except Exception as e:
                logger.warning(f"Failed to convert component {component_id} to {selected_format}: {e}")
                # Fall back to original content
                files[component.filename] = component.content
        
        return files, selected_components
    
    def _create_pkcs12_bundle(self, cert_pem, key_pem, ca_bundle, password):
        """Create PKCS#12 bundle from PEM components with proper type checking"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography import x509
        
        # Parse certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Parse private key
        private_key = serialization.load_pem_private_key(
            key_pem.encode(), password=None
        )
        
        # Check if private key type is supported by PKCS#12
        from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
        
        supported_key_types = (
            rsa.RSAPrivateKey,
            dsa.DSAPrivateKey, 
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey
        )
        
        if not isinstance(private_key, supported_key_types):
            raise ValueError(f"Private key type {type(private_key).__name__} is not supported for PKCS#12 bundles")
        
        # Parse CA certificates
        ca_certs = []
        if ca_bundle:
            for ca_cert_pem in ca_bundle.split('-----END CERTIFICATE-----'):
                if '-----BEGIN CERTIFICATE-----' in ca_cert_pem:
                    ca_cert_full = ca_cert_pem + '-----END CERTIFICATE-----'
                    try:
                        ca_cert = x509.load_pem_x509_certificate(ca_cert_full.encode())
                        ca_certs.append(ca_cert)
                    except Exception as e:
                        logger.warning(f"Failed to parse CA certificate: {e}")
        
        # Create PKCS#12 bundle 
        p12_data = pkcs12.serialize_key_and_certificates(
            name=b"certificate-bundle",
            key=private_key,  # Now type-checked as supported
            cert=cert,
            cas=ca_certs if ca_certs else None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        return p12_data
    
    def _create_zip_bundle(self, files, session_id, bundle_type, selected_components, bundle_password=None):
        """Create password-protected ZIP bundle"""
        try:
            if bundle_type == BundleType.APACHE:
                zip_data, password = secure_zip_creator.create_apache_bundle(
                    certificate=files.get('certificate.crt'),
                    private_key=files.get('private-key.pem'),
                    ca_bundle=files.get('ca-bundle.crt'),
                    apache_guide=files.get('APACHE_INSTALLATION_GUIDE.txt'),
                    nginx_guide=files.get('NGINX_INSTALLATION_GUIDE.txt'),
                    session_id=session_id,
                    selected_components=selected_components
                )
            elif bundle_type == BundleType.IIS:
                # Get the PKCS#12 filename (should be only one .pfx/.p12 file)
                p12_filename = None
                p12_content = None
                for filename, content in files.items():
                    if filename.lower().endswith(('.pfx', '.p12')):
                        p12_filename = filename
                        p12_content = content
                        break
                
                if p12_content is None:
                    raise ValueError("No PKCS#12 bundle found in files")
                
                zip_data, password = secure_zip_creator.create_iis_bundle(
                    p12_bundle=p12_content,
                    iis_guide=files.get('IIS_INSTALLATION_GUIDE.txt', ''),
                    password=None,
                    session_id=session_id,
                    selected_components=selected_components,
                    bundle_password=bundle_password
                )
            else:
                # Custom bundle or other types - use a simple file-based approach
                zip_data, password = secure_zip_creator.create_protected_zip(files)
            
            return zip_data, password
            
        except SecureZipCreatorError as e:
            logger.error(f"ZIP creation failed for session {session_id}: {e}")
            raise ValueError("Failed to create certificate bundle")
    
    def _extract_domain_name_from_metadata(self, metadata):
        """Extract domain name from certificate metadata"""
        # Try common name first
        subject = metadata.get('subject', '')
        if 'CN=' in subject:
            cn_part = subject.split('CN=')[1].split(',')[0].strip()
            return cn_part
        
        # Try SAN if available
        san = metadata.get('subject_alt_names', [])
        if san and isinstance(san, list) and len(san) > 0:
            return san[0]
        
        # Fallback to generic name
        return 'certificate'
    
    def get_available_bundle_types(self, session_id: str) -> Dict[str, Any]:
        """Get available bundle types and their requirements for a session"""
        session = session_pki_storage.get_or_create_session(session_id)
        
        if not session.components:
            return {
                "available_types": [],
                "requirements_met": {},
                "message": "No components available"
            }
        
        # Check what components are available
        has_certificate = any(c.type == PKIComponentType.CERTIFICATE for c in session.components.values())
        has_private_key = any(c.type == PKIComponentType.PRIVATE_KEY for c in session.components.values())
        has_ca_certs = any(c.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA] for c in session.components.values())
        
        # Determine which bundle types are available
        available_types = []
        requirements_met = {}
        
        if has_certificate:
            # Apache/Nginx can work with just certificate
            available_types.extend([BundleType.APACHE, BundleType.NGINX])
            requirements_met[BundleType.APACHE] = {
                "certificate": has_certificate,
                "private_key": has_private_key,
                "ca_bundle": has_ca_certs,
                "can_create": True
            }
            requirements_met[BundleType.NGINX] = {
                "certificate": has_certificate,
                "private_key": has_private_key,
                "ca_bundle": has_ca_certs,
                "can_create": True
            }
            
            # IIS requires certificate + private key
            if has_certificate and has_private_key:
                available_types.append(BundleType.IIS)
                requirements_met[BundleType.IIS] = {
                    "certificate": has_certificate,
                    "private_key": has_private_key,
                    "ca_bundle": has_ca_certs,
                    "can_create": True
                }
            else:
                requirements_met[BundleType.IIS] = {
                    "certificate": has_certificate,
                    "private_key": has_private_key,
                    "ca_bundle": has_ca_certs,
                    "can_create": False,
                    "missing": "private_key"
                }
            
            # Custom is always available if we have any components
            available_types.append(BundleType.CUSTOM)
            requirements_met[BundleType.CUSTOM] = {
                "can_create": True,
                "component_count": len(session.components)
            }
        
        return {
            "available_types": list(set(available_types)),
            "requirements_met": requirements_met,
            "component_summary": {
                "has_certificate": has_certificate,
                "has_private_key": has_private_key,
                "has_ca_certs": has_ca_certs,
                "total_components": len(session.components)
            }
        }

# Create singleton instance
download_service = DownloadService()