# backend-fastapi/services/download_service.py
# Unified download service - consolidates Apache, IIS, and advanced downloads

import logging
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime

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
    PKCS7 = "pkcs7"
    PKCS12 = "pkcs12"
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
        
        # Find primary certificate for bundles that need it
        primary_cert = self._find_primary_certificate(session)
        
        # Prepare download package based on bundle type
        files = {}
        bundle_password = None
        selected_components = list(session.components.values())

        logger.debug(f"Preparing bundle of type: {config.bundle_type}")
        
        if config.bundle_type in [BundleType.APACHE, BundleType.NGINX]:
            files, selected_components = self._prepare_apache_nginx_bundle(
                primary_cert, session, config, include_instructions
            )
        elif config.bundle_type == BundleType.IIS:
            files, selected_components, bundle_password = self._prepare_iis_bundle(
                primary_cert, session, config, include_instructions
            )
        elif config.bundle_type == BundleType.PKCS7:
            files, selected_components = self._prepare_pkcs7_bundle(
                primary_cert, session, config
            )
        elif config.bundle_type == BundleType.PKCS12:
            files, selected_components, bundle_password = self._prepare_pkcs12_bundle(
                primary_cert, session, config
            )
        elif config.bundle_type == BundleType.CUSTOM:
            files, selected_components, bundle_password = self._prepare_custom_bundle(
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
    
    def _extract_certificate_data(self, primary_cert, session):
        """Extract certificate data from session components"""
        if not primary_cert:
            raise ValueError("No end-entity certificate found")
            
        certificate_pem = primary_cert.content
        if not certificate_pem:
            raise ValueError("Certificate PEM not found")
        
        # Find private key component
        private_key_pem = None
        for component in session.components.values():
            if component.type == PKIComponentType.PRIVATE_KEY:
                private_key_pem = component.content
                break
        
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
    
    def _prepare_apache_nginx_bundle(self, primary_cert, session, config, include_instructions):
        """Prepare Apache/Nginx bundle with separate files"""
        certificate_data = self._extract_certificate_data(primary_cert, session)
        files = {}
        
        # Add certificate files with standardized names
        files['certificate.crt'] = certificate_data['certificate']
        
        if certificate_data['private_key']:
            files['private-key.pem'] = certificate_data['private_key']
        
        if certificate_data['ca_bundle']:
            files['ca-bundle.crt'] = certificate_data['ca_bundle']
        
        # Add instructions if requested
        if include_instructions:
            if config.bundle_type == BundleType.APACHE:
                apache_guide = self.instruction_generator.generate_instructions(
                    'apache', certificate_data
                )
                if apache_guide:
                    files['APACHE_INSTALLATION_GUIDE.txt'] = apache_guide
            
            if config.bundle_type == BundleType.NGINX:
                nginx_guide = self.instruction_generator.generate_instructions(
                    'nginx', certificate_data
                )
                if nginx_guide:
                    files['NGINX_INSTALLATION_GUIDE.txt'] = nginx_guide
            
            # For Apache bundles, also generate nginx guide
            if config.bundle_type == BundleType.APACHE:
                nginx_guide = self.instruction_generator.generate_instructions(
                    'nginx', certificate_data
                )
                if nginx_guide:
                    files['NGINX_INSTALLATION_GUIDE.txt'] = nginx_guide
        
        # Get selected components for manifest
        selected_components = list(session.components.values())
        
        return files, selected_components
    
    def _prepare_iis_bundle(self, primary_cert, session, config, include_instructions):
        """Prepare IIS PKCS#12 bundle"""
        certificate_data = self._extract_certificate_data(primary_cert, session)
        
        # IIS requires private key
        if not certificate_data['private_key']:
            raise ValueError("No private key found. IIS requires a private key for PKCS#12 bundle.")
        
        files = {}
        
        # Generate PKCS#12 password
        bundle_password = secure_zip_creator.generate_secure_password()

        logger.debug(f"Creating PKCS#12 with cert: {bool(certificate_data['certificate'])}, key: {bool(certificate_data['private_key'])}")
        
        # Use format_converter for PKCS#12 creation
        p12_bundle = format_converter.create_pkcs12_bundle(
            certificate_data['certificate'],
            certificate_data['private_key'],
            certificate_data['ca_bundle'],
            bundle_password
        )
        logger.debug(f"PKCS#12 bundle created successfully, size: {len(p12_bundle)}")
        
        # Choose filename extension based on whether IIS instructions are included
        if include_instructions:
            p12_filename = get_standard_filename(PKIComponentType.CERTIFICATE, "PFX")
        else:
            p12_filename = get_standard_filename(PKIComponentType.CERTIFICATE, "PKCS12")
        
        files[p12_filename] = p12_bundle

        # Add instructions if requested
        if include_instructions:
            certificate_data['filenames'] = {'pkcs12': p12_filename}
            iis_guide = self.instruction_generator.generate_instructions('iis', certificate_data)
            if iis_guide:
                files['IIS_INSTALLATION_GUIDE.txt'] = iis_guide
        
        selected_components = list(session.components.values())
        return files, selected_components, bundle_password

    def _prepare_pkcs7_bundle(self, primary_cert, session, config):
        """Prepare PKCS7 bundle as certificate chain"""
        certificate_data = self._extract_certificate_data(primary_cert, session)
        files = {}
        
        # Get format from config
        format_type = config.format_selections.get('pkcs7', 'pem')
        
        # Collect all certificates for the chain
        cert_chain = []
        
        # Add end-entity certificate
        if certificate_data['certificate']:
            cert_chain.append(certificate_data['certificate'])
        
        # Add CA bundle  
        if certificate_data['ca_bundle']:
            cert_chain.append(certificate_data['ca_bundle'])
        
        if not cert_chain:
            raise ValueError("No certificates found for PKCS7 bundle")
        
        # Create certificate chain file
        chain_content = '\n'.join(cert_chain)
        
        if format_type == 'der':
            # Use existing format_converter to convert PEM chain to DER
            chain_content = format_converter.convert_certificate(chain_content, 'der')
            filename = 'certificate-chain.p7b'
        else:
            # PEM format - just use the concatenated PEM
            filename = 'certificate-chain.p7c'
        
        files[filename] = chain_content
        
        # Use original session components for manifest (same as IIS)
        selected_components = list(session.components.values())
        return files, selected_components

    def _prepare_pkcs12_bundle(self, primary_cert, session, config):
        """Prepare standalone PKCS12 bundle"""
        certificate_data = self._extract_certificate_data(primary_cert, session)
        
        # PKCS12 requires private key
        if not certificate_data['private_key']:
            raise ValueError("No private key found. PKCS12 requires a private key.")
        
        files = {}
        
        # Get encryption setting from config
        encryption = config.format_selections.get('pkcs12', 'encrypted')
        
        # Generate password only if encrypted
        bundle_password = None
        if encryption == 'encrypted':
            bundle_password = secure_zip_creator.generate_secure_password()
        
        # Use format_converter with optional password (None for unencrypted)
        p12_bundle = format_converter.create_pkcs12_bundle(
            certificate_data['certificate'],
            certificate_data['private_key'], 
            certificate_data['ca_bundle'],
            bundle_password  # Will be None for unencrypted
        )
        
        # Choose filename
        filename = get_standard_filename(PKIComponentType.CERTIFICATE, "PKCS12")
        files[filename] = p12_bundle
        
        # Use original session components for manifest (same as IIS)
        selected_components = list(session.components.values())
        
        return files, selected_components, bundle_password
    
    def _prepare_custom_bundle(self, session, config, include_instructions):
        """Prepare custom bundle using format_converter service"""
        files = {}
        selected_components = []
        bundle_password = None  # For encrypted formats
        
        # Check if this is a special bundle request (PKCS7 or PKCS12)
        is_bundle_request = 'bundle_pkcs7' in config.format_selections or 'bundle_pkcs12' in config.format_selections
        
        if is_bundle_request:
            # For bundle requests, ONLY create the bundle file, not individual components
            logger.info("Processing bundle request - skipping individual component processing")
            bundle_files = self._process_bundle_requests(session, config.format_selections, selected_components)
            files.update(bundle_files)
            
            # Check if bundle creation generated a password
            if hasattr(self, '_bundle_password'):
                bundle_password = self._bundle_password
                delattr(self, '_bundle_password')  # Clean up
            
            # For bundle requests, use all session components for manifest but don't convert them
            selected_components = list(session.components.values())
            
        else:
            # Regular custom download - process individual components
            # Determine which components to include
            if config.component_selection:
                component_ids = config.component_selection
            else:
                component_ids = list(session.components.keys())
            
            # Process each selected component using format_converter
            for component_id in component_ids:
                if component_id not in session.components:
                    continue
                    
                component = session.components[component_id]
                
                # Get format selection for this component
                selected_format = config.format_selections.get(component_id, 'pem')
                if selected_format == 'pem':  # If not found, try with type prefix
                    format_key = f"{component.type.type_name.lower()}_{component_id}"
                    selected_format = config.format_selections.get(format_key, 'pem')
                
                logger.debug(f"Component {component_id}: format={selected_format}")
                
                # Use standardized filename for selected format
                standard_filename = get_standard_filename(component.type, selected_format)
                
                # Use existing format_converter for format conversion
                try:
                    if component.type.type_name == 'PrivateKey':
                        converted_content = format_converter.convert_private_key(
                            component.content, selected_format, password=None
                        )
                        
                        # Check if encryption password was generated
                        if selected_format in ['pkcs8_encrypted', 'pem_encrypted']:
                            # Get the generated password from format_converter
                            from services.format_converter import get_last_encryption_password, get_last_password_type
                            encryption_password = get_last_encryption_password()
                            password_type = get_last_password_type()
                            
                            if encryption_password:
                                bundle_password = encryption_password
                                logger.info(f"🔐 Captured encryption password for {selected_format}: {encryption_password}")
                                
                                # Store password type for manifest
                                self._bundle_password_type = password_type
                                
                    elif component.type.type_name == 'Certificate':
                        converted_content = format_converter.convert_certificate(
                            component.content, selected_format
                        )
                    elif component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA]:
                        converted_content = format_converter.convert_certificate(
                            component.content, selected_format
                        )
                    else:
                        # CSR or other types
                        converted_content = format_converter.convert_csr(
                            component.content, selected_format
                        )
                    
                    # Handle bytes/string conversion for ZIP storage
                    if selected_format.lower() in ['pem', 'pem_encrypted']:
                        # PEM formats should be stored as strings
                        if isinstance(converted_content, bytes):
                            file_content = converted_content.decode('utf-8')
                        else:
                            file_content = converted_content
                    else:
                        # DER, PKCS8, etc. should be stored as bytes
                        file_content = converted_content
                    
                    files[standard_filename] = file_content
                    
                    # For manifest, always use string representation
                    if isinstance(file_content, bytes):
                        # For binary formats, create a description for manifest
                        manifest_content = f"Binary {selected_format.upper()} file ({len(file_content)} bytes)"
                    else:
                        manifest_content = file_content
                    
                    # Create virtual component for manifest with actual ZIP filename
                    virtual_component = self._create_virtual_component(
                        component, standard_filename, manifest_content, selected_format
                    )
                    selected_components.append(virtual_component)
                    
                except Exception as e:
                    logger.warning(f"Failed to convert component {component_id} to {selected_format}: {e}")
                    # Fall back to original content and filename
                    files[component.filename] = component.content
                    selected_components.append(component)
        
        return files, selected_components, bundle_password
    
    def _process_bundle_requests(self, session, format_selections, selected_components):
        """Process special bundle format requests (PKCS7, PKCS12)"""
        bundle_files = {}
        
        # Check for PKCS7 bundle request
        if 'bundle_pkcs7' in format_selections:
            format_type = format_selections['bundle_pkcs7']
            logger.info(f"Creating PKCS7 bundle in {format_type} format")
            
            try:
                # Find certificate and CA certificates for chain
                certificate_components = []
                for component in session.components.values():
                    if component.type == PKIComponentType.CERTIFICATE:
                        certificate_components.append(component)
                    elif component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
                        certificate_components.append(component)
                
                if not certificate_components:
                    raise ValueError("No certificates found for PKCS7 bundle")
                
                # Create certificate chain content
                chain_parts = []
                for cert_component in certificate_components:
                    chain_parts.append(cert_component.content.strip())
                
                chain_content = '\n'.join(chain_parts)
                
                if format_type == 'der':
                    # Convert PEM chain to DER PKCS7
                    chain_content = format_converter.convert_certificate(chain_content, 'der')
                    filename = 'certificate-chain.p7b'
                else:
                    # PEM format - use concatenated PEM
                    filename = 'certificate-chain.p7c'
                
                bundle_files[filename] = chain_content
                logger.info(f"Created PKCS7 bundle: {filename}")
                
            except Exception as e:
                logger.error(f"Failed to create PKCS7 bundle: {e}")
                raise ValueError(f"PKCS7 bundle creation failed: {e}")
        
        # Check for PKCS12 bundle request
        if 'bundle_pkcs12' in format_selections:
            encryption = format_selections['bundle_pkcs12']
            logger.info(f"Creating PKCS12 bundle with encryption: {encryption}")
            
            try:
                # Find required components
                certificate = None
                private_key = None
                ca_certs = []
                
                for component in session.components.values():
                    if component.type == PKIComponentType.CERTIFICATE:
                        certificate = component
                    elif component.type == PKIComponentType.PRIVATE_KEY:
                        private_key = component
                    elif component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
                        ca_certs.append(component)
                
                if not certificate:
                    raise ValueError("Certificate required for PKCS12 bundle")
                if not private_key:
                    raise ValueError("Private key required for PKCS12 bundle")
                
                # Build CA bundle
                ca_bundle = None
                if ca_certs:
                    ca_bundle = '\n'.join([ca.content.strip() for ca in ca_certs])
                
                # Generate password if encrypted
                bundle_password = None
                if encryption == 'encrypted':
                    bundle_password = secure_zip_creator.generate_secure_password()
                
                # Create PKCS12 bundle
                p12_bundle = format_converter.create_pkcs12_bundle(
                    certificate.content,
                    private_key.content,
                    ca_bundle,
                    bundle_password
                )
                
                filename = get_standard_filename(PKIComponentType.CERTIFICATE, "PKCS12")
                bundle_files[filename] = p12_bundle
                logger.info(f"Created PKCS12 bundle: {filename}")
                
                # Update bundle password for main method to return
                if bundle_password:
                    self._bundle_password = bundle_password
                
            except Exception as e:
                logger.error(f"Failed to create PKCS12 bundle: {e}")
                raise ValueError(f"PKCS12 bundle creation failed: {e}")
        
        return bundle_files
    
    def _create_virtual_component(self, original_component, zip_filename, converted_content, format_type):
        """Create virtual component with ZIP filename for manifest"""
        import copy
        from datetime import datetime
        
        virtual_component = copy.deepcopy(original_component)
        virtual_component.filename = zip_filename  # Use actual ZIP filename
        virtual_component.content = converted_content
        virtual_component.uploaded_at = datetime.now().isoformat()
        
        # Update metadata with format information
        if not virtual_component.metadata:
            virtual_component.metadata = {}
        virtual_component.metadata['converted_format'] = format_type
        virtual_component.metadata['original_filename'] = original_component.filename
        
        return virtual_component
    
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
                    bundle_password=bundle_password,
                    p12_filename=p12_filename
                )
            elif bundle_type == BundleType.PKCS12:
                # Use IIS bundle creator but with PKCS12 settings
                p12_filename = None
                p12_content = None
                for filename, content in files.items():
                    if filename.lower().endswith(('.p12')):
                        p12_filename = filename
                        p12_content = content
                        break
                
                if p12_content is None:
                    raise ValueError("No PKCS#12 bundle found in files")
                
                zip_data, password = secure_zip_creator.create_iis_bundle(
                    p12_bundle=p12_content,
                    iis_guide='',  # No instructions for standalone PKCS12
                    password=None,
                    session_id=session_id,
                    selected_components=selected_components,
                    bundle_password=bundle_password,
                    bundle_type="PKCS12",
                    p12_filename=p12_filename
                )
            elif bundle_type == BundleType.PKCS7:
                # Use IIS bundle creator but with PKCS7 settings  
                p7_filename = None
                p7_content = None
                for filename, content in files.items():
                    if filename.lower().endswith(('.p7b', '.p7c')):
                        p7_filename = filename
                        p7_content = content
                        break
                
                if p7_content is None:
                    raise ValueError("No PKCS7 bundle found in files")
                
                zip_data, password = secure_zip_creator.create_iis_bundle(
                    p12_bundle=p7_content,  # Reuse p12_bundle param for PKCS7 content
                    iis_guide='',  # No instructions for PKCS7
                    password=None,
                    session_id=session_id,
                    selected_components=selected_components,
                    bundle_password=None,
                    bundle_type="PKCS7",
                    p12_filename=p7_filename
                )
            else:
                # CUSTOM bundle - dedicated clean implementation
                bundle_password_type = getattr(self, '_bundle_password_type', None)
                zip_data, password = secure_zip_creator.create_custom_bundle(
                    files=files,
                    bundles={},  # No sub-bundles for custom downloads
                    session_id=session_id,
                    selected_components=selected_components,
                    bundle_password=bundle_password,
                    bundle_password_type=bundle_password_type
                )
            
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
        """Get available bundle types and their requirements for a session - UPDATED: Server bundles + custom only"""
        session = session_pki_storage.get_or_create_session(session_id)
        
        if not session.components:
            return {
                "available_types": [],
                "requirements_met": {},
                "component_summary": {
                    "has_certificate": False,
                    "has_private_key": False,
                    "has_ca_certs": False,
                    "total_components": 0
                }
            }
        
        # Check what components are available
        has_certificate = any(c.type == PKIComponentType.CERTIFICATE for c in session.components.values())
        has_private_key = any(c.type == PKIComponentType.PRIVATE_KEY for c in session.components.values())
        has_ca_certs = any(c.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA] for c in session.components.values())
        
        # UPDATED: Only check server bundle types (Apache, IIS, Nginx)
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