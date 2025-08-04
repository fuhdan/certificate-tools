# backend-fastapi/services/content_manifest_generator.py
"""
Content Manifest Generator Service

Generates content manifest files for ZIP bundles using PKI component storage.
Creates detailed file listings with descriptions for certificate bundles.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from certificates.storage.session_pki_storage import PKIComponent, PKIComponentType

logger = logging.getLogger(__name__)

class ContentManifestGenerator:
    """Service to generate content manifest files for ZIP bundles"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent / "templates" / "content_manifest"
        
    def generate_manifest(self, 
                         selected_components: List[PKIComponent],
                         bundle_type: str,
                         session_id: str,
                         zip_password: Optional[str] = None,
                         bundle_password: Optional[str] = None) -> str:
        """
        Generate content manifest from selected PKI components
        
        Args:
            selected_components: List of PKI components to include
            bundle_type: Type of bundle ("Apache/Nginx", "IIS/Windows", "Advanced Selection")
            session_id: Session identifier
            zip_password: Password for ZIP file
            bundle_password: Password for P12 bundle (IIS only)
            
        Returns:
            Generated manifest content as string
        """
        try:
            logger.info(f"Generating content manifest for {bundle_type} bundle with {len(selected_components)} components")
            
            # Load template
            template_content = self._load_template()
            
            # Prepare template variables
            variables = self._prepare_template_variables(
                selected_components, bundle_type, session_id, zip_password, bundle_password
            )
            
            # Replace variables in template  
            manifest_content = self._replace_template_variables(template_content, variables)
            
            logger.info(f"Generated content manifest for {bundle_type} bundle")
            return manifest_content
            
        except Exception as e:
            logger.error(f"Failed to generate content manifest: {e}")
            raise
    
    def _load_template(self) -> str:
        """Load the content manifest template from external file"""
        template_path = self.templates_dir / "content_manifest_template.txt"
        
        if not template_path.exists():
            raise FileNotFoundError(f"Content manifest template not found: {template_path}")
        
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def _prepare_template_variables(self, 
                                   selected_components: List[PKIComponent],
                                   bundle_type: str,
                                   session_id: str,
                                   zip_password: Optional[str],
                                   bundle_password: Optional[str]) -> Dict[str, str]:
        """Prepare all template variables from PKI components"""
        
        # Basic bundle information
        variables = {
            'bundle_type': bundle_type,
            'session_id': session_id,
            'generation_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'zip_password': zip_password or 'N/A',
            'tool_version': '2.0-PKI'
        }
        
        # Bundle password line (only for IIS)
        if bundle_password:
            variables['bundle_password_line'] = f"- P12 Password: {bundle_password}"
            variables['bundle_password_security'] = "- Store the P12 password securely for certificate import"
        else:
            variables['bundle_password_line'] = ""
            variables['bundle_password_security'] = ""
        
        # Calculate file information
        file_list = []
        file_descriptions = []
        total_size = 0
        
        for component in selected_components:
            # Calculate file size
            file_size = len(component.content.encode('utf-8'))
            total_size += file_size
            
            # Add to file list
            file_list.append(f"- {component.filename} ({file_size:,} bytes)")
            
            # Generate file description
            description = self._get_file_description(component)
            file_descriptions.append(f"{component.filename}:\n  {description}")
        
        variables.update({
            'file_list': '\n'.join(file_list),
            'file_descriptions': '\n\n'.join(file_descriptions),
            'total_files': str(len(selected_components)),
            'total_size': f"{total_size:,}",
            'total_size_mb': f"{total_size / (1024*1024):.2f}"
        })
        
        # Extract certificate information (if any certificate component exists)
        cert_component = self._find_certificate_component(selected_components)
        
        if cert_component and cert_component.metadata:
            variables.update(self._extract_certificate_variables(cert_component))
            variables['certificate_details_section'] = self._build_certificate_details_section(cert_component)
        else:
            variables.update(self._extract_non_certificate_variables(selected_components))
            variables['certificate_details_section'] = self._build_non_certificate_details_section(selected_components)
        
        # Installation summary based on bundle type
        variables['installation_summary'] = self._get_installation_summary(bundle_type, selected_components)
        
        # Validation checklist based on components
        variables['validation_checklist_section'] = self._build_validation_checklist(selected_components)
        
        # Support section based on components
        variables['support_section'] = self._build_support_section(cert_component)
        
        return variables
    
    def _get_file_description(self, component: PKIComponent) -> str:
        """Generate description based on PKI component type and metadata"""
        
        metadata = component.metadata
        
        if component.type == PKIComponentType.PRIVATE_KEY:
            algorithm = metadata.get('algorithm', 'Unknown')
            key_size = metadata.get('key_size', 'Unknown')
            is_encrypted = metadata.get('is_encrypted', False)
            encryption_status = "encrypted" if is_encrypted else "unencrypted"
            return f"Private key ({algorithm} {key_size}-bit, {encryption_status})"
        
        elif component.type == PKIComponentType.CSR:
            subject = metadata.get('subject', 'Unknown subject')
            algorithm = metadata.get('public_key_algorithm', 'Unknown')
            key_size = metadata.get('public_key_size', 'Unknown')
            return f"Certificate Signing Request for {subject} ({algorithm} {key_size}-bit)"
        
        elif component.type == PKIComponentType.CERTIFICATE:
            subject = metadata.get('subject', 'Unknown subject')
            algorithm = metadata.get('public_key_algorithm', 'Unknown')
            key_size = metadata.get('public_key_size', 'Unknown')
            return f"End-entity certificate for {subject} ({algorithm} {key_size}-bit)"
        
        elif component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
            subject = metadata.get('subject', 'Unknown CA')
            algorithm = metadata.get('public_key_algorithm', 'Unknown')
            key_size = metadata.get('public_key_size', 'Unknown')
            return f"{component.type.type_name} certificate for {subject} ({algorithm} {key_size}-bit)"
        
        else:
            return f"{component.type.type_name} component ({component.filename})"
    
    def _find_certificate_component(self, components: List[PKIComponent]) -> Optional[PKIComponent]:
        """Find the first certificate component for extracting cert info"""
        for component in components:
            if component.type in [PKIComponentType.CERTIFICATE, PKIComponentType.ROOT_CA, 
                                 PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
                return component
        return None
    
    def _extract_certificate_variables(self, cert_component: PKIComponent) -> Dict[str, str]:
        """Extract certificate-specific variables"""
        metadata = cert_component.metadata
        
        # Extract domain name from subject
        subject = metadata.get('subject', '')
        domain_name = self._extract_domain_from_subject(subject)
        
        return {
            'primary_domain': domain_name,
            'certificate_subject': metadata.get('subject', 'N/A'),
            'certificate_issuer': metadata.get('issuer', 'N/A'),
            'valid_from': metadata.get('not_valid_before', 'N/A'),
            'valid_to': metadata.get('not_valid_after', 'N/A'),
            'key_algorithm': metadata.get('public_key_algorithm', 'N/A'),
            'key_size': str(metadata.get('public_key_size', 'N/A')),
            'certificate_serial': metadata.get('serial_number', 'N/A')
        }
    
    def _extract_non_certificate_variables(self, components: List[PKIComponent]) -> Dict[str, str]:
        """Extract variables when no certificate is present"""
        # Try to get domain from CSR if available
        csr_component = next((c for c in components if c.type == PKIComponentType.CSR), None)
        
        if csr_component and csr_component.metadata:
            subject = csr_component.metadata.get('subject', '')
            domain_name = self._extract_domain_from_subject(subject)
        else:
            domain_name = 'N/A'
        
        return {
            'primary_domain': domain_name,
            'certificate_subject': 'N/A',
            'certificate_issuer': 'N/A', 
            'valid_from': 'N/A',
            'valid_to': 'N/A',
            'key_algorithm': 'N/A',
            'key_size': 'N/A',
            'certificate_serial': 'N/A'
        }
    
    def _extract_domain_from_subject(self, subject: str) -> str:
        """Extract domain name from certificate subject"""
        if not subject:
            return 'N/A'
        
        # Try to find CN= in subject
        for part in subject.split(','):
            part = part.strip()
            if part.startswith('CN='):
                return part[3:].strip()
        
        return 'N/A'
    
    def _build_certificate_details_section(self, cert_component: PKIComponent) -> str:
        """Build certificate details section when certificate is present"""
        metadata = cert_component.metadata
        
        return f"""Certificate Details:
- Subject: {metadata.get('subject', 'N/A')}
- Issuer: {metadata.get('issuer', 'N/A')}
- Valid From: {metadata.get('not_valid_before', 'N/A')}
- Valid Until: {metadata.get('not_valid_after', 'N/A')}
- Key Algorithm: {metadata.get('public_key_algorithm', 'N/A')}
- Key Size: {metadata.get('public_key_size', 'N/A')} bits"""
    
    def _build_non_certificate_details_section(self, components: List[PKIComponent]) -> str:
        """Build details section when no certificate is present"""
        # Count components by type
        component_counts = {}
        for component in components:
            type_name = component.type.type_name
            component_counts[type_name] = component_counts.get(type_name, 0) + 1
        
        # Build component summary
        component_summary = []
        for type_name, count in component_counts.items():
            component_summary.append(f"- {type_name}: {count}")
        
        return f"""Bundle Contents:
{chr(10).join(component_summary)}
- Note: No certificate data available in this bundle
- This bundle contains individual PKI components only"""
    
    def _get_installation_summary(self, bundle_type: str, components: List[PKIComponent]) -> str:
        """Get installation summary based on bundle type"""
        if bundle_type == "Apache/Nginx":
            return """This bundle contains certificate files for Apache and Nginx web servers.
Use the provided installation guides to configure SSL/TLS on your server.
Ensure proper file permissions are set for security."""
        
        elif bundle_type == "IIS/Windows":
            return """This bundle contains a PKCS#12 file for Windows IIS.
Import the P12 file using the provided installation guide.
The P12 file contains both certificate and private key."""
        
        else:  # Advanced Selection
            component_types = [c.type.type_name for c in components]
            return f"""This is a custom selection containing: {', '.join(set(component_types))}.
Use appropriate tools to process each component type.
Refer to documentation for your specific use case."""
    
    def _build_validation_checklist(self, components: List[PKIComponent]) -> str:
        """Build validation checklist based on component types"""
        has_cert = any(c.type in [PKIComponentType.CERTIFICATE, PKIComponentType.ROOT_CA, 
                                 PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA] 
                      for c in components)
        has_key = any(c.type == PKIComponentType.PRIVATE_KEY for c in components)
        has_csr = any(c.type == PKIComponentType.CSR for c in components)
        
        checklist = ["Before using these files, verify:",
                    "□ All files are present and not corrupted",
                    "□ File sizes match the values listed above"]
        
        if has_cert and has_key:
            checklist.extend([
                "□ Private key matches the certificate",
                "□ Certificate has not expired",
                "□ Certificate covers your intended domain(s)"
            ])
        elif has_cert:
            checklist.extend([
                "□ Certificate has not expired",
                "□ Certificate chain is complete and properly ordered"
            ])
        elif has_key:
            checklist.extend([
                "□ Private key can be loaded without errors",
                "□ Private key format is compatible with target system",
                "□ File permissions are properly secured"
            ])
        elif has_csr:
            checklist.extend([
                "□ CSR contains correct subject information",
                "□ CSR is properly formatted and valid"
            ])
        
        return '\n'.join(checklist)
    
    def _build_support_section(self, cert_component: Optional[PKIComponent]) -> str:
        """Build support section based on available certificate info"""
        if cert_component and cert_component.metadata:
            issuer = cert_component.metadata.get('issuer', 'Unknown CA')
            serial = cert_component.metadata.get('serial_number', 'N/A')
            return f"""Certificate Authority: {issuer}
Certificate Serial: {serial}"""
        else:
            return """File Type: PKI Component Bundle
Component Format: PEM"""
    
    def _replace_template_variables(self, template: str, variables: Dict[str, str]) -> str:
        """Replace template variables with actual values"""
        result = template
        
        for key, value in variables.items():
            placeholder = f"{{{key}}}"
            result = result.replace(placeholder, str(value))
        
        return result