# backend-fastapi/services/content_manifest_generator.py
"""
Content Manifest Generator Service

Generates content manifest files for ZIP bundles using PKI component storage.
Creates detailed file listings with descriptions for certificate bundles.
Enhanced with SHA256 hash verification for file integrity.
"""

import logging
import hashlib
from datetime import datetime
from typing import List, Dict, Optional
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
                selected_components, bundle_type, session_id, bundle_password
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
    
    def _calculate_file_hash(self, content: str) -> str:
        """Calculate SHA256 hash of file content"""
        content_bytes = content.encode('utf-8')
        sha256_hash = hashlib.sha256(content_bytes).hexdigest().upper()
        return sha256_hash
    
    def _prepare_template_variables(self, 
                                   selected_components: List[PKIComponent],
                                   bundle_type: str,
                                   session_id: str,
                                   bundle_password: Optional[str]) -> Dict[str, str]:
        """Prepare all template variables from PKI components"""
        
        # Basic bundle information
        variables = {
            'bundle_type': bundle_type,
            'session_id': session_id,
            'generation_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'tool_version': '2.0-PKI'
        }
        
        # Bundle password line (only for IIS)
        if bundle_password:
            variables['bundle_password_line'] = f"- P12 Password: {bundle_password}"
            variables['bundle_password_security'] = "- Store the P12 password securely for certificate import"
        else:
            variables['bundle_password_line'] = ""
            variables['bundle_password_security'] = ""
        
        # Calculate file information with hashes
        file_list = []
        file_list_with_hashes = []
        file_descriptions = []
        linux_commands = []
        windows_commands = []
        total_size = 0
        
        for component in selected_components:
            # Calculate file size and hash
            file_size = len(component.content.encode('utf-8'))
            file_hash = self._calculate_file_hash(component.content)
            total_size += file_size
            
            # Add to file lists
            file_list.append(f"- {component.filename} ({file_size:,} bytes)")
            file_list_with_hashes.append(f"- {component.filename} ({file_size:,} bytes) - SHA256: {file_hash}")
            
            # Generate verification commands
            linux_commands.append(f"echo '{file_hash.lower()}  {component.filename}' | sha256sum -c -")
            windows_commands.append(f"Get-FileHash -Path '{component.filename}' -Algorithm SHA256 | Select-Object Hash")
            
            # Generate file description
            description = self._get_file_description(component)
            file_descriptions.append(f"{component.filename}:\n  {description}\n  SHA256: {file_hash}")
        
        # ADD THE MANIFEST ITSELF to the file listing
        manifest_description = "Bundle contents manifest and file information"
        manifest_size_estimate = 4096  # Increased estimate due to hash content
        manifest_hash = "CALCULATED_AFTER_GENERATION"  # Placeholder
        
        file_list.append(f"- CONTENT_MANIFEST.txt ({manifest_size_estimate:,} bytes)")
        file_list_with_hashes.append(f"- CONTENT_MANIFEST.txt ({manifest_size_estimate:,} bytes) - SHA256: {manifest_hash}")
        file_descriptions.append(f"CONTENT_MANIFEST.txt:\n  {manifest_description}\n  SHA256: {manifest_hash}")
        
        # Update totals to include manifest
        total_size += manifest_size_estimate
        total_files = len(selected_components) + 1  # +1 for manifest
        
        # Generate verification command blocks
        linux_verification_commands = self._generate_linux_verification_commands(linux_commands)
        windows_verification_commands = self._generate_windows_verification_commands(windows_commands)
        
        variables.update({
            'file_list': '\n'.join(file_list),
            'file_list_with_hashes': '\n'.join(file_list_with_hashes),
            'file_descriptions': '\n\n'.join(file_descriptions),
            'total_files': str(total_files),
            'total_size': f"{total_size:,}",
            'total_size_mb': f"{total_size / (1024*1024):.2f}",
            'linux_verification_commands': linux_verification_commands,
            'windows_verification_commands': windows_verification_commands
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
    
    def _generate_linux_verification_commands(self, commands: List[str]) -> str:
        """Generate Linux verification command block"""
        command_block = """LINUX / UNIX / macOS Verification:

1) Create hash verification file:
   cat > expected_hashes.txt << 'EOF'
""" + '\n'.join([cmd.split("'")[1] for cmd in commands]) + """
EOF

2) Verify all files at once:
   sha256sum -c expected_hashes.txt

3) Verify individual files:
"""
        
        # Add individual verification commands
        individual_commands = []
        for cmd in commands:
            individual_commands.append(f"   {cmd}")
        
        command_block += '\n'.join(individual_commands)
        
        command_block += """

Expected output for each file: "filename: OK"
If any file shows "FAILED", do not use the file - re-download the bundle."""
        
        return command_block
    
    def _generate_windows_verification_commands(self, commands: List[str]) -> str:
        """Generate Windows verification command block"""
        command_block = """WINDOWS PowerShell Verification:

1) Open PowerShell as Administrator

2) Navigate to extracted ZIP directory:
   cd "C:\\path\\to\\extracted\\files"

3) Verify individual files:
"""
        
        # Add individual verification commands  
        individual_commands = []
        for cmd in commands:
            individual_commands.append(f"   {cmd}")
        
        command_block += '\n'.join(individual_commands)
        
        command_block += """

4) Compare displayed hash values with the SHA256 values listed above
5) All hash values must match exactly (case insensitive)

Alternative one-liner to check all files:
   Get-ChildItem *.* | Get-FileHash -Algorithm SHA256 | Format-Table Name, Hash -AutoSize

If any hash doesn't match, do not use the file - re-download the bundle."""
        
        return command_block
    
    def _get_file_description(self, component: PKIComponent) -> str:
        """Generate description based on PKI component type and metadata"""
        
        if not component.metadata:
            return f"{component.type.type_name} component ({component.filename})"
        
        metadata = component.metadata
        
        # Check if this is a text file based on metadata or filename
        if (metadata.get('file_type') == 'text' or 
            component.filename.endswith('.txt') or 
            component.filename.endswith('.md')):
            # Use description from metadata if available
            if 'description' in metadata:
                return metadata['description']
            
            # Generate description based on filename patterns
            if 'INSTALLATION_GUIDE' in component.filename.upper():
                server_type = component.filename.upper().split('_')[0].lower()
                return f"{server_type.title()} web server installation guide"
            elif 'CERTIFICATE_INFO' in component.filename.upper():
                return "Certificate information and passwords"
            elif 'README' in component.filename.upper():
                return "Bundle information and instructions"
            else:
                return f"Text file: {component.filename}"
        
        # Handle PKI component types - but check for text file metadata first
        if component.type == PKIComponentType.PRIVATE_KEY:
            # Check if this is actually a text file using our component type as placeholder
            if metadata.get('file_type') == 'text':
                return metadata.get('description', f'Text file: {component.filename}')
            
            # This is a real private key
            algorithm = metadata.get('algorithm', 'Unknown')
            key_size = metadata.get('key_size', 'Unknown')
            is_encrypted = metadata.get('is_encrypted', False)
            encryption_status = "encrypted" if is_encrypted else "unencrypted"
            return f"Private key ({algorithm} {key_size}-bit, {encryption_status})"
        
        elif component.type == PKIComponentType.CSR:
            # Only use CSR description if it's actually a CSR file
            if component.filename.endswith('.csr') or 'CSR' in component.filename.upper():
                subject = metadata.get('subject', 'Unknown subject')
                algorithm = metadata.get('public_key_algorithm', 'Unknown')
                key_size = metadata.get('public_key_size', 'Unknown')
                return f"Certificate Signing Request for {subject} ({algorithm} {key_size}-bit)"
            else:
                # This is a text file misclassified as CSR - use description from metadata
                return metadata.get('description', f'Text file: {component.filename}')
        
        elif component.type == PKIComponentType.CERTIFICATE:
            subject = metadata.get('subject', 'Unknown subject')
            algorithm = metadata.get('public_key_algorithm', 'Unknown')
            key_size = metadata.get('public_key_size', 'Unknown')
            
            # Special handling for P12 bundles
            if metadata.get('format') == 'PKCS#12':
                contains = metadata.get('contains', 'Certificate bundle')
                password_protected = metadata.get('password_protected', 'Unknown')
                return f"PKCS#12 bundle for {subject} - {contains} (Password protected: {password_protected})"
            
            return f"End-entity certificate for {subject} ({algorithm} {key_size}-bit)"
        
        elif component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
            subject = metadata.get('subject', 'Unknown CA')
            
            # Check if this is actually a CA certificate or just a text file with CA bundle content
            if component.filename.endswith(('.crt', '.cer', '.pem')) and not component.filename.startswith('ca-bundle'):
                algorithm = metadata.get('public_key_algorithm', 'Unknown')
                key_size = metadata.get('public_key_size', 'Unknown')
                return f"{component.type.type_name} certificate for {subject} ({algorithm} {key_size}-bit)"
            else:
                # This is likely a CA bundle file
                return metadata.get('description', 'Certificate Authority bundle')
        
        else:
            # Fallback for any other types
            if 'description' in metadata:
                return metadata['description']
            return f"{component.type.type_name} component ({component.filename})"
    
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
                    "□ File SHA256 hashes match the values above (see verification commands below)",
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

    def _find_certificate_component(self, components: List[PKIComponent]) -> Optional[PKIComponent]:
        """Find the first certificate component for extracting cert info"""
        for component in components:
            if component.type in [PKIComponentType.CERTIFICATE, PKIComponentType.ROOT_CA, 
                                 PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
                return component
        return None