# backend-fastapi/services/instruction_generator.py
"""
Installation Instructions Generator Service - ENHANCED

Generates customized installation instructions for Linux Apache/Nginx and Windows IIS.
Properly extracts data from certificate metadata and replaces template variables.
NO EXTERNAL DEPENDENCIES - uses only Python standard library.
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class InstructionGenerator:
    """Service to generate customized installation instructions for web servers"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent / "templates" / "instructions"

    def generate_instructions(self, server_type: str, certificate_data: Dict[str, Any], 
                            zip_password: Optional[str] = None, bundle_password: Optional[str] = None) -> str:
        """
        Generate installation instructions for specified server type
        
        Args:
            server_type: 'apache', 'nginx', or 'iis'
            certificate_data: Certificate information dictionary
            zip_password: Password for ZIP file
            bundle_password: Password for PKCS#12 bundle
            
        Returns:
            Generated instruction text
        """
        try:
            template_path = self.templates_dir / f"{server_type}_template.txt"
            
            if not template_path.exists():
                logger.warning(f"Template not found: {template_path}, using fallback")
                return self._generate_fallback_instructions(server_type, certificate_data)
            
            # Read template
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
            
            # Prepare template variables
            variables = self._prepare_template_variables(
                certificate_data, zip_password, bundle_password, server_type
            )
            
            # Replace variables in template
            instructions = self._replace_template_variables(template, variables)
            
            logger.info(f"Generated {server_type} installation instructions with {len(variables)} variables")
            return instructions
            
        except Exception as e:
            logger.error(f"Failed to generate {server_type} instructions: {e}")
            return self._generate_fallback_instructions(server_type, certificate_data)

    def generate_certificate_info(self, certificate_data: Dict[str, Any], zip_password: str, p12_password: Optional[str] = None) -> str:
        """Generate certificate information text for IIS bundles"""
        
        try:
            # Extract certificate details
            domain_name = self._extract_domain_name(certificate_data)
            subject = certificate_data.get('subject', 'N/A')
            issuer = certificate_data.get('issuer', 'N/A')
            filename = certificate_data.get('filename', 'certificate.p12')
            expiry_date = certificate_data.get('expiry_date', 'N/A')
            
            # Format expiry date if it exists - NO EXTERNAL DEPENDENCIES
            if expiry_date and expiry_date != 'N/A':
                try:
                    if hasattr(expiry_date, 'strftime'):
                        # It's already a datetime object
                        expiry_date = expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC')
                    elif isinstance(expiry_date, str):
                        # Try basic string formatting - no external dependency
                        # Just keep the original format if it looks reasonable
                        if len(expiry_date) > 10:  # Looks like a datetime string
                            expiry_date = expiry_date[:19]  # Keep first 19 chars (YYYY-MM-DD HH:MM:SS)
                except Exception:
                    pass  # Keep original format if anything fails
            
            info_lines = [
                "CERTIFICATE INFORMATION",
                "=" * 50,
                "",
                f"Domain: {domain_name}",
                f"Subject: {subject}",
                f"Issuer: {issuer}",
                f"Original Filename: {filename}",
                f"Expiry Date: {expiry_date}",
                "",
                "BUNDLE CONTENTS:",
                "- Certificate file (PKCS#12 format)",
                "- Private key (included in PKCS#12)",
                "- Certificate chain (if available)",
                "- Installation guides",
                "",
                "PASSWORDS:",
                f"ZIP Password: {zip_password}",
            ]
            
            if p12_password:
                info_lines.append(f"PKCS#12 Password: {p12_password}")
            else:
                info_lines.append("PKCS#12 Password: Not encrypted")
            
            info_lines.extend([
                "",
                "INSTALLATION:",
                "1. Extract the PKCS#12 file from this ZIP using the ZIP password",
                "2. Import the PKCS#12 file into Windows Certificate Store",
                "3. Configure IIS SSL bindings for your website",
                "4. Follow the IIS_INSTALLATION_GUIDE.txt for detailed steps",
                "",
                "SECURITY NOTES:",
                "- Store all passwords securely and separately",
                "- Delete this bundle after successful installation",
                "- Backup your certificate in a secure location",
                "- Monitor certificate expiry and renew before expiration",
                "",
                f"Generated by Certificate Analysis Tool at {datetime.now().isoformat()}"
            ])
            
            return '\n'.join(info_lines)
            
        except Exception as e:
            logger.error(f"Failed to generate certificate info: {e}")
            return f"Certificate Information\n\nDomain: {certificate_data.get('domain_name', 'N/A')}\nGenerated: {datetime.now().isoformat()}"

    def generate_advanced_download_info(self, session_id: str, component_count: int, zip_password: str) -> str:
        """Generate information file for advanced downloads"""
        
        info_lines = [
            "ADVANCED DOWNLOAD PACKAGE",
            "=" * 50,
            "",
            f"Session ID: {session_id}",
            f"Package created: {datetime.now().isoformat()}",
            f"Components included: {component_count}",
            "",
            "SECURITY INFORMATION:",
            f"ZIP Password: {zip_password}",
            "",
            "- This ZIP file is password-protected using AES-256 encryption",
            "- Store the password securely and separately from the ZIP file",
            "- Individual PKCS#12 bundles may have additional passwords",
            "",
            "PACKAGE CONTENTS:",
            "- Individual PKI components in requested formats",
            "- PKI bundles (if selected)",
            "- This information file",
            "",
            "SUPPORTED FORMATS:",
            "- PEM: Base64 encoded text format",
            "- DER: Binary encoded format", 
            "- PKCS#8: Standard private key format",
            "- PKCS#7: Certificate chain format",
            "- PKCS#12: Complete certificate bundle",
            "",
            "INSTALLATION:",
            "1. Extract files using the ZIP password above",
            "2. Use the appropriate files for your server configuration",
            "3. Follow server-specific installation guides if included",
            "4. Set proper file permissions (private keys should be 600)",
            "",
            "SECURITY BEST PRACTICES:",
            "- Never share private keys or passwords",
            "- Use strong file permissions on extracted files",
            "- Delete temporary files after installation",
            "- Monitor certificate expiry dates",
            "- Keep backups in secure locations",
            "",
            f"Generated by Certificate Analysis Tool"
        ]
        
        return '\n'.join(info_lines)

    def _prepare_template_variables(self, cert_data: Dict[str, Any], 
                                  zip_password: Optional[str] = None, 
                                  bundle_password: Optional[str] = None,
                                  server_type: str = 'apache') -> Dict[str, str]:
        """Prepare variables for template replacement with PROPER data extraction"""
        
        logger.debug(f"Preparing template variables for {server_type}")
        logger.debug(f"Certificate data keys: {list(cert_data.keys())}")
        
        # Extract domain name (most important variable)
        domain_name = self._extract_domain_name(cert_data)
        
        # Create filesystem-safe domain name
        safe_domain_name = domain_name.replace('.', '_').replace('*', 'wildcard')
        
        # Extract subject and issuer
        subject = cert_data.get('subject', domain_name)
        issuer = cert_data.get('issuer', 'Unknown CA')
        
        # Extract dates - NO EXTERNAL DEPENDENCIES
        expiry_date = cert_data.get('expiry_date', 'N/A')
        if expiry_date and expiry_date != 'N/A':
            try:
                if hasattr(expiry_date, 'strftime'):
                    # It's already a datetime object
                    expiry_date = expiry_date.strftime('%Y-%m-%d')
                elif isinstance(expiry_date, str):
                    # Try basic string formatting - no external dependency
                    # Extract date part if it looks like ISO format
                    if 'T' in expiry_date:  # ISO format like 2024-12-31T23:59:59
                        expiry_date = expiry_date.split('T')[0]  # Keep just the date part
                    elif len(expiry_date) >= 10 and '-' in expiry_date:
                        expiry_date = expiry_date[:10]  # Keep first 10 chars (YYYY-MM-DD)
            except Exception:
                expiry_date = str(expiry_date)
        
        # Generate appropriate filenames based on server type and actual content
        filenames = self._generate_filenames(domain_name, server_type)
        
        # Extract SAN domains
        san_domains = self._extract_san_domains(cert_data)
        
        variables = {
            # Domain information
            'domain_name': domain_name,
            'safe_domain_name': safe_domain_name,
            'san_domains': san_domains,
            'certificate_cn': domain_name,
            
            # File names (corrected for actual download names)
            'certificate_filename': filenames['certificate'],
            'private_key_filename': filenames['private_key'],
            'certificate_chain_filename': filenames['ca_bundle'],
            'pkcs12_filename': filenames['pkcs12'],
            
            # Certificate details
            'subject': subject,
            'issuer': issuer,
            'expiry_date': expiry_date,
            'certificate_type': cert_data.get('certificate_type', 'RSA Certificate'),
            'validity_period': f"Valid until {expiry_date}",
            
            # Passwords
            'zip_password': zip_password or 'PROVIDED_IN_DOWNLOAD_RESPONSE',
            'bundle_password': bundle_password or 'N/A',
            
            # Timestamps
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            
            # Additional fields for template compatibility
            'key_algorithm': 'RSA',
            'key_size': '2048',
            'issuer_name': issuer
        }
        
        logger.debug(f"Prepared {len(variables)} template variables")
        return variables

    def _extract_domain_name(self, cert_data: Dict[str, Any]) -> str:
        """Extract primary domain name from certificate data"""
        
        # Try domain_name field first (from advanced downloads)
        if 'domain_name' in cert_data and cert_data['domain_name']:
            return cert_data['domain_name']
        
        # Try subject_common_name
        if 'subject_common_name' in cert_data and cert_data['subject_common_name']:
            return cert_data['subject_common_name']
        
        # Try extracting from subject string
        subject = cert_data.get('subject', '')
        if 'CN=' in subject:
            for part in subject.split(','):
                if 'CN=' in part:
                    cn = part.split('CN=')[1].strip()
                    if cn:
                        return cn
        
        # Try SAN domains
        san_domains = self._extract_san_domains(cert_data)
        if san_domains and san_domains != 'N/A':
            first_san = san_domains.split(',')[0].strip()
            if first_san:
                return first_san
        
        # Fallback to filename without extension
        filename = cert_data.get('filename', 'example.com')
        if '.' in filename:
            # Remove file extension
            base_name = '.'.join(filename.split('.')[:-1])
            if base_name:
                return base_name
        
        return 'example.com'

    def _extract_san_domains(self, cert_data: Dict[str, Any]) -> str:
        """Extract Subject Alternative Names from certificate data"""
        
        # Try subject_alt_name field
        san_list = cert_data.get('subject_alt_name', [])
        if isinstance(san_list, list) and san_list:
            # Filter out DNS entries and clean them
            dns_names = []
            for san in san_list:
                if isinstance(san, str):
                    if san.startswith('DNS:'):
                        dns_names.append(san[4:])  # Remove 'DNS:' prefix
                    elif '.' in san:  # Looks like a domain
                        dns_names.append(san)
            
            if dns_names:
                return ', '.join(dns_names)
        
        # Try subject_alt_name as string
        san_str = cert_data.get('subject_alt_name', '')
        if isinstance(san_str, str) and san_str:
            return san_str
        
        # Fallback to domain name
        domain_name = self._extract_domain_name(cert_data)
        return domain_name if domain_name != 'example.com' else 'N/A'

    def _generate_filenames(self, domain_name: str, server_type: str) -> Dict[str, str]:
        """Generate appropriate filenames based on server type and actual download names"""
        
        safe_domain = domain_name.replace('.', '_').replace('*', 'wildcard')
        
        if server_type == 'apache':
            return {
                'certificate': 'certificate.crt',  # Matches Apache download
                'private_key': 'private-key.pem',      # Matches Apache download  
                'ca_bundle': 'ca-bundle.crt',     # Matches Apache download
                'pkcs12': f'{safe_domain}.p12'
            }
        elif server_type == 'nginx':
            return {
                'certificate': 'certificate.crt',  # Matches Apache download
                'private_key': 'private-key.pem',      # Matches Apache download
                'ca_bundle': 'ca-bundle.crt',     # Matches Apache download
                'pkcs12': f'{safe_domain}.p12'
            }
        elif server_type == 'iis':
            return {
                'certificate': f'{safe_domain}.crt',
                'private_key': f'{safe_domain}.key',
                'ca_bundle': 'ca-bundle.crt',
                'pkcs12': 'certificate-bundle.pfx'       # Matches IIS download
            }
        else:  # advanced downloads
            return {
                'certificate': f'{safe_domain}.crt',
                'private_key': f'{safe_domain}.key',
                'ca_bundle': 'ca-bundle.crt',
                'pkcs12': f'{safe_domain}.p12'
            }

    def _replace_template_variables(self, template: str, variables: Dict[str, str]) -> str:
        """Replace template variables with actual values"""
        result = template
        
        replacements_made = 0
        for key, value in variables.items():
            placeholder = f"{{{key}}}"
            if placeholder in result:
                result = result.replace(placeholder, str(value))
                replacements_made += 1
        
        logger.debug(f"Made {replacements_made} template variable replacements")
        return result

    def _generate_fallback_instructions(self, server_type: str, certificate_data: Dict[str, Any]) -> str:
        """Generate basic fallback instructions when template is not available"""
        
        domain_name = self._extract_domain_name(certificate_data)
        
        return f"""
{server_type.upper()} SSL CERTIFICATE INSTALLATION

Domain: {domain_name}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

This is a basic installation guide. Please consult your {server_type} documentation
for detailed configuration instructions.

1. Extract the certificate files from the downloaded ZIP
2. Copy certificate files to your {server_type} SSL directory
3. Configure your {server_type} virtual host/server block
4. Test the SSL configuration
5. Restart {server_type}

For detailed instructions, please refer to:
- {server_type.title()} official documentation
- Your system administrator
- Certificate Authority support

Generated by Certificate Analysis Tool
"""

    def get_available_templates(self) -> list:
        """Get list of available instruction templates"""
        templates = []
        if self.templates_dir.exists():
            for template_file in self.templates_dir.glob("*_template.txt"):
                server_type = template_file.stem.replace('_template', '')
                templates.append(server_type)
        return templates