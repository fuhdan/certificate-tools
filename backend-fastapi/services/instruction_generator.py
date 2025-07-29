# backend-fastapi/services/instruction_generator.py
"""
Installation Instructions Generator Service

Generates customized installation instructions for Linux Apache/Nginx and Windows IIS.
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
                raise FileNotFoundError(f"Template not found: {template_path}")
            
            # Read template
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
            
            # Prepare template variables
            variables = self._prepare_template_variables(
                certificate_data, zip_password, bundle_password
            )
            
            # Replace variables in template
            instructions = self._replace_template_variables(template, variables)
            
            logger.info(f"Generated {server_type} installation instructions")
            return instructions
            
        except Exception as e:
            logger.error(f"Failed to generate {server_type} instructions: {e}")
            raise
    
    def _prepare_template_variables(self, cert_data: Dict[str, Any], 
                                   zip_password: Optional[str] = None, 
                                   bundle_password: Optional[str] = None) -> Dict[str, str]:
        """Prepare variables for template replacement"""
        
        # Extract certificate information
        common_name = cert_data.get('subject', {}).get('commonName', 'example.com')
        
        # Get SAN domains
        san_list = []
        extensions = cert_data.get('extensions', {})
        if 'subjectAltName' in extensions:
            san_data = extensions['subjectAltName']
            if isinstance(san_data, dict) and 'dnsNames' in san_data:
                san_list = san_data['dnsNames']
        
        san_domains = ', '.join(san_list) if san_list else common_name
        
        # Primary domain (first SAN or CN)
        domain_name = san_list[0] if san_list else common_name
        
        # Filesystem-safe domain name
        safe_domain_name = domain_name.replace('.', '_').replace('*', 'wildcard')
        
        # Certificate dates
        valid_from = cert_data.get('validFrom', 'N/A')
        valid_to = cert_data.get('validTo', 'N/A')
        
        # Key information
        key_info = cert_data.get('publicKey', {})
        key_algorithm = key_info.get('algorithm', 'RSA')
        key_size = str(key_info.get('keySize', 2048))
        
        # Issuer
        issuer_info = cert_data.get('issuer', {})
        issuer_name = issuer_info.get('commonName', 'Unknown CA')
        
        # Prepare file names based on template structure from documents
        certificate_filename = f"{safe_domain_name}.crt"
        private_key_filename = f"{safe_domain_name}.key"
        certificate_chain_filename = "ca-bundle.crt"
        pkcs12_filename = f"{safe_domain_name}.p12"
        
        # Calculate validity period
        try:
            if valid_from != 'N/A' and valid_to != 'N/A':
                # Assuming dates are in a parseable format
                validity_period = f"{valid_from} to {valid_to}"
            else:
                validity_period = "See certificate details"
        except:
            validity_period = "See certificate details"
        
        return {
            'certificate_cn': common_name,
            'san_domains': san_domains,
            'domain_name': domain_name,
            'safe_domain_name': safe_domain_name,
            'zip_password': zip_password or 'N/A',
            'bundle_password': bundle_password or 'N/A',
            'expiry_date': valid_to,
            'valid_from': valid_from,
            'issuer_name': issuer_name,
            'key_algorithm': key_algorithm,
            'key_size': key_size,
            'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            # Additional variables for template compatibility
            'certificate_filename': certificate_filename,
            'private_key_filename': private_key_filename,
            'certificate_chain_filename': certificate_chain_filename,
            'pkcs12_filename': pkcs12_filename,
            'certificate_type': f"{key_algorithm} {key_size}-bit",
            'validity_period': validity_period,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        }
    
    def _replace_template_variables(self, template: str, variables: Dict[str, str]) -> str:
        """Replace template variables with actual values"""
        result = template
        
        for key, value in variables.items():
            placeholder = f"{{{key}}}"
            result = result.replace(placeholder, str(value))
        
        return result
    
    def get_available_templates(self) -> list:
        """Get list of available instruction templates"""
        templates = []
        for template_file in self.templates_dir.glob("*_template.txt"):
            server_type = template_file.stem.replace('_template', '')
            templates.append(server_type)
        return templates