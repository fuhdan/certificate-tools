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
        """Prepare variables for template replacement - FIXED to handle flat certificate data"""
        
        # FIXED: Handle both nested and flat certificate data structures
        # Extract certificate information - support both formats
        if isinstance(cert_data.get('subject'), dict):
            # Nested format: {'subject': {'commonName': 'example.com'}}
            common_name = cert_data.get('subject', {}).get('commonName', 'example.com')
        else:
            # Flat format: {'subject_common_name': 'example.com'}
            common_name = cert_data.get('subject_common_name', 'example.com')
        
        # Get SAN domains - handle both formats
        san_list = []
        if 'extensions' in cert_data and 'subjectAltName' in cert_data['extensions']:
            # Nested format
            san_data = cert_data['extensions']['subjectAltName']
            if isinstance(san_data, dict) and 'dnsNames' in san_data:
                san_list = san_data['dnsNames']
        elif 'subject_alt_name' in cert_data:
            # Flat format: ['DNS:web.example.com', 'IP:192.168.1.100']
            subject_alt_names = cert_data['subject_alt_name']
            if isinstance(subject_alt_names, list):
                san_list = [san.replace('DNS:', '') for san in subject_alt_names if san.startswith('DNS:')]
        
        san_domains = ', '.join(san_list) if san_list else common_name
        
        # Primary domain (first SAN or CN)
        domain_name = san_list[0] if san_list else common_name
        
        # Filesystem-safe domain name
        safe_domain_name = domain_name.replace('.', '_').replace('*', 'wildcard')
        
        # Certificate dates - handle both formats
        valid_from = cert_data.get('validFrom') or cert_data.get('not_valid_before', 'N/A')
        valid_to = cert_data.get('validTo') or cert_data.get('not_valid_after') or cert_data.get('expiry_date', 'N/A')
        
        # Key information - handle both formats
        if 'publicKey' in cert_data:
            # Nested format
            key_info = cert_data.get('publicKey', {})
            key_algorithm = key_info.get('algorithm', 'RSA')
            key_size = str(key_info.get('keySize', 2048))
        else:
            # Flat format
            key_algorithm = cert_data.get('public_key_algorithm', 'RSA')
            key_size = str(cert_data.get('public_key_size', 2048))
        
        # Issuer - handle both formats
        if isinstance(cert_data.get('issuer'), dict):
            # Nested format
            issuer_info = cert_data.get('issuer', {})
            issuer_name = issuer_info.get('commonName', 'Unknown CA')
        else:
            # Flat format
            issuer_name = cert_data.get('issuer_common_name', 'Unknown CA')
        
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