# backend-fastapi/services/format_converter.py
"""
Format Converter Service

Converts PKI components between different formats (PEM, DER, PKCS#8, etc.)
"""

import logging
from typing import Union, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

logger = logging.getLogger(__name__)

class FormatConverter:
    """Service to convert PKI components between formats"""
    
    def __init__(self):
        pass
    
    def convert_private_key(self, 
                          private_key_content: str, 
                          target_format: str, 
                          password: Optional[str] = None) -> bytes:
        """
        Convert private key to target format
        
        Args:
            private_key_content: Original PEM/DER private key content
            target_format: Target format (pem, der, pkcs8, pkcs8_encrypted, pem_encrypted)
            password: Password for encrypted formats
            
        Returns:
            Converted private key as bytes
        """
        logger.debug(f"Converting private key to format: {target_format}")
        
        # Parse the original private key
        if isinstance(private_key_content, str):
            # Assume PEM if it's a string
            private_key = serialization.load_pem_private_key(
                private_key_content.encode(), 
                password=None
            )
        else:
            # Assume DER if it's bytes
            private_key = serialization.load_der_private_key(
                private_key_content, 
                password=None
            )
        
        # Convert to target format
        if target_format.lower() == 'pem':
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
        elif target_format.lower() == 'der':
            return private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
        elif target_format.lower() in ['pkcs8', 'p8']:
            return private_key.private_bytes(
                encoding=serialization.Encoding.DER,  # FIXED: Use DER for PKCS#8
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
        elif target_format.lower() == 'pkcs8_encrypted':
            if not password:
                from services.secure_zip_creator import secure_zip_creator
                password = secure_zip_creator.generate_secure_password()
                # Store password for manifest use
                self._last_encryption_password = password
                # Log the generated password so it's visible
                logger.info(f"🔐 Generated PKCS#8 encryption password: {password}")
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        
        elif target_format.lower() == 'pem_encrypted':
            if not password:
                from services.secure_zip_creator import secure_zip_creator
                password = secure_zip_creator.generate_secure_password()
                # Store password for manifest use
                self._last_encryption_password = password
                # Log the generated password so it's visible
                logger.info(f"🔐 Generated PEM encryption password: {password}")
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        
        else:
            # Default to PEM
            logger.warning(f"Unknown format {target_format}, defaulting to PEM")
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
    
    def convert_certificate(self, 
                          certificate_content: str, 
                          target_format: str) -> bytes:
        """
        Convert certificate to target format
        
        Args:
            certificate_content: Original PEM/DER certificate content
            target_format: Target format (pem, der)
            
        Returns:
            Converted certificate as bytes
        """
        logger.debug(f"Converting certificate to format: {target_format}")
        
        # Parse the original certificate
        if isinstance(certificate_content, str):
            # Assume PEM if it's a string
            certificate = x509.load_pem_x509_certificate(certificate_content.encode())
        else:
            # Assume DER if it's bytes
            certificate = x509.load_der_x509_certificate(certificate_content)
        
        # Convert to target format
        if target_format.lower() == 'pem':
            return certificate.public_bytes(serialization.Encoding.PEM)
        elif target_format.lower() == 'der':
            return certificate.public_bytes(serialization.Encoding.DER)
        else:
            # Default to PEM
            logger.warning(f"Unknown format {target_format}, defaulting to PEM")
            return certificate.public_bytes(serialization.Encoding.PEM)
    
    def convert_csr(self, 
                   csr_content: str, 
                   target_format: str) -> bytes:
        """
        Convert CSR to target format
        
        Args:
            csr_content: Original PEM/DER CSR content
            target_format: Target format (pem, der)
            
        Returns:
            Converted CSR as bytes
        """
        logger.debug(f"Converting CSR to format: {target_format}")
        
        # Parse the original CSR
        if isinstance(csr_content, str):
            # Assume PEM if it's a string
            csr = x509.load_pem_x509_csr(csr_content.encode())
        else:
            # Assume DER if it's bytes
            csr = x509.load_der_x509_csr(csr_content)
        
        # Convert to target format
        if target_format.lower() == 'pem':
            return csr.public_bytes(serialization.Encoding.PEM)
        elif target_format.lower() == 'der':
            return csr.public_bytes(serialization.Encoding.DER)
        else:
            # Default to PEM
            logger.warning(f"Unknown format {target_format}, defaulting to PEM")
            return csr.public_bytes(serialization.Encoding.PEM)

# Global instance
format_converter = FormatConverter()

# Add method to get the last encryption password
def get_last_encryption_password() -> Optional[str]:
    """Get the last encryption password generated from the global instance"""
    return format_converter._last_encryption_password