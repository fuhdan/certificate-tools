# backend-fastapi/certificates/storage/crypto_access.py
# Clean crypto object access from unified PEM storage

import logging
from typing import Dict, Any, Optional, List
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from .unified_storage import unified_storage

logger = logging.getLogger(__name__)

class CryptoObjectAccess:
    """
    Clean interface to access crypto objects from unified PEM storage
    Converts PEM content to crypto objects on-demand
    """
    
    @staticmethod
    def get_certificate(cert_id: str, session_id: str) -> Optional[x509.Certificate]:
        """Get certificate crypto object from PEM"""
        unified_cert = unified_storage.get_certificate(cert_id, session_id)
        if not unified_cert or not unified_cert.certificate_pem:
            return None
        
        try:
            return x509.load_pem_x509_certificate(unified_cert.certificate_pem.encode())
        except Exception as e:
            logger.error(f"Error loading certificate {cert_id}: {e}")
            return None
    
    @staticmethod
    def get_private_key(cert_id: str, session_id: str):
        """Get private key crypto object from PEM"""
        unified_cert = unified_storage.get_certificate(cert_id, session_id)
        if not unified_cert or not unified_cert.private_key_pem:
            return None
        
        try:
            return serialization.load_pem_private_key(
                unified_cert.private_key_pem.encode(), 
                password=None
            )
        except Exception as e:
            logger.error(f"Error loading private key {cert_id}: {e}")
            return None
    
    @staticmethod
    def get_csr(cert_id: str, session_id: str) -> Optional[x509.CertificateSigningRequest]:
        """Get CSR crypto object from PEM"""
        unified_cert = unified_storage.get_certificate(cert_id, session_id)
        if not unified_cert or not unified_cert.csr_pem:
            return None
        
        try:
            return x509.load_pem_x509_csr(unified_cert.csr_pem.encode())
        except Exception as e:
            logger.error(f"Error loading CSR {cert_id}: {e}")
            return None
    
    @staticmethod
    def get_additional_certificates(cert_id: str, session_id: str) -> List[x509.Certificate]:
        """Get additional certificates crypto objects from PEM"""
        unified_cert = unified_storage.get_certificate(cert_id, session_id)
        if not unified_cert or not unified_cert.additional_certificates_pem:
            return []
        
        certificates = []
        for cert_pem in unified_cert.additional_certificates_pem:
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode())
                certificates.append(cert)
            except Exception as e:
                logger.error(f"Error loading additional certificate: {e}")
        
        return certificates
    
    @staticmethod
    def get_all_crypto_objects(cert_id: str, session_id: str) -> Dict[str, Any]:
        """Get all available crypto objects for a certificate"""
        crypto_objects = {}
        
        cert = CryptoObjectAccess.get_certificate(cert_id, session_id)
        if cert:
            crypto_objects['certificate'] = cert
        
        private_key = CryptoObjectAccess.get_private_key(cert_id, session_id)
        if private_key:
            crypto_objects['private_key'] = private_key
        
        csr = CryptoObjectAccess.get_csr(cert_id, session_id)
        if csr:
            crypto_objects['csr'] = csr
        
        additional_certs = CryptoObjectAccess.get_additional_certificates(cert_id, session_id)
        if additional_certs:
            crypto_objects['additional_certificates'] = additional_certs
        
        return crypto_objects