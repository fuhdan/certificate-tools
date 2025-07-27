# backend-fastapi/certificates/validation/utils.py
# Helper functions for certificate validation

import logging
from typing import Dict, Any
from cryptography import x509
from cryptography.x509 import oid

logger = logging.getLogger(__name__)

def compare_subject_names(csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> Dict[str, Any]:
    """Compare subject names between CSR and certificate"""
    logger.debug("Comparing subject names...")
    
    try:
        # Extract common names
        csr_cn = None
        cert_cn = None
        
        for attribute in csr.subject:
            if attribute.oid == oid.NameOID.COMMON_NAME:
                csr_cn = attribute.value
                break
        
        for attribute in certificate.subject:
            if attribute.oid == oid.NameOID.COMMON_NAME:
                cert_cn = attribute.value
                break
        
        logger.debug(f"CSR CN: {csr_cn}")
        logger.debug(f"Certificate CN: {cert_cn}")
        
        cn_match = csr_cn == cert_cn
        
        return {
            "match": cn_match,
            "commonName": {
                "csr": csr_cn or "N/A",
                "certificate": cert_cn or "N/A",
                "match": cn_match
            }
        }
        
    except Exception as e:
        logger.error(f"Error comparing subject names: {e}")
        return {"match": False, "error": str(e)}

def compare_sans(csr: x509.CertificateSigningRequest, certificate: x509.Certificate) -> Dict[str, Any]:
    """Compare Subject Alternative Names between CSR and certificate"""
    logger.debug("Comparing Subject Alternative Names...")
    
    try:
        # Extract SANs from CSR
        csr_sans = []
        try:
            csr_san_ext = csr.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_values = csr_san_ext.value
            # Type cast to help Pylance understand this is a SubjectAlternativeName which is iterable
            if isinstance(san_values, x509.SubjectAlternativeName):
                for san in san_values:
                    if isinstance(san, x509.DNSName):
                        csr_sans.append(f"DNS:{san.value}")
                    elif isinstance(san, x509.IPAddress):
                        csr_sans.append(f"IP:{str(san.value)}")
                    elif isinstance(san, x509.RFC822Name):
                        csr_sans.append(f"Email:{san.value}")
                    elif isinstance(san, x509.UniformResourceIdentifier):
                        csr_sans.append(f"URI:{san.value}")
                    else:
                        csr_sans.append(f"Other:{str(san)}")
        except x509.ExtensionNotFound:
            logger.debug("No SAN extension found in CSR")
        
        # Extract SANs from certificate
        cert_sans = []
        try:
            cert_san_ext = certificate.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_values = cert_san_ext.value
            # Type cast to help Pylance understand this is a SubjectAlternativeName which is iterable
            if isinstance(san_values, x509.SubjectAlternativeName):
                for san in san_values:
                    if isinstance(san, x509.DNSName):
                        cert_sans.append(f"DNS:{san.value}")
                    elif isinstance(san, x509.IPAddress):
                        cert_sans.append(f"IP:{str(san.value)}")
                    elif isinstance(san, x509.RFC822Name):
                        cert_sans.append(f"Email:{san.value}")
                    elif isinstance(san, x509.UniformResourceIdentifier):
                        cert_sans.append(f"URI:{san.value}")
                    else:
                        cert_sans.append(f"Other:{str(san)}")
        except x509.ExtensionNotFound:
            logger.debug("No SAN extension found in certificate")
        
        logger.debug(f"CSR SANs: {csr_sans}")
        logger.debug(f"Certificate SANs: {cert_sans}")
        
        # Convert to sets for comparison
        csr_sans_set = set(csr_sans)
        cert_sans_set = set(cert_sans)
        
        # Check if they match
        sans_match = csr_sans_set == cert_sans_set
        
        # Find differences
        only_in_csr = list(csr_sans_set - cert_sans_set)
        only_in_certificate = list(cert_sans_set - csr_sans_set)
        
        return {
            "match": sans_match,
            "csr": csr_sans,
            "certificate": cert_sans,
            "onlyInCsr": only_in_csr,
            "onlyInCertificate": only_in_certificate
        }
        
    except Exception as e:
        logger.error(f"Error comparing SANs: {e}")
        return {"match": False, "error": str(e)}