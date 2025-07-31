# certificates/types.py
# Standardized certificate type definitions for consistent naming across the system

from enum import Enum
from typing import Dict, Any, Optional

class CertificateType(Enum):
    """Standardized certificate types for consistent naming"""
    CSR = "CSR"
    PRIVATE_KEY = "PrivateKey"
    CERTIFICATE = "Certificate"  # End-entity certificate
    ISSUING_CA = "IssuingCA"
    INTERMEDIATE_CA = "IntermediateCA"
    ROOT_CA = "RootCA"
    CERTIFICATE_CHAIN = "CertificateChain"
    UNKNOWN = "Unknown"

class DisplayLabels:
    """Human-readable labels for certificate types"""
    LABELS = {
        CertificateType.CSR: "Certificate Signing Request",
        CertificateType.PRIVATE_KEY: "Private Key",
        CertificateType.CERTIFICATE: "End-Entity Certificate",
        CertificateType.ISSUING_CA: "Issuing CA Certificate",
        CertificateType.INTERMEDIATE_CA: "Intermediate CA Certificate", 
        CertificateType.ROOT_CA: "Root CA Certificate",
        CertificateType.CERTIFICATE_CHAIN: "Certificate Chain",
        CertificateType.UNKNOWN: "Unknown"
    }
    
    @classmethod
    def get_label(cls, cert_type: CertificateType) -> str:
        return cls.LABELS.get(cert_type, "Unknown")

class HierarchyOrder:
    """PKI hierarchy ordering for certificates"""
    ORDER = {
        CertificateType.CSR: 1,
        CertificateType.PRIVATE_KEY: 2,
        CertificateType.CERTIFICATE: 3,  # End-entity
        CertificateType.ISSUING_CA: 4,
        CertificateType.INTERMEDIATE_CA: 5,
        CertificateType.ROOT_CA: 6,
        CertificateType.CERTIFICATE_CHAIN: 7,
        CertificateType.UNKNOWN: 8
    }
    
    @classmethod
    def get_order(cls, cert_type: CertificateType) -> int:
        return cls.ORDER.get(cert_type, 999)

def normalize_certificate_type(raw_type: str, details: Optional[Dict[str, Any]] = None) -> CertificateType:
    """
    Normalize various certificate type strings to standard CertificateType enum
    
    Args:
        raw_type: Raw type string from analysis
        details: Certificate details for CA classification
        
    Returns:
        Standardized CertificateType enum value
    """
    if not raw_type:
        return CertificateType.UNKNOWN
    
    raw_type = raw_type.strip()
    
    # Direct mappings
    if raw_type in ['CSR', 'Certificate Signing Request']:
        return CertificateType.CSR
    
    if raw_type in ['Private Key', 'PrivateKey']:
        return CertificateType.PRIVATE_KEY
    
    if raw_type in ['Certificate Chain', 'CertificateChain']:
        return CertificateType.CERTIFICATE_CHAIN
    
    # Certificate types - need to analyze CA vs end-entity
    if raw_type in ['Certificate', 'PKCS12 Certificate']:
        if details:
            extensions = details.get('extensions', {})
            basic_constraints = extensions.get('basicConstraints', {})
            is_ca = basic_constraints.get('isCA', False)
            
            if not is_ca:
                return CertificateType.CERTIFICATE  # End-entity
            else:
                # Determine CA type
                subject = details.get('subject', {})
                issuer = details.get('issuer', {})
                subject_cn = subject.get('commonName', '')
                issuer_cn = issuer.get('commonName', '')
                
                # Self-signed = Root CA
                if subject_cn == issuer_cn:
                    return CertificateType.ROOT_CA
                # Check for issuing CA indicators
                elif any(indicator in subject_cn.lower() for indicator in ['issuing', 'leaf']):
                    return CertificateType.ISSUING_CA
                else:
                    return CertificateType.INTERMEDIATE_CA
        
        # Default to end-entity if no details
        return CertificateType.CERTIFICATE
    
    # Legacy CA Certificate handling
    if raw_type in ['CA Certificate', 'Root CA Certificate', 'RootCA']:
        if details:
            subject = details.get('subject', {})
            issuer = details.get('issuer', {})
            subject_cn = subject.get('commonName', '')
            issuer_cn = issuer.get('commonName', '')
            
            if subject_cn == issuer_cn:
                return CertificateType.ROOT_CA
            else:
                return CertificateType.INTERMEDIATE_CA
        return CertificateType.ROOT_CA
    
    # Direct CA type mappings
    if raw_type in ['IssuingCA', 'Issuing CA']:
        return CertificateType.ISSUING_CA
    
    if raw_type in ['IntermediateCA', 'Intermediate CA Certificate']:
        return CertificateType.INTERMEDIATE_CA
    
    # Legacy end-entity handling
    if raw_type in ['End-entity Certificate', 'End Entity Certificate']:
        return CertificateType.CERTIFICATE
    
    return CertificateType.UNKNOWN

def get_consistent_types(raw_type: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    Get consistent type representations for all system parts
    
    Returns:
        Dict with 'type', 'fileType', and 'displayLabel' keys
    """
    cert_type = normalize_certificate_type(raw_type, details)
    
    return {
        'type': cert_type.value,           # For analysis.type
        'fileType': cert_type.value,       # For PKI bundle fileType  
        'displayLabel': DisplayLabels.get_label(cert_type)  # For UI display
    }