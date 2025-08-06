# backend-fastapi/services/file_naming_service.py
"""
Simple file naming service for standardized certificate download filenames.
"""

import logging

logger = logging.getLogger(__name__)

def get_standard_filename(component_type, file_format: str) -> str:
    """
    Get standardized filename for certificate downloads.
    
    Args:
        component_type: PKIComponentType from storage
        file_format: File format string (PEM, DER, PKCS12, etc.)
        
    Returns:
        Standard filename string
    """
    from certificates.storage.session_pki_storage import PKIComponentType
    
    format_lower = file_format.lower()
    
    # CSR files
    if component_type == PKIComponentType.CSR:
        return "csr.der" if format_lower == 'der' else "csr.pem"
    
    # Private key files  
    elif component_type == PKIComponentType.PRIVATE_KEY:
        if format_lower == 'der':
            return "private-key.der"
        elif format_lower in ['p8', 'pkcs8']:
            return "private-key.p8"
        else:
            return "private-key.pem"
    
    # Certificate files
    elif component_type == PKIComponentType.CERTIFICATE:
        return "certificate.der" if format_lower == 'der' else "certificate.crt"
    
    # CA certificates (issuing, intermediate, root) - always chain files
    elif component_type in [PKIComponentType.ISSUING_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ROOT_CA]:
        return "certificate-chain.der" if format_lower == 'der' else "certificate-chain.pem"
    
    # Bundle formats
    if format_lower in ['p12', 'pkcs12']:
        return "certificate-bundle.p12"
    elif format_lower == 'pfx':
        return "certificate-bundle.pfx"
    elif format_lower in ['p7b', 'pkcs7']:
        return "certificate-bundle.p7b"
    elif format_lower == 'p7c':
        return "certificate-bundle.p7c"
    
    # Fallback
    return f"{component_type.type_name.lower()}.{format_lower}"