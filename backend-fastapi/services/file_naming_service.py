# backend-fastapi/services/file_naming_service.py
"""
Simple file naming service for standardized certificate download filenames.
"""

import logging

logger = logging.getLogger(__name__)

def get_standard_filename(component_type, file_format: str) -> str:
    """
    Get standardized filename for certificate downloads.
    """
    from certificates.storage.session_pki_storage import PKIComponentType

    logger.debug(f"Generating standard filename for component_type={component_type}, file_format={file_format}")

    format_lower = file_format.lower()

    # Bundle formats FIRST (before component-specific checks)
    if format_lower in ['p12', 'pkcs12']:
        logger.debug("Matched bundle format: PKCS#12")
        return "certificate-bundle.p12"
    elif format_lower == 'pfx':
        logger.debug("Matched bundle format: PFX")
        return "certificate-bundle.pfx"
    elif format_lower in ['p7b', 'pkcs7']:
        logger.debug("Matched bundle format: PKCS#7 (.p7b)")
        return "certificate-bundle.p7b"
    elif format_lower == 'p7c':
        logger.debug("Matched bundle format: PKCS#7 (.p7c)")
        return "certificate-bundle.p7c"

    # CSR files
    if component_type == PKIComponentType.CSR:
        logger.debug("Matched component type: CSR")
        filename = "csr.der" if format_lower == 'der' else "csr.pem"
        logger.debug(f"Returning filename: {filename}")
        return filename

    # Private key files
    elif component_type == PKIComponentType.PRIVATE_KEY:
        logger.debug("Matched component type: PRIVATE_KEY")
        if format_lower == 'der':
            filename = "private-key.der"
        elif format_lower in ['p8', 'pkcs8', 'pkcs8_encrypted']:
            # All PKCS#8 variants use .p8 extension
            filename = "private-key.p8"
        elif format_lower in ['pem_encrypted']:
            # Encrypted PEM still uses .pem extension
            filename = "private-key.pem"
        else:
            filename = "private-key.pem"
        logger.debug(f"Returning filename: {filename}")
        return filename

    # Certificate files
    elif component_type == PKIComponentType.CERTIFICATE:
        logger.debug("Matched component type: CERTIFICATE")
        filename = "certificate.der" if format_lower == 'der' else "certificate.crt"
        logger.debug(f"Returning filename: {filename}")
        return filename

    # CA certificates
    elif component_type in [PKIComponentType.ISSUING_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ROOT_CA]:
        logger.debug("Matched component type: CA certificate")
        filename = "certificate-chain.der" if format_lower == 'der' else "certificate-chain.pem"
        logger.debug(f"Returning filename: {filename}")
        return filename

    # Fallback
    filename = f"{component_type.type_name.lower()}.{format_lower}"
    logger.debug(f"No specific match found, using fallback filename: {filename}")
    return filename
