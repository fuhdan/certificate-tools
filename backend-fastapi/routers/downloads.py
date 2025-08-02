# backend-fastapi/routers/downloads.py
# Updated download endpoints for unified PEM storage

import logging
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Response, Depends
from fastapi.responses import StreamingResponse

from middleware.session_middleware import get_session_id
from certificates.storage import CertificateStorage, CryptoObjectAccess
from services.secure_zip_creator import secure_zip_creator, SecureZipCreatorError
from services.instruction_generator import InstructionGenerator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/downloads", tags=["downloads"])

@router.post("/apache/{session_id}")
async def download_apache_bundle(
    session_id: str,
    session_id_validated: str = Depends(get_session_id)
):
    """
    Generate Apache-compatible certificate bundle as password-protected ZIP file.
    Updated for unified PEM storage.
    """
    logger.info(f"Apache bundle download started for session: {session_id}")
    
    try:
        # Validate session_id from path matches validated session
        if session_id != session_id_validated:
            logger.warning(f"Session ID mismatch: path={session_id}, validated={session_id_validated}")
            raise HTTPException(
                status_code=400, 
                detail="Session ID validation failed"
            )
        
        # Get all certificates from unified storage
        certificates = CertificateStorage.get_all(session_id)
        
        if not certificates:
            logger.warning(f"No certificates found in session: {session_id}")
            raise HTTPException(
                status_code=404,
                detail="No certificates found in session"
            )
        
        # Debug: Log certificate types
        logger.debug(f"Found {len(certificates)} certificates in session:")
        for i, cert in enumerate(certificates):
            logger.debug(f"  [{i}] {cert.filename} - has_cert: {cert.has_certificate}, has_key: {cert.has_private_key}")
        
        # Find the primary end-entity certificate
        primary_cert = _find_primary_certificate(certificates)
        if not primary_cert:
            logger.warning(f"No end-entity certificate found in session: {session_id}")
            raise HTTPException(
                status_code=404,
                detail="No end-entity certificate found in session"
            )
        
        logger.debug(f"Using primary certificate: {primary_cert.filename}")
        
        # Extract certificate data from unified storage
        try:
            certificate_data = _extract_certificate_data_for_apache(primary_cert, certificates, session_id)
        except ValueError as e:
            logger.warning(f"Certificate data extraction error for session {session_id}: {e}")
            raise HTTPException(status_code=404, detail=f"Certificate data incomplete: {e}")
        
        # Generate installation guides
        instruction_generator = InstructionGenerator()
        
        apache_guide = instruction_generator.generate_instructions(
            server_type="apache",
            certificate_data=certificate_data
        )
        
        nginx_guide = instruction_generator.generate_instructions(
            server_type="nginx", 
            certificate_data=certificate_data
        )
        
        # Create password-protected ZIP bundle
        zip_data, password = secure_zip_creator.create_apache_bundle(
            certificate=certificate_data['certificate'],
            private_key=certificate_data['private_key'],
            ca_bundle=certificate_data['ca_bundle'],
            apache_guide=apache_guide,
            nginx_guide=nginx_guide
        )
        
        logger.info(f"Apache bundle created successfully for session: {session_id}")
        
        # Return ZIP file with password in header
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=apache-bundle-{session_id}.zip",
                "X-Zip-Password": password,
                "Content-Length": str(len(zip_data))
            }
        )
        
    except SecureZipCreatorError as e:
        logger.error(f"ZIP creation failed for session {session_id}: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Failed to create certificate bundle"
        )
    
    except HTTPException as http_exc:
        raise http_exc
    
    except Exception as e:
        logger.error(f"Unexpected error creating Apache bundle for session {session_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while creating bundle"
        )

@router.post("/iis/{session_id}")
async def download_iis_bundle(
    session_id: str,
    session_id_validated: str = Depends(get_session_id)
):
    """
    Generate IIS-compatible PKCS#12 bundle.
    Updated for unified PEM storage.
    """
    logger.info(f"IIS bundle download started for session: {session_id}")
    
    try:
        # Validate session_id
        if session_id != session_id_validated:
            raise HTTPException(status_code=400, detail="Session ID validation failed")
        
        # Get certificates from unified storage
        certificates = CertificateStorage.get_all(session_id)
        
        if not certificates:
            raise HTTPException(status_code=404, detail="No certificates found in session")
        
        # Find primary certificate
        primary_cert = _find_primary_certificate(certificates)
        if not primary_cert:
            raise HTTPException(status_code=404, detail="No end-entity certificate found")
        
        # Extract certificate data for IIS
        try:
            certificate_data = _extract_certificate_data_for_iis(primary_cert, certificates, session_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=f"Certificate data incomplete: {e}")
        
        # Create PKCS#12 bundle first
        p12_bundle = _create_pkcs12_bundle(
            certificate_data['certificate'],
            certificate_data['private_key'],
            certificate_data['ca_bundle']
        )
        
        # Generate installation guide
        instruction_generator = InstructionGenerator()
        iis_guide = instruction_generator.generate_instructions(
            server_type="iis",
            certificate_data=certificate_data
        )
        
        # Create certificate info text
        cert_info = _create_certificate_info_text(certificate_data)
        
        # Create password-protected ZIP bundle
        zip_data, password = secure_zip_creator.create_iis_bundle(
            p12_bundle=p12_bundle,
            iis_guide=iis_guide,
            cert_info=cert_info
        )
        
        logger.info(f"IIS bundle created successfully for session: {session_id}")
        
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=iis-bundle-{session_id}.zip",
                "X-Zip-Password": password,
                "Content-Length": str(len(zip_data))
            }
        )
        
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.error(f"Unexpected error creating IIS bundle for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while creating bundle")

# Helper functions for unified storage

def _find_primary_certificate(certificates):
    """Find the primary end-entity certificate from unified storage"""
    
    # Look for end-entity certificates (has certificate but is not CA)
    for cert in certificates:
        if (cert.has_certificate and 
            cert.certificate_info and 
            not cert.certificate_info.is_ca):
            return cert
    
    # Fallback: any certificate that's not a CA
    for cert in certificates:
        if cert.has_certificate:
            return cert
    
    return None

def _extract_certificate_data_for_apache(primary_cert, all_certificates, session_id):
    """
    Extract certificate data for Apache bundle from unified storage
    
    Args:
        primary_cert: Primary end-entity certificate (UnifiedCertificateModel)
        all_certificates: All certificates in session
        session_id: Session identifier
        
    Returns:
        Dictionary containing certificate, private_key, ca_bundle, and metadata
    """
    logger.debug(f"Extracting certificate data for Apache bundle")
    
    # Get unified certificate data
    unified_cert = CertificateStorage.get_unified_by_id(primary_cert.id, session_id)
    if not unified_cert:
        raise ValueError("Primary certificate not found in unified storage")
    
    # Extract certificate PEM
    if not unified_cert.certificate_pem:
        raise ValueError("Certificate PEM not found")
    certificate_pem = unified_cert.certificate_pem
    
    # Extract private key PEM
    private_key_pem = None
    if unified_cert.private_key_pem:
        private_key_pem = unified_cert.private_key_pem
        logger.debug("Found private key bundled with certificate")
    else:
        # Search for separate private key in session
        for cert in all_certificates:
            if cert.has_private_key and not cert.has_certificate:
                separate_unified = CertificateStorage.get_unified_by_id(cert.id, session_id)
                if separate_unified and separate_unified.private_key_pem:
                    private_key_pem = separate_unified.private_key_pem
                    logger.debug("Found separate private key in session")
                    break
    
    if not private_key_pem:
        raise ValueError("No private key found. Apache requires a private key.")
    
    # Build CA bundle from additional certificates
    ca_bundle_parts = []
    
    # Add additional certificates from primary cert
    if unified_cert.additional_certificates_pem:
        ca_bundle_parts.extend(unified_cert.additional_certificates_pem)
    
    # Add CA certificates from other certs in session
    for cert in all_certificates:
        if cert.id != primary_cert.id and cert.has_certificate:
            other_unified = CertificateStorage.get_unified_by_id(cert.id, session_id)
            if (other_unified and 
                other_unified.certificate_pem and 
                other_unified.certificate_info and 
                other_unified.certificate_info.is_ca):
                ca_bundle_parts.append(other_unified.certificate_pem)
    
    ca_bundle = '\n'.join(ca_bundle_parts) if ca_bundle_parts else None
    
    # Extract metadata from certificate info
    cert_info = unified_cert.certificate_info
    domain_name = "example.com"  # Default
    
    if cert_info:
        # Try to extract common name from subject
        subject_parts = cert_info.subject.split(',')
        for part in subject_parts:
            if 'CN=' in part:
                domain_name = part.split('CN=')[1].strip()
                break
        
        # Try SAN if available
        if 'subject_alt_name' in cert_info.extensions:
            san_names = cert_info.extensions['subject_alt_name']
            if san_names and len(san_names) > 0:
                domain_name = san_names[0]  # Use first SAN
    
    return {
        'certificate': certificate_pem,
        'private_key': private_key_pem,
        'ca_bundle': ca_bundle,
        'domain_name': domain_name,
        'subject': cert_info.subject if cert_info else "",
        'issuer': cert_info.issuer if cert_info else "",
        'expiry_date': cert_info.not_valid_after if cert_info else None,
        'filename': unified_cert.filename
    }

def _extract_certificate_data_for_iis(primary_cert, all_certificates, session_id):
    """
    Extract certificate data for IIS PKCS#12 bundle from unified storage
    
    Args:
        primary_cert: Primary end-entity certificate
        all_certificates: All certificates in session
        session_id: Session identifier
        
    Returns:
        Dictionary containing certificate, private_key, ca_bundle, and metadata
    """
    logger.debug("Extracting certificate data for IIS bundle")
    
    # Get unified certificate data
    unified_cert = CertificateStorage.get_unified_by_id(primary_cert.id, session_id)
    if not unified_cert:
        raise ValueError("Primary certificate not found in unified storage")
    
    # Extract certificate PEM
    if not unified_cert.certificate_pem:
        raise ValueError("Certificate PEM not found")
    certificate_pem = unified_cert.certificate_pem
    
    # Extract private key PEM - IIS requires private key
    private_key_pem = None
    if unified_cert.private_key_pem:
        private_key_pem = unified_cert.private_key_pem
    else:
        # Search for separate private key
        for cert in all_certificates:
            if cert.has_private_key and not cert.has_certificate:
                separate_unified = CertificateStorage.get_unified_by_id(cert.id, session_id)
                if separate_unified and separate_unified.private_key_pem:
                    private_key_pem = separate_unified.private_key_pem
                    break
    
    if not private_key_pem:
        raise ValueError("No private key found. IIS requires a private key for PKCS#12 bundle.")
    
    # Build CA bundle
    ca_bundle_parts = []
    
    if unified_cert.additional_certificates_pem:
        ca_bundle_parts.extend(unified_cert.additional_certificates_pem)
    
    # Add CA certificates from session
    for cert in all_certificates:
        if cert.id != primary_cert.id and cert.has_certificate:
            other_unified = CertificateStorage.get_unified_by_id(cert.id, session_id)
            if (other_unified and 
                other_unified.certificate_pem and 
                other_unified.certificate_info and 
                other_unified.certificate_info.is_ca):
                ca_bundle_parts.append(other_unified.certificate_pem)
    
    ca_bundle = '\n'.join(ca_bundle_parts) if ca_bundle_parts else None
    
    return {
        'certificate': certificate_pem,
        'private_key': private_key_pem,
        'ca_bundle': ca_bundle,
        'filename': unified_cert.filename
    }

def _create_pkcs12_bundle(certificate_pem: str, private_key_pem: str, ca_bundle_pem: Optional[str] = None) -> bytes:
    """Create PKCS#12 bundle from PEM content"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography import x509
    
    # Load certificate and private key from PEM
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    
    # Validate private key type for PKCS#12 compatibility
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey, dsa.DSAPrivateKey)):
        raise ValueError(f"Unsupported private key type for PKCS#12: {type(private_key)}")
    
    # Load additional certificates if provided
    additional_certs = []
    if ca_bundle_pem:
        # Split CA bundle into individual certificates
        import re
        cert_blocks = re.findall(
            r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
            ca_bundle_pem,
            re.DOTALL
        )
        for cert_block in cert_blocks:
            try:
                ca_cert = x509.load_pem_x509_certificate(cert_block.encode())
                additional_certs.append(ca_cert)
            except Exception as e:
                logger.warning(f"Failed to load CA certificate: {e}")
    
    # Create PKCS#12 bundle
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"certificate",
        key=private_key,
        cert=cert,
        cas=additional_certs if additional_certs else None,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return p12_data

def _create_certificate_info_text(certificate_data: Dict[str, Any]) -> str:
    """Create certificate information text"""
    info_lines = [
        "CERTIFICATE INFORMATION",
        "=" * 50,
        "",
        f"Domain: {certificate_data.get('domain_name', 'N/A')}",
        f"Subject: {certificate_data.get('subject', 'N/A')}",
        f"Issuer: {certificate_data.get('issuer', 'N/A')}",
        f"Expiry Date: {certificate_data.get('expiry_date', 'N/A')}",
        f"Filename: {certificate_data.get('filename', 'N/A')}",
        "",
        "BUNDLE CONTENTS:",
        "- Certificate file (PEM format)",
        "- Private key file (PEM format)",
    ]
    
    if certificate_data.get('ca_bundle'):
        info_lines.append("- CA certificate chain (PEM format)")
    
    info_lines.extend([
        "",
        "INSTALLATION:",
        "1. Extract the PKCS#12 file from this ZIP",
        "2. Import the PKCS#12 file into IIS",
        "3. Follow the IIS installation guide included",
        "",
        "For detailed instructions, see IIS_INSTALLATION_GUIDE.txt"
    ])
    
    return '\n'.join(info_lines)