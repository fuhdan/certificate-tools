# backend-fastapi/routers/downloads.py
# Complete rewrite for session_pki_storage with ALL features preserved

import logging
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Response, Depends
from fastapi.responses import StreamingResponse

from middleware.session_middleware import get_session_id
from certificates.storage.session_pki_storage import session_pki_storage, PKIComponentType
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
    Rewritten for session_pki_storage.
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
        
        # Get session from PKI storage
        session = session_pki_storage.get_or_create_session(session_id)
        
        if not session.components:
            logger.warning(f"No PKI components found in session: {session_id}")
            raise HTTPException(
                status_code=404,
                detail="No PKI components found in session"
            )
        
        # Debug: Log component types
        logger.debug(f"Found {len(session.components)} components in session:")
        for component in session.components.values():
            logger.debug(f"  {component.filename} - type: {component.type.type_name}")
        
        # Find the primary end-entity certificate
        primary_cert = _find_primary_certificate_component(session)
        if not primary_cert:
            logger.warning(f"No end-entity certificate found in session: {session_id}")
            raise HTTPException(
                status_code=404,
                detail="No end-entity certificate found in session"
            )
        
        logger.debug(f"Using primary certificate: {primary_cert.filename}")
        
        # Extract certificate data from session components
        try:
            certificate_data = _extract_certificate_data_for_apache(primary_cert, session, session_id)
        except ValueError as e:
            logger.warning(f"Certificate data extraction error for session {session_id}: {e}")
            raise HTTPException(status_code=404, detail=f"Certificate data incomplete: {e}")
        
        # 🔍 DEBUG: Log the exact certificate_data structure
        logger.info("🔥 CERTIFICATE_DATA DEBUG:")
        logger.info(f"🔥 Type: {type(certificate_data)}")
        logger.info(f"🔥 Keys: {list(certificate_data.keys()) if isinstance(certificate_data, dict) else 'NOT A DICT'}")
        for key, value in certificate_data.items():
            logger.info(f"🔥 {key}: {type(value)} = {value[:100] if isinstance(value, str) else value}")
        
        # 🔍 DEBUG: Log primary_cert.metadata specifically
        logger.info("🔥 PRIMARY_CERT.METADATA DEBUG:")
        logger.info(f"🔥 metadata type: {type(primary_cert.metadata)}")
        logger.info(f"🔥 metadata value: {primary_cert.metadata}")
        
        # Generate installation guides
        instruction_generator = InstructionGenerator()
        
        logger.info("🔥 CALLING INSTRUCTION GENERATOR WITH:")
        logger.info(f"🔥 server_type: apache")
        logger.info(f"🔥 certificate_data type: {type(certificate_data)}")
        
        apache_guide = instruction_generator.generate_instructions(
            server_type="apache",
            certificate_data=certificate_data
        )
        
        nginx_guide = instruction_generator.generate_instructions(
            server_type="nginx", 
            certificate_data=certificate_data
        )
        
        # Create password-protected ZIP bundle using secure_zip_creator
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
    Generate IIS-compatible PKCS#12 bundle as password-protected ZIP file.
    Rewritten for session_pki_storage.
    """
    logger.info(f"IIS bundle download started for session: {session_id}")
    
    try:
        # Validate session_id
        if session_id != session_id_validated:
            raise HTTPException(status_code=400, detail="Session ID validation failed")
        
        # Get session from PKI storage
        session = session_pki_storage.get_or_create_session(session_id)
        
        if not session.components:
            raise HTTPException(status_code=404, detail="No PKI components found in session")
        
        # Find primary certificate
        primary_cert = _find_primary_certificate_component(session)
        if not primary_cert:
            raise HTTPException(status_code=404, detail="No end-entity certificate found")
        
        # Extract certificate data for IIS
        try:
            certificate_data = _extract_certificate_data_for_iis(primary_cert, session, session_id)
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
        
        # Create password-protected ZIP bundle using secure_zip_creator
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

# Helper functions for session PKI storage

def _find_primary_certificate_component(session):
    """Find the primary end-entity certificate component"""
    
    # Look for end-entity certificates first (non-CA certificates)
    for component in session.components.values():
        if component.type == PKIComponentType.CERTIFICATE:
            # Check if it's actually an end-entity cert (not CA)
            if not component.metadata.get('is_ca', False):
                return component
    
    # If no clear end-entity, look for any certificate component
    for component in session.components.values():
        if component.type == PKIComponentType.CERTIFICATE:
            return component
    
    # Fallback: any certificate-like component
    for component in session.components.values():
        if component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
            return component
    
    return None

def _extract_certificate_data_for_apache(primary_cert, session, session_id):
    """
    Extract certificate data for Apache bundle from session PKI storage
    
    Args:
        primary_cert: Primary certificate component
        session: PKI session object
        session_id: Session identifier
        
    Returns:
        Dictionary containing certificate, private_key, ca_bundle, and metadata
    """
    logger.debug(f"Extracting certificate data for Apache bundle")
    
    # Extract certificate PEM
    certificate_pem = primary_cert.content
    if not certificate_pem:
        raise ValueError("Certificate PEM not found")
    
    # Find private key component
    private_key_pem = None
    for component in session.components.values():
        if component.type == PKIComponentType.PRIVATE_KEY:
            private_key_pem = component.content
            logger.debug("Found private key in session")
            break
    
    if not private_key_pem:
        raise ValueError("No private key found. Apache requires a private key.")
    
    # Build CA bundle from CA components
    ca_bundle_parts = []
    for component in session.components.values():
        if component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
            if component.id != primary_cert.id:  # Don't include the primary cert in CA bundle
                ca_bundle_parts.append(component.content)
    
    ca_bundle = '\n'.join(ca_bundle_parts) if ca_bundle_parts else None
    
    # Extract metadata from certificate component
    cert_metadata = primary_cert.metadata or {}
    domain_name = _extract_domain_name_from_metadata(cert_metadata)
    
    # FIXED: Return proper dictionary format for instruction_generator
    return {
        'certificate': certificate_pem,
        'private_key': private_key_pem,
        'ca_bundle': ca_bundle,
        'domain_name': domain_name,
        'subject': cert_metadata.get('subject', ''),
        'issuer': cert_metadata.get('issuer', ''),
        'expiry_date': cert_metadata.get('not_valid_after', ''),
        'filename': primary_cert.filename
    }

def _extract_certificate_data_for_iis(primary_cert, session, session_id):
    """
    Extract certificate data for IIS PKCS#12 bundle from session PKI storage
    
    Args:
        primary_cert: Primary certificate component
        session: PKI session object
        session_id: Session identifier
        
    Returns:
        Dictionary containing certificate, private_key, ca_bundle, and metadata
    """
    logger.debug("Extracting certificate data for IIS bundle")
    
    # Extract certificate PEM
    certificate_pem = primary_cert.content
    if not certificate_pem:
        raise ValueError("Certificate PEM not found")
    
    # Find private key component - IIS requires private key
    private_key_pem = None
    for component in session.components.values():
        if component.type == PKIComponentType.PRIVATE_KEY:
            private_key_pem = component.content
            break
    
    if not private_key_pem:
        raise ValueError("No private key found. IIS requires a private key for PKCS#12 bundle.")
    
    # Build CA bundle from CA components
    ca_bundle_parts = []
    for component in session.components.values():
        if component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
            if component.id != primary_cert.id:  # Don't include the primary cert
                ca_bundle_parts.append(component.content)
    
    ca_bundle = '\n'.join(ca_bundle_parts) if ca_bundle_parts else None
    
    # FIXED: Handle metadata properly - make sure it's a dict
    cert_metadata = primary_cert.metadata or {}
    
    # Ensure metadata is a dictionary, not a string
    if isinstance(cert_metadata, str):
        logger.warning(f"Certificate metadata is a string, not a dict: {cert_metadata}")
        cert_metadata = {}
    
    domain_name = _extract_domain_name_from_metadata(cert_metadata)
    
    return {
        'certificate': certificate_pem,
        'private_key': private_key_pem,
        'ca_bundle': ca_bundle,
        'domain_name': domain_name,
        'subject': cert_metadata.get('subject', ''),
        'issuer': cert_metadata.get('issuer', ''),
        'filename': primary_cert.filename
    }

def _extract_domain_name_from_metadata(cert_metadata):
    """Extract domain name from certificate metadata - FIXED"""
    # FIXED: Add type checking for cert_metadata
    if not isinstance(cert_metadata, dict):
        logger.warning(f"cert_metadata is not a dict: {type(cert_metadata)} - {cert_metadata}")
        return "example.com"
    
    # Try Subject Alternative Names first
    if 'subject_alt_name' in cert_metadata:
        sans = cert_metadata['subject_alt_name']
        if isinstance(sans, list) and len(sans) > 0:
            # Look for DNS entries in SAN
            for san in sans:
                if isinstance(san, str) and san.startswith('DNS:'):
                    return san[4:]  # Remove 'DNS:' prefix
    
    # Try common name from subject
    if 'subject_common_name' in cert_metadata:
        cn = cert_metadata['subject_common_name']
        if cn:
            return cn
    
    # Fall back to extracting CN from full subject
    subject = cert_metadata.get('subject', '')
    if 'CN=' in subject:
        for part in subject.split(','):
            if 'CN=' in part:
                return part.split('CN=')[1].strip()
    
    return "example.com"  # Default fallback

def _create_pkcs12_bundle(certificate_pem: str, private_key_pem: str, ca_bundle_pem: Optional[str] = None) -> bytes:
    """Create PKCS#12 bundle from PEM content"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography import x509
    import re
    
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
        "For detailed instructions, see IIS_INSTALLATION_GUIDE.txt",
        "",
        f"Generated by Certificate Analysis Tool at {__import__('datetime').datetime.now().isoformat()}"
    ])
    
    return '\n'.join(info_lines)