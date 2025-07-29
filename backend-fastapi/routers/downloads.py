"""
backend-fastapi/routers/downloads.py
Download endpoints for certificate bundles with secure ZIP packaging - CWT-24 Implementation
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Response, Depends
from fastapi.responses import StreamingResponse

from middleware.session_middleware import get_session_id
from certificates.storage.core import CertificateStorage
from certificates.storage.crypto_storage import CryptoObjectsStorage
from services.secure_zip_creator import secure_zip_creator, SecureZipCreatorError
from services.instruction_generator import InstructionGenerator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/downloads", tags=["downloads"])


@router.post("/apache/{session_id}")
async def download_apache_bundle(
    session_id: str,
    session_id_validated: str = Depends(get_session_id)
):
    """
    Generate Apache-compatible certificate bundle as password-protected ZIP file.
    
    CWT-24: Backend API: Apache/Linux Download Endpoint (UPDATED)
    
    Args:
        session_id: Session identifier from URL path
        session_id_validated: Validated session ID from dependency injection
    
    Returns:
        Password-protected ZIP file containing:
        - certificate.crt - End entity certificate (PEM)
        - private-key.key - Private key (PEM) 
        - ca-bundle.crt - CA certificate chain (PEM)
        - APACHE_INSTALLATION_GUIDE.txt - Detailed Apache instructions
        - NGINX_INSTALLATION_GUIDE.txt - Detailed Nginx instructions
        
    Response Headers:
        X-Zip-Password: Generated secure random password (16+ characters)
        
    Security:
        - AES-256 encryption for ZIP files
        - Session-proof implementation
        - Clean logging: function start + success summary
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
        
        # Get all certificates from session
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
            cert_type = cert.get('analysis', {}).get('type')
            filename = cert.get('filename', 'unknown')
            logger.debug(f"  [{i}] {filename} - type: {cert_type}")
        
        # Find the primary certificate (first end-entity certificate)
        primary_cert = None
        for cert in certificates:
            cert_type = cert.get('analysis', {}).get('type')
            # Check for various end-entity certificate types
            if cert_type in ['certificate', 'Certificate', 'end_entity_certificate', 'PKCS12 Certificate']:
                primary_cert = cert
                break
        
        # If no explicit end-entity cert found, look for certificates that aren't CA certificates
        if not primary_cert:
            for cert in certificates:
                cert_type = cert.get('analysis', {}).get('type')
                # Skip CA certificates and private keys, look for actual certificates
                if cert_type and 'CA' not in cert_type and 'Private' not in cert_type and 'Key' not in cert_type:
                    primary_cert = cert
                    break
        
        if not primary_cert:
            logger.warning(f"No end-entity certificate found in session: {session_id}")
            # Debug: Show what certificates we do have
            logger.debug("Available certificate types:")
            for cert in certificates:
                cert_type = cert.get('analysis', {}).get('type')
                filename = cert.get('filename', 'unknown')
                logger.debug(f"  - {filename}: {cert_type}")
            raise HTTPException(
                status_code=404,
                detail="No end-entity certificate found in session"
            )
        
        logger.info(f"Using primary certificate: {primary_cert.get('filename')} (type: {primary_cert.get('analysis', {}).get('type')})")
        
        # Extract certificate data
        certificate_data = _extract_certificate_data(primary_cert, certificates, session_id)
        
        # Generate installation guides using InstructionGenerator service
        instruction_generator = InstructionGenerator()
        
        apache_guide = instruction_generator.generate_instructions(
            server_type="apache",
            certificate_data=certificate_data
        )
        
        nginx_guide = instruction_generator.generate_instructions(
            server_type="nginx", 
            certificate_data=certificate_data
        )
        
        # Create password-protected ZIP bundle with AES-256 encryption
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
    
    except Exception as e:
        logger.error(f"Unexpected error creating Apache bundle for session {session_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


def _extract_certificate_data(primary_cert, all_certificates, session_id):
    """
    Extract certificate data needed for bundle creation.
    
    Args:
        primary_cert: Primary end-entity certificate
        all_certificates: All certificates in session
        session_id: Session identifier
        
    Returns:
        Dictionary containing certificate, private_key, ca_bundle, and metadata
    """
    try:
        # Get crypto objects for primary certificate
        crypto_objects = CryptoObjectsStorage.get_crypto_objects(
            primary_cert['id'], 
            session_id
        )
        
        if not crypto_objects:
            raise ValueError("No cryptographic objects found for certificate")
        
        # Extract certificate PEM
        certificate_obj = crypto_objects.get('certificate')
        if not certificate_obj:
            raise ValueError("Certificate object not found")
        
        from cryptography.hazmat.primitives import serialization
        certificate_pem = certificate_obj.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Extract private key PEM
        private_key_obj = crypto_objects.get('private_key')
        if not private_key_obj:
            raise ValueError("Private key not found")
        
        private_key_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Build CA bundle from other certificates
        ca_bundle_parts = []
        
        for cert in all_certificates:
            cert_type = cert.get('analysis', {}).get('type')
            # Include CA certificates and intermediate certificates
            if (cert_type and ('CA' in cert_type or 'ca_certificate' in cert_type or 
                              'intermediate_certificate' in cert_type or 'IssuingCA' in cert_type or 
                              'IntermediateCA' in cert_type or 'RootCA' in cert_type)):
                cert_crypto = CryptoObjectsStorage.get_crypto_objects(
                    cert['id'],
                    session_id
                )
                
                if cert_crypto and 'certificate' in cert_crypto:
                    ca_cert_pem = cert_crypto['certificate'].public_bytes(
                        encoding=serialization.Encoding.PEM
                    ).decode('utf-8')
                    ca_bundle_parts.append(ca_cert_pem)
        
        ca_bundle = '\n'.join(ca_bundle_parts) if ca_bundle_parts else ''
        
        # Extract certificate metadata
        analysis = primary_cert.get('analysis', {})
        
        return {
            'certificate': certificate_pem,
            'private_key': private_key_pem,
            'ca_bundle': ca_bundle,
            'domain_name': analysis.get('subject', {}).get('common_name', 'example.com'),
            'subject': analysis.get('subject', {}),
            'issuer': analysis.get('issuer', {}),
            'expiry_date': analysis.get('validity', {}).get('not_after'),
            'filename': primary_cert.get('filename', 'certificate')
        }
        
    except Exception as e:
        logger.error(f"Failed to extract certificate data: {e}")
        raise ValueError(f"Certificate data extraction failed: {e}")