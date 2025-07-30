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
        
        logger.debug(f"Using primary certificate: {primary_cert.get('filename')} (type: {primary_cert.get('analysis', {}).get('type')})")
        
        # Extract certificate data
        try:
            certificate_data = _extract_certificate_data(primary_cert, certificates, session_id)
        except ValueError as e:
            logger.warning(f"Certificate data extraction error for session {session_id}: {e}")
            raise HTTPException(status_code=404, detail=f"Certificate data incomplete: {e}")
        
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
    
    except HTTPException as http_exc:
        # Re-raise HTTPExceptions to let FastAPI handle them properly
        raise http_exc
    
    except Exception as e:
        logger.error(f"Unexpected error creating Apache bundle for session {session_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )

@router.post("/iis/{session_id}")
async def download_iis_bundle(
    session_id: str,
    session_id_validated: str = Depends(get_session_id)
):
    logger.info(f"IIS bundle download started for session: {session_id}")
    
    try:
        if session_id != session_id_validated:
            logger.warning(f"Session ID mismatch: path={session_id}, validated={session_id_validated}")
            raise HTTPException(
                status_code=400, 
                detail="Session ID validation failed"
            )
        
        certificates = CertificateStorage.get_all(session_id)
        
        if not certificates:
            logger.warning(f"No certificates found in session: {session_id}")
            raise HTTPException(
                status_code=404,
                detail="No certificates found in session"
            )
        
        logger.debug(f"Found {len(certificates)} certificates in session:")
        for i, cert in enumerate(certificates):
            cert_type = cert.get('analysis', {}).get('type')
            filename = cert.get('filename', 'unknown')
            logger.debug(f"  [{i}] {cert_type} - {filename}")
        
        primary_cert = None
        for cert in certificates:
            analysis = cert.get('analysis', {})
            if analysis.get('type') in ['Certificate', 'X509 Certificate', 'PKCS12 Certificate']:
                basic_constraints = analysis.get('details', {}).get('extensions', {}).get('basicConstraints')
                if not basic_constraints or not basic_constraints.get('ca', False):
                    primary_cert = cert
                    break
        
        if not primary_cert:
            logger.warning(f"No end-entity certificate found in session: {session_id}")
            raise HTTPException(
                status_code=400,
                detail="No end-entity certificate found. A complete certificate chain is required for IIS."
            )
        
        certificate_data = _extract_certificate_data_for_iis(primary_cert, certificates, session_id)
        
        zip_password = secure_zip_creator.generate_secure_password()
        p12_password = secure_zip_creator.generate_secure_password()
        
        logger.debug(f"Generated passwords - ZIP: {len(zip_password)} chars, P12: {len(p12_password)} chars")
        
        p12_bundle = _create_pkcs12_bundle(
            certificate_data['certificate'],
            certificate_data['private_key'], 
            certificate_data['ca_bundle'],
            p12_password,
            certificate_data['domain_name']
        )
        
        instruction_generator = InstructionGenerator()
        
        iis_guide = instruction_generator.generate_instructions(
            server_type="iis",
            certificate_data=certificate_data,
            zip_password=zip_password,
            bundle_password=p12_password
        )
        
        cert_info = _create_certificate_info_text(certificate_data, zip_password, p12_password)
        
        files = {
            'certificate-bundle.p12': p12_bundle,
            'IIS_INSTALLATION_GUIDE.txt': iis_guide,
            'CERTIFICATE_INFO.txt': cert_info
        }
        
        zip_data, final_zip_password = secure_zip_creator.create_protected_zip(files, zip_password)
        
        logger.info(f"IIS bundle created successfully for session: {session_id}")
        
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=iis-bundle-{session_id}.zip",
                "X-Zip-Password": final_zip_password,
                "X-P12-Password": p12_password,
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
        # Re-raise FastAPI HTTPExceptions to avoid them being wrapped as 500
        raise http_exc
    
    except Exception as e:
        logger.error(f"Unexpected error creating IIS bundle for session {session_id}: {e}")
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
        
        # Find matching private key from all certificates in session
        private_key_obj = None
        private_key_pem = None
        
        # First, try to get private key from the same crypto objects (for PKCS12 bundles)
        if 'private_key' in crypto_objects:
            private_key_obj = crypto_objects['private_key']
            logger.debug(f"Found private key in same crypto objects as certificate")
        else:
            # Search for private key in other certificates (separate uploads)
            logger.debug(f"Searching for separate private key in {len(all_certificates)} certificates")
            for cert in all_certificates:
                cert_type = cert.get('analysis', {}).get('type')
                if cert_type == 'Private Key':
                    logger.debug(f"Found private key candidate: {cert.get('filename')}")
                    cert_crypto = CryptoObjectsStorage.get_crypto_objects(
                        cert['id'],
                        session_id
                    )
                    
                    if cert_crypto and 'private_key' in cert_crypto:
                        # TODO: In future, validate that this private key matches the certificate
                        private_key_obj = cert_crypto['private_key']
                        logger.debug(f"Using private key from: {cert.get('filename')}")
                        break
        
        if not private_key_obj:
            raise ValueError("Private key not found - please upload a matching private key")
        
        private_key_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Build CA bundle from other certificates
        ca_bundle_parts = []
        
        # DEBUG: Log all certificate types
        logger.debug(f"Building CA bundle - examining {len(all_certificates)} certificates:")
        for i, cert in enumerate(all_certificates):
            cert_type = cert.get('analysis', {}).get('type')
            cert_filename = cert.get('filename', 'unknown')
            cert_id = cert.get('id', 'no-id')
            logger.debug(f"  [{i}] {cert_filename} (ID: {cert_id}) - type: '{cert_type}'")
        
        for cert in all_certificates:
            cert_type = cert.get('analysis', {}).get('type')
            cert_filename = cert.get('filename', 'unknown')
            
            # Include CA certificates and intermediate certificates
            # FIXED: Added more specific logging and fixed condition logic
            is_ca_cert = (cert_type and (
                'CA' in cert_type or 
                'ca_certificate' in cert_type or 
                'intermediate_certificate' in cert_type or 
                'IssuingCA' in cert_type or 
                'IntermediateCA' in cert_type or 
                'RootCA' in cert_type
            ))
            
            logger.debug(f"Certificate '{cert_filename}' type '{cert_type}' - is_ca_cert: {is_ca_cert}")
            
            if is_ca_cert:
                logger.debug(f"Including CA certificate: {cert_filename}")
                cert_crypto = CryptoObjectsStorage.get_crypto_objects(
                    cert['id'],
                    session_id
                )
                
                if cert_crypto and 'certificate' in cert_crypto:
                    logger.debug(f"Successfully retrieved crypto objects for {cert_filename}")
                    ca_cert_pem = cert_crypto['certificate'].public_bytes(
                        encoding=serialization.Encoding.PEM
                    ).decode('utf-8')
                    ca_bundle_parts.append(ca_cert_pem)
                    logger.debug(f"Added {cert_filename} to CA bundle (size: {len(ca_cert_pem)} bytes)")
                else:
                    logger.warning(f"No crypto objects found for CA certificate: {cert_filename}")
            else:
                logger.debug(f"Skipping non-CA certificate: {cert_filename}")
        
        ca_bundle = '\n'.join(ca_bundle_parts) if ca_bundle_parts else ''
        
        # DEBUG: Log final CA bundle info
        logger.debug(f"CA bundle creation complete - {len(ca_bundle_parts)} CA certificates, total size: {len(ca_bundle)} bytes")
        if not ca_bundle:
            logger.debug("CA bundle is empty! This will cause test failures.")
            logger.debug("Available certificate types:")
            for cert in all_certificates:
                cert_type = cert.get('analysis', {}).get('type')
                cert_filename = cert.get('filename', 'unknown')
                logger.debug(f"  - {cert_filename}: {cert_type}")
        
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

def _extract_certificate_data_for_iis(primary_cert, all_certificates, session_id):
    """
    Extract certificate data needed for IIS PKCS#12 bundle creation.

    Args:
        primary_cert: Primary end-entity certificate 
        all_certificates: All certificates in session
        session_id: Session identifier for logging

    Returns:
        Dictionary containing certificate, private_key, ca_bundle, and metadata

    Raises:
        ValueError: If required data cannot be extracted
    """
    logger.debug(f"Extracting certificate data for IIS bundle creation")

    try:
        from cryptography.hazmat.primitives import serialization

        # Flexible key selection for cryptographic lookup — use 'id' if present or fallback to 'content_hash'
        cert_key = primary_cert.get('id') or primary_cert.get('content_hash')
        if not cert_key:
            raise ValueError("Primary certificate has no identifier key ('id' or 'content_hash')")

        cert_crypto = CryptoObjectsStorage.get_crypto_objects(cert_key, session_id)
        if not cert_crypto or 'certificate' not in cert_crypto:
            raise ValueError("Primary certificate cryptographic object not found")

        certificate_obj = cert_crypto['certificate']
        certificate_pem = certificate_obj.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')

        # Attempt to get private key from primary certificate crypto objects
        private_key_obj = cert_crypto.get('private_key')
        private_key_pem = None

        if private_key_obj:
            private_key_pem = private_key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            logger.debug("Found private key bundled with certificate")
        else:
            # Fallback: search all session certificates for a separate private key
            for cert in all_certificates:
                if cert.get('analysis', {}).get('type') == 'Private Key':
                    key_crypto = CryptoObjectsStorage.get_crypto_objects(cert.get('id') or cert.get('content_hash'), session_id)
                    if key_crypto and 'private_key' in key_crypto:
                        private_key_obj = key_crypto['private_key']
                        private_key_pem = private_key_obj.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ).decode('utf-8')
                        logger.debug("Found separate private key in session")
                        break

        if not private_key_pem:
            raise ValueError("No private key found. IIS requires a private key for PKCS#12 bundle.")

        # Build CA certificate chain from CA or issuing CA certificates
        ca_bundle_parts = []

        for cert in all_certificates:
            analysis = cert.get('analysis', {})
            if analysis.get('type') in ['X509 Certificate', 'PKCS12 Certificate']:
                basic_constraints = analysis.get('details', {}).get('extensions', {}).get('basicConstraints')
                if basic_constraints and basic_constraints.get('ca', False):
                    cert_crypto = CryptoObjectsStorage.get_crypto_objects(cert.get('id') or cert.get('content_hash'), session_id)
                    if cert_crypto and 'certificate' in cert_crypto:
                        ca_cert_pem = cert_crypto['certificate'].public_bytes(
                            encoding=serialization.Encoding.PEM
                        ).decode('utf-8')
                        ca_bundle_parts.append(ca_cert_pem)
                        logger.debug(f"Added CA certificate to chain: {cert.get('filename', 'unknown')}")

        ca_bundle = '\n'.join(ca_bundle_parts) if ca_bundle_parts else ''
        logger.debug(f"Built CA bundle with {len(ca_bundle_parts)} certificates")

        # Extract certificate metadata
        analysis = primary_cert.get('analysis', {})
        details = analysis.get('details', {})

        return {
            'certificate': certificate_pem,
            'private_key': private_key_pem,
            'ca_bundle': ca_bundle,
            # Store objects for PKCS#12 creation
            'certificate_obj': certificate_obj,
            'private_key_obj': private_key_obj,
            'domain_name': details.get('subject', {}).get('commonName', 'example.com'),
            'subject': details.get('subject', {}),
            'issuer': details.get('issuer', {}),
            'expiry_date': details.get('validity', {}).get('not_after'),
            'filename': primary_cert.get('filename', 'certificate')
        }

    except Exception as e:
        logger.error(f"Failed to extract certificate data for IIS: {e}")
        raise ValueError(f"Certificate data extraction failed: {e}")


def _create_pkcs12_bundle(certificate_pem, private_key_pem, ca_bundle, password, friendly_name):
    """
    Create PKCS#12 bundle from certificate components.
    
    Args:
        certificate_pem: End-entity certificate in PEM format
        private_key_pem: Private key in PEM format
        ca_bundle: CA certificates in PEM format (concatenated)
        password: Password for PKCS#12 bundle
        friendly_name: Friendly name for the certificate
        
    Returns:
        bytes: PKCS#12 bundle data
    """
    logger.debug("Creating PKCS#12 bundle")
    
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography import x509
        
        # Parse certificate
        cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))
        
        # Parse private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'), 
            password=None
        )
        
        # Type check for PKCS#12 compatibility
        from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
        if not isinstance(private_key, (rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, 
                                       ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            raise ValueError(f"Private key type {type(private_key).__name__} is not supported for PKCS#12")
        
        # Parse CA certificates
        cas = []
        if ca_bundle:
            # Split concatenated PEM certificates
            import re
            cert_pattern = r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
            ca_certs = re.findall(cert_pattern, ca_bundle, re.DOTALL)
            
            for ca_cert_pem in ca_certs:
                try:
                    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'))
                    cas.append(ca_cert)
                    logger.debug(f"Added CA certificate to PKCS#12: {ca_cert.subject}")
                except Exception as ca_err:
                    logger.warning(f"Failed to parse CA certificate: {ca_err}")
        
        # Create PKCS#12 bundle
        p12_data = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode('utf-8'),
            key=private_key,
            cert=cert,
            cas=cas,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )
        
        logger.debug(f"Created PKCS#12 bundle with {len(cas)} CA certificates")
        return p12_data
        
    except Exception as e:
        logger.error(f"PKCS#12 bundle creation failed: {e}")
        raise ValueError(f"Failed to create PKCS#12 bundle: {e}")


def _create_certificate_info_text(certificate_data, zip_password, p12_password):
    """
    Create certificate information text file for IIS bundle.
    
    Args:
        certificate_data: Certificate metadata dictionary
        zip_password: Password for ZIP file
        p12_password: Password for PKCS#12 bundle
        
    Returns:
        str: Certificate information text
    """
    from datetime import datetime
    
    domain_name = certificate_data.get('domain_name', 'example.com')
    subject = certificate_data.get('subject', {})
    issuer = certificate_data.get('issuer', {})
    expiry_date = certificate_data.get('expiry_date', 'Unknown')
    
    info_text = f"""Certificate Information and Passwords
================================================================================

PASSWORDS (IMPORTANT - SAVE SECURELY):
- ZIP File Password: {zip_password}
- PKCS#12 Bundle Password: {p12_password}

CERTIFICATE DETAILS:
- Domain Name: {domain_name}
- Subject: {subject.get('commonName', 'N/A')}
- Organization: {subject.get('organizationName', 'N/A')}
- Organizational Unit: {subject.get('organizationalUnitName', 'N/A')}
- Country: {subject.get('countryName', 'N/A')}

ISSUER INFORMATION:
- Issued By: {issuer.get('commonName', 'N/A')}
- Issuer Organization: {issuer.get('organizationName', 'N/A')}

VALIDITY:
- Expires: {expiry_date}

FILES IN THIS BUNDLE:
1. certificate-bundle.p12 - PKCS#12 bundle (use P12 password above)
2. IIS_INSTALLATION_GUIDE.txt - Complete installation instructions
3. CERTIFICATE_INFO.txt - This file

SECURITY NOTES:
- Store these passwords securely (password manager recommended)
- Delete this file after successful installation
- The PKCS#12 file contains both certificate and private key
- Use Windows Certificate Store for long-term certificate storage

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
================================================================================
"""
    
    return info_text