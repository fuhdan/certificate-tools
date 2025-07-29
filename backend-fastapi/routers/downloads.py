"""
backend-fastapi/routers/downloads.py
Download endpoints integration with SecureZipCreator service
"""

from fastapi import APIRouter, HTTPException, Response, Header
from fastapi.responses import StreamingResponse
import logging
from typing import Optional
from services.secure_zip_creator import secure_zip_creator, SecureZipCreatorError

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/download/apache-bundle/{certificate_id}")
async def download_apache_bundle(
    certificate_id: str,
    custom_password: Optional[str] = Header(None, alias="X-Zip-Password")
):
    """
    Download Apache certificate bundle as password-protected ZIP.
    
    Headers:
        X-Zip-Password: Custom password for ZIP file (optional)
    
    Returns:
        Password-protected ZIP file with Apache certificate bundle
        Password returned in X-Zip-Password response header
    """
    try:
        # Fetch certificate data (mock implementation)
        certificate_data = await get_certificate_data(certificate_id)
        
        if not certificate_data:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Generate installation guides
        apache_guide = generate_apache_installation_guide(certificate_data)
        nginx_guide = generate_nginx_installation_guide(certificate_data)
        
        # Create password-protected ZIP bundle
        zip_data, password = secure_zip_creator.create_apache_bundle(
            certificate=certificate_data['certificate'],
            private_key=certificate_data['private_key'],
            ca_bundle=certificate_data['ca_bundle'],
            apache_guide=apache_guide,
            nginx_guide=nginx_guide,
            password=custom_password
        )
        
        logger.info(f"Apache bundle created for certificate {certificate_id}")
        
        # Return ZIP file with password in header
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=apache-bundle-{certificate_id}.zip",
                "X-Zip-Password": password,
                "Content-Length": str(len(zip_data))
            }
        )
        
    except SecureZipCreatorError as e:
        logger.error(f"ZIP creation failed for certificate {certificate_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to create certificate bundle")
    
    except Exception as e:
        logger.error(f"Unexpected error downloading Apache bundle {certificate_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/download/iis-bundle/{certificate_id}")
async def download_iis_bundle(
    certificate_id: str,
    custom_password: Optional[str] = Header(None, alias="X-Zip-Password")
):
    """
    Download IIS certificate bundle as password-protected ZIP.
    
    Headers:
        X-Zip-Password: Custom password for ZIP file (optional)
    
    Returns:
        Password-protected ZIP file with IIS certificate bundle
        Password returned in X-Zip-Password response header
    """
    try:
        # Fetch certificate data
        certificate_data = await get_certificate_data(certificate_id)
        
        if not certificate_data:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Generate P12 bundle and guides
        p12_bundle = await generate_p12_bundle(certificate_data)
        iis_guide = generate_iis_installation_guide(certificate_data)
        cert_info = generate_certificate_info(certificate_data)
        
        # Create password-protected ZIP bundle
        zip_data, password = secure_zip_creator.create_iis_bundle(
            p12_bundle=p12_bundle,
            iis_guide=iis_guide,
            cert_info=cert_info,
            password=custom_password
        )
        
        logger.info(f"IIS bundle created for certificate {certificate_id}")
        
        # Return ZIP file with password in header
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=iis-bundle-{certificate_id}.zip",
                "X-Zip-Password": password,
                "Content-Length": str(len(zip_data))
            }
        )
        
    except SecureZipCreatorError as e:
        logger.error(f"ZIP creation failed for certificate {certificate_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to create certificate bundle")
    
    except Exception as e:
        logger.error(f"Unexpected error downloading IIS bundle {certificate_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/download/custom-bundle/{certificate_id}")
async def download_custom_bundle(
    certificate_id: str,
    bundle_type: str = "apache",
    custom_password: Optional[str] = Header(None, alias="X-Zip-Password")
):
    """
    Download custom certificate bundle as password-protected ZIP.
    
    Args:
        certificate_id: Certificate identifier
        bundle_type: Type of bundle (apache, iis, nginx, etc.)
        
    Headers:
        X-Zip-Password: Custom password for ZIP file (optional)
    """
    try:
        certificate_data = await get_certificate_data(certificate_id)
        
        if not certificate_data:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Build custom file set based on bundle type
        files = {}
        
        if bundle_type.lower() in ["apache", "nginx"]:
            files.update({
                'certificate.crt': certificate_data['certificate'],
                'private-key.key': certificate_data['private_key'],
                'ca-bundle.crt': certificate_data['ca_bundle'],
                'installation-guide.txt': generate_installation_guide(bundle_type, certificate_data)
            })
        elif bundle_type.lower() == "iis":
            p12_bundle = await generate_p12_bundle(certificate_data)
            files.update({
                'certificate-bundle.p12': p12_bundle,
                'installation-guide.txt': generate_iis_installation_guide(certificate_data),
                'certificate-info.txt': generate_certificate_info(certificate_data)
            })
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported bundle type: {bundle_type}")
        
        # Create password-protected ZIP
        zip_data, password = secure_zip_creator.create_protected_zip(
            files=files,
            password=custom_password
        )
        
        logger.info(f"Custom {bundle_type} bundle created for certificate {certificate_id}")
        
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename={bundle_type}-bundle-{certificate_id}.zip",
                "X-Zip-Password": password,
                "Content-Length": str(len(zip_data))
            }
        )
        
    except SecureZipCreatorError as e:
        logger.error(f"ZIP creation failed for {bundle_type} bundle {certificate_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to create certificate bundle")
    
    except Exception as e:
        logger.error(f"Unexpected error downloading {bundle_type} bundle {certificate_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/download/batch-certificates")
async def download_batch_certificates(
    certificate_ids: list[str],
    custom_password: Optional[str] = Header(None, alias="X-Zip-Password")
):
    """
    Download multiple certificates as a single password-protected ZIP.
    
    Body:
        certificate_ids: List of certificate IDs to include
        
    Headers:
        X-Zip-Password: Custom password for ZIP file (optional)
    """
    try:
        if not certificate_ids:
            raise HTTPException(status_code=400, detail="No certificate IDs provided")
        
        if len(certificate_ids) > 50:  # Limit batch size
            raise HTTPException(status_code=400, detail="Too many certificates requested (max 50)")
        
        files = {}
        
        # Collect all certificate files
        for cert_id in certificate_ids:
            certificate_data = await get_certificate_data(cert_id)
            
            if not certificate_data:
                logger.warning(f"Certificate {cert_id} not found, skipping")
                continue
            
            # Add files with certificate ID prefix
            files[f"{cert_id}/certificate.crt"] = certificate_data['certificate']
            files[f"{cert_id}/private-key.key"] = certificate_data['private_key']
            files[f"{cert_id}/ca-bundle.crt"] = certificate_data['ca_bundle']
            files[f"{cert_id}/installation-guide.txt"] = generate_apache_installation_guide(certificate_data)
        
        if not files:
            raise HTTPException(status_code=404, detail="No valid certificates found")
        
        # Estimate memory usage
        memory_estimate = secure_zip_creator.get_memory_usage_estimate(files)
        if memory_estimate > 100 * 1024 * 1024:  # 100MB limit
            raise HTTPException(status_code=413, detail="Batch too large, reduce number of certificates")
        
        # Create password-protected ZIP
        zip_data, password = secure_zip_creator.create_protected_zip(
            files=files,
            password=custom_password
        )
        
        logger.info(f"Batch ZIP created with {len(certificate_ids)} certificates")
        
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=certificates-batch-{len(certificate_ids)}.zip",
                "X-Zip-Password": password,
                "Content-Length": str(len(zip_data))
            }
        )
        
    except SecureZipCreatorError as e:
        logger.error(f"Batch ZIP creation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to create certificate batch")
    
    except Exception as e:
        logger.error(f"Unexpected error in batch download: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Helper functions (mock implementations)

async def get_certificate_data(certificate_id: str) -> dict:
    """Mock function to fetch certificate data"""
    # In real implementation, this would fetch from database
    return {
        'certificate': b'-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----',
        'private_key': b'-----BEGIN PRIVATE KEY-----\nMOCK_KEY_DATA\n-----END PRIVATE KEY-----',
        'ca_bundle': b'-----BEGIN CERTIFICATE-----\nMOCK_CA_DATA\n-----END CERTIFICATE-----',
        'domain': f'example-{certificate_id}.com',
        'issuer': 'Mock CA',
        'expires': '2025-12-31'
    }


def generate_apache_installation_guide(certificate_data: dict) -> str:
    """Generate Apache installation guide"""
    return f"""
Apache SSL Certificate Installation Guide
=========================================

Domain: {certificate_data['domain']}
Issuer: {certificate_data['issuer']}
Expires: {certificate_data['expires']}

Installation Steps:
1. Copy certificate.crt to /etc/ssl/certs/
2. Copy private-key.key to /etc/ssl/private/
3. Copy ca-bundle.crt to /etc/ssl/certs/

Apache Configuration:
<VirtualHost *:443>
    ServerName {certificate_data['domain']}
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/certificate.crt
    SSLCertificateKeyFile /etc/ssl/private/private-key.key
    SSLCertificateChainFile /etc/ssl/certs/ca-bundle.crt
    
    # Additional SSL settings
    SSLProtocol all -SSLv2 -SSLv3
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
</VirtualHost>

Restart Apache after configuration:
sudo systemctl restart apache2
"""


def generate_nginx_installation_guide(certificate_data: dict) -> str:
    """Generate Nginx installation guide"""
    return f"""
Nginx SSL Certificate Installation Guide
========================================

Domain: {certificate_data['domain']}
Issuer: {certificate_data['issuer']}
Expires: {certificate_data['expires']}

Installation Steps:
1. Copy certificate.crt to /etc/nginx/ssl/
2. Copy private-key.key to /etc/nginx/ssl/
3. Copy ca-bundle.crt to /etc/nginx/ssl/

Nginx Configuration:
server {{
    listen 443 ssl;
    server_name {certificate_data['domain']};
    
    ssl_certificate /etc/nginx/ssl/certificate.crt;
    ssl_certificate_key /etc/nginx/ssl/private-key.key;
    ssl_trusted_certificate /etc/nginx/ssl/ca-bundle.crt;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
}}

Reload Nginx after configuration:
sudo nginx -t && sudo systemctl reload nginx
"""


def generate_iis_installation_guide(certificate_data: dict) -> str:
    """Generate IIS installation guide"""
    return f"""
IIS SSL Certificate Installation Guide
======================================

Domain: {certificate_data['domain']}
Issuer: {certificate_data['issuer']}
Expires: {certificate_data['expires']}

Installation Steps:
1. Open IIS Manager
2. Select your server in the left panel
3. Double-click "Server Certificates"
4. Click "Import..." in the Actions panel
5. Browse to certificate-bundle.p12
6. Enter the certificate password when prompted
7. Select your website
8. Click "Bindings..." in Actions panel
9. Add/Edit HTTPS binding
10. Select the imported certificate

Certificate Password:
The P12 bundle is protected with a secure password.
Use the password provided with this download.

Verification:
After installation, test your SSL certificate at:
https://{certificate_data['domain']}
"""


def generate_certificate_info(certificate_data: dict) -> str:
    """Generate certificate information"""
    return f"""
Certificate Information
======================

Domain: {certificate_data['domain']}
Issuer: {certificate_data['issuer']}
Expiration Date: {certificate_data['expires']}

Security Features:
- 2048-bit RSA key
- SHA-256 signature algorithm
- Extended Validation (EV)

Support:
For technical support, contact your certificate provider.
Keep this information secure and do not share passwords.
"""


async def generate_p12_bundle(certificate_data: dict) -> bytes:
    """Mock function to generate P12 bundle"""
    # In real implementation, this would create actual P12 bundle
    return b'MOCK_P12_BUNDLE_DATA'


def generate_installation_guide(bundle_type: str, certificate_data: dict) -> str:
    """Generate installation guide based on bundle type"""
    if bundle_type.lower() == "apache":
        return generate_apache_installation_guide(certificate_data)
    elif bundle_type.lower() == "nginx":
        return generate_nginx_installation_guide(certificate_data)
    elif bundle_type.lower() == "iis":
        return generate_iis_installation_guide(certificate_data)
    else:
        return f"Installation guide for {bundle_type} server type."