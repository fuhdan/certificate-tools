# backend-fastapi/services/format_converter.py
"""
Format Converter Service

Converts PKI components between different formats (PEM, DER, PKCS#8, etc.)
"""

import logging
from typing import Union, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

logger = logging.getLogger(__name__)

class FormatConverter:
    """Service to convert PKI components between formats"""
    
    def __init__(self):
        pass
    
    def convert_private_key(self, 
                          private_key_content: str, 
                          target_format: str, 
                          password: Optional[str] = None) -> bytes:
        """
        Convert private key to target format
        
        Args:
            private_key_content: Original PEM/DER private key content
            target_format: Target format (pem, der, pkcs8, pkcs8_encrypted, pem_encrypted)
            password: Password for encrypted formats
            
        Returns:
            Converted private key as bytes
        """
        logger.debug(f"Converting private key to format: {target_format}")
        
        # Parse the original private key
        if isinstance(private_key_content, str):
            # Assume PEM if it's a string
            private_key = serialization.load_pem_private_key(
                private_key_content.encode(), 
                password=None
            )
        else:
            # Assume DER if it's bytes
            private_key = serialization.load_der_private_key(
                private_key_content, 
                password=None
            )
        
        # Convert to target format
        if target_format.lower() == 'pem':
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
        elif target_format.lower() == 'der':
            return private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
        elif target_format.lower() in ['pkcs8', 'p8']:
            return private_key.private_bytes(
                encoding=serialization.Encoding.DER,  # FIXED: Use DER for PKCS#8
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        
        elif target_format.lower() == 'pkcs8_encrypted':
            if not password:
                from services.secure_zip_creator import secure_zip_creator
                password = secure_zip_creator.generate_secure_password()
                # Store password for manifest use
                self._last_encryption_password = password
                self._last_password_type = "PKCS#8"  # Track password type
                # Log the generated password so it's visible
                logger.info(f"🔐 Generated PKCS#8 encryption password: {password}")
            return private_key.private_bytes(
                encoding=serialization.Encoding.DER,  # FIXED: Use DER for proper PKCS#8
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        
        elif target_format.lower() == 'pem_encrypted':
            if not password:
                from services.secure_zip_creator import secure_zip_creator
                password = secure_zip_creator.generate_secure_password()
                # Store password for manifest use
                self._last_encryption_password = password
                self._last_password_type = "PEM"  # Track password type
                # Log the generated password so it's visible
                logger.info(f"🔐 Generated PEM encryption password: {password}")
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        
        else:
            # Default to PEM
            logger.warning(f"Unknown format {target_format}, defaulting to PEM")
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

    def convert_certificate(self, 
                          certificate_content: str, 
                          target_format: str) -> bytes:
        """
        Convert certificate to target format
        
        Args:
            certificate_content: Original PEM/DER certificate content
            target_format: Target format (pem, der)
            
        Returns:
            Converted certificate as bytes
        """
        logger.debug(f"Converting certificate to format: {target_format}")
        
        # Parse the original certificate
        if isinstance(certificate_content, str):
            # Assume PEM if it's a string
            certificate = x509.load_pem_x509_certificate(certificate_content.encode())
        else:
            # Assume DER if it's bytes
            certificate = x509.load_der_x509_certificate(certificate_content)
        
        # Convert to target format
        if target_format.lower() == 'pem':
            return certificate.public_bytes(serialization.Encoding.PEM)
        elif target_format.lower() == 'der':
            return certificate.public_bytes(serialization.Encoding.DER)
        else:
            # Default to PEM
            logger.warning(f"Unknown format {target_format}, defaulting to PEM")
            return certificate.public_bytes(serialization.Encoding.PEM)

    def convert_csr(self, 
                   csr_content: str, 
                   target_format: str) -> bytes:
        """
        Convert CSR to target format
        
        Args:
            csr_content: Original PEM/DER CSR content
            target_format: Target format (pem, der)
            
        Returns:
            Converted CSR as bytes
        """
        logger.debug(f"Converting CSR to format: {target_format}")
        
        # Parse the original CSR
        if isinstance(csr_content, str):
            # Assume PEM if it's a string
            csr = x509.load_pem_x509_csr(csr_content.encode())
        else:
            # Assume DER if it's bytes
            csr = x509.load_der_x509_csr(csr_content)
        
        # Convert to target format
        if target_format.lower() == 'pem':
            return csr.public_bytes(serialization.Encoding.PEM)
        elif target_format.lower() == 'der':
            return csr.public_bytes(serialization.Encoding.DER)
        else:
            # Default to PEM
            logger.warning(f"Unknown format {target_format}, defaulting to PEM")
            return csr.public_bytes(serialization.Encoding.PEM)

    # ===== ENHANCED METHODS FOR BUNDLE CREATION =====

    def create_pkcs12_bundle(self, cert_pem: str, key_pem: str, ca_bundle: Optional[str], password: Optional[str] = None) -> bytes:
        """
        Create PKCS#12 bundle from PEM components
        
        Args:
            cert_pem: Certificate in PEM format
            key_pem: Private key in PEM format  
            ca_bundle: CA certificate chain in PEM format (optional)
            password: Password to encrypt the PKCS#12 bundle (optional - None creates unencrypted)
            
        Returns:
            PKCS#12 bundle as bytes
        """
        logger.debug(f"Creating PKCS#12 bundle with password protection")
        
        try:
            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            
            # Parse private key
            private_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None
            )
            
            # Validate key type is supported by PKCS#12
            self._validate_pkcs12_key_type(private_key)
            
            # Parse CA certificates
            ca_certs = self._parse_ca_bundle(ca_bundle)
            
            # Type cast to satisfy Pylance - we've already validated the key type above
            from typing import cast
            from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12PrivateKeyTypes
            validated_key = cast(PKCS12PrivateKeyTypes, private_key)
            
            # FIXED: Handle optional password properly
            if password and password.strip():
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            # Create PKCS#12 bundle with validated key type
            p12_data = pkcs12.serialize_key_and_certificates(
                name=b"certificate-bundle",
                key=validated_key,
                cert=cert,
                cas=ca_certs if ca_certs else None,
                encryption_algorithm=encryption_algorithm
            )
            
            logger.info(f"Created PKCS#12 bundle ({len(p12_data)} bytes)")
            return p12_data
            
        except Exception as e:
            logger.error(f"PKCS#12 creation failed: {e}")
            raise

    def create_pkcs7_bundle(self, certificates_pem: list) -> str:
        """
        Create PKCS#7 certificate chain bundle
        
        Args:
            certificates_pem: List of certificate PEM strings
            
        Returns:
            PKCS#7 bundle in PEM format (fallback to concatenated PEM)
        """
        logger.debug(f"Creating PKCS#7 bundle with {len(certificates_pem)} certificates")
        
        try:
            # The cryptography library's PKCS#7 support is limited
            # For certificate bundles, concatenated PEM is often preferred and more compatible
            cert_data = ""
            valid_certs = 0
            
            for cert_pem in certificates_pem:
                try:
                    # Validate the certificate can be parsed
                    x509.load_pem_x509_certificate(cert_pem.encode())
                    cert_data += cert_pem + "\n"
                    valid_certs += 1
                except Exception as e:
                    logger.warning(f"Failed to parse certificate for bundle: {e}")
            
            if valid_certs == 0:
                raise ValueError("No valid certificates found for certificate bundle")
            
            logger.info(f"Created certificate bundle with {valid_certs} certificates")
            return cert_data
            
        except Exception as e:
            logger.error(f"Certificate bundle creation failed: {e}")
            raise

    def process_bundle_requests(self, session, format_selections: dict) -> dict:
        """
        Process special bundle format requests (PKCS7, PKCS12)
        
        Args:
            session: PKI session
            format_selections: Dictionary of format requests
            
        Returns:
            Dictionary of bundle files {filename: content}
        """
        bundle_files = {}
        
        # PKCS#7 bundle
        if 'pkcs7_bundle' in format_selections:
            try:
                # Collect certificate PEM strings
                cert_pems = []
                for component in session.components.values():
                    if component.type.type_name in ['Certificate', 'RootCA', 'IntermediateCA']:
                        cert_pems.append(component.content)
                
                if cert_pems:
                    pkcs7_content = self.create_pkcs7_bundle(cert_pems)
                    bundle_files['certificate-chain.p7b'] = pkcs7_content
                    logger.info("Added PKCS#7 bundle to download")
                
            except Exception as e:
                logger.warning(f"Failed to create PKCS#7 bundle: {e}")
        
        # PKCS#12 bundle  
        if 'pkcs12_bundle' in format_selections:
            try:
                cert_component, key_component = self._find_cert_and_key(session)
                if cert_component and key_component:
                    # Generate bundle password
                    from services.secure_zip_creator import secure_zip_creator
                    bundle_password = secure_zip_creator.generate_secure_password()
                    
                    # Get CA bundle
                    ca_bundle = self._extract_ca_bundle(session)
                    
                    # Create PKCS#12 bundle
                    pkcs12_content = self.create_pkcs12_bundle(
                        cert_component.content,
                        key_component.content,
                        ca_bundle,
                        bundle_password
                    )
                    
                    bundle_files['certificate.p12'] = pkcs12_content
                    logger.info("Added PKCS#12 bundle to download")
                    
            except Exception as e:
                logger.warning(f"Failed to create PKCS#12 bundle: {e}")
        
        return bundle_files

    def get_password_type_for_manifest(self) -> Optional[str]:
        """Get the type of password that was last generated for manifest display"""
        return getattr(self, '_last_password_type', None)

    # ===== HELPER METHODS =====

    def _validate_pkcs12_key_type(self, private_key):
        """Validate private key type is supported by PKCS#12"""
        from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, dh
        
        supported_key_types = (
            rsa.RSAPrivateKey,
            dsa.DSAPrivateKey, 
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey
        )
        
        # Check for unsupported DH keys
        if isinstance(private_key, dh.DHPrivateKey):
            raise ValueError("Diffie-Hellman (DH) private keys are not supported for PKCS#12 bundles")
        
        if not isinstance(private_key, supported_key_types):
            raise ValueError(f"Private key type {type(private_key).__name__} is not supported for PKCS#12 bundles")

    def _parse_ca_bundle(self, ca_bundle: Optional[str]) -> list:
        """Parse CA certificate bundle into list of certificates"""
        ca_certs = []
        
        if ca_bundle:
            for ca_cert_pem in ca_bundle.split('-----END CERTIFICATE-----'):
                if '-----BEGIN CERTIFICATE-----' in ca_cert_pem:
                    ca_cert_full = ca_cert_pem + '-----END CERTIFICATE-----'
                    try:
                        ca_cert = x509.load_pem_x509_certificate(ca_cert_full.encode())
                        ca_certs.append(ca_cert)
                    except Exception as e:
                        logger.warning(f"Failed to parse CA certificate: {e}")
        
        return ca_certs

    def _find_cert_and_key(self, session):
        """Find certificate and private key components in session"""
        from certificates.storage.session_pki_storage import PKIComponentType
        
        cert_component = None
        key_component = None
        
        for component in session.components.values():
            if component.type == PKIComponentType.CERTIFICATE:
                cert_component = component
            elif component.type == PKIComponentType.PRIVATE_KEY:
                key_component = component
        
        return cert_component, key_component

    def _extract_ca_bundle(self, session) -> Optional[str]:
        """Extract CA certificate bundle from session"""
        from certificates.storage.session_pki_storage import PKIComponentType
        
        ca_certs = []
        
        for component in session.components.values():
            if component.type in [PKIComponentType.ROOT_CA, PKIComponentType.INTERMEDIATE_CA, PKIComponentType.ISSUING_CA]:
                ca_certs.append(component.content)
        
        return '\n'.join(ca_certs) if ca_certs else None

# Global instance
format_converter = FormatConverter()

# Add methods to get the last encryption password and type
def get_last_encryption_password() -> Optional[str]:
    """Get the last encryption password generated from the global instance"""
    return getattr(format_converter, '_last_encryption_password', None)

def get_last_password_type() -> Optional[str]:
    """Get the type of the last password generated (PKCS#8, PEM, P12)"""
    return getattr(format_converter, '_last_password_type', None)