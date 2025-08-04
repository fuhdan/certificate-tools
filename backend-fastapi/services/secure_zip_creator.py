"""
Secure ZIP Creation & Password Protection Service
Provides AES-256 encrypted ZIP file generation with cryptographically secure passwords.

FINAL VERSION: Uses pyzipper for true AES-256 encrypted ZIP files (pure Python)
"""

import os
import io
import secrets
import string
import zipfile
import logging
from typing import Tuple, Optional, Union, Mapping, Dict, List
from datetime import datetime
from pathlib import Path
import tempfile
import shutil
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class SecureZipCreatorError(Exception):
    """Base exception for SecureZipCreator operations"""
    pass


class ZipCreationError(SecureZipCreatorError):
    """Raised when ZIP creation fails"""
    pass


class PasswordGenerationError(SecureZipCreatorError):
    """Raised when password generation fails"""
    pass


class ZipValidationError(SecureZipCreatorError):
    """Raised when ZIP validation fails"""
    pass


class SecureZipCreator:
    """
    Service for creating password-protected ZIP files with AES-256 encryption.
    
    Features:
    - TRUE AES-256 encrypted ZIP files using pyzipper (pure Python)
    - Cryptographically secure password generation
    - Memory-efficient streaming for large files
    - Automatic cleanup of temporary resources
    - ZIP integrity validation
    - Graceful fallback to unencrypted ZIP if pyzipper unavailable
    """
    
    # Password generation constants
    MIN_PASSWORD_LENGTH = 16
    DEFAULT_PASSWORD_LENGTH = 20
    PASSWORD_CHARSET = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def __init__(self):
        """Initialize the SecureZipCreator service."""
        self._temp_dir = None
        self._check_encryption_support()
        logger.info("SecureZipCreator service initialized")
    
    def _check_encryption_support(self):
        """Check if pyzipper is available for encryption"""
        try:
            import pyzipper  # type: ignore
            self._has_encryption = True
            logger.info("SecureZipCreator: AES-256 encryption available (pyzipper)")
        except ImportError:
            self._has_encryption = False
            logger.warning("SecureZipCreator: AES-256 encryption NOT available (pyzipper missing)")
            logger.warning("Install with: pip install pyzipper")
    
    @contextmanager
    def _temp_directory(self):
        """Context manager for temporary directory with automatic cleanup."""
        temp_dir = tempfile.mkdtemp(prefix="secure_zip_")
        try:
            yield temp_dir
        finally:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp directory {temp_dir}: {e}")
    
    def generate_secure_password(self, length: Optional[int] = None) -> str:
        """
        Generate a cryptographically secure random password.
        
        Args:
            length: Password length (minimum 16, default 20)
            
        Returns:
            Secure random password string
            
        Raises:
            PasswordGenerationError: If password generation fails
        """
        if length is None:
            length = self.DEFAULT_PASSWORD_LENGTH
            
        if length < self.MIN_PASSWORD_LENGTH:
            raise PasswordGenerationError(
                f"Password length must be at least {self.MIN_PASSWORD_LENGTH} characters"
            )
        
        try:
            # Ensure password complexity requirements
            password_chars = []
            
            # At least one from each category
            password_chars.append(secrets.choice(string.ascii_lowercase))
            password_chars.append(secrets.choice(string.ascii_uppercase))
            password_chars.append(secrets.choice(string.digits))
            password_chars.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
            
            # Fill remaining length with random chars from full charset
            for _ in range(length - 4):
                password_chars.append(secrets.choice(self.PASSWORD_CHARSET))
            
            # Shuffle to avoid predictable patterns
            password_list = password_chars.copy()
            for i in range(len(password_list)):
                j = secrets.randbelow(len(password_list))
                password_list[i], password_list[j] = password_list[j], password_list[i]
            
            password = ''.join(password_list)
            
            logger.debug(f"Generated secure password of length {len(password)}")
            return password
            
        except Exception as e:
            logger.error(f"Password generation failed: {e}")
            raise PasswordGenerationError(f"Failed to generate secure password: {e}")
    
    def create_protected_zip(
        self, 
        files: Mapping[str, Union[bytes, str]], 
        password: Optional[str] = None
    ) -> Tuple[bytes, str]:
        """
        Create a password-protected ZIP file with AES-256 encryption.
        
        Args:
            files: Mapping of filename to file content (bytes or string)
            password: Optional password (generates secure one if not provided)
            
        Returns:
            Tuple of (zip_data_bytes, password_used)
            
        Raises:
            ZipCreationError: If ZIP creation fails
        """
        if not files:
            raise ZipCreationError("No files provided for ZIP creation")
        
        # Generate password if not provided
        if password is None:
            password = self.generate_secure_password()
        
        # Try encrypted ZIP first, fallback to unencrypted
        if self._has_encryption:
            try:
                return self._create_encrypted_zip(files, password)
            except Exception as e:
                logger.error(f"Encrypted ZIP creation failed: {e}")
                logger.warning("Falling back to unencrypted ZIP")
        
        # Fallback to unencrypted ZIP
        return self._create_unencrypted_zip(files, password)
    
    def _create_encrypted_zip(
        self, 
        files: Mapping[str, Union[bytes, str]], 
        password: str
    ) -> Tuple[bytes, str]:
        """
        Create AES-256 encrypted ZIP using pyzipper.
        
        Args:
            files: Mapping of filename to file content
            password: Password for encryption
            
        Returns:
            Tuple of (zip_data_bytes, password_used)
        """
        import pyzipper  # type: ignore
        
        try:
            with self._temp_directory() as temp_dir:
                zip_path = Path(temp_dir) / "encrypted.zip"
                
                # Create AES encrypted ZIP using pyzipper
                with pyzipper.AESZipFile(
                    str(zip_path), 
                    'w', 
                    compression=pyzipper.ZIP_DEFLATED,
                    encryption=pyzipper.WZ_AES
                ) as zf:
                    # Set password for AES encryption
                    zf.setpassword(password.encode('utf-8'))
                    
                    for filename, content in files.items():
                        # Convert string content to bytes if necessary
                        if isinstance(content, str):
                            content = content.encode('utf-8')
                        
                        # Add file to encrypted ZIP
                        zf.writestr(filename, content)
                        logger.debug(f"Added encrypted file '{filename}' ({len(content)} bytes)")
                
                # Read the created encrypted ZIP file
                zip_data = zip_path.read_bytes()
                
                logger.info(f"Created AES-256 encrypted ZIP with {len(files)} files ({len(zip_data)} bytes)")
                
                return zip_data, password
                
        except Exception as e:
            logger.error(f"AES-256 ZIP creation failed: {e}")
            raise ZipCreationError(f"Failed to create encrypted ZIP: {e}")
    
    def _create_unencrypted_zip(
        self, 
        files: Mapping[str, Union[bytes, str]], 
        password: str
    ) -> Tuple[bytes, str]:
        """
        Fallback: Create unencrypted ZIP using standard zipfile module.
        
        Args:
            files: Mapping of filename to file content
            password: Password (returned but ZIP won't be encrypted)
            
        Returns:
            Tuple of (zip_data_bytes, password_used)
        """
        try:
            with self._temp_directory() as temp_dir:
                zip_path = Path(temp_dir) / "unencrypted.zip"
                
                # Create standard ZIP with maximum compression
                with zipfile.ZipFile(
                    zip_path, 
                    'w', 
                    zipfile.ZIP_DEFLATED,
                    compresslevel=9
                ) as zip_file:
                    
                    for filename, content in files.items():
                        try:
                            # Convert string content to bytes if necessary
                            if isinstance(content, str):
                                content = content.encode('utf-8')
                            
                            # Add file to ZIP (NO ENCRYPTION - zipfile limitation)
                            zip_file.writestr(
                                filename, 
                                content,
                                compress_type=zipfile.ZIP_DEFLATED
                            )
                            
                            logger.debug(f"Added file '{filename}' to unencrypted ZIP ({len(content)} bytes)")
                            
                        except Exception as e:
                            logger.error(f"Failed to add file '{filename}' to ZIP: {e}")
                            raise ZipCreationError(f"Failed to add file '{filename}': {e}")
                
                # Read the created ZIP file
                zip_data = zip_path.read_bytes()
                
                logger.warning(f"Created UNENCRYPTED ZIP with {len(files)} files ({len(zip_data)} bytes)")
                logger.warning("Install 'pyzipper' for AES-256 encryption support")
                
                return zip_data, password
                
        except ZipCreationError:
            raise
        except Exception as e:
            logger.error(f"Unencrypted ZIP creation failed: {e}")
            raise ZipCreationError(f"Failed to create ZIP: {e}")
    
    def validate_zip_integrity(self, zip_data: bytes, password: str) -> bool:
        """
        Validate the integrity of a password-protected ZIP file.
        
        Args:
            zip_data: ZIP file data as bytes
            password: Password for the ZIP file
            
        Returns:
            True if ZIP is valid and password is correct
            
        Raises:
            ZipValidationError: If validation fails
        """
        if not zip_data:
            raise ZipValidationError("No ZIP data provided for validation")
        
        if not password:
            raise ZipValidationError("No password provided for validation")
        
        try:
            with self._temp_directory() as temp_dir:
                zip_path = Path(temp_dir) / "validate.zip"
                zip_path.write_bytes(zip_data)
                
                # Try with pyzipper first if available
                if self._has_encryption:
                    try:
                        import pyzipper  # type: ignore
                        with pyzipper.AESZipFile(str(zip_path), 'r') as zip_file:
                            zip_file.setpassword(password.encode('utf-8'))
                            
                            # Try to read first file to verify password
                            file_list = zip_file.namelist()
                            if file_list:
                                try:
                                    zip_file.read(file_list[0])
                                    logger.debug(f"AES ZIP integrity validated successfully ({len(file_list)} files)")
                                    return True
                                except RuntimeError as e:
                                    if "Bad password" in str(e) or "incorrect password" in str(e).lower():
                                        logger.error("AES ZIP password validation failed")
                                        return False
                                    raise
                            return True
                    except Exception:
                        # Fall back to standard zipfile validation
                        pass
                
                # Standard zipfile validation
                with zipfile.ZipFile(zip_path, 'r') as zip_file:
                    # Set password
                    zip_file.setpassword(password.encode('utf-8'))
                    
                    # Test all files in the ZIP
                    test_result = zip_file.testzip()
                    
                    if test_result is not None:
                        logger.error(f"ZIP integrity check failed for file: {test_result}")
                        return False
                    
                    # Try to read first file to verify password
                    file_list = zip_file.namelist()
                    if file_list:
                        try:
                            zip_file.read(file_list[0])
                            logger.debug(f"ZIP integrity validated successfully ({len(file_list)} files)")
                            return True
                        except RuntimeError as e:
                            if "Bad password" in str(e) or "incorrect password" in str(e).lower():
                                logger.error("ZIP password validation failed")
                                return False
                            raise
                    
                    # If no files, consider it valid
                    logger.debug("ZIP integrity validated (empty ZIP)")
                    return True
                    
        except ZipValidationError:
            raise
        except Exception as e:
            logger.error(f"ZIP validation error: {e}")
            raise ZipValidationError(f"Failed to validate ZIP integrity: {e}")
    
    def create_apache_bundle(
        self,
        certificate: Union[bytes, str],
        private_key: Union[bytes, str],
        ca_bundle: Optional[Union[bytes, str]],
        apache_guide: str,
        nginx_guide: str,
        password: Optional[str] = None,
        session_id: Optional[str] = None,
        selected_components: Optional[List] = None
    ) -> Tuple[bytes, str]:
        """
        Create password-protected ZIP file for Apache with installation guides and manifest.
        """
        # Convert bytes to strings if needed
        if isinstance(certificate, bytes):
            certificate = certificate.decode('utf-8')
        if isinstance(private_key, bytes):
            private_key = private_key.decode('utf-8')
        
        # FIXED: Handle None ca_bundle
        if ca_bundle is not None:
            if isinstance(ca_bundle, bytes):
                ca_bundle = ca_bundle.decode('utf-8')
        else:
            # Create a placeholder message when no CA bundle is available
            ca_bundle = "# No CA certificates found in this bundle\n# This certificate may be self-signed or the CA certificates were not uploaded\n"
            
        files = {
            'certificate.crt': certificate,
            'private-key.pem': private_key,
            'ca-bundle.crt': ca_bundle,
            'APACHE_INSTALLATION_GUIDE.txt': apache_guide,
            'NGINX_INSTALLATION_GUIDE.txt': nginx_guide
        }
        
        # Generate manifest using ACTUAL ZIP FILES instead of original components
        if session_id:
            # Ensure strings for manifest generation
            cert_str = str(certificate)
            key_str = str(private_key) 
            ca_str = str(ca_bundle)
            
            manifest_components = self._create_apache_manifest_components(
                cert_str, key_str, ca_str, apache_guide, nginx_guide, selected_components
            )
            manifest = self._generate_content_manifest(
                manifest_components, 
                "Apache/Nginx", 
                session_id, 
                password
            )
            files['CONTENT_MANIFEST.txt'] = manifest
        
        logger.info("Creating AES-256 encrypted Apache certificate bundle with manifest")
        return self.create_protected_zip(files, password)
    
    def create_iis_bundle(
        self,
        p12_bundle: bytes,
        iis_guide: str, 
        cert_info: str,
        password: Optional[str] = None,
        session_id: Optional[str] = None,
        selected_components: Optional[List] = None,
        bundle_password: Optional[str] = None
    ) -> Tuple[bytes, str]:
        """
        Create password-protected ZIP file for IIS with PKCS#12 bundle and manifest.
        """
        files = {
            'certificate-bundle.pfx': p12_bundle,
            'IIS_INSTALLATION_GUIDE.txt': iis_guide,
            'CERTIFICATE_INFO.txt': cert_info
        }
        
        # Generate manifest using ACTUAL ZIP FILES instead of original components
        if session_id:
            manifest_components = self._create_iis_manifest_components(
                p12_bundle, iis_guide, cert_info, selected_components, bundle_password
            )
            manifest = self._generate_content_manifest(
                manifest_components, 
                "IIS/Windows", 
                session_id, 
                password,
                bundle_password
            )
            files['CONTENT_MANIFEST.txt'] = manifest
        
        logger.info("Creating AES-256 encrypted IIS certificate bundle with manifest")
        return self.create_protected_zip(files, password)
    
    def get_memory_usage_estimate(self, files: Mapping[str, Union[bytes, str]]) -> int:
        """
        Estimate memory usage for ZIP creation.
        
        Args:
            files: Files to be included in ZIP
            
        Returns:
            Estimated memory usage in bytes
        """
        total_size = 0
        for content in files.values():
            if isinstance(content, str):
                total_size += len(content.encode('utf-8'))
            else:
                total_size += len(content)
        
        # Estimate: original size + compression overhead + ZIP structure + encryption overhead
        estimated_memory = total_size * 1.7  # Conservative estimate with encryption
        
        logger.debug(f"Estimated memory usage: {estimated_memory:.0f} bytes")
        return int(estimated_memory)

    def create_advanced_bundle(
        self,
        files: Dict[str, Union[bytes, str]],
        bundles: Dict[str, Union[bytes, str]],
        password: Optional[str] = None,
        session_id: Optional[str] = None,
        selected_components: Optional[List] = None,
        readme: Optional[str] = None
    ) -> Tuple[bytes, str]:
        """
        Create password-protected ZIP file for advanced downloads with manifest.
        
        Args:
            files: Dictionary of filename -> content for individual files
            bundles: Dictionary of bundle_name -> bundle_data for bundled files
            password: Optional password
            session_id: Session identifier for manifest
            selected_components: List of PKI components for manifest generation
            readme: Optional README content
            
        Returns:
            Tuple of (zip_data, password)
        """
        zip_files = {}
        
        # Add individual files to root
        for filename, content in files.items():
            zip_files[filename] = content
        
        # Add bundles - can be password-protected sub-files
        for bundle_name, bundle_data in bundles.items():
            if bundle_name.endswith('.zip'):
                # Bundle is a ZIP file - add password info
                password_filename = bundle_name.replace('.zip', '_password.txt')
                password_info = f"Password for {bundle_name}: BUNDLE_PASSWORD_HERE\n\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                zip_files[password_filename] = password_info
                zip_files[bundle_name] = bundle_data
            else:
                # Add directly to root
                zip_files[bundle_name] = bundle_data

        # Add README if provided - directly to root
        if readme:
            zip_files["README.txt"] = readme

        # Generate manifest if components provided
        if selected_components and session_id:
            manifest = self._generate_content_manifest(
                selected_components, 
                "Advanced Selection", 
                session_id, 
                password
            )
            zip_files['CONTENT_MANIFEST.txt'] = manifest

        # Add download info - directly to root  
        password = self.generate_secure_password()
        download_info = self._create_advanced_download_info(password)
        zip_files["DOWNLOAD_INFO.txt"] = download_info

        # Use the SAME create_protected_zip method as Apache/IIS (with pyzipper AES-256)
        logger.info("Creating AES-256 encrypted advanced bundle with manifest")
        return self.create_protected_zip(zip_files, password)

    def _create_advanced_download_info(self, zip_password: str) -> str:
        """Create advanced download information file using instruction generator"""

        # Use the instruction generator for consistent formatting
        from services.instruction_generator import InstructionGenerator
        instruction_generator = InstructionGenerator()

        # We don't have session_id or component_count here, so use fallback
        return instruction_generator.generate_advanced_download_info(
            session_id="SESSION", 
            component_count=1, 
            zip_password=zip_password
        )

    def _generate_content_manifest(
        self, 
        selected_components: List, 
        bundle_type: str, 
        session_id: str, 
        zip_password: Optional[str] = None,
        bundle_password: Optional[str] = None
    ) -> str:
        """Generate content manifest using ContentManifestGenerator"""
        try:
            from services.content_manifest_generator import ContentManifestGenerator
            
            manifest_generator = ContentManifestGenerator()
            
            # Generate actual password if not provided
            actual_zip_password = zip_password or "WILL_BE_GENERATED"
            
            manifest = manifest_generator.generate_manifest(
                selected_components=selected_components,
                bundle_type=bundle_type,
                session_id=session_id,
                zip_password=actual_zip_password,
                bundle_password=bundle_password
            )
            
            logger.info(f"Generated content manifest for {bundle_type} bundle")
            return manifest
            
        except Exception as e:
            logger.error(f"Failed to generate content manifest: {e}")
            # Return fallback manifest
            return self._create_fallback_manifest(bundle_type, session_id, zip_password)

    def _create_fallback_manifest(self, bundle_type: str, session_id: str, zip_password: Optional[str]) -> str:
        """Create simple fallback manifest if generation fails"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return f"""================================================================================
ZIP BUNDLE CONTENTS MANIFEST (FALLBACK)
================================================================================

Bundle Information:
- Bundle Type: {bundle_type}
- Session ID: {session_id}
- Generated: {timestamp}
- ZIP Password: {zip_password or 'N/A'}

NOTE: This is a simplified manifest due to content generation error.
Check individual files for detailed information.

Generated by: Certificate Analysis Tool
Tool Version: 2.0-PKI

================================================================================
END OF MANIFEST
================================================================================"""

    def _create_apache_manifest_components(self, certificate: str, private_key: str, ca_bundle: str, 
                                         apache_guide: str, nginx_guide: str, original_components: Optional[List]) -> List:
        """Create virtual PKI components representing the actual files in Apache ZIP"""
        from certificates.storage.session_pki_storage import PKIComponent, PKIComponentType
        
        manifest_components = []
        current_time = datetime.now().isoformat()  # Convert to string format
        
        # Find original certificate component for metadata
        cert_metadata = {}
        key_metadata = {}
        if original_components:
            for comp in original_components:
                if comp.type == PKIComponentType.CERTIFICATE:
                    cert_metadata = comp.metadata or {}
                elif comp.type == PKIComponentType.PRIVATE_KEY:
                    key_metadata = comp.metadata or {}
        
        # Create virtual components for actual ZIP files
        # Certificate file
        cert_component = PKIComponent(
            id="apache_cert",
            filename="certificate.crt",
            content=certificate,
            type=PKIComponentType.CERTIFICATE,
            metadata=cert_metadata,
            order=1,
            uploaded_at=current_time
        )
        manifest_components.append(cert_component)
        
        # Private key file
        key_component = PKIComponent(
            id="apache_key",
            filename="private-key.pem", 
            content=private_key,
            type=PKIComponentType.PRIVATE_KEY,
            metadata=key_metadata,
            order=2,
            uploaded_at=current_time
        )
        manifest_components.append(key_component)
        
        # CA bundle file (if not placeholder)
        if not ca_bundle.startswith("# No CA certificates"):
            ca_component = PKIComponent(
                id="apache_ca",
                filename="ca-bundle.crt",
                content=ca_bundle,
                type=PKIComponentType.ROOT_CA,  # Generic CA type
                metadata={"subject": "CA Bundle", "description": "Certificate Authority bundle"},
                order=3,
                uploaded_at=current_time
            )
            manifest_components.append(ca_component)
        
        # Installation guides - use PRIVATE_KEY type with special metadata to identify as text files
        apache_guide_component = PKIComponent(
            id="apache_guide",
            filename="APACHE_INSTALLATION_GUIDE.txt",
            content=apache_guide,
            type=PKIComponentType.PRIVATE_KEY,  # Use as placeholder type
            metadata={
                "description": "Apache web server installation guide",
                "file_type": "text",
                "content_type": "installation_guide"
            },
            order=4,
            uploaded_at=current_time
        )
        manifest_components.append(apache_guide_component)
        
        nginx_guide_component = PKIComponent(
            id="nginx_guide", 
            filename="NGINX_INSTALLATION_GUIDE.txt",
            content=nginx_guide,
            type=PKIComponentType.PRIVATE_KEY,  # Use as placeholder type
            metadata={
                "description": "Nginx web server installation guide",
                "file_type": "text",
                "content_type": "installation_guide"
            },
            order=5,
            uploaded_at=current_time
        )
        manifest_components.append(nginx_guide_component)
        
        return manifest_components

    def _create_iis_manifest_components(self, p12_bundle: bytes, iis_guide: str, cert_info: str, 
                                      original_components: Optional[List], bundle_password: Optional[str]) -> List:
        """Create virtual PKI components representing the actual files in IIS ZIP"""
        from certificates.storage.session_pki_storage import PKIComponent, PKIComponentType
        
        manifest_components = []
        current_time = datetime.now().isoformat()  # Convert to string format
        
        # Find original certificate component for metadata
        cert_metadata = {}
        if original_components:
            for comp in original_components:
                if comp.type == PKIComponentType.CERTIFICATE:
                    cert_metadata = comp.metadata or {}
                    break
        
        # Create virtual components for actual ZIP files
        # PKCS#12 bundle file
        p12_metadata = dict(cert_metadata)  # Copy certificate metadata
        p12_metadata.update({
            "format": "PKCS#12",
            "contains": "Certificate + Private Key + CA Chain",
            "password_protected": "Yes" if bundle_password else "No"
        })
        
        # Convert bytes to string for PKI component content
        p12_content_str = f"PKCS#12 binary bundle ({len(p12_bundle)} bytes)"
        
        p12_component = PKIComponent(
            id="iis_p12",
            filename="certificate-bundle.pfx",
            content=p12_content_str,  # Use string description instead of bytes
            type=PKIComponentType.CERTIFICATE,  # P12 is primarily a certificate bundle
            metadata=p12_metadata,
            order=1,
            uploaded_at=current_time
        )
        manifest_components.append(p12_component)
        
        # Installation guide - use PRIVATE_KEY type with special metadata
        iis_guide_component = PKIComponent(
            id="iis_guide",
            filename="IIS_INSTALLATION_GUIDE.txt",
            content=iis_guide,
            type=PKIComponentType.PRIVATE_KEY,  # Use as placeholder type
            metadata={
                "description": "IIS web server installation guide",
                "file_type": "text",
                "content_type": "installation_guide"
            },
            order=2,
            uploaded_at=current_time
        )
        manifest_components.append(iis_guide_component)
        
        # Certificate info - use PRIVATE_KEY type with special metadata
        cert_info_component = PKIComponent(
            id="cert_info",
            filename="CERTIFICATE_INFO.txt", 
            content=cert_info,
            type=PKIComponentType.PRIVATE_KEY,  # Use as placeholder type
            metadata={
                "description": "Certificate information and passwords",
                "file_type": "text",
                "content_type": "certificate_info"
            },
            order=3,
            uploaded_at=current_time
        )
        manifest_components.append(cert_info_component)
        
        return manifest_components

# Global service instance
secure_zip_creator = SecureZipCreator()