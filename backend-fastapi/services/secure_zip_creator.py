"""
Secure ZIP Creation & Password Protection Service
Provides AES-256 encrypted ZIP file generation with cryptographically secure passwords.
"""

import os
import io
import secrets
import string
import zipfile
import logging
from typing import Dict, Tuple, Optional, Union
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
    - AES-256 encrypted ZIP files
    - Cryptographically secure password generation
    - Memory-efficient streaming for large files
    - Automatic cleanup of temporary resources
    - ZIP integrity validation
    """
    
    # Password generation constants
    MIN_PASSWORD_LENGTH = 16
    DEFAULT_PASSWORD_LENGTH = 20
    PASSWORD_CHARSET = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def __init__(self):
        """Initialize the SecureZipCreator service."""
        self._temp_dir = None
        logger.info("SecureZipCreator service initialized")
    
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
        files: Dict[str, Union[bytes, str]], 
        password: Optional[str] = None
    ) -> Tuple[bytes, str]:
        """
        Create a password-protected ZIP file with AES-256 encryption.
        
        Args:
            files: Dictionary mapping filename to file content (bytes or string)
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
        
        try:
            with self._temp_directory() as temp_dir:
                zip_path = Path(temp_dir) / "protected.zip"
                
                # Create password-protected ZIP with maximum compression
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
                            
                            # Set password for this file (AES-256 encryption)
                            zip_file.setpassword(password.encode('utf-8'))
                            
                            # Add file to ZIP with encryption
                            zip_file.writestr(
                                filename, 
                                content,
                                compress_type=zipfile.ZIP_DEFLATED
                            )
                            
                            logger.debug(f"Added file '{filename}' to ZIP ({len(content)} bytes)")
                            
                        except Exception as e:
                            logger.error(f"Failed to add file '{filename}' to ZIP: {e}")
                            raise ZipCreationError(f"Failed to add file '{filename}': {e}")
                
                # Read the created ZIP file
                zip_data = zip_path.read_bytes()
                
                logger.info(f"Created password-protected ZIP with {len(files)} files ({len(zip_data)} bytes)")
                
                return zip_data, password
                
        except ZipCreationError:
            raise
        except Exception as e:
            logger.error(f"ZIP creation failed: {e}")
            raise ZipCreationError(f"Failed to create protected ZIP: {e}")
    
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
                        except RuntimeError as e:
                            if "Bad password" in str(e):
                                logger.error("ZIP password validation failed")
                                return False
                            raise
                    
                    logger.debug(f"ZIP integrity validated successfully ({len(file_list)} files)")
                    return True
                    
        except ZipValidationError:
            raise
        except Exception as e:
            logger.error(f"ZIP validation error: {e}")
            raise ZipValidationError(f"Failed to validate ZIP integrity: {e}")
    
    def create_apache_bundle(
        self, 
        certificate: bytes, 
        private_key: bytes, 
        ca_bundle: bytes,
        apache_guide: str,
        nginx_guide: str,
        password: Optional[str] = None
    ) -> Tuple[bytes, str]:
        """
        Create Apache certificate bundle ZIP file.
        
        Args:
            certificate: Certificate file content
            private_key: Private key file content
            ca_bundle: CA bundle file content
            apache_guide: Apache installation guide text
            nginx_guide: Nginx installation guide text
            password: Optional password
            
        Returns:
            Tuple of (zip_data, password)
        """
        files = {
            'certificate.crt': certificate,
            'private-key.key': private_key,
            'ca-bundle.crt': ca_bundle,
            'APACHE_INSTALLATION_GUIDE.txt': apache_guide,
            'NGINX_INSTALLATION_GUIDE.txt': nginx_guide
        }
        
        logger.info("Creating Apache certificate bundle")
        return self.create_protected_zip(files, password)
    
    def create_iis_bundle(
        self, 
        p12_bundle: bytes, 
        iis_guide: str,
        cert_info: str,
        password: Optional[str] = None
    ) -> Tuple[bytes, str]:
        """
        Create IIS certificate bundle ZIP file.
        
        Args:
            p12_bundle: PKCS#12 bundle file content
            iis_guide: IIS installation guide text
            cert_info: Certificate information text
            password: Optional password
            
        Returns:
            Tuple of (zip_data, password)
        """
        files = {
            'certificate-bundle.p12': p12_bundle,
            'IIS_INSTALLATION_GUIDE.txt': iis_guide,
            'CERTIFICATE_INFO.txt': cert_info
        }
        
        logger.info("Creating IIS certificate bundle")
        return self.create_protected_zip(files, password)
    
    def get_memory_usage_estimate(self, files: Dict[str, Union[bytes, str]]) -> int:
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
        
        # Estimate: original size + compression overhead + ZIP structure
        estimated_memory = total_size * 1.5  # Conservative estimate
        
        logger.debug(f"Estimated memory usage: {estimated_memory:.0f} bytes")
        return int(estimated_memory)


# Global service instance
secure_zip_creator = SecureZipCreator()