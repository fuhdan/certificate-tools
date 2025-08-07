# backend-fastapi/services/password_entry_service.py
"""
Centralized Password Entry Service

Handles all encrypted content password validation and decryption across different formats:
- PEM private keys (with various encryption methods)
- PKCS#8 private keys  
- PKCS#12 bundles
- Any other password-protected cryptographic content

This service standardizes password handling to ensure consistent behavior
across all certificate formats and eliminates format-specific password logic.
"""

import logging
from typing import Dict, Any, Optional, Tuple, Union
from enum import Enum
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

from certificates.utils.hashing import generate_file_hash

logger = logging.getLogger(__name__)

class ContentType(Enum):
    """Types of encrypted content this service can handle"""
    PEM_PRIVATE_KEY = "pem_private_key"
    DER_PRIVATE_KEY = "der_private_key" 
    PKCS8_PRIVATE_KEY = "pkcs8_private_key"
    PKCS12_BUNDLE = "pkcs12_bundle"
    UNKNOWN = "unknown"

class PasswordResult(Enum):
    """Results of password validation attempts"""
    SUCCESS = "success"
    WRONG_PASSWORD = "wrong_password"
    NO_PASSWORD_NEEDED = "no_password_needed"
    PASSWORD_REQUIRED = "password_required"
    INVALID_FORMAT = "invalid_format"
    UNKNOWN_ERROR = "unknown_error"

class PasswordEntryService:
    """Centralized service for handling encrypted content passwords"""
    
    def __init__(self):
        """Initialize the password entry service"""
        logger.debug("Password Entry Service initialized")
        
        # Keywords that indicate password-related errors in different formats
        self.password_error_keywords = {
            'general': ['password', 'decrypt', 'encrypted', 'bad decrypt', 'authentication'],
            'pkcs12': ['mac', 'integrity', 'authentication', 'invalid', 'password'],
            'pem': ['bad decrypt', 'incorrect password', 'wrong password', 'encrypted'],
            'der': ['bad decrypt', 'could not deserialize', 'password']
        }
        
        # Encryption markers for different formats
        self.encryption_markers = {
            'pem': [
                '-----BEGIN ENCRYPTED PRIVATE KEY-----',
                'Proc-Type: 4,ENCRYPTED', 
                'DEK-Info:'
            ],
            'pkcs8': ['-----BEGIN ENCRYPTED PRIVATE KEY-----']
        }
    
    def detect_content_type(self, file_content: bytes, filename: str = "") -> ContentType:
        """
        Detect the type of encrypted content
        
        Args:
            file_content: Raw file bytes
            filename: Original filename for additional context
            
        Returns:
            ContentType enum value
        """
        try:
            # Check file extension first
            if filename:
                ext = filename.lower().split('.')[-1]
                if ext in ['p12', 'pfx']:
                    return ContentType.PKCS12_BUNDLE
                elif ext in ['p8', 'pk8']:
                    return ContentType.PKCS8_PRIVATE_KEY
                elif ext == 'der':
                    return ContentType.DER_PRIVATE_KEY
            
            # Check content markers for PEM
            try:
                content_str = file_content.decode('utf-8', errors='ignore')
                
                # PKCS#12 detection (binary format, starts with ASN.1 sequence)
                if len(file_content) >= 4 and file_content[0] == 0x30:
                    return ContentType.PKCS12_BUNDLE
                
                # PEM format detection
                if '-----BEGIN' in content_str:
                    if any(marker in content_str for marker in self.encryption_markers['pem']):
                        return ContentType.PEM_PRIVATE_KEY
                    elif '-----BEGIN PRIVATE KEY-----' in content_str:
                        return ContentType.PEM_PRIVATE_KEY
                    elif '-----BEGIN RSA PRIVATE KEY-----' in content_str:
                        return ContentType.PEM_PRIVATE_KEY
                    elif '-----BEGIN EC PRIVATE KEY-----' in content_str:
                        return ContentType.PEM_PRIVATE_KEY
                
            except UnicodeDecodeError:
                # Binary content - could be DER or PKCS#12
                if len(file_content) >= 4 and file_content[0] == 0x30:
                    # ASN.1 sequence - could be DER private key or PKCS#12
                    # Try to determine by attempting PKCS#12 parse first
                    try:
                        pkcs12.load_key_and_certificates(file_content, password=None)
                        return ContentType.PKCS12_BUNDLE
                    except:
                        return ContentType.DER_PRIVATE_KEY
            
            return ContentType.UNKNOWN
            
        except Exception as e:
            logger.warning(f"Content type detection failed: {e}")
            return ContentType.UNKNOWN
    
    def is_encrypted(self, file_content: bytes, content_type: ContentType) -> bool:
        """
        Check if content is encrypted (requires password)
        
        Args:
            file_content: Raw file bytes
            content_type: Detected content type
            
        Returns:
            True if content is encrypted, False otherwise
        """
        logger.debug(f"Checking encryption for content type: {content_type}")
        
        try:
            if content_type == ContentType.PEM_PRIVATE_KEY:
                return self._is_pem_encrypted(file_content)
            elif content_type == ContentType.DER_PRIVATE_KEY:
                return self._is_der_encrypted(file_content)
            elif content_type == ContentType.PKCS8_PRIVATE_KEY:
                return self._is_pkcs8_encrypted(file_content)
            elif content_type == ContentType.PKCS12_BUNDLE:
                return self._is_pkcs12_encrypted(file_content)
            else:
                logger.warning(f"Unknown content type for encryption check: {content_type}")
                return False
                
        except Exception as e:
            logger.error(f"Encryption check failed: {e}")
            return False
    
    def validate_password(
        self, 
        file_content: bytes, 
        password: Optional[str], 
        content_type: ContentType
    ) -> Tuple[PasswordResult, Optional[Any], Optional[str]]:
        """
        Validate password for encrypted content and return decrypted content
        
        Args:
            file_content: Raw file bytes
            password: Password to try (None for unencrypted content)
            content_type: Type of content being decrypted
            
        Returns:
            Tuple of (result_status, decrypted_content_or_components, error_message)
        """
        logger.debug(f"Validating password for {content_type}")
        logger.debug(f"Password provided: {'YES' if password else 'NO'}")
        
        try:
            # First check if content is actually encrypted
            if not self.is_encrypted(file_content, content_type):
                logger.debug("Content is not encrypted, attempting to load without password")
                return self._load_without_password(file_content, content_type)
            
            # Content is encrypted - password is required
            if not password:
                logger.debug("Content is encrypted but no password provided")
                return (PasswordResult.PASSWORD_REQUIRED, None, "Password required for encrypted content")
            
            # Try to decrypt with provided password
            return self._decrypt_with_password(file_content, password, content_type)
            
        except Exception as e:
            logger.error(f"Password validation failed: {e}")
            return (PasswordResult.UNKNOWN_ERROR, None, str(e))
    
    def create_password_required_response(
        self, 
        file_content: bytes, 
        content_type: ContentType,
        filename: str = ""
    ) -> Dict[str, Any]:
        """
        Create standardized response for password-required content
        
        Args:
            file_content: Raw file bytes for hash generation
            content_type: Type of encrypted content
            filename: Original filename
            
        Returns:
            Standardized response dictionary
        """
        
        type_names = {
            ContentType.PEM_PRIVATE_KEY: "Private Key - Password Required",
            ContentType.DER_PRIVATE_KEY: "Private Key - Password Required", 
            ContentType.PKCS8_PRIVATE_KEY: "Private Key - Password Required",
            ContentType.PKCS12_BUNDLE: "PKCS12 Certificate - Password Required"
        }
        
        algorithm_names = {
            ContentType.PEM_PRIVATE_KEY: "Encrypted PEM (password required)",
            ContentType.DER_PRIVATE_KEY: "Encrypted DER (password required)",
            ContentType.PKCS8_PRIVATE_KEY: "Encrypted PKCS#8 (password required)", 
            ContentType.PKCS12_BUNDLE: "PKCS12 (password required)"
        }
        
        return {
            "type": type_names.get(content_type, "Encrypted Content - Password Required"),
            "isValid": False,
            "requiresPassword": True,
            "content_hash": generate_file_hash(file_content),
            "details": {
                "algorithm": algorithm_names.get(content_type, "Encrypted (password required)"),
                "key_size": 0,
                "curve": "N/A", 
                "is_encrypted": True,
                "requiresPassword": True
            }
        }
    
    def create_wrong_password_response(
        self, 
        file_content: bytes, 
        content_type: ContentType
    ) -> Dict[str, Any]:
        """
        Create standardized response for wrong password attempts
        
        Args:
            file_content: Raw file bytes for hash generation
            content_type: Type of encrypted content
            
        Returns:
            Standardized response dictionary
        """
        
        type_names = {
            ContentType.PEM_PRIVATE_KEY: "Private Key - Invalid Password",
            ContentType.DER_PRIVATE_KEY: "Private Key - Invalid Password",
            ContentType.PKCS8_PRIVATE_KEY: "Private Key - Invalid Password", 
            ContentType.PKCS12_BUNDLE: "PKCS12 Certificate - Invalid Password"
        }
        
        algorithm_names = {
            ContentType.PEM_PRIVATE_KEY: "Encrypted PEM (incorrect password)",
            ContentType.DER_PRIVATE_KEY: "Encrypted DER (incorrect password)",
            ContentType.PKCS8_PRIVATE_KEY: "Encrypted PKCS#8 (incorrect password)",
            ContentType.PKCS12_BUNDLE: "PKCS12 (incorrect password)"
        }
        
        return {
            "type": type_names.get(content_type, "Encrypted Content - Invalid Password"),
            "isValid": False,
            "requiresPassword": True,
            "content_hash": generate_file_hash(file_content),
            "details": {
                "algorithm": algorithm_names.get(content_type, "Encrypted (incorrect password)"),
                "key_size": 0,
                "curve": "N/A",
                "is_encrypted": True,
                "requiresPassword": True
            }
        }
    
    # Private helper methods
    
    def _is_pem_encrypted(self, file_content: bytes) -> bool:
        """Check if PEM content is encrypted"""
        try:
            content_str = file_content.decode('utf-8', errors='ignore')
            return any(marker in content_str for marker in self.encryption_markers['pem'])
        except:
            return False
    
    def _is_der_encrypted(self, file_content: bytes) -> bool:
        """Check if DER private key is encrypted by attempting to load it"""
        try:
            serialization.load_der_private_key(file_content, password=None)
            return False  # Loaded successfully without password
        except Exception as e:
            error_str = str(e).lower()
            return any(keyword in error_str for keyword in self.password_error_keywords['der'])
    
    def _is_pkcs8_encrypted(self, file_content: bytes) -> bool:
        """Check if PKCS#8 content is encrypted"""
        logger.debug("Checking PKCS#8 encryption status...")
        
        try:
            # Try to decode as PEM first
            try:
                content_str = file_content.decode('utf-8', errors='ignore')
                if '-----BEGIN' in content_str:
                    logger.debug("PKCS#8 content appears to be PEM format")
                    # Check PEM encryption markers
                    is_pem_encrypted = any(marker in content_str for marker in self.encryption_markers['pem'])
                    logger.debug(f"PEM encryption markers found: {is_pem_encrypted}")
                    return is_pem_encrypted
            except UnicodeDecodeError:
                pass
            
            # For DER format, try to load without password
            logger.debug("PKCS#8 content appears to be DER format, testing encryption...")
            
            # Try DER loading first (most common for .p8 files)
            try:
                serialization.load_der_private_key(file_content, password=None)
                logger.debug("Successfully loaded DER PKCS#8 without password - not encrypted")
                return False
            except Exception as der_error:
                logger.debug(f"DER loading without password failed: {der_error}")
                
                # Check if the error indicates encryption
                error_str = str(der_error).lower()
                der_encryption_keywords = [
                    'encrypted', 'password', 'decrypt', 'bad decrypt',
                    'pbes', 'pbes1', 'pbes2',  # PKCS#8 encryption schemes
                    'aes', 'des', '3des',      # Encryption algorithms
                    'pkcs8'                     # PKCS#8 specific
                ]
                
                is_der_encrypted = any(keyword in error_str for keyword in der_encryption_keywords)
                logger.debug(f"DER encryption indicators found: {is_der_encrypted}")
                
                if is_der_encrypted:
                    logger.debug("DER PKCS#8 appears to be encrypted")
                    return True
                
                # Try PEM as fallback
                try:
                    serialization.load_pem_private_key(file_content, password=None)
                    logger.debug("Successfully loaded PEM PKCS#8 without password - not encrypted")
                    return False
                except Exception as pem_error:
                    logger.debug(f"PEM loading without password also failed: {pem_error}")
                    
                    # Check PEM error for encryption indicators
                    pem_error_str = str(pem_error).lower()
                    is_pem_encrypted = any(keyword in pem_error_str for keyword in self.password_error_keywords['pem'])
                    logger.debug(f"PEM encryption indicators found: {is_pem_encrypted}")
                    return is_pem_encrypted
            
        except Exception as e:
            logger.error(f"PKCS#8 encryption check failed: {e}")
            # If we can't determine, assume not encrypted to avoid false positives
            return False
    
    def _is_pkcs12_encrypted(self, file_content: bytes) -> bool:
        """Check if PKCS#12 bundle is encrypted by attempting to load it"""
        try:
            pkcs12.load_key_and_certificates(file_content, password=None)
            return False  # Loaded successfully without password
        except Exception as e:
            error_str = str(e).lower()
            return any(keyword in error_str for keyword in self.password_error_keywords['pkcs12'])
    
    def _load_without_password(
        self, 
        file_content: bytes, 
        content_type: ContentType
    ) -> Tuple[PasswordResult, Optional[Any], Optional[str]]:
        """Load unencrypted content"""
        try:
            if content_type == ContentType.PEM_PRIVATE_KEY:
                private_key = serialization.load_pem_private_key(file_content, password=None)
                return (PasswordResult.NO_PASSWORD_NEEDED, private_key, None)

            elif content_type == ContentType.DER_PRIVATE_KEY:
                private_key = serialization.load_der_private_key(file_content, password=None)
                return (PasswordResult.NO_PASSWORD_NEEDED, private_key, None)

            # FIXED: PKCS8 - try DER first for .p8 files
            elif content_type == ContentType.PKCS8_PRIVATE_KEY:
                try:
                    # Try DER first (most common for .p8 files)
                    private_key = serialization.load_der_private_key(file_content, password=None)
                    return (PasswordResult.NO_PASSWORD_NEEDED, private_key, None)
                except Exception as der_error:
                    try:
                        # Fallback to PEM
                        private_key = serialization.load_pem_private_key(file_content, password=None)
                        return (PasswordResult.NO_PASSWORD_NEEDED, private_key, None)
                    except Exception as pem_error:
                        # Neither worked - return the original error
                        return (PasswordResult.UNKNOWN_ERROR, None, str(der_error))

            elif content_type == ContentType.PKCS12_BUNDLE:
                private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                    file_content, password=None
                )
                return (PasswordResult.NO_PASSWORD_NEEDED, (private_key, cert, additional_certs), None)

            else:
                return (PasswordResult.INVALID_FORMAT, None, f"Unsupported content type: {content_type}")

        except Exception as e:
            logger.error(f"Failed to load content without password: {e}")
            return (PasswordResult.UNKNOWN_ERROR, None, str(e))
    
    def _decrypt_with_password(
        self, 
        file_content: bytes, 
        password: str, 
        content_type: ContentType
    ) -> Tuple[PasswordResult, Optional[Any], Optional[str]]:
        """Decrypt content with provided password"""
        try:
            password_bytes = password.encode('utf-8')

            if content_type == ContentType.PEM_PRIVATE_KEY:
                private_key = serialization.load_pem_private_key(file_content, password=password_bytes)
                return (PasswordResult.SUCCESS, private_key, None)

            elif content_type == ContentType.DER_PRIVATE_KEY:
                private_key = serialization.load_der_private_key(file_content, password=password_bytes)
                return (PasswordResult.SUCCESS, private_key, None)

            # FIXED: PKCS8 - try DER first for .p8 files
            elif content_type == ContentType.PKCS8_PRIVATE_KEY:
                try:
                    # Try DER first (most common for .p8 files)
                    private_key = serialization.load_der_private_key(file_content, password=password_bytes)
                    return (PasswordResult.SUCCESS, private_key, None)
                except Exception as der_error:
                    try:
                        # Fallback to PEM
                        private_key = serialization.load_pem_private_key(file_content, password=password_bytes)
                        return (PasswordResult.SUCCESS, private_key, None)
                    except Exception as pem_error:
                        # Check if either was a password error
                        error_str = str(der_error).lower()
                        if any(keyword in error_str for keyword in self.password_error_keywords['general']):
                            return (PasswordResult.WRONG_PASSWORD, None, "Invalid password provided")
                        else:
                            return (PasswordResult.UNKNOWN_ERROR, None, str(der_error))

            elif content_type == ContentType.PKCS12_BUNDLE:
                private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                    file_content, password=password_bytes
                )
                return (PasswordResult.SUCCESS, (private_key, cert, additional_certs), None)

            else:
                return (PasswordResult.INVALID_FORMAT, None, f"Unsupported content type: {content_type}")

        except Exception as e:
            logger.error(f"Decryption with password failed: {e}")
            # Determine if this was a wrong password or other error
            error_str = str(e).lower()

            if content_type == ContentType.PKCS12_BUNDLE:
                keywords = self.password_error_keywords['pkcs12']
            else:
                keywords = self.password_error_keywords['general']

            if any(keyword in error_str for keyword in keywords):
                return (PasswordResult.WRONG_PASSWORD, None, "Invalid password provided")
            else:
                return (PasswordResult.UNKNOWN_ERROR, None, str(e))
    
    def _is_password_error(self, error: Exception, content_type: ContentType) -> bool:
        """Determine if an error is password-related"""
        error_str = str(error).lower()
        
        if content_type == ContentType.PKCS12_BUNDLE:
            keywords = self.password_error_keywords['pkcs12']
        elif content_type == ContentType.PEM_PRIVATE_KEY:
            keywords = self.password_error_keywords['pem']
        elif content_type == ContentType.DER_PRIVATE_KEY:
            keywords = self.password_error_keywords['der']
        else:
            keywords = self.password_error_keywords['general']
        
        return any(keyword in error_str for keyword in keywords)


# Global service instance
password_entry_service = PasswordEntryService()

# Convenience functions for easy import
def handle_encrypted_content(
    file_content: bytes, 
    password: Optional[str], 
    filename: str = ""
) -> Tuple[PasswordResult, Optional[Any], Optional[str], ContentType]:
    """
    Main entry point for handling any encrypted content
    
    Args:
        file_content: Raw file bytes
        password: Password to try (None for unencrypted)
        filename: Original filename for context
        
    Returns:
        Tuple of (result_status, content, error_message, content_type)
    """
    content_type = password_entry_service.detect_content_type(file_content, filename)
    result, content, error = password_entry_service.validate_password(file_content, password, content_type)
    return result, content, error, content_type

def create_password_required_response(file_content: bytes, filename: str = "") -> Dict[str, Any]:
    """Create password required response for any content type"""
    content_type = password_entry_service.detect_content_type(file_content, filename)
    return password_entry_service.create_password_required_response(file_content, content_type, filename)

def create_wrong_password_response(file_content: bytes, filename: str = "") -> Dict[str, Any]:
    """Create wrong password response for any content type"""
    content_type = password_entry_service.detect_content_type(file_content, filename)
    return password_entry_service.create_wrong_password_response(file_content, content_type)