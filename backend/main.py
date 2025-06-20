from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from typing import Dict, Any, Optional, Union
import base64
import re
from datetime import datetime

# Cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import NameOID, ExtensionOID
import cryptography.exceptions

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Certificate Tools API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CertificateProcessor:
    """Advanced certificate and CSR processor with intelligent file type detection"""
    
    @staticmethod
    def detect_file_format(content: bytes) -> str:
        """Detect the format of the certificate/CSR file"""
        # Check for PEM format (Base64 encoded with headers)
        try:
            content_str = content.decode('utf-8', errors='ignore')
            if '-----BEGIN' in content_str and '-----END' in content_str:
                return 'PEM'
        except:
            pass
        
        # Check for DER format (binary)
        if content.startswith(b'\x30'):  # ASN.1 SEQUENCE tag
            return 'DER'
            
        # Check for base64 without PEM headers
        try:
            base64.b64decode(content, validate=True)
            return 'Base64'
        except:
            pass
            
        return 'Unknown'
    
    @staticmethod
    def detect_file_type(content: bytes) -> Dict[str, str]:
        """Intelligently detect what type of cryptographic object this is"""
        format_type = CertificateProcessor.detect_file_format(content)
        
        # Convert to string for pattern matching
        try:
            content_str = content.decode('utf-8', errors='ignore')
        except:
            content_str = ""
        
        # PEM header detection
        pem_patterns = {
            'certificate': [
                r'-----BEGIN CERTIFICATE-----',
                r'-----BEGIN X509 CERTIFICATE-----'
            ],
            'csr': [
                r'-----BEGIN CERTIFICATE REQUEST-----',
                r'-----BEGIN NEW CERTIFICATE REQUEST-----'
            ],
            'private_key': [
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----',
                r'-----BEGIN DSA PRIVATE KEY-----'
            ],
            'public_key': [
                r'-----BEGIN PUBLIC KEY-----',
                r'-----BEGIN RSA PUBLIC KEY-----'
            ],
            'pkcs7': [
                r'-----BEGIN PKCS7-----'
            ],
            'pkcs12': [
                r'-----BEGIN PKCS12-----'
            ]
        }
        
        detected_type = 'unknown'
        
        # Check PEM patterns
        for obj_type, patterns in pem_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_str, re.IGNORECASE):
                    detected_type = obj_type
                    break
            if detected_type != 'unknown':
                break
        
        # For binary formats, try to parse and determine type
        if detected_type == 'unknown' and format_type in ['DER', 'Base64']:
            detected_type = CertificateProcessor._detect_binary_type(content)
        
        return {
            'type': detected_type,
            'format': format_type
        }
    
    @staticmethod
    def _detect_binary_type(content: bytes) -> str:
        """Try to determine the type of binary cryptographic object"""
        try:
            # Try to parse as certificate
            x509.load_der_x509_certificate(content)
            return 'certificate'
        except:
            pass
        
        try:
            # Try to parse as CSR
            x509.load_der_x509_csr(content)
            return 'csr'
        except:
            pass
        
        try:
            # Try to parse as private key
            serialization.load_der_private_key(content, password=None)
            return 'private_key'
        except:
            pass
        
        try:
            # Try to parse as public key
            serialization.load_der_public_key(content)
            return 'public_key'
        except:
            pass
        
        return 'unknown'
    
    @staticmethod
    def normalize_content(content: bytes, file_format: str) -> bytes:
        """Normalize content to DER format for consistent parsing"""
        if file_format == 'DER':
            return content
            
        if file_format == 'PEM':
            return content
            
        if file_format == 'Base64':
            # Add PEM headers and try to determine type
            content_str = content.decode('utf-8').strip()
            # Default to certificate if we can't determine
            pem_content = f"-----BEGIN CERTIFICATE-----\n{content_str}\n-----END CERTIFICATE-----"
            return pem_content.encode('utf-8')
            
        return content
    
    @staticmethod
    def parse_certificate(content: bytes, file_format: str) -> Dict[str, Any]:
        """Parse X.509 certificate and extract all relevant information"""
        try:
            # Load certificate
            if file_format == 'PEM':
                cert = x509.load_pem_x509_certificate(content)
            else:
                cert = x509.load_der_x509_certificate(content)
            
            # Extract basic certificate information
            # Handle different attribute names in different cryptography versions
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
            
            result = {
                'Version': cert.version.value + 1,  # X.509 version (1, 2, or 3)
                'Serial Number': str(cert.serial_number),
                'Signature Algorithm': cert.signature_algorithm_oid._name,
                'Not Valid Before': not_before.isoformat(),
                'Not Valid After': not_after.isoformat(),
            }
            
            # Extract issuer information
            issuer_info = CertificateProcessor._extract_name_attributes(cert.issuer)
            for key, value in issuer_info.items():
                result[f'Issuer.{key}'] = value
            
            # Extract subject information
            subject_info = CertificateProcessor._extract_name_attributes(cert.subject)
            for key, value in subject_info.items():
                result[f'Subject.{key}'] = value
            
            # Extract public key information
            public_key = cert.public_key()
            result.update(CertificateProcessor._extract_public_key_info(public_key))
            
            # Extract extensions
            extensions = CertificateProcessor._extract_extensions(cert)
            result.update(extensions)
            
            # Calculate validity period
            try:
                # Try UTC versions first (newer cryptography)
                now = datetime.now(cert.not_valid_before_utc.tzinfo) if hasattr(cert, 'not_valid_before_utc') else datetime.now()
                not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
                not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
            except AttributeError:
                # Fallback for older versions
                now = datetime.now()
                not_after = cert.not_valid_after
                not_before = cert.not_valid_before
            
            days_until_expiry = (not_after - now).days
            result['Days Until Expiry'] = days_until_expiry
            result['Is Valid'] = not_before <= now <= not_after
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing certificate: {str(e)}")
            raise ValueError(f"Failed to parse certificate: {str(e)}")
    
    @staticmethod
    def parse_csr(content: bytes, file_format: str) -> Dict[str, Any]:
        """Parse Certificate Signing Request and extract all relevant information"""
        try:
            # Load CSR
            if file_format == 'PEM':
                csr = x509.load_pem_x509_csr(content)
            else:
                csr = x509.load_der_x509_csr(content)
            
            # Extract basic CSR information
            result = {
                'Signature Algorithm': csr.signature_algorithm_oid._name,
                'Is Signature Valid': csr.is_signature_valid,
            }
            
            # Extract subject information
            subject_info = CertificateProcessor._extract_name_attributes(csr.subject)
            for key, value in subject_info.items():
                result[f'Subject.{key}'] = value
            
            # Extract public key information
            public_key = csr.public_key()
            result.update(CertificateProcessor._extract_public_key_info(public_key))
            
            # Extract extensions from CSR
            try:
                extensions = CertificateProcessor._extract_csr_extensions(csr)
                result.update(extensions)
            except Exception as e:
                logger.warning(f"Could not extract CSR extensions: {str(e)}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing CSR: {str(e)}")
            raise ValueError(f"Failed to parse CSR: {str(e)}")
    
    @staticmethod
    def _extract_name_attributes(name: x509.Name) -> Dict[str, str]:
        """Extract name attributes from X.509 Name object"""
        attributes = {}
        
        name_mapping = {
            NameOID.COMMON_NAME: 'Common Name',
            NameOID.COUNTRY_NAME: 'Country',
            NameOID.LOCALITY_NAME: 'Locality',
            NameOID.STATE_OR_PROVINCE_NAME: 'State/Province',
            NameOID.ORGANIZATION_NAME: 'Organization',
            NameOID.ORGANIZATIONAL_UNIT_NAME: 'Organizational Unit',
            NameOID.EMAIL_ADDRESS: 'Email Address',
            NameOID.SERIAL_NUMBER: 'Serial Number',
            NameOID.SURNAME: 'Surname',
            NameOID.GIVEN_NAME: 'Given Name',
            NameOID.TITLE: 'Title',
            NameOID.GENERATION_QUALIFIER: 'Generation Qualifier',
            NameOID.DN_QUALIFIER: 'DN Qualifier',
            NameOID.PSEUDONYM: 'Pseudonym',
        }
        
        for attribute in name:
            oid_name = name_mapping.get(attribute.oid, str(attribute.oid))
            attributes[oid_name] = attribute.value
        
        return attributes
    
    @staticmethod
    def _extract_public_key_info(public_key) -> Dict[str, Any]:
        """Extract public key information"""
        info = {}
        
        # Determine key type and extract relevant information
        if hasattr(public_key, 'key_size'):  # RSA key
            info['Public Key Algorithm'] = 'RSA'
            info['Key Size'] = f"{public_key.key_size} bits"
            info['Public Exponent'] = public_key.public_numbers().e
        elif hasattr(public_key, 'curve'):  # EC key
            info['Public Key Algorithm'] = 'Elliptic Curve'
            info['Curve'] = public_key.curve.name
            info['Key Size'] = f"{public_key.curve.key_size} bits"
        elif hasattr(public_key, 'parameter_numbers'):  # DSA key
            info['Public Key Algorithm'] = 'DSA'
            info['Key Size'] = f"{public_key.key_size} bits"
        else:
            info['Public Key Algorithm'] = 'Unknown'
        
        return info
    
    @staticmethod
    def _extract_extensions(cert: x509.Certificate) -> Dict[str, Any]:
        """Extract certificate extensions"""
        extensions = {}
        
        try:
            # Subject Alternative Names
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = []
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_names.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_names.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    san_names.append(f"Email:{name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_names.append(f"URI:{name.value}")
            if san_names:
                extensions['Subject Alternative Names'] = ', '.join(san_names)
        except x509.ExtensionNotFound:
            pass
        
        try:
            # Key Usage
            key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            key_usages = []
            ku = key_usage_ext.value
            if ku.digital_signature:
                key_usages.append("Digital Signature")
            if ku.key_cert_sign:
                key_usages.append("Certificate Sign")
            if ku.crl_sign:
                key_usages.append("CRL Sign")
            if ku.key_encipherment:
                key_usages.append("Key Encipherment")
            if ku.data_encipherment:
                key_usages.append("Data Encipherment")
            if ku.key_agreement:
                key_usages.append("Key Agreement")
            if ku.content_commitment:
                key_usages.append("Content Commitment")
            if key_usages:
                extensions['Key Usage'] = ', '.join(key_usages)
        except x509.ExtensionNotFound:
            pass
        
        try:
            # Extended Key Usage
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_usages = []
            for usage in eku_ext.value:
                if usage == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    eku_usages.append("TLS Web Server Authentication")
                elif usage == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    eku_usages.append("TLS Web Client Authentication")
                elif usage == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                    eku_usages.append("Code Signing")
                elif usage == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    eku_usages.append("Email Protection")
                else:
                    eku_usages.append(str(usage))
            if eku_usages:
                extensions['Extended Key Usage'] = ', '.join(eku_usages)
        except x509.ExtensionNotFound:
            pass
        
        try:
            # Basic Constraints
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            bc = bc_ext.value
            constraints = []
            if bc.ca:
                constraints.append("CA:TRUE")
                if bc.path_length is not None:
                    constraints.append(f"Path Length:{bc.path_length}")
            else:
                constraints.append("CA:FALSE")
            extensions['Basic Constraints'] = ', '.join(constraints)
        except x509.ExtensionNotFound:
            pass
        
        return extensions
    
    @staticmethod
    def _extract_csr_extensions(csr: x509.CertificateSigningRequest) -> Dict[str, Any]:
        """Extract extensions from CSR"""
        extensions = {}
        
        try:
            # Subject Alternative Names in CSR
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = []
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_names.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_names.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    san_names.append(f"Email:{name.value}")
            if san_names:
                extensions['Requested Subject Alternative Names'] = ', '.join(san_names)
        except x509.ExtensionNotFound:
            pass
        
        try:
            # Key Usage in CSR
            key_usage_ext = csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            key_usages = []
            ku = key_usage_ext.value
            if ku.digital_signature:
                key_usages.append("Digital Signature")
            if ku.key_encipherment:
                key_usages.append("Key Encipherment")
            if key_usages:
                extensions['Requested Key Usage'] = ', '.join(key_usages)
        except x509.ExtensionNotFound:
            pass
        
        return extensions

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload and process certificate, CSR, or other cryptographic files
    """
    try:
        # Read file content
        content = await file.read()
        
        if not content:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        # Detect file type and format
        detection = CertificateProcessor.detect_file_type(content)
        file_type = detection['type']
        file_format = detection['format']
        
        logger.info(f"Processing file: {file.filename}, detected type: {file_type}, format: {file_format}")
        
        # Process based on detected type
        if file_type == 'certificate':
            certificate_data = CertificateProcessor.parse_certificate(content, file_format)
            
            return {
                "success": True,
                "filename": file.filename,
                "filetype": file_type,
                "fileformat": file_format,
                "certificate": certificate_data,
                "message": f"Certificate processed successfully. Valid until: {certificate_data.get('Not Valid After', 'Unknown')}"
            }
            
        elif file_type == 'csr':
            csr_data = CertificateProcessor.parse_csr(content, file_format)
            
            return {
                "success": True,
                "filename": file.filename,
                "filetype": file_type,
                "fileformat": file_format,
                "certificate": csr_data,  # Using same key for frontend compatibility
                "message": f"Certificate Signing Request processed successfully. Subject: {csr_data.get('Subject.Common Name', 'Unknown')}"
            }
            
        elif file_type == 'private_key':
            return {
                "success": False,
                "error": "Private key files are not supported for security reasons",
                "filename": file.filename,
                "filetype": file_type,
                "fileformat": file_format
            }
            
        elif file_type == 'public_key':
            # Could add public key parsing here if needed
            return {
                "success": False,
                "error": "Public key files are not yet supported",
                "filename": file.filename,
                "filetype": file_type,
                "fileformat": file_format
            }
            
        else:
            return {
                "success": False,
                "error": f"Unsupported file type: {file_type}. Please upload a certificate (.crt, .pem) or certificate signing request (.csr)",
                "filename": file.filename,
                "filetype": file_type,
                "fileformat": file_format
            }
    
    except ValueError as e:
        logger.error(f"Parsing error for file {file.filename}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"parsing_error: {str(e)}")
    
    except Exception as e:
        logger.error(f"Unexpected error processing file {file.filename}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"internal_error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)