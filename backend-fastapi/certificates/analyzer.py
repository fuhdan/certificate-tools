# certificates/analyzer.py
# Main certificate analysis entry point with comprehensive debugging

import hashlib
import logging
from typing import Dict, Any, Optional, List

from .formats.pem import (
    analyze_pem_certificate, analyze_pem_csr, 
    analyze_pem_private_key, analyze_pem_public_key
)
from .formats.der import analyze_der_formats
from .formats.pkcs12 import analyze_pkcs12
from .formats.pkcs7 import analyze_pkcs7
from .utils.hashing import generate_file_hash

logger = logging.getLogger(__name__)

def get_file_format(filename: str) -> str:
    """Determine file format from filename - UPDATED with PKCS7 support"""
    extension = filename.split('.')[-1].lower()
    format_map = {
        'pem': 'PEM',
        'crt': 'PEM', 
        'cer': 'PEM',
        'der': 'DER',
        'p12': 'PKCS12',
        'pfx': 'PKCS12',
        'p7b': 'PKCS7',  # Added PKCS7 formats
        'p7c': 'PKCS7',
        'p7s': 'PKCS7',
        'spc': 'PKCS7',  # Software Publisher Certificate
        'jks': 'JKS',
        'key': 'Private Key',
        'csr': 'CSR',
        'p8': 'PKCS8',
        'pk8': 'PKCS8'
    }
    detected_format = format_map.get(extension, extension.upper())
    logger.debug(f"File format detection: {filename} -> extension: {extension} -> format: {detected_format}")
    return detected_format

def analyze_uploaded_certificate(file_content: bytes, filename: str, password: Optional[str] = None) -> Dict[str, Any]:
    """Main certificate analysis function - routes to format-specific analyzers and stores crypto objects separately"""
    logger.debug(f"=== CERTIFICATE ANALYSIS START ===")
    logger.debug(f"File: {filename}")
    logger.debug(f"Size: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    
    analysis = {
        "type": "Unknown",
        "format": get_file_format(filename),
        "isValid": False,
        "size": len(file_content),
        "hash": hashlib.sha256(file_content).hexdigest(),
        "content_hash": None,
        "details": None,
        "requiresPassword": False
        # NOTE: crypto_objects will be stored separately, not in this response
    }
    
    # This will hold crypto objects temporarily
    temp_crypto_objects = {}
    
    try:
        # Try to decode as text first
        try:
            content_str = file_content.decode('utf-8')
            is_pem = '-----BEGIN' in content_str
            logger.debug(f"UTF-8 decode successful. PEM format: {is_pem}")
        except UnicodeDecodeError:
            content_str = None
            is_pem = False
            logger.debug("Binary content detected")
        
        if is_pem and content_str:
            logger.info("Analyzing PEM content...")
            result = _analyze_pem_content_with_crypto_extraction(content_str, file_content, password)
            if isinstance(result, dict) and 'analysis' in result:
                analysis.update(result['analysis'])
                temp_crypto_objects = result.get('crypto_objects', {})
            else:
                # Fallback: result is the analysis directly
                analysis.update(result)
                temp_crypto_objects = {}
            
        else:
            logger.info("Analyzing binary content...")
            result = _analyze_binary_content_with_crypto_extraction(file_content, analysis['format'], password)
            if isinstance(result, dict) and 'analysis' in result:
                analysis.update(result['analysis'])
                temp_crypto_objects = result.get('crypto_objects', {})
            else:
                # Fallback: result is the analysis directly (THIS IS THE ISSUE!)
                analysis.update(result)
                temp_crypto_objects = {}
                
    except Exception as e:
        logger.error(f"Certificate analysis error: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        analysis["error"] = str(e)
        if analysis["content_hash"] is None:
            analysis["content_hash"] = generate_file_hash(file_content)
    
    # Ensure content_hash is always set
    if analysis["content_hash"] is None:
        analysis["content_hash"] = analysis["hash"]
    
    logger.info(f"Analysis complete - Type: {analysis['type']}, Valid: {analysis.get('isValid')}")
    logger.debug(f"Crypto objects extracted: {list(temp_crypto_objects.keys())}")
    
    # Return both analysis and crypto objects (crypto objects will be stored separately)
    return {
        'analysis': analysis,
        'crypto_objects': temp_crypto_objects
    }

def _analyze_pem_content_with_crypto_extraction(content_str: str, file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Route PEM content to appropriate analyzer with crypto object extraction - FIXED PKCS7 DETECTION"""
    logger.debug("=== PEM CONTENT ANALYSIS WITH CRYPTO EXTRACTION ===")
    logger.debug(f"Content length: {len(content_str)} chars")
    logger.debug(f"Content preview (first 200 chars): {content_str[:200]}")
    
    # Check for PKCS7 content FIRST (before other certificate types)
    if ('-----BEGIN PKCS7-----' in content_str or 
        content_str.count('-----BEGIN CERTIFICATE-----') > 1):
        logger.info("Detected PKCS7 content - routing to PKCS7 analyzer")
        from .formats.pkcs7 import analyze_pkcs7
        analysis_result = analyze_pkcs7(file_content, password)
        crypto_objects = {}
        
        # Extract crypto objects if valid
        if analysis_result.get('isValid'):
            crypto_objects = _extract_pkcs7_crypto_objects(analysis_result, file_content)
        
        return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
    
    # Single certificate
    elif content_str.count('-----BEGIN CERTIFICATE-----') == 1:
        logger.info("Detected single PEM certificate")
        from .formats.pem import analyze_pem_certificate
        analysis_result = analyze_pem_certificate(content_str, file_content)
        crypto_objects = {}
        
        # Extract certificate object if valid
        if analysis_result.get('isValid'):
            try:
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(file_content)
                crypto_objects['certificate'] = cert
                logger.debug("Stored certificate crypto object")
            except Exception as e:
                logger.error(f"Error extracting certificate crypto object: {e}")
        
        return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
        
    elif '-----BEGIN CERTIFICATE REQUEST-----' in content_str:
        logger.info("Detected PEM CSR")
        from .formats.pem import analyze_pem_csr
        analysis_result = analyze_pem_csr(file_content)
        crypto_objects = {}
        
        # Extract CSR object if valid
        if analysis_result.get('isValid'):
            try:
                from cryptography import x509
                csr = x509.load_pem_x509_csr(file_content)
                crypto_objects['csr'] = csr
                logger.debug("Stored CSR crypto object")
            except Exception as e:
                logger.error(f"Error extracting CSR crypto object: {e}")
        
        return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
        
    elif ('-----BEGIN PRIVATE KEY-----' in content_str or 
          '-----BEGIN RSA PRIVATE KEY-----' in content_str or
          '-----BEGIN EC PRIVATE KEY-----' in content_str or
          '-----BEGIN ENCRYPTED PRIVATE KEY-----' in content_str):
        logger.info("Detected PEM private key")
        from .formats.pem import analyze_pem_private_key
        analysis_result = analyze_pem_private_key(file_content, password)
        crypto_objects = {}
        
        # Extract private key object if valid
        if analysis_result.get('isValid'):
            try:
                from cryptography.hazmat.primitives import serialization
                private_key = serialization.load_pem_private_key(
                    file_content, 
                    password=password.encode('utf-8') if password else None
                )
                crypto_objects['private_key'] = private_key
                logger.debug("Stored private key crypto object")
            except Exception as e:
                logger.error(f"Error extracting private key crypto object: {e}")
        
        return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
        
    elif '-----BEGIN PUBLIC KEY-----' in content_str:
        logger.info("Detected PEM public key")
        from .formats.pem import analyze_pem_public_key
        analysis_result = analyze_pem_public_key(file_content)
        crypto_objects = {}
        
        # Extract public key object if valid
        if analysis_result.get('isValid'):
            try:
                from cryptography.hazmat.primitives import serialization
                public_key = serialization.load_pem_public_key(file_content)
                crypto_objects['public_key'] = public_key
                logger.debug("Stored public key crypto object")
            except Exception as e:
                logger.error(f"Error extracting public key crypto object: {e}")
        
        return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
        
    else:
        # Unknown PEM content
        logger.warning("Unknown PEM content - no recognized BEGIN markers found")
        logger.debug("Available BEGIN markers in content:")
        import re
        begin_markers = re.findall(r'-----BEGIN ([^-]+)-----', content_str)
        for marker in begin_markers:
            logger.debug(f"  Found marker: {marker}")
        
        from .utils.hashing import generate_file_hash
        return {
            'analysis': {
                "type": "Unknown PEM",
                "isValid": False,
                "content_hash": generate_file_hash(file_content),
                "error": f"Unrecognized PEM content type. Found markers: {begin_markers}"
            },
            'crypto_objects': {}
        }

def _analyze_binary_content_with_crypto_extraction(file_content: bytes, file_format: str, password: Optional[str]) -> Dict[str, Any]:
    """Route binary content to appropriate analyzer with crypto object extraction - UPDATED"""
    logger.debug("=== BINARY CONTENT ANALYSIS WITH CRYPTO EXTRACTION ===")
    logger.debug(f"File format: {file_format}")
    
    if file_format in ['DER', 'PKCS8']:
        from .formats.der import analyze_der_formats
        analysis_result = analyze_der_formats(file_content, password)
        crypto_objects = {}
        
        if analysis_result.get('isValid'):
            crypto_objects = _extract_der_crypto_objects(analysis_result, file_content, password)
        
        return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
        
    elif file_format == 'PKCS12':
        from .formats.pkcs12 import analyze_pkcs12
        analysis_result = analyze_pkcs12(file_content, password)
        crypto_objects = {}
        
        if analysis_result.get('isValid'):
            crypto_objects = _extract_pkcs12_crypto_objects(analysis_result, file_content, password)
        
        return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
        
    elif file_format in ['PKCS7', 'P7B', 'P7C']:
        from .formats.pkcs7 import analyze_pkcs7
        analysis_result = analyze_pkcs7(file_content, password)
        crypto_objects = {}
        
        if analysis_result.get('isValid'):
            crypto_objects = _extract_pkcs7_crypto_objects(analysis_result, file_content)
        
        return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
        
    else:
        # Try DER as fallback
        try:
            from .formats.der import analyze_der_formats
            analysis_result = analyze_der_formats(file_content, password)
            crypto_objects = {}
            
            if analysis_result.get('isValid'):
                crypto_objects = _extract_der_crypto_objects(analysis_result, file_content, password)
            
            return {'analysis': analysis_result, 'crypto_objects': crypto_objects}
        except Exception as der_err:
            logger.debug(f"DER fallback failed: {der_err}")
        
        from .utils.hashing import generate_file_hash
        return {
            'analysis': {
                "type": "Unknown Binary",
                "isValid": False,
                "content_hash": generate_file_hash(file_content)
            },
            'crypto_objects': {}
        }

def _extract_der_crypto_objects(analysis_result: Dict[str, Any], file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Extract crypto objects for DER formats"""
    logger.debug("Extracting DER crypto objects...")
    crypto_objects = {}
    
    try:
        cert_type = analysis_result.get('type', '')
        if 'Certificate' in cert_type and 'Chain' not in cert_type:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(file_content)
            crypto_objects['certificate'] = cert
            logger.debug("Stored DER certificate crypto object")
            
        elif cert_type == 'CSR':
            from cryptography import x509
            csr = x509.load_der_x509_csr(file_content)
            crypto_objects['csr'] = csr
            logger.debug("Stored DER CSR crypto object")
            
        elif cert_type == 'Private Key':
            from cryptography.hazmat.primitives import serialization
            private_key = serialization.load_der_private_key(
                file_content,
                password=password.encode('utf-8') if password else None
            )
            crypto_objects['private_key'] = private_key
            logger.debug("Stored DER private key crypto object")
            
    except Exception as e:
        logger.error(f"Error extracting DER crypto objects: {e}")
    
    return crypto_objects

def _extract_pkcs12_crypto_objects(analysis_result: Dict[str, Any], file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Extract crypto objects for PKCS12 formats - FIXED VERSION"""
    logger.debug("Extracting PKCS12 crypto objects...")
    crypto_objects = {}
    
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
        
        # Use the password as bytes if provided
        password_bytes = None
        if password:
            password_bytes = password.encode('utf-8')
        
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
            file_content, 
            password=password_bytes
        )
        
        if cert:
            crypto_objects['certificate'] = cert
            logger.debug("Stored PKCS12 certificate crypto object")
        if private_key:
            crypto_objects['private_key'] = private_key
            logger.debug("Stored PKCS12 private key crypto object")
        if additional_certs:
            crypto_objects['additional_certificates'] = additional_certs
            logger.debug(f"Stored {len(additional_certs)} additional PKCS12 certificate crypto objects")
            
    except Exception as e:
        logger.error(f"Error extracting PKCS12 crypto objects: {e}")
    
    return crypto_objects

def _extract_pkcs7_crypto_objects(analysis_result: Dict[str, Any], file_content: bytes) -> Dict[str, Any]:
    """Extract crypto objects for PKCS7 formats - IMPROVED VERSION"""
    logger.debug("Extracting PKCS7 crypto objects...")
    crypto_objects = {}
    
    try:
        # Try to decode as text first for PEM format
        try:
            content_str = file_content.decode('utf-8')
            is_pem = '-----BEGIN' in content_str
        except UnicodeDecodeError:
            content_str = None
            is_pem = False
        
        certificates = []
        
        if is_pem and content_str:
            logger.debug("Processing PEM PKCS7...")
            
            # Handle -----BEGIN PKCS7----- format
            import re
            import base64
            
            if '-----BEGIN PKCS7-----' in content_str:
                logger.debug("Found -----BEGIN PKCS7----- block")
                pkcs7_match = re.search(
                    r'-----BEGIN PKCS7-----\s*(.*?)\s*-----END PKCS7-----',
                    content_str,
                    re.DOTALL
                )
                
                if pkcs7_match:
                    pkcs7_b64 = pkcs7_match.group(1).replace('\n', '').replace('\r', '').replace(' ', '')
                    pkcs7_der = base64.b64decode(pkcs7_b64)
                    certificates = _extract_certificates_from_pkcs7_der(pkcs7_der)
                    logger.debug(f"Extracted {len(certificates)} certificates from PKCS7 DER")
            
            # Handle multiple -----BEGIN CERTIFICATE----- blocks (PKCS7-like)
            if not certificates:
                logger.debug("Checking for multiple certificate blocks...")
                from cryptography import x509
                cert_blocks = re.findall(
                    r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                    content_str,
                    re.DOTALL
                )
                
                logger.debug(f"Found {len(cert_blocks)} certificate blocks")
                
                for i, cert_block in enumerate(cert_blocks):
                    try:
                        cert = x509.load_pem_x509_certificate(cert_block.encode())
                        certificates.append(cert)
                        logger.debug(f"Loaded certificate block {i}")
                    except Exception as cert_err:
                        logger.warning(f"Failed to parse certificate block {i}: {cert_err}")
                        continue
        else:
            logger.debug("Processing binary PKCS7...")
            # Handle binary PKCS7
            certificates = _extract_certificates_from_pkcs7_der(file_content)
        
        if certificates:
            if len(certificates) == 1:
                crypto_objects['certificate'] = certificates[0]
                logger.info(f"Stored single PKCS7 certificate crypto object")
            else:
                crypto_objects['certificate'] = certificates[0]  # Main certificate
                crypto_objects['additional_certificates'] = certificates[1:]  # Additional certificates
                logger.info(f"Stored PKCS7 main certificate + {len(certificates)-1} additional certificates")
        else:
            logger.warning("No certificates extracted from PKCS7")
            
    except Exception as e:
        logger.error(f"Error extracting PKCS7 crypto objects: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
    
    return crypto_objects

def _extract_certificates_from_pkcs7_der(der_data: bytes) -> List:
    """Extract certificates from PKCS7 DER data - IMPROVED PARSER"""
    logger.debug(f"Extracting certificates from PKCS7 DER data ({len(der_data)} bytes)...")
    certificates = []
    
    try:
        from cryptography import x509
        
        # Look for certificate sequences in the DER data
        data_hex = der_data.hex()
        logger.debug(f"DER data hex length: {len(data_hex)} chars")
        logger.debug(f"DER data header: {data_hex[:64]}")
        
        i = 0
        cert_count = 0
        
        while i < len(data_hex) - 8:
            if data_hex[i:i+4].lower() == '3082':  # ASN.1 SEQUENCE with long form length
                try:
                    # Get the length
                    length_hex = data_hex[i+4:i+8]
                    length = int(length_hex, 16)
                    
                    # Extract potential certificate
                    cert_start = i // 2
                    cert_length = length + 4
                    
                    logger.debug(f"Potential cert at position {cert_start}, length {cert_length}")
                    
                    if cert_start + cert_length <= len(der_data):
                        cert_data = der_data[cert_start:cert_start + cert_length]
                        
                        try:
                            cert = x509.load_der_x509_certificate(cert_data)
                            certificates.append(cert)
                            cert_count += 1
                            
                            # Log certificate info
                            try:
                                subject_cn = None
                                for attribute in cert.subject:
                                    if attribute.oid._name == 'commonName':
                                        subject_cn = attribute.value
                                        break
                                logger.info(f"Extracted certificate {cert_count}: {subject_cn}")
                            except Exception:
                                logger.info(f"Extracted certificate {cert_count} (subject extraction failed)")
                            
                            # Skip past this certificate
                            i += cert_length * 2
                            continue
                            
                        except Exception as cert_parse_err:
                            logger.debug(f"Certificate parsing failed at position {cert_start}: {cert_parse_err}")
                
                except Exception as extract_err:
                    logger.debug(f"Error during certificate extraction: {extract_err}")
            
            i += 2
        
        logger.info(f"PKCS7 certificate extraction complete: found {len(certificates)} certificates")
        
    except Exception as e:
        logger.error(f"Error extracting certificates from PKCS7 DER: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
    
    return certificates