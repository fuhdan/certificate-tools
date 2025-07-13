# certificates/analyzer.py
# Main certificate analysis entry point with comprehensive debugging

import hashlib
import logging
from typing import Dict, Any, Optional

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
    """Determine file format from filename"""
    extension = filename.split('.')[-1].lower()
    format_map = {
        'pem': 'PEM',
        'crt': 'PEM', 
        'cer': 'PEM',
        'der': 'DER',
        'p12': 'PKCS12',
        'pfx': 'PKCS12',
        'p7b': 'PKCS7',
        'p7c': 'PKCS7', 
        'p7s': 'PKCS7',
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
    """Main certificate analysis function - routes to format-specific analyzers"""
    logger.debug(f"=== CERTIFICATE ANALYSIS START ===")
    logger.debug(f"File: {filename}")
    logger.debug(f"Size: {len(file_content)} bytes")
    logger.debug(f"Password provided: {'YES' if password else 'NO'}")
    logger.debug(f"Content preview (first 100 bytes): {file_content[:100]}")
    
    analysis = {
        "type": "Unknown",
        "format": get_file_format(filename),
        "isValid": False,
        "size": len(file_content),
        "hash": hashlib.sha256(file_content).hexdigest(),
        "content_hash": None,
        "details": None,
        "requiresPassword": False
    }
    
    logger.debug(f"Initial analysis structure: {analysis}")
    
    try:
        # Try to decode as text first
        logger.debug("Attempting to decode file content as UTF-8...")
        try:
            content_str = file_content.decode('utf-8')
            is_pem = '-----BEGIN' in content_str
            logger.debug(f"UTF-8 decode successful. Content length: {len(content_str)} chars")
            logger.debug(f"Contains PEM markers: {is_pem}")
            if is_pem:
                logger.debug("PEM markers found in content:")
                for line in content_str.split('\n')[:10]:  # First 10 lines
                    if '-----' in line:
                        logger.debug(f"  PEM marker: {line.strip()}")
        except UnicodeDecodeError as decode_err:
            content_str = None
            is_pem = False
            logger.debug(f"UTF-8 decode failed: {decode_err}. Treating as binary content.")
        
        if is_pem and content_str:
            logger.info("Routing to PEM content analyzer...")
            result = _analyze_pem_content(content_str, file_content, password)
            logger.info(f"PEM analysis result: type={result.get('type')}, valid={result.get('isValid')}")
            logger.debug(f"Full PEM analysis result: {result}")
            analysis.update(result)
            
        else:
            logger.info("Routing to binary content analyzer...")
            result = _analyze_binary_content(file_content, analysis['format'], password)
            logger.info(f"Binary analysis result: type={result.get('type')}, valid={result.get('isValid')}")
            logger.debug(f"Full binary analysis result: {result}")
            analysis.update(result)
                
    except Exception as e:
        logger.error(f"Certificate analysis error: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Error details: {str(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        analysis["error"] = str(e)
        if analysis["content_hash"] is None:
            analysis["content_hash"] = generate_file_hash(file_content)
            logger.warning(f"Set fallback content_hash due to error: {analysis['content_hash'][:16]}...")
    
    # Ensure content_hash is always set
    if analysis["content_hash"] is None:
        analysis["content_hash"] = analysis["hash"]
        logger.warning(f"Using file hash as fallback for content_hash: {analysis['content_hash'][:16]}...")
    
    logger.debug(f"=== ANALYSIS COMPLETE ===")
    logger.info(f"Final type: {analysis['type']}")
    logger.debug(f"Valid: {analysis.get('isValid')}")
    logger.debug(f"Requires password: {analysis.get('requiresPassword', False)}")
    logger.debug(f"Content hash: {analysis['content_hash'][:16]}..." if analysis['content_hash'] else "No content hash")
    logger.debug(f"Additional items: {len(analysis.get('additional_items', []))}")
    
    return analysis

def _analyze_pem_content(content_str: str, file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Route PEM content to appropriate analyzer"""
    logger.debug("=== PEM CONTENT ANALYSIS ===")
    
    # Count different PEM types
    cert_count = content_str.count('-----BEGIN CERTIFICATE-----')
    csr_count = content_str.count('-----BEGIN CERTIFICATE REQUEST-----')
    private_key_count = (content_str.count('-----BEGIN PRIVATE KEY-----') + 
                        content_str.count('-----BEGIN RSA PRIVATE KEY-----') + 
                        content_str.count('-----BEGIN EC PRIVATE KEY-----') + 
                        content_str.count('-----BEGIN ENCRYPTED PRIVATE KEY-----'))
    public_key_count = content_str.count('-----BEGIN PUBLIC KEY-----')
    pkcs7_count = content_str.count('-----BEGIN PKCS7-----')
    
    logger.debug(f"PEM content analysis:")
    logger.debug(f"  Certificates: {cert_count}")
    logger.debug(f"  CSRs: {csr_count}")
    logger.debug(f"  Private keys: {private_key_count}")
    logger.debug(f"  Public keys: {public_key_count}")
    logger.debug(f"  PKCS7: {pkcs7_count}")
    
    if '-----BEGIN CERTIFICATE-----' in content_str:
        if cert_count > 1:
            logger.info(f"Multiple certificates detected ({cert_count}), treating as PKCS7 chain")
            from .formats.pkcs7 import analyze_pkcs7
            return analyze_pkcs7(file_content, password)
        else:
            logger.info("Single certificate detected, analyzing as PEM certificate")
            return analyze_pem_certificate(content_str, file_content)
    elif '-----BEGIN PKCS7-----' in content_str:
        logger.info("PKCS7 PEM format detected")
        from .formats.pkcs7 import analyze_pkcs7  
        return analyze_pkcs7(file_content, password)
    elif '-----BEGIN CERTIFICATE REQUEST-----' in content_str:
        logger.info("CSR PEM format detected")
        return analyze_pem_csr(file_content)
    elif ('-----BEGIN PRIVATE KEY-----' in content_str or 
          '-----BEGIN RSA PRIVATE KEY-----' in content_str or
          '-----BEGIN EC PRIVATE KEY-----' in content_str or
          '-----BEGIN ENCRYPTED PRIVATE KEY-----' in content_str):
        logger.info("Private key PEM format detected")
        encrypted_markers = ['-----BEGIN ENCRYPTED PRIVATE KEY-----', 'Proc-Type: 4,ENCRYPTED', 'DEK-Info:']
        is_encrypted = any(marker in content_str for marker in encrypted_markers)
        logger.debug(f"Private key encryption status: {is_encrypted}")
        return analyze_pem_private_key(file_content, password)
    elif '-----BEGIN PUBLIC KEY-----' in content_str:
        logger.info("Public key PEM format detected")
        return analyze_pem_public_key(file_content)
    else:
        logger.warning("Unknown PEM format - no recognized markers found")
        logger.debug("Content sample for unknown PEM:")
        for i, line in enumerate(content_str.split('\n')[:5]):
            logger.debug(f"  Line {i+1}: {line}")
        return {
            "type": "Unknown PEM",
            "isValid": False,
            "content_hash": generate_file_hash(file_content)
        }

def _analyze_binary_content(file_content: bytes, file_format: str, password: Optional[str]) -> Dict[str, Any]:
    """Route binary content to appropriate analyzer"""
    logger.debug("=== BINARY CONTENT ANALYSIS ===")
    logger.debug(f"File format: {file_format}")
    logger.debug(f"Content size: {len(file_content)} bytes")
    logger.debug(f"First 32 bytes (hex): {file_content[:32].hex()}")
    
    # Analyze binary structure
    if len(file_content) >= 4:
        header = file_content[:4]
        logger.debug(f"Header bytes: {header.hex()}")
        
        # Check for common binary formats
        if header[:2] == b'\x30\x82':
            logger.debug("Detected ASN.1 SEQUENCE with long form length (typical for certificates/keys)")
        elif header[:2] == b'\x30\x81':
            logger.debug("Detected ASN.1 SEQUENCE with medium form length")
        elif header[:2] == b'\x30\x80':
            logger.debug("Detected ASN.1 SEQUENCE with indefinite length")
        elif header == b'\x30\x82':
            logger.debug("Likely DER-encoded certificate or key")
    
    if file_format in ['DER', 'PKCS8']:
        logger.info(f"Routing to DER analyzer for format: {file_format}")
        from .formats.der import analyze_der_formats
        result = analyze_der_formats(file_content, password)
        logger.debug(f"DER analysis completed: {result.get('type')}")
        return result
    elif file_format == 'PKCS12':
        logger.info("Routing to PKCS12 analyzer")
        result = analyze_pkcs12(file_content, password)
        logger.debug(f"PKCS12 analysis completed: {result.get('type')}")
        return result
    elif file_format == 'PKCS7':
        logger.info("Routing to PKCS7 analyzer")
        result = analyze_pkcs7(file_content, password)
        logger.debug(f"PKCS7 analysis completed: {result.get('type')}")
        return result
    else:
        logger.warning(f"Unknown binary format: {file_format}")
        logger.debug("Attempting to detect format from content...")
        
        # Try to detect format from content
        try:
            # Check if it might be DER despite the extension
            from .formats.der import analyze_der_formats
            logger.debug("Attempting DER analysis as fallback...")
            result = analyze_der_formats(file_content, password)
            if result.get('isValid'):
                logger.info(f"Successfully detected as DER format: {result.get('type')}")
                return result
        except Exception as der_err:
            logger.debug(f"DER fallback failed: {der_err}")
        
        return {
            "type": "Unknown Binary",
            "isValid": False,
            "content_hash": generate_file_hash(file_content),
            "format_hint": f"Unrecognized format: {file_format}"
        }