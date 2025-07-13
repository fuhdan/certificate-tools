# certificates/analyzer.py
# Main certificate analysis entry point

import hashlib
import logging
from typing import Dict, Any, Optional

from .formats.pem import (
    analyze_pem_certificate, analyze_pem_csr, 
    analyze_pem_private_key, analyze_pem_public_key
)
from .formats.der import analyze_der_formats
from .formats.pkcs12 import analyze_pkcs12
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
        'jks': 'JKS',
        'key': 'Private Key',
        'csr': 'CSR',
        'p8': 'PKCS8',
        'pk8': 'PKCS8'
    }
    return format_map.get(extension, extension.upper())

def analyze_uploaded_certificate(file_content: bytes, filename: str, password: Optional[str] = None) -> Dict[str, Any]:
    """Main certificate analysis function - routes to format-specific analyzers"""
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
    
    logger.info(f"Analyzing file: {filename}, size: {len(file_content)} bytes, format: {analysis['format']}")
    
    try:
        # Try to decode as text first
        try:
            content_str = file_content.decode('utf-8')
            is_pem = '-----BEGIN' in content_str
        except UnicodeDecodeError:
            content_str = None
            is_pem = False
        
        if is_pem and content_str:
            # Route to PEM format analyzers
            result = _analyze_pem_content(content_str, file_content, password)
            analysis.update(result)
            
        else:
            # Route to binary format analyzers  
            result = _analyze_binary_content(file_content, analysis['format'], password)
            analysis.update(result)
                
    except Exception as e:
        logger.error(f"Certificate analysis error: {e}")
        analysis["error"] = str(e)
        if analysis["content_hash"] is None:
            analysis["content_hash"] = generate_file_hash(file_content)
    
    # Ensure content_hash is always set
    if analysis["content_hash"] is None:
        analysis["content_hash"] = analysis["hash"]
        logger.warning(f"Using file hash as fallback for content_hash")
    
    logger.info(f"Analysis complete: {analysis['type']}, requiresPassword: {analysis.get('requiresPassword', False)}")
    return analysis

def _analyze_pem_content(content_str: str, file_content: bytes, password: Optional[str]) -> Dict[str, Any]:
    """Route PEM content to appropriate analyzer"""
    if '-----BEGIN CERTIFICATE-----' in content_str:
        return analyze_pem_certificate(content_str, file_content)
    elif '-----BEGIN CERTIFICATE REQUEST-----' in content_str:
        return analyze_pem_csr(file_content)
    elif ('-----BEGIN PRIVATE KEY-----' in content_str or 
          '-----BEGIN RSA PRIVATE KEY-----' in content_str or
          '-----BEGIN EC PRIVATE KEY-----' in content_str or
          '-----BEGIN ENCRYPTED PRIVATE KEY-----' in content_str):
        return analyze_pem_private_key(file_content, password)
    elif '-----BEGIN PUBLIC KEY-----' in content_str:
        return analyze_pem_public_key(file_content)
    else:
        return {
            "type": "Unknown PEM",
            "isValid": False,
            "content_hash": generate_file_hash(file_content)
        }

def _analyze_binary_content(file_content: bytes, file_format: str, password: Optional[str]) -> Dict[str, Any]:
    """Route binary content to appropriate analyzer"""
    if file_format in ['DER', 'PKCS8']:
        return analyze_der_formats(file_content, password)
    elif file_format == 'PKCS12':
        return analyze_pkcs12(file_content, password)
    else:
        return {
            "type": "Unknown Binary",
            "isValid": False,
            "content_hash": generate_file_hash(file_content)
        }