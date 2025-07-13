# utils/certificate_utils.py
# Adapted from your existing utils.py for certificate analysis

import datetime
import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def utils_check_fstring(fstring: str) -> tuple[bool, List[str]]:
    """
    EXISTING - NO MERGE NEEDED (can reuse directly)
    Check if f-string contains only allowed variables
    """
    allowed: list = [
        "domain",
        "port", 
        "email",
        "mode",
        "expiry",
        "checked",
        "issuer",
        "comment",
        "filename",  # Added for certificate analysis
        "type",      # Added for certificate analysis
        "hash"       # Added for certificate analysis
    ]
    pattern = r"\{(.*?)\}"
    found = re.findall(pattern, fstring)
    mismapped: list = []
    result = True
    if found:
        for item in found:
            if item not in allowed:
                result = False
                mismapped.append(item)
    return result, mismapped

def utils_cert_to_usable_vars(cert: Dict[str, Any]) -> Dict[str, Any]:
    """
    NEW - MERGE NEEDED (adapted from your list-based version)
    Convert certificate dict to usable variables for templates
    """
    # Adapted for our in-memory certificate structure
    analysis = cert.get('analysis', {})
    details = analysis.get('details', {})
    
    usable_vars = {
        "filename": cert.get('filename', 'N/A'),
        "domain": extract_domain_from_cert(details),
        "port": "443",  # Default for certificates
        "email": extract_email_from_cert(details),
        "mode": "Automatic",  # Our analysis is automatic
        "expiry": extract_expiry_from_cert(details),
        "checked": cert.get('uploadedAt', datetime.datetime.now().isoformat()),
        "issuer": extract_issuer_from_cert(details),
        "comment": f"Analyzed certificate: {analysis.get('type', 'Unknown')}",
        "type": analysis.get('type', 'Unknown'),
        "hash": analysis.get('hash', 'N/A'),
        "size": analysis.get('size', 0),
        "format": analysis.get('format', 'Unknown'),
        "isValid": analysis.get('isValid', False)
    }
    return usable_vars

def extract_domain_from_cert(details: Dict[str, Any]) -> str:
    """
    NEW - MERGE NEEDED
    Extract domain/common name from certificate details
    """
    if not details:
        return "N/A"
    
    subject = details.get('subject', {})
    
    # Try common name first
    domain = subject.get('commonName', 'N/A')
    if domain != 'N/A':
        return domain
    
    # Try SAN if no CN
    extensions = details.get('extensions', {})
    san_list = extensions.get('subjectAltName', [])
    for san in san_list:
        if san.get('typeName') == 'DNS':
            return san.get('value', 'N/A')
    
    return 'N/A'

def extract_email_from_cert(details: Dict[str, Any]) -> str:
    """
    NEW - MERGE NEEDED
    Extract email from certificate details
    """
    if not details:
        return "N/A"
    
    subject = details.get('subject', {})
    email = subject.get('emailAddress', 'N/A')
    
    if email != 'N/A':
        return email
    
    # Try SAN for email
    extensions = details.get('extensions', {})
    san_list = extensions.get('subjectAltName', [])
    for san in san_list:
        if san.get('typeName') == 'Email':
            return san.get('value', 'N/A')
    
    return 'N/A'

def extract_expiry_from_cert(details: Dict[str, Any]) -> str:
    """
    NEW - MERGE NEEDED
    Extract expiry date from certificate details
    """
    if not details:
        return "N/A"
    
    validity = details.get('validity', {})
    not_after = validity.get('notAfter', 'N/A')
    
    if not_after != 'N/A':
        try:
            # Parse ISO format and return date only
            dt = datetime.datetime.fromisoformat(not_after.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d')
        except:
            return not_after
    
    return 'N/A'

def extract_issuer_from_cert(details: Dict[str, Any]) -> str:
    """
    NEW - MERGE NEEDED
    Extract issuer from certificate details
    """
    if not details:
        return "N/A"
    
    issuer = details.get('issuer', {})
    
    # Build issuer string similar to your original format
    issuer_parts = []
    
    if issuer.get('commonName', 'N/A') != 'N/A':
        issuer_parts.append(issuer['commonName'])
    if issuer.get('organization', 'N/A') != 'N/A':
        issuer_parts.append(issuer['organization'])
    if issuer.get('country', 'N/A') != 'N/A':
        issuer_parts.append(issuer['country'])
    
    return '-'.join(issuer_parts) if issuer_parts else 'N/A'

def validate_certificate_data(cert_data: Dict[str, Any]) -> tuple[bool, str]:
    """
    NEW - MERGE NEEDED
    Validate certificate data structure
    """
    required_fields = ['filename', 'analysis']
    
    for field in required_fields:
        if field not in cert_data:
            return False, f"Missing required field: {field}"
    
    analysis = cert_data['analysis']
    if not isinstance(analysis, dict):
        return False, "Analysis must be a dictionary"
    
    if 'type' not in analysis:
        return False, "Analysis missing type field"
    
    return True, "Valid"

def format_certificate_size(size_bytes: int) -> str:
    """
    NEW - MERGE NEEDED
    Format certificate size in human readable format
    """
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"

def is_certificate_expired(details: Dict[str, Any]) -> bool:
    """
    NEW - MERGE NEEDED
    Check if certificate is expired
    """
    if not details:
        return False
    
    validity = details.get('validity', {})
    return validity.get('isExpired', False)

def days_until_expiry(details: Dict[str, Any]) -> int:
    """
    NEW - MERGE NEEDED
    Get days until certificate expiry
    """
    if not details:
        return -1
    
    validity = details.get('validity', {})
    return validity.get('daysUntilExpiry', -1)

def get_certificate_summary(cert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    NEW - MERGE NEEDED
    Get a summary of certificate information
    """
    analysis = cert_data.get('analysis', {})
    details = analysis.get('details', {})
    
    return {
        "filename": cert_data.get('filename', 'Unknown'),
        "type": analysis.get('type', 'Unknown'),
        "format": analysis.get('format', 'Unknown'),
        "isValid": analysis.get('isValid', False),
        "size": format_certificate_size(analysis.get('size', 0)),
        "domain": extract_domain_from_cert(details),
        "issuer": extract_issuer_from_cert(details),
        "expiry": extract_expiry_from_cert(details),
        "isExpired": is_certificate_expired(details),
        "daysUntilExpiry": days_until_expiry(details)
    }
