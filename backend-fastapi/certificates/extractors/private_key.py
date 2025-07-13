# certificates/extractors/private_key.py
# Private key detail extraction functions

import logging
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, ec

logger = logging.getLogger(__name__)

def extract_private_key_details(private_key) -> Dict[str, Any]:
    """Extract details from private key"""
    details = {
        "algorithm": "Unknown",
        "keySize": 0,
        "curve": "N/A"
    }
    
    try:
        if isinstance(private_key, rsa.RSAPrivateKey):
            details["algorithm"] = "RSA"
            details["keySize"] = private_key.key_size
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            details["algorithm"] = "EC"
            details["curve"] = private_key.curve.name
    except Exception as e:
        logger.warning(f"Error extracting private key details: {e}")
    
    return details