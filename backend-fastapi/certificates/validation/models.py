# backend-fastapi/certificates/validation/models.py
# Clean validation result model - no backward compatibility

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ValidationResult:
    """Clean validation result container"""
    
    def __init__(
        self, 
        is_valid: bool, 
        validation_type: str, 
        description: str,
        certificate_1: str,
        certificate_2: str = "",
        error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.is_valid = is_valid
        self.validation_type = validation_type
        self.description = description
        self.certificate_1 = certificate_1
        self.certificate_2 = certificate_2
        self.error = error
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "isValid": self.is_valid,
            "validationType": self.validation_type,
            "description": self.description,
            "certificate1": self.certificate_1,
            "certificate2": self.certificate_2,
            "error": self.error,
            "details": self.details
        }