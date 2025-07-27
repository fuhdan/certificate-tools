# backend-fastapi/certificates/validation/models.py
# Validation result models

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ValidationResult:
    """Validation result container"""
    def __init__(self, is_valid: bool, validation_type: str, details: Optional[Dict[str, Any]] = None, error: Optional[str] = None):
        self.is_valid = is_valid
        self.validation_type = validation_type
        self.details = details or {}
        self.error = error
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "isValid": self.is_valid,
            "validationType": self.validation_type,
            "details": self.details,
            "error": self.error
        }