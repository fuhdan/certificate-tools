"""
Simple session manager without JWT dependency for immediate testing
Save this as: backend-fastapi/middleware/jwt_session.py
"""

import uuid
import json
import base64
import hmac
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional
from config import settings

logger = logging.getLogger(__name__)

class SimpleSessionManager:
    """Temporary session manager using simple HMAC instead of JWT"""
    
    def __init__(self):
        self.secret_key = settings.SECRET_KEY.encode()
        self.session_expire_hours = settings.SESSION_EXPIRE_HOURS
        
    def create_session_jwt(self, session_id: Optional[str] = None) -> tuple[str, str]:
        """Create session token using simple HMAC"""
        if not session_id:
            session_id = str(uuid.uuid4())
            
        # Simple payload
        payload = {
            "session_id": session_id,
            "exp": (datetime.utcnow() + timedelta(hours=self.session_expire_hours)).timestamp(),
            "type": "session"
        }
        
        # Encode payload
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
        
        # Create HMAC signature
        signature = hmac.new(
            self.secret_key, 
            payload_b64.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        # Simple token format: payload.signature
        token = f"{payload_b64}.{signature}"
        
        logger.debug(f"Created simple session token for {session_id[:8]}...")
        return session_id, token
    
    def validate_session_jwt(self, token: str) -> Optional[str]:
        """Validate simple session token"""
        try:
            if '.' not in token:
                return None
                
            payload_b64, signature = token.rsplit('.', 1)
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key, 
                payload_b64.encode(), 
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                logger.warning("Invalid token signature")
                return None
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
            payload = json.loads(payload_json)
            
            # Check expiration
            if datetime.utcnow().timestamp() > payload.get('exp', 0):
                logger.info("Session token expired")
                return None
                
            # Check type
            if payload.get('type') != 'session':
                return None
                
            session_id = payload.get('session_id')
            if not session_id:
                return None
                
            logger.debug(f"Validated simple session token for {session_id[:8]}...")
            return session_id
            
        except Exception as e:
            logger.warning(f"Error validating session token: {e}")
            return None
    
    def extract_session_id(self, token: str) -> str:
        """Extract session ID or create new one"""
        if token:
            session_id = self.validate_session_jwt(token)
            if session_id:
                return session_id
        
        session_id, _ = self.create_session_jwt()
        logger.info(f"Created new session {session_id[:8]}... (invalid/missing token)")
        return session_id

# Singleton instance
jwt_session_manager = SimpleSessionManager()

# Convenience functions (same interface as JWT version)
def create_session_jwt(session_id: Optional[str] = None) -> tuple[str, str]:
    return jwt_session_manager.create_session_jwt(session_id)

def validate_session_jwt(token: str) -> Optional[str]:
    return jwt_session_manager.validate_session_jwt(token)

def extract_session_id(token: str) -> str:
    return jwt_session_manager.extract_session_id(token)