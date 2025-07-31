"""
Session Middleware for FastAPI Certificate Management API

Provides automatic session ID extraction and generation via FastAPI dependency injection.
Ensures every API request has a valid session ID for multi-user data isolation.
"""

import uuid
import re
import logging
from config import settings
from fastapi import Request, HTTPException
from typing import Optional

logger = logging.getLogger(__name__)


def is_valid_uuid(uuid_string: str) -> bool:
    """
    Validate UUID format (specifically UUID v4)
    
    Args:
        uuid_string: String to validate as UUID
        
    Returns:
        True if valid UUID format, False otherwise
    """
    if not isinstance(uuid_string, str):
        return False
    
    # UUID v4 pattern: 8-4-4-4-12 hex digits with version 4 and variant bits
    uuid_pattern = re.compile(
        r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$',
        re.IGNORECASE
    )
    
    return bool(uuid_pattern.match(uuid_string))


async def get_session_id(request: Request) -> str:
    """
    FastAPI dependency to extract session ID from request header or use default session
    
    This function serves as a FastAPI dependency that:
    - Extracts X-Session-ID from request headers
    - Validates UUID format
    - Uses default session if missing (for backward compatibility)
    - Generates new UUID only if header is invalid
    - Updates SessionManager activity tracking
    - Provides comprehensive logging
    
    Args:
        request: FastAPI Request object
        
    Returns:
        str: Valid UUID session ID
        
    Raises:
        HTTPException: If session creation fails
    """
    # Extract session ID from headers
    session_id = request.headers.get("X-Session-ID")
    request_info = f"{request.method} {request.url.path}"
    
    if not session_id:
        # No session ID provided - use default session for backward compatibility
        # session_id = SessionMiddlewareConfig.DEFAULT_SESSION_ID
        logger.warning(
            f"No session ID for {request_info} (no X-Session-ID header)"
        )
        raise HTTPException(
            status_code=400,
            detail=f"No session ID received. Expected UUID v4 ..."
        )
    elif not is_valid_uuid(session_id):
        # Invalid session ID format - generate replacement
        logger.warning(
            f"Invalid session ID format: {session_id} for {request_info}"
        )
        raise HTTPException(
            status_code=400,
            detail=f"Invalid session ID format. Expected UUID v4, got: {session_id[:50]}..."
        )
    else:
        # Valid existing session ID
        logger.debug(
            f"Using existing session ID: {session_id} for {request_info}"
        )
    
    # Update SessionManager activity tracking
    try:
        from session_manager import SessionManager
        SessionManager.get_or_create_session(session_id)
        logger.debug(f"Updated session activity for: {session_id}")
    except Exception as e:
        logger.error(
            f"Failed to update session activity for {session_id}: {e}"
        )
        # Don't fail the request, but log the error
        # The session ID is still valid for this request
    
    return session_id


async def get_optional_session_id(request: Request) -> Optional[str]:
    """
    FastAPI dependency to extract session ID without creating new one
    
    Useful for endpoints that don't require session isolation but can benefit
    from it if a session ID is provided.
    
    Args:
        request: FastAPI Request object
        
    Returns:
        str or None: Valid UUID session ID or None if not provided/invalid
    """
    session_id = request.headers.get("X-Session-ID")
    request_info = f"{request.method} {request.url.path}"
    
    if not session_id:
        logger.debug(f"No session ID provided for optional endpoint: {request_info}")
        return None
    
    if not is_valid_uuid(session_id):
        logger.warning(
            f"Invalid session ID format for optional endpoint: {session_id} "
            f"for {request_info}"
        )
        raise HTTPException(
            status_code=400,
            detail=f"Invalid session ID format. Expected UUID v4, got: {session_id[:50]}..."
        )
    
    # Valid session ID - update activity if session exists
    try:
        from session_manager import SessionManager
        if SessionManager.session_exists(session_id):
            SessionManager.get_or_create_session(session_id)
            logger.debug(f"Updated existing session activity: {session_id}")
        else:
            logger.debug(f"Session ID provided but session doesn't exist: {session_id}")
    except Exception as e:
        logger.error(
            f"Failed to check/update session for {session_id}: {e}"
        )
    
    return session_id


def validate_session_header(session_id: str) -> bool:
    """
    Standalone function to validate session ID format
    
    Useful for manual validation or testing scenarios.
    
    Args:
        session_id: Session ID to validate
        
    Returns:
        True if valid, False otherwise
    """
    return is_valid_uuid(session_id)


def generate_session_id() -> str:
    """
    Generate a new UUID v4 session ID
    
    Returns:
        str: New UUID v4 as string
    """
    new_id = str(uuid.uuid4())
    logger.debug(f"Generated new session ID: {new_id}")
    return new_id


def get_default_session_id() -> str:
    """
    Get the default session ID for backward compatibility
    
    Returns:
        str: Default session ID
    """
    return SessionMiddlewareConfig.DEFAULT_SESSION_ID


class SessionContext:
    """
    Context manager for session operations
    
    Provides a convenient way to work with session data in a controlled manner.
    """
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self._session_data = None
    
    def __enter__(self):
        """Enter session context and get session data"""
        try:
            from session_manager import SessionManager
            self._session_data = SessionManager.get_or_create_session(self.session_id)
            logger.debug(f"Entered session context: {self.session_id}")
            return self._session_data
        except Exception as e:
            logger.error(f"Failed to enter session context {self.session_id}: {e}")
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit session context"""
        if exc_type is not None:
            logger.warning(
                f"Session context {self.session_id} exited with exception: {exc_val}"
            )
        else:
            logger.debug(f"Exited session context: {self.session_id}")


# Middleware configuration for automatic cleanup
class SessionMiddlewareConfig:
    """Configuration for session middleware behavior"""
    
    # Default session ID for backward compatibility (when no X-Session-ID header is provided)
    DEFAULT_SESSION_ID = settings.DEFAULT_SESSION_ID
    
    # Default timeout for inactive sessions (hours)
    DEFAULT_SESSION_TIMEOUT = 24
    
    # How often to run cleanup (hours)
    DEFAULT_CLEANUP_INTERVAL = 6
    
    # Whether to log all session operations
    VERBOSE_LOGGING = False
    
    # Maximum number of sessions before forced cleanup
    MAX_ACTIVE_SESSIONS = 1000
    
    @classmethod
    def configure_logging(cls, verbose: bool = False):
        """Configure session middleware logging level"""
        cls.VERBOSE_LOGGING = verbose
        level = logging.DEBUG if verbose else logging.INFO
        logging.getLogger(__name__).setLevel(level)
        logger.info(f"Session middleware logging set to: {level}")
    
    @classmethod
    def set_default_session_id(cls, session_id: str):
        """Set custom default session ID"""
        if not is_valid_uuid(session_id):
            raise ValueError(f"Invalid UUID format for default session ID: {session_id}")
        cls.DEFAULT_SESSION_ID = session_id
        logger.info(f"Default session ID updated to: {session_id}")


# Example usage patterns for endpoints:
"""
Usage Examples:

1. Required session ID (uses default if no header):
from middleware.session_middleware import get_session_id

@router.post("/certificates/upload")
async def upload_certificate(
    session_id: str = Depends(get_session_id),
    certificate: UploadFile = File(...)
):
    # session_id is guaranteed to be valid UUID
    # Will be default session if no X-Session-ID header provided
    result = CertificateStorage.add(certificate_data, session_id)
    return result

2. Optional session ID (None if not provided):
from middleware.session_middleware import get_optional_session_id

@router.get("/health")
async def health_check(
    session_id: Optional[str] = Depends(get_optional_session_id)
):
    # session_id might be None
    if session_id:
        # Use session-specific data
        pass
    else:
        # Use global/default behavior
        pass

3. Using session context manager:
from middleware.session_middleware import SessionContext

def some_operation(session_id: str):
    with SessionContext(session_id) as session_data:
        # Work with session_data
        session_data["certificates"].append(new_cert)

4. Get default session ID programmatically:
from middleware.session_middleware import get_default_session_id

default_session = get_default_session_id()  # settings.DEFAULT_SESSION_ID

5. Frontend usage patterns:

Without session header (uses default):
fetch('/certificates')  // Uses default session

With specific session:
fetch('/certificates', {
    headers: { 'X-Session-ID': 'user-specific-uuid' }
})

Generate new session for user:
const sessionId = crypto.randomUUID()
fetch('/certificates', {
    headers: { 'X-Session-ID': sessionId }
})
"""