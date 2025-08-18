"""
Session Decorator for automatic JWT session handling
Decorator that automatically handles JWT validation and session management
"""

import logging
from functools import wraps
from typing import Callable, Any
from fastapi import Request, Response, HTTPException
from middleware.jwt_session import jwt_session_manager

logger = logging.getLogger(__name__)

def require_session(func: Callable) -> Callable:
    """
    Decorator that automatically handles JWT session management
    
    What it does:
    1. Reads JWT from 'session_token' cookie
    2. Validates JWT and extracts session ID
    3. Creates new session if JWT is missing/invalid
    4. Sets HTTP-only cookie with JWT on response
    5. Injects session_id into request.state for route access
    
    Usage:
        @router.post("/upload")
        @require_session
        async def upload_file(request: Request):
            session_id = request.state.session_id  # Available here
            # Your route logic
    """
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Find Request and Response objects in function arguments
        request = None
        response = None
        
        # Check args for Request/Response objects
        for arg in args:
            if isinstance(arg, Request):
                request = arg
            elif isinstance(arg, Response):
                response = arg
        
        # Check kwargs for Request/Response objects
        for key, value in kwargs.items():
            if isinstance(value, Request):
                request = value
            elif isinstance(value, Response):
                response = value
        
        if not request:
            raise HTTPException(500, "Session decorator requires Request object")
        
        # Get JWT token from cookie
        jwt_token = request.cookies.get("session_token")
        session_id = None
        needs_new_cookie = False
        
        if jwt_token:
            # Try to validate existing JWT
            session_id = jwt_session_manager.validate_session_jwt(jwt_token)
            if session_id:
                logger.debug(f"Valid session found: {session_id[:8]}...")
            else:
                logger.info("Invalid/expired JWT token, creating new session")
                needs_new_cookie = True
        else:
            logger.info("No session token found, creating new session")
            needs_new_cookie = True
        
        # Create new session if needed
        if not session_id:
            session_id, new_jwt = jwt_session_manager.create_session_jwt()
            needs_new_cookie = True
            logger.info(f"Created new session: {session_id[:8]}...")
        
        # Inject session_id into request state
        request.state.session_id = session_id
        
        # Call the original function
        result = await func(*args, **kwargs)
        
        # Set cookie on response if needed
        if needs_new_cookie:
            # Create new JWT for the session
            if 'new_jwt' not in locals():
                _, new_jwt = jwt_session_manager.create_session_jwt(session_id)
            
            # Find or create response object
            if not response:
                # If no Response object provided, we need to modify the result
                # This handles cases where the route returns data directly
                if hasattr(result, 'headers'):
                    # Result is already a Response object
                    response = result
                else:
                    # Need to wrap result in Response - this is handled by FastAPI
                    # We'll add a hook to set the cookie after the response is created
                    pass
            
            # Set HTTP-only cookie
            if response:
                _set_session_cookie(response, new_jwt)
            else:
                # For routes that return data directly, we need to use a different approach
                # Store the JWT in the request state for middleware to handle
                request.state.new_session_jwt = new_jwt
        
        return result
    
    return wrapper


def _set_session_cookie(response: Response, jwt_token: str, secure: bool = None):
    """
    Set HTTP-only session cookie with JWT
    
    Args:
        response: FastAPI Response object
        jwt_token: JWT token to store in cookie
        secure: Use secure flag (auto-detect if None)
    """
    from config import settings
    
    # Auto-detect secure flag based on environment
    if secure is None:
        # Use secure cookies in production, allow non-secure in development
        secure = not settings.DEBUG
    
    response.set_cookie(
        key="session_token",
        value=jwt_token,
        httponly=True,              # Prevent XSS - JavaScript cannot access
        secure=secure,              # HTTPS only in production
        samesite="strict",          # CSRF protection
        max_age=86400,             # 24 hours (matches JWT expiration)
        path="/"                   # Available for all routes
    )
    
    logger.debug(f"Set session JWT cookie (secure={secure})")


def clear_session_cookie(response: Response):
    """
    Clear session cookie (for logout functionality)
    
    Args:
        response: FastAPI Response object
    """
    from config import settings
    
    response.delete_cookie(
        key="session_token",
        path="/",
        httponly=True,
        secure=not settings.DEBUG,  # Match production settings
        samesite="strict"
    )
    logger.debug("Cleared session cookie")


# Optional: Response middleware to handle cookie setting for direct returns
class SessionCookieMiddleware:
    """
    Middleware that automatically sets session cookies when decorator can't
    This handles cases where routes return data directly without Response object
    """
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Store original send
        original_send = send
        request_state = {}
        
        async def send_wrapper(message):
            nonlocal request_state
            
            if message["type"] == "http.response.start":
                # Check if we need to set a session cookie
                if hasattr(scope.get('state', {}), 'new_session_jwt'):
                    headers = dict(message.get("headers", []))
                    
                    # Add session cookie header
                    jwt_token = scope['state'].new_session_jwt
                    cookie_value = f"session_token={jwt_token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"
                    
                    headers[b"set-cookie"] = cookie_value.encode()
                    message["headers"] = list(headers.items())
            
            await original_send(message)
        
        await self.app(scope, receive, send_wrapper)


# Convenience functions for manual session management
def get_session_from_request(request: Request) -> str:
    """
    Get session ID from request state (after @require_session decorator)
    
    Args:
        request: FastAPI Request object
        
    Returns:
        str: Session ID
        
    Raises:
        HTTPException: If session not found (decorator not applied)
    """
    if not hasattr(request.state, 'session_id'):
        raise HTTPException(500, "Session not initialized. Apply @require_session decorator.")
    
    return request.state.session_id


def create_session_response(response: Response) -> str:
    """
    Manually create new session and set cookie
    
    Args:
        response: FastAPI Response object
        
    Returns:
        str: New session ID
    """
    session_id, jwt_token = jwt_session_manager.create_session_jwt()
    _set_session_cookie(response, jwt_token)
    
    logger.info(f"Manually created session: {session_id[:8]}...")
    return session_id