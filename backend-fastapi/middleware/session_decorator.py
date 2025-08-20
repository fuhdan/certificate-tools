"""
Session Decorator for automatic JWT session handling
Decorator that automatically handles JWT validation and session management
"""

import logging
from functools import wraps
from typing import Callable
from fastapi import Request, Response, HTTPException
from middleware.jwt_session import jwt_session_manager
from config import settings

logger = logging.getLogger(__name__)

def require_session(func: Callable) -> Callable:
    """
    Decorator that EXTENDS existing sessions instead of creating new ones
    """
    logger.error("🔥 NEW REQUIRE_SESSION CODE IS RUNNING! 🔥") 
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Find Request object
        request = None
        for arg in args:
            if isinstance(arg, Request):
                request = arg
                break
        
        if not request:
            raise HTTPException(500, "Session decorator requires Request object")
        
        # Get JWT token from cookie
        jwt_token = request.cookies.get("session_token")
        session_id = None
        needs_new_cookie = False
        clear_expired_cookie = False
        
        if jwt_token:
            # Try to validate existing JWT
            session_id = jwt_session_manager.validate_session_jwt(jwt_token)
            if session_id:
                logger.debug(f"FOUND VALID SESSION: {session_id[:8]}...")
                # ALWAYS refresh JWT to extend session lifetime
                needs_new_cookie = True
            else:
                logger.info("JWT EXPIRED - extending with new token")
                clear_expired_cookie = True
                needs_new_cookie = True
        else:
            logger.info("NO JWT FOUND - creating first session")
            needs_new_cookie = True
        
        # Only create NEW session if we have no valid session ID
        if not session_id:
            session_id, new_jwt = jwt_session_manager.create_session_jwt()
            logger.info(f"CREATED NEW SESSION: {session_id[:8]}...")
        else:
            # EXTEND existing session with fresh JWT
            _, new_jwt = jwt_session_manager.create_session_jwt(session_id)
            logger.info(f"EXTENDED EXISTING SESSION: {session_id[:8]}...")
        
        # Inject session_id into request state
        request.state.session_id = session_id
        
        # Call the original function
        result = await func(*args, **kwargs)
        
        # Set cookies if needed
        if needs_new_cookie or clear_expired_cookie:
            # Store JWT for middleware to handle
            request.state.new_session_jwt = new_jwt
            if clear_expired_cookie:
                request.state.clear_expired_cookie = True
        
        return result
    
    return wrapper


def _set_session_cookie(response: Response, jwt_token: str, secure: bool = True):
    """
    Set HTTP-only session cookie with JWT
    
    Args:
        response: FastAPI Response object
        jwt_token: JWT token to store in cookie
        secure: Use secure flag (HTTPS only)
    """
    response.set_cookie(
        key="session_token",
        value=jwt_token,
        httponly=True,              # Prevent XSS - JavaScript cannot access
        secure=secure,              # HTTPS only in production
        samesite="strict",          # CSRF protection
        max_age=settings.SESSION_EXPIRE_HOURS * 3600,  # Convert hours to seconds
        path="/"                   # Available for all routes
    )
    logger.debug("Set session JWT cookie")


def clear_session_cookie(response: Response):
    """
    Clear session cookie (for logout functionality or expired/invalid sessions)
    
    Args:
        response: FastAPI Response object
    """
    response.delete_cookie(
        key="session_token",
        path="/",
        httponly=True,
        secure=True,
        samesite="strict"
    )
    logger.debug("Deleted session cookie")


# Enhanced Response middleware to handle cookie setting for direct returns
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
                # Check if we need to handle cookies
                state = scope.get('state', {})
                
                # Handle expired cookie clearing
                if hasattr(state, 'clear_expired_cookie') and state.clear_expired_cookie:
                    headers = dict(message.get("headers", []))
                    # Add cookie deletion header - force immediate expiration
                    clear_cookie_value = "session_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
                    headers[b"set-cookie"] = clear_cookie_value.encode()
                    message["headers"] = list(headers.items())
                    logger.debug("Deleted expired session cookie via middleware")
                
                # Check if we need to set a new session cookie
                elif hasattr(state, 'new_session_jwt'):
                    headers = dict(message.get("headers", []))
                    
                    # Add session cookie header
                    jwt_token = state.new_session_jwt
                    max_age = settings.SESSION_EXPIRE_HOURS * 3600
                    cookie_value = f"session_token={jwt_token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}"
                    
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