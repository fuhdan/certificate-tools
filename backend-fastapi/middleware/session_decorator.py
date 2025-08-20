"""
Session Decorator for automatic JWT session handling
Decorator that automatically handles JWT validation and session management
"""

import logging
from functools import wraps
from typing import Callable
from datetime import datetime
from fastapi import Request, Response, HTTPException
from middleware.jwt_session import jwt_session_manager
from config import settings

logger = logging.getLogger(__name__)

def require_session(func: Callable) -> Callable:
    """
    Decorator that automatically handles JWT session management
    
    What it does:
    1. Reads JWT from 'session_token' cookie
    2. Validates JWT and extracts session ID
    3. Creates new session if JWT is missing/invalid
    4. Sets HTTP-only cookie with JWT on response
    5. Deletes expired cookies automatically
    6. Injects session_id into request.state for route access
    
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
        
        # DEBUGGING: Log all cookies received (only when debugging session issues)
        all_cookies = dict(request.cookies)
        logger.info(f"🍪 [SESSION DEBUG] All cookies received: {all_cookies}")
        
        # Get JWT token from cookie
        jwt_token = request.cookies.get("session_token")
        session_id = None
        needs_new_cookie = False
        clear_expired_cookie = False
        expiry_reason = None
        
        # DEBUGGING: Enhanced JWT token analysis
        if jwt_token:
            logger.debug(f"🔑 [SESSION DEBUG] JWT token found: {jwt_token[:20]}...{jwt_token[-10:]} (length: {len(jwt_token)})")
            
            # Try to validate existing JWT with detailed error tracking
            session_id = jwt_session_manager.validate_session_jwt(jwt_token)
            if session_id:
                logger.debug(f"✅ [SESSION DEBUG] Valid session found: {session_id}")
                logger.debug(f"Valid session found: {session_id[:8]}...")
            else:
                # Analyze WHY the JWT failed
                try:
                    # Try to decode without validation to see expiry info
                    import base64, json
                    if '.' in jwt_token:
                        payload_b64 = jwt_token.split('.')[0]
                        # Add padding if needed
                        payload_b64 += '=' * (4 - len(payload_b64) % 4)
                        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
                        payload = json.loads(payload_json)
                        
                        exp_timestamp = payload.get('exp', 0)
                        current_timestamp = datetime.utcnow().timestamp()
                        
                        if current_timestamp > exp_timestamp:
                            exp_time = datetime.fromtimestamp(exp_timestamp)
                            current_time = datetime.fromtimestamp(current_timestamp)
                            time_diff = current_timestamp - exp_timestamp
                            expiry_reason = f"EXPIRED - Token expired {time_diff:.1f} seconds ago (exp: {exp_time}, now: {current_time})"
                        else:
                            expiry_reason = "INVALID - Bad signature or malformed token"
                            
                        logger.warning(f"❌ [SESSION DEBUG] JWT validation failed - {expiry_reason}")
                        logger.warning(f"🕐 [SESSION DEBUG] Token payload: {payload}")
                    else:
                        expiry_reason = "MALFORMED - No dot separator found"
                        logger.warning(f"❌ [SESSION DEBUG] JWT validation failed - {expiry_reason}")
                        
                except Exception as decode_error:
                    expiry_reason = f"DECODE_ERROR - {str(decode_error)}"
                    logger.warning(f"❌ [SESSION DEBUG] JWT decode failed - {expiry_reason}")
                
                logger.info("Invalid/expired JWT token, deleting expired cookie and creating new session")
                needs_new_cookie = True
                clear_expired_cookie = True  # Always clear expired/invalid cookies
        else:
            logger.debug(f"🚫 [SESSION DEBUG] No JWT token found in cookies")
            logger.info("No session token found, creating new session")
            needs_new_cookie = True
        
        # Create new session if needed
        old_session_id = session_id
        if not session_id:
            session_id, new_jwt = jwt_session_manager.create_session_jwt()
            needs_new_cookie = True
            logger.info(f"🆕 [SESSION DEBUG] Created new session: {session_id} (replacing: {old_session_id or 'none'})")
            logger.debug(f"🔑 [SESSION DEBUG] New JWT token: {new_jwt[:20]}...{new_jwt[-10:]} (length: {len(new_jwt)})")
            logger.info(f"Created new session: {session_id[:8]}...")
        
        # DEBUGGING: Log session transition (only for important transitions)
        if old_session_id != session_id:
            logger.warning(f"🔄 [SESSION DEBUG] Session transition: {old_session_id or 'none'} → {session_id}")
            if expiry_reason:
                logger.warning(f"🕰️ [SESSION DEBUG] Transition reason: {expiry_reason}")
        
        # Inject session_id into request state
        request.state.session_id = session_id
        
        # Call the original function
        result = await func(*args, **kwargs)
        
        # Handle cookie operations on response
        if clear_expired_cookie or needs_new_cookie:
            # Create new JWT for the session if not already created
            if 'new_jwt' not in locals():
                _, new_jwt = jwt_session_manager.create_session_jwt(session_id)
                logger.debug(f"🔑 [SESSION DEBUG] Generated additional JWT for existing session: {session_id}")
            
            # Find or create response object
            response_available = False
            if not response:
                # If no Response object provided, we need to modify the result
                # This handles cases where the route returns data directly
                if hasattr(result, 'headers'):
                    # Result is already a Response object
                    response = result
                    response_available = True
                    logger.debug(f"📤 [SESSION DEBUG] Found Response object in result")
                else:
                    # Need to wrap result in Response - this is handled by FastAPI
                    # We'll add a hook to set the cookie after the response is created
                    logger.debug(f"📤 [SESSION DEBUG] No Response object available, using middleware fallback")
                    response_available = False
            else:
                response_available = True
                logger.debug(f"📤 [SESSION DEBUG] Response object provided directly")
            
            # Handle cookie operations
            if response and response_available:
                if clear_expired_cookie:
                    # Always clear expired/invalid cookies first
                    clear_session_cookie(response)
                    logger.info("🗑️ [SESSION DEBUG] Cleared expired/invalid session cookie via Response")
                    logger.info("Deleted expired/invalid session cookie")
                
                if needs_new_cookie:
                    # Then set the new cookie
                    _set_session_cookie(response, new_jwt)
                    logger.info(f"✅ [SESSION DEBUG] Set new session cookie via Response for session: {session_id}")
            else:
                # For routes that return data directly, we need to use a different approach
                # Store the JWT in the request state for middleware to handle
                request.state.new_session_jwt = new_jwt
                if clear_expired_cookie:
                    request.state.clear_expired_cookie = True
                    logger.info(f"🔄 [SESSION DEBUG] Marked for middleware: clear_expired_cookie=True, new_jwt={new_jwt[:20]}...")
                else:
                    logger.info(f"🔄 [SESSION DEBUG] Marked for middleware: new_jwt={new_jwt[:20]}...")
        
        return result
    
    return wrapper


def _set_session_cookie(response: Response, jwt_token: str):
    """
    Set HTTP-only session cookie with JWT using config settings
    
    Args:
        response: FastAPI Response object
        jwt_token: JWT token to store in cookie
    """
    max_age = settings.SESSION_EXPIRE_HOURS * 3600
    
    response.set_cookie(
        key="session_token",
        value=jwt_token,
        httponly=settings.COOKIE_HTTPONLY,      # Always True for security
        secure=settings.COOKIE_SECURE,          # From config: False in DEBUG, True in production
        samesite=settings.COOKIE_SAMESITE,      # From config: "strict"
        max_age=max_age,  # From config
        path="/"
    )
    
    # DEBUGGING: Enhanced cookie setting log
    logger.info(f"🍪 [COOKIE DEBUG] Set session cookie:")
    logger.info(f"   - Token: {jwt_token[:20]}...{jwt_token[-10:]}")
    logger.info(f"   - Max-Age: {max_age} seconds ({settings.SESSION_EXPIRE_HOURS} hours)")
    logger.info(f"   - Secure: {settings.COOKIE_SECURE}")
    logger.info(f"   - SameSite: {settings.COOKIE_SAMESITE}")
    logger.info(f"   - HttpOnly: {settings.COOKIE_HTTPONLY}")
    logger.debug(f"Set session JWT cookie (secure={settings.COOKIE_SECURE})")


def clear_session_cookie(response: Response):
    """
    Clear session cookie using config settings
    
    Args:
        response: FastAPI Response object
    """
    response.delete_cookie(
        key="session_token",
        path="/",
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,          # From config
        samesite=settings.COOKIE_SAMESITE       # From config
    )
    
    # DEBUGGING: Enhanced cookie clearing log
    logger.info(f"🗑️ [COOKIE DEBUG] Deleted session cookie:")
    logger.info(f"   - Secure: {settings.COOKIE_SECURE}")
    logger.info(f"   - SameSite: {settings.COOKIE_SAMESITE}")
    logger.info(f"   - HttpOnly: {settings.COOKIE_HTTPONLY}")
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
                
                # Handle expired cookie clearing - FORCE CLEAR OLD COOKIES
                if hasattr(state, 'clear_expired_cookie') and state.clear_expired_cookie:
                    headers = dict(message.get("headers", []))
                    # Add cookie deletion header - force immediate expiration with multiple methods
                    clear_cookie_values = [
                        "session_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                        "session_token=deleted; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
                    ]
                    
                    # Set multiple clear cookie headers to ensure deletion
                    if b"set-cookie" in headers:
                        existing = headers[b"set-cookie"].decode()
                        headers[b"set-cookie"] = f"{existing}, {', '.join(clear_cookie_values)}".encode()
                    else:
                        headers[b"set-cookie"] = ", ".join(clear_cookie_values).encode()
                    
                    message["headers"] = list(headers.items())
                    logger.warning("🍪 [MIDDLEWARE DEBUG] FORCE CLEARED expired session cookie via middleware")
                
                # Check if we need to set a new session cookie
                elif hasattr(state, 'new_session_jwt'):
                    headers = dict(message.get("headers", []))
                    
                    # Add session cookie header
                    jwt_token = state.new_session_jwt
                    max_age = settings.SESSION_EXPIRE_HOURS * 3600
                    cookie_value = f"session_token={jwt_token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}"
                    
                    headers[b"set-cookie"] = cookie_value.encode()
                    message["headers"] = list(headers.items())
                    logger.info(f"🍪 [MIDDLEWARE DEBUG] SET NEW session cookie via middleware:")
                    logger.info(f"   - Token: {jwt_token[:20]}...{jwt_token[-10:]}")
                    logger.info(f"   - Max-Age: {max_age} seconds")
            
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
    
    logger.info(f"🆕 [MANUAL SESSION DEBUG] Manually created session: {session_id}")
    logger.info(f"Manually created session: {session_id[:8]}...")
    return session_id