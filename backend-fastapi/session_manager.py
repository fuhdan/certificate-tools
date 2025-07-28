"""
Session Manager for Multi-User Certificate Management

Provides UUID-based session management with automatic cleanup and thread safety.
Enables multiple users to work simultaneously without data interference.
"""

import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging
import sys

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages per-session certificate storage and lifecycle"""
    
    # Class-level storage for all sessions
    _sessions: Dict[str, Dict[str, Any]] = {}
    _last_activity: Dict[str, datetime] = {}
    _lock = threading.RLock()  # Reentrant lock for thread safety
    
    @staticmethod
    def get_or_create_session(session_id: str) -> Dict[str, Any]:
        """
        Get session storage or create if not exists
        
        Args:
            session_id: UUID string for the session
            
        Returns:
            Dict containing session data
            
        Raises:
            ValueError: If session_id is not a valid UUID format
        """
        if not SessionManager._is_valid_uuid(session_id):
            raise ValueError(f"Invalid session ID format: {session_id}")
        
        with SessionManager._lock:
            current_time = datetime.now()
            
            if session_id not in SessionManager._sessions:
                # Create new session with initial structure
                session_data = {
                    "certificates": [],          # List of uploaded certificates
                    "crypto_objects": {},        # Cryptographic objects by cert_id
                    "pki_bundle": {},           # Generated PKI bundle
                    "last_activity": current_time,
                    "created_at": current_time,
                    "request_count": 0          # Track usage
                }
                
                SessionManager._sessions[session_id] = session_data
                SessionManager._last_activity[session_id] = current_time
                
                logger.info(f"Created new session: {session_id}")
            else:
                # Update activity timestamp
                SessionManager._sessions[session_id]["last_activity"] = current_time
                SessionManager._sessions[session_id]["request_count"] += 1
                SessionManager._last_activity[session_id] = current_time
                
                logger.debug(f"Accessed existing session: {session_id}")
            
            return SessionManager._sessions[session_id]
    
    @staticmethod
    def cleanup_inactive_sessions(timeout_hours: int = 24) -> int:
        """
        Remove sessions inactive for specified hours
        
        Args:
            timeout_hours: Hours of inactivity before cleanup (default: 24)
            
        Returns:
            Number of sessions cleaned up
        """
        if timeout_hours <= 0:
            raise ValueError("Timeout hours must be positive")
        
        cutoff_time = datetime.now() - timedelta(hours=timeout_hours)
        cleaned_count = 0
        
        with SessionManager._lock:
            # Get list of sessions to remove (avoid modifying dict during iteration)
            sessions_to_remove = [
                session_id for session_id, last_activity 
                in SessionManager._last_activity.items()
                if last_activity < cutoff_time
            ]
            
            # Remove inactive sessions
            for session_id in sessions_to_remove:
                if session_id in SessionManager._sessions:
                    session_data = SessionManager._sessions[session_id]
                    logger.info(
                        f"Cleaning up inactive session: {session_id}, "
                        f"last activity: {SessionManager._last_activity[session_id]}, "
                        f"requests: {session_data.get('request_count', 0)}"
                    )
                    
                    del SessionManager._sessions[session_id]
                    del SessionManager._last_activity[session_id]
                    cleaned_count += 1
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} inactive sessions")
        
        return cleaned_count
    
    @staticmethod
    def get_session_stats() -> Dict[str, Any]:
        """
        Get statistics about active sessions
        
        Returns:
            Dict with session statistics including count, memory usage, etc.
        """
        with SessionManager._lock:
            current_time = datetime.now()
            session_count = len(SessionManager._sessions)
            
            if session_count == 0:
                return {
                    "active_sessions": 0,
                    "total_memory_mb": 0.0,
                    "oldest_session_age_hours": 0,
                    "newest_session_age_hours": 0,
                    "total_requests": 0,
                    "average_requests_per_session": 0.0
                }
            
            # Calculate memory usage (approximate)
            total_memory_bytes = sys.getsizeof(SessionManager._sessions)
            for session_data in SessionManager._sessions.values():
                total_memory_bytes += sys.getsizeof(session_data)
                for key, value in session_data.items():
                    total_memory_bytes += sys.getsizeof(key) + sys.getsizeof(value)
            
            total_memory_mb = total_memory_bytes / (1024 * 1024)
            
            # Calculate age statistics
            creation_times = [
                session_data["created_at"] 
                for session_data in SessionManager._sessions.values()
            ]
            
            oldest_creation = min(creation_times)
            newest_creation = max(creation_times)
            
            oldest_age_hours = (current_time - oldest_creation).total_seconds() / 3600
            newest_age_hours = (current_time - newest_creation).total_seconds() / 3600
            
            # Calculate request statistics
            total_requests = sum(
                session_data.get("request_count", 0)
                for session_data in SessionManager._sessions.values()
            )
            
            avg_requests = total_requests / session_count if session_count > 0 else 0
            
            return {
                "active_sessions": session_count,
                "total_memory_mb": round(total_memory_mb, 2),
                "oldest_session_age_hours": round(oldest_age_hours, 2),
                "newest_session_age_hours": round(newest_age_hours, 2),
                "total_requests": total_requests,
                "average_requests_per_session": round(avg_requests, 1)
            }
    
    @staticmethod
    def delete_session(session_id: str) -> bool:
        """
        Manually delete a specific session
        
        Args:
            session_id: UUID string for the session to delete
            
        Returns:
            True if session was deleted, False if not found
        """
        if not SessionManager._is_valid_uuid(session_id):
            return False
        
        with SessionManager._lock:
            if session_id in SessionManager._sessions:
                session_data = SessionManager._sessions[session_id]
                logger.info(
                    f"Manually deleting session: {session_id}, "
                    f"requests: {session_data.get('request_count', 0)}"
                )
                
                del SessionManager._sessions[session_id]
                del SessionManager._last_activity[session_id]
                return True
            
            return False
    
    @staticmethod
    def session_exists(session_id: str) -> bool:
        """
        Check if a session exists
        
        Args:
            session_id: UUID string for the session
            
        Returns:
            True if session exists, False otherwise
        """
        if not SessionManager._is_valid_uuid(session_id):
            return False
        
        with SessionManager._lock:
            return session_id in SessionManager._sessions
    
    @staticmethod
    def _is_valid_uuid(session_id: str) -> bool:
        """
        Validate that session_id is a proper UUID format
        
        Args:
            session_id: String to validate
            
        Returns:
            True if valid UUID format, False otherwise
        """
        if not isinstance(session_id, str):
            return False
        
        try:
            uuid.UUID(session_id)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def get_session_info(session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific session without updating activity
        
        Args:
            session_id: UUID string for the session
            
        Returns:
            Dict with session info or None if not found
        """
        if not SessionManager._is_valid_uuid(session_id):
            return None
        
        with SessionManager._lock:
            if session_id not in SessionManager._sessions:
                return None
            
            session_data = SessionManager._sessions[session_id]
            return {
                "session_id": session_id,
                "created_at": session_data["created_at"],
                "last_activity": session_data["last_activity"],
                "request_count": session_data.get("request_count", 0),
                "certificates_count": len(session_data.get("certificates", [])),
                "crypto_objects_count": len(session_data.get("crypto_objects", {})),
                "has_pki_bundle": bool(session_data.get("pki_bundle"))
            }


# Utility function for easy session cleanup scheduling
def schedule_cleanup_task(timeout_hours: int = 24, interval_hours: int = 6):
    """
    Example function showing how to schedule automatic cleanup
    Note: In production, use proper task scheduler like Celery or APScheduler
    
    Args:
        timeout_hours: Hours of inactivity before cleanup
        interval_hours: Hours between cleanup runs
    """
    import time
    import threading
    
    def cleanup_worker():
        while True:
            try:
                cleaned = SessionManager.cleanup_inactive_sessions(timeout_hours)
                if cleaned > 0:
                    logger.info(f"Background cleanup removed {cleaned} sessions")
                time.sleep(interval_hours * 3600)  # Convert hours to seconds
            except Exception as e:
                logger.error(f"Error in background session cleanup: {e}")
                time.sleep(300)  # Wait 5 minutes before retry
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    logger.info(f"Started background session cleanup (every {interval_hours}h, timeout {timeout_hours}h)")