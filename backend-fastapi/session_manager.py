"""
Session Manager for Multi-User Certificate Management

Now uses Redis for distributed session storage to enable Docker Swarm 
deployments with multiple instances. Maintains the same API for compatibility.
"""

import redis
import json
import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging
import time
from config import settings  # Import centralized settings

logger = logging.getLogger(__name__)


class SessionManagerImplementation:
    """The actual Redis-based session manager implementation"""
    
    def __init__(self):
        """Initialize Redis connection using centralized config"""
        # Create Redis connection with connection pooling
        self.redis_pool = redis.ConnectionPool(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            db=settings.REDIS_DB,
            decode_responses=True,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT
        )
        self.redis_client = redis.Redis(connection_pool=self.redis_pool)
        
        # Test connection
        try:
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
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
    
    def get_or_create_session(self, session_id: str) -> Dict[str, Any]:
        """
        Get session storage or create if not exists
        
        Args:
            session_id: UUID string for the session
            
        Returns:
            Dict containing session data
            
        Raises:
            ValueError: If session_id is not a valid UUID format
        """
        if not self._is_valid_uuid(session_id):
            raise ValueError(f"Invalid session ID format: {session_id}")
        
        try:
            # Try to get existing session
            session_key = f"session:{session_id}"
            session_data_json = self.redis_client.get(session_key)
            
            current_time = datetime.now()
            
            if session_data_json:
                # Deserialize existing session
                session_data = json.loads(session_data_json)
                
                # Convert datetime strings back to datetime objects
                session_data["last_activity"] = datetime.fromisoformat(session_data["last_activity"])
                session_data["created_at"] = datetime.fromisoformat(session_data["created_at"])
                
                # Update activity
                session_data["last_activity"] = current_time
                session_data["request_count"] += 1
                
                logger.debug(f"Accessed existing session: {session_id}")
            else:
                # Create new session with initial structure (matching original)
                session_data = {
                    "certificates": [],          # List of uploaded certificates
                    "crypto_objects": {},        # Cryptographic objects by cert_id
                    "pki_bundle": {},            # Generated PKI bundle
                    "last_activity": current_time,
                    "created_at": current_time,
                    "request_count": 0           # Track usage
                }
                logger.info(f"Created new session: {session_id}")
            
            # Save session back to Redis with expiration
            self._save_session(session_id, session_data)
            
            return session_data
            
        except redis.RedisError as e:
            logger.error(f"Redis error in get_or_create_session: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in session: {session_id}, error: {e}")
            # Delete corrupted session and create new one
            self.redis_client.delete(f"session:{session_id}")
            return self.get_or_create_session(session_id)
    
    def _save_session(self, session_id: str, session_data: Dict[str, Any]):
        """Save session data to Redis with expiration"""
        try:
            # Prepare data for JSON serialization
            serializable_data = session_data.copy()
            serializable_data["last_activity"] = session_data["last_activity"].isoformat()
            serializable_data["created_at"] = session_data["created_at"].isoformat()
            
            session_key = f"session:{session_id}"
            session_json = json.dumps(serializable_data, default=str)
            
            # Set with configured expiration
            expire_seconds = settings.SESSION_EXPIRE_HOURS * 3600
            self.redis_client.setex(session_key, expire_seconds, session_json)
            
        except (redis.RedisError, json.JSONEncodeError) as e:  # keep as-is except for main fix
            logger.error(f"Error saving session {session_id}: {e}")
            raise
    
    def cleanup_inactive_sessions(self, timeout_hours: int = None) -> int:
        """
        Remove sessions inactive for specified hours
        
        Args:
            timeout_hours: Hours of inactivity before cleanup (uses config default if None)
            
        Returns:
            Number of sessions cleaned up
        """
        if timeout_hours is None:
            timeout_hours = settings.SESSION_EXPIRE_HOURS
            
        if timeout_hours <= 0:
            raise ValueError("Timeout hours must be positive")
        
        try:
            cutoff_time = datetime.now() - timedelta(hours=timeout_hours)
            cleaned_count = 0
            
            # Get all session keys
            session_keys = self.redis_client.keys("session:*")
            
            for session_key in session_keys:
                try:
                    session_data_json = self.redis_client.get(session_key)
                    if session_data_json:
                        session_data = json.loads(session_data_json)
                        last_activity = datetime.fromisoformat(session_data["last_activity"])
                        
                        if last_activity < cutoff_time:
                            session_id = session_key.replace("session:", "")
                            logger.info(
                                f"Cleaning up inactive session: {session_id}, "
                                f"last activity: {last_activity}, "
                                f"requests: {session_data.get('request_count', 0)}"
                            )
                            self.redis_client.delete(session_key)
                            cleaned_count += 1
                            
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(f"Corrupted session {session_key}, deleting: {e}")
                    self.redis_client.delete(session_key)
                    cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} inactive sessions")
            
            return cleaned_count
            
        except redis.RedisError as e:
            logger.error(f"Error during session cleanup: {e}")
            return 0
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get statistics about active sessions
        
        Returns:
            Dict with session statistics including count, memory usage, etc.
        """
        try:
            session_keys = self.redis_client.keys("session:*")
            session_count = len(session_keys)
            
            if session_count == 0:
                return {
                    "active_sessions": 0,
                    "total_memory_mb": 0.0,
                    "oldest_session_age_hours": 0,
                    "newest_session_age_hours": 0,
                    "total_requests": 0,
                    "average_requests_per_session": 0.0
                }
            
            # Sample sessions for statistics (limit to avoid performance issues)
            sample_keys = session_keys[:min(100, len(session_keys))]
            creation_times = []
            total_requests = 0
            
            for session_key in sample_keys:
                try:
                    session_data_json = self.redis_client.get(session_key)
                    if session_data_json:
                        session_data = json.loads(session_data_json)
                        creation_times.append(datetime.fromisoformat(session_data["created_at"]))
                        total_requests += session_data.get("request_count", 0)
                except (json.JSONDecodeError, KeyError):
                    continue
            
            if not creation_times:
                return {"active_sessions": session_count, "error": "No valid sessions found"}
            
            current_time = datetime.now()
            oldest_age_hours = (current_time - min(creation_times)).total_seconds() / 3600
            newest_age_hours = (current_time - max(creation_times)).total_seconds() / 3600
            
            # Get memory usage from Redis
            try:
                memory_info = self.redis_client.info('memory')
                total_memory_mb = memory_info.get('used_memory', 0) / (1024 * 1024)
            except redis.RedisError:
                total_memory_mb = 0.0
            
            avg_requests = total_requests / session_count if session_count > 0 else 0
            
            return {
                "active_sessions": session_count,
                "total_memory_mb": round(total_memory_mb, 2),
                "oldest_session_age_hours": round(oldest_age_hours, 2),
                "newest_session_age_hours": round(newest_age_hours, 2),
                "total_requests": total_requests,
                "average_requests_per_session": round(avg_requests, 1)
            }
            
        except redis.RedisError as e:
            logger.error(f"Error getting session stats: {e}")
            return {"error": f"Redis error: {e}"}
    
    def delete_session(self, session_id: str) -> bool:
        """
        Manually delete a specific session
        
        Args:
            session_id: UUID string for the session to delete
            
        Returns:
            True if session was deleted, False if not found
        """
        if not self._is_valid_uuid(session_id):
            return False
        
        try:
            session_key = f"session:{session_id}"
            
            # Get session data for logging before deletion
            session_data_json = self.redis_client.get(session_key)
            if session_data_json:
                session_data = json.loads(session_data_json)
                logger.info(
                    f"Manually deleting session: {session_id}, "
                    f"requests: {session_data.get('request_count', 0)}"
                )
            
            result = self.redis_client.delete(session_key)
            return bool(result)
            
        except (redis.RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error deleting session {session_id}: {e}")
            return False
    
    def session_exists(self, session_id: str) -> bool:
        """
        Check if a session exists
        
        Args:
            session_id: UUID string for the session
            
        Returns:
            True if session exists, False otherwise
        """
        if not self._is_valid_uuid(session_id):
            return False
        
        try:
            session_key = f"session:{session_id}"
            return bool(self.redis_client.exists(session_key))
        except redis.RedisError as e:
            logger.error(f"Error checking session existence {session_id}: {e}")
            return False
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific session without updating activity
        
        Args:
            session_id: UUID string for the session
            
        Returns:
            Dict with session info or None if not found
        """
        if not self._is_valid_uuid(session_id):
            return None
        
        try:
            session_key = f"session:{session_id}"
            session_data_json = self.redis_client.get(session_key)
            
            if not session_data_json:
                return None
            
            session_data = json.loads(session_data_json)
            
            return {
                "session_id": session_id,
                "created_at": datetime.fromisoformat(session_data["created_at"]),
                "last_activity": datetime.fromisoformat(session_data["last_activity"]),
                "request_count": session_data.get("request_count", 0),
                "certificates_count": len(session_data.get("certificates", [])),
                "crypto_objects_count": len(session_data.get("crypto_objects", {})),
                "has_pki_bundle": bool(session_data.get("pki_bundle"))
            }
            
        except (redis.RedisError, json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error getting session info {session_id}: {e}")
            return None


# Create singleton instance for direct access
_session_manager_instance = None

def get_session_manager() -> SessionManagerImplementation:
    """Get or create the SessionManager singleton"""
    global _session_manager_instance
    if _session_manager_instance is None:
        _session_manager_instance = SessionManagerImplementation()
    return _session_manager_instance


# Create static interface to maintain compatibility with existing code
class SessionManager:
    """Static wrapper to maintain existing static method API"""
    
    @staticmethod
    def get_or_create_session(session_id: str) -> Dict[str, Any]:
        return get_session_manager().get_or_create_session(session_id)
    
    @staticmethod
    def cleanup_inactive_sessions(timeout_hours: int = None) -> int:
        return get_session_manager().cleanup_inactive_sessions(timeout_hours)
    
    @staticmethod
    def get_session_stats() -> Dict[str, Any]:
        return get_session_manager().get_session_stats()
    
    @staticmethod
    def delete_session(session_id: str) -> bool:
        return get_session_manager().delete_session(session_id)
    
    @staticmethod
    def session_exists(session_id: str) -> bool:
        return get_session_manager().session_exists(session_id)
    
    @staticmethod
    def get_session_info(session_id: str) -> Optional[Dict[str, Any]]:
        return get_session_manager().get_session_info(session_id)
    
    @staticmethod
    def _is_valid_uuid(session_id: str) -> bool:
        return SessionManagerImplementation._is_valid_uuid(session_id)


# Utility function for easy session cleanup scheduling
def schedule_cleanup_task(timeout_hours: int = None, interval_hours: int = 6):
    """
    Schedule automatic cleanup task - now works with Redis backend
    Note: In production, use proper task scheduler like Celery or APScheduler
    
    Args:
        timeout_hours: Hours of inactivity before cleanup (uses config default if None)
        interval_hours: Hours between cleanup runs
    """
    if timeout_hours is None:
        timeout_hours = settings.SESSION_EXPIRE_HOURS
    
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
