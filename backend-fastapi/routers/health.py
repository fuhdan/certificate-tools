# routers/health.py
# Health check endpoints

import datetime
import time
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    uptime: int
    redis: Dict[str, Any]  # Add Redis status
    sessions: Dict[str, Any]  # Add session statistics

router = APIRouter()

# Keep a local start time as fallback
_local_start_time = time.time()

def get_uptime():
    """Get uptime from when the application started"""
    try:
        # Import from shared_state module (should be in parent directory)
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.dirname(__file__)))
        from shared_state import start_time
        return int(time.time() - start_time)
    except (ImportError, AttributeError):
        # Fallback to local start time
        return int(time.time() - _local_start_time)

def get_redis_health():
    """Check Redis connectivity and get session stats"""
    try:
        # Import session manager
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.dirname(__file__)))
        from session_manager import get_session_manager, SessionManager
        
        # Test Redis connectivity
        session_manager = get_session_manager()
        session_manager.redis_client.ping()
        redis_status = "healthy"
        
        # Get session statistics
        session_stats = SessionManager.get_session_stats()
        
        return {
            "redis": {
                "status": redis_status,
                "connection": "active"
            },
            "sessions": session_stats
        }
        
    except ImportError as e:
        # Redis not available or session_manager not found
        return {
            "redis": {
                "status": "not_configured",
                "error": f"Import error: {str(e)}"
            },
            "sessions": {"error": "Redis session manager not available"}
        }
    except Exception as e:
        # Redis connection failed
        return {
            "redis": {
                "status": "unhealthy",
                "error": str(e)
            },
            "sessions": {"error": "Cannot retrieve session stats"}
        }

@router.get("/health", response_model=HealthResponse, tags=["health"])
def health_check():
    """Enhanced health check endpoint with Redis status"""
    health_data = get_redis_health()
    
    # Determine overall status
    overall_status = "online"
    if health_data["redis"]["status"] == "unhealthy":
        overall_status = "degraded"  # Still online but with issues
    
    return HealthResponse(
        status=overall_status,
        timestamp=datetime.datetime.now().isoformat(),
        uptime=get_uptime(),
        redis=health_data["redis"],
        sessions=health_data["sessions"]
    )

# Optional: Add a more detailed health endpoint
@router.get("/health/detailed", tags=["health"])
def detailed_health_check():
    """Detailed health check with more information"""
    health_data = get_redis_health()
    
    return {
        "status": "online" if health_data["redis"]["status"] != "unhealthy" else "degraded",
        "timestamp": datetime.datetime.now().isoformat(),
        "uptime": get_uptime(),
        "components": {
            "redis": health_data["redis"],
            "sessions": health_data["sessions"]
        },
        "system": {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "start_time": _local_start_time
        }
    }