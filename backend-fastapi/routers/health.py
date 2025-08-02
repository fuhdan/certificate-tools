# routers/health.py
# Health check endpoints

import datetime
import time
from fastapi import APIRouter
from pydantic import BaseModel

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    uptime: int

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

@router.get("/health", response_model=HealthResponse, tags=["health"])
def health_check():
    """Basic health check endpoint"""
    return HealthResponse(
        status="online",
        timestamp=datetime.datetime.now().isoformat(),
        uptime=get_uptime()
    )