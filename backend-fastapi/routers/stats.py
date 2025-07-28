# routers/stats.py
# Statistics endpoints

import datetime
import time
import logging
from typing import Annotated
from fastapi import APIRouter, Depends

from auth.models import User
from auth.dependencies import get_current_active_user
from config import settings
from middleware.session_middleware import get_session_id

logger = logging.getLogger(__name__)

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

@router.get("/api/stats", tags=["statistics"])
def get_system_stats(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session_id: str = Depends(get_session_id)
):
    """Get system statistics"""
    from certificates.storage import CertificateStorage
    
    storage_summary = CertificateStorage.get_summary(session_id)
    
    return {
        "success": True,
        "stats": {
            "uptime_seconds": get_uptime(),
            "certificates": storage_summary,
            "system": {
                "version": settings.APP_VERSION,
                "debug": settings.DEBUG,
                "max_file_size": settings.MAX_FILE_SIZE,
                "allowed_extensions": list(settings.ALLOWED_EXTENSIONS)
            }
        },
        "timestamp": datetime.datetime.now().isoformat()
    }