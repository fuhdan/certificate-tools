# routers/stats.py
# Statistics endpoints

import datetime
import time
import logging
from fastapi import APIRouter, Request

from config import settings
from middleware.session_decorator import require_session

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

@router.get("/stats", tags=["statistics"])
def get_system_stats(request: Request):
    session_id = request.state.session_id
    """Get system statistics"""
    from certificates.storage.session_pki_storage import session_pki_storage
    
    # Get PKI components summary instead of using non-existent method
    components = session_pki_storage.get_session_components(session_id)
    
    # Create storage summary from components
    storage_summary = {
        "total_components": len(components),
        "components_by_type": {},
        "session_id": session_id
    }
    
    # Count components by type
    for comp in components:
        comp_type = comp["type"]
        storage_summary["components_by_type"][comp_type] = storage_summary["components_by_type"].get(comp_type, 0) + 1
    
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