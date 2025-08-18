# backend-fastapi/middleware/__init__.py
# Middleware module initialization - Updated for JWT session decorator

from .certificates import router as certificates_router
from .downloads import router as downloads_router
from .health import router as health_router
from .stats import router as stats_router

__all__ = [
    'certificates_router',
    'downloads_router', 
    'health_router',
    'stats_router'
]