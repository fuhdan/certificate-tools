# routers/__init__.py
# Router module initialization

from .auth import router as auth_router
from .certificates import router as certificates_router
from .health import router as health_router
from .pki import router as pki_router
from .stats import router as stats_router

__all__ = [
    'auth_router',
    'certificates_router', 
    'health_router',
    'pki_router',
    'stats_router'
]