# routers/__init__.py
# Router module initialization

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