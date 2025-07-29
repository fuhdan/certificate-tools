# main.py - Modular FastAPI Certificate Analysis Backend
# Clean main application file with separated router modules

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from routers import (
    auth_router,
    certificates_router,
    downloads_router,    # Add the new downloads router
    health_router,
    pki_router,
    stats_router
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ============================================================================
# FASTAPI APPLICATION SETUP
# ============================================================================

app = FastAPI(
    title=settings.APP_NAME,
    description="FastAPI backend for certificate analysis and management",
    version=settings.APP_VERSION,
    debug=settings.DEBUG
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# INCLUDE ROUTERS
# ============================================================================

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(certificates_router)
app.include_router(downloads_router)    # Add the downloads router
app.include_router(pki_router)
app.include_router(stats_router)

# ============================================================================
# ROOT ENDPOINT
# ============================================================================

@app.get("/", tags=["root"])
def read_root():
    """Root endpoint"""
    return {
        "message": settings.APP_NAME,
        "status": "online",
        "version": settings.APP_VERSION,
        "endpoints": {
            "health": "/health",
            "login": "/token",
            "certificates": "/api/certificates",
            "downloads": "/download",        # Add downloads endpoint info
            "docs": "/docs"
        }
    }

# ============================================================================
# APPLICATION STARTUP/SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    logger.info(f"Default login: {settings.DEFAULT_USERNAME} / {settings.DEFAULT_PASSWORD}")
    logger.info("SecureZipCreator service initialized and ready")

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    logger.info(f"Shutting down {settings.APP_NAME}")
    logger.info("SecureZipCreator service cleanup completed")

# ============================================================================
# DEVELOPMENT SERVER
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )