# config.py
# Configuration settings for the application

import os
from typing import Optional

class Settings:
    """Application settings"""
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # Application
    APP_NAME: str = "Certificate Analysis API"
    APP_VERSION: str = "1.0.0"
    # DEBUG: bool = os.getenv("DEBUG", "OFF").upper() == "ON"
    DEBUG: bool = True  # Set to False in production
    
    # API
    API_PREFIX: str = "/api"
    
    # Session Management
    DEFAULT_SESSION_ID: str = "00000000-0000-4000-8000-000000000000"
    
    # File upload limits
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS: set = {
        "pem", "crt", "cer", "der", "p12", "pfx", "jks", "csr", "key"
    }
    
    # Logging
    LOG_LEVEL: str = "DEBUG" if DEBUG else "INFO"
    
    # CORS
    CORS_ORIGINS: list = ["*"]  # In production, specify actual origins
    
    # Default user (for testing only)
    DEFAULT_USERNAME: str = os.getenv("DEFAULT_USERNAME", "admin")
    DEFAULT_PASSWORD: str = os.getenv("DEFAULT_PASSWORD", "admin123")

# Global settings instance
settings = Settings()