# config.py
# Configuration settings for the application

import os

class Settings:
    """Application settings"""
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "splfhkkivbulcykgqogycpeumvhdcjxprrvvnqqwiofgnpfknxaruyreszdmlkft")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # JWT Session Settings
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    SESSION_EXPIRE_HOURS: int = int(os.getenv("SESSION_EXPIRE_HOURS", "1"))

    # Application
    APP_NAME: str = "Certificate Analysis API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "OFF").upper() == "ON"
    
    # API
    API_PREFIX: str = "/api"

    # Cookie Security Settings
    # COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "true" if not DEBUG else "false").lower() == "true"
    COOKIE_SECURE: bool = True  # Always True for security
    COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "strict")
    COOKIE_HTTPONLY: bool = True  # Always True for security
    
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