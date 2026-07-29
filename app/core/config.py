# app/core/config.py
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "sqlite:////dominusvobiscum/hospiapp_et.db"
    
    # JWT - Make sure this is also set in Render's environment variables
    JWT_SECRET_KEY: str = "new-theclapp-jwt-secret-2024-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Encryption
    ENCRYPTION_KEY: str = "your-32-byte-base64-key-here"
    
    # CORS - ADD YOUR RENDER URL HERE
    CORS_ORIGINS: List[str] = [
        "https://theclappet-backend.onrender.com",  # ← YOUR RENDER BACKEND
        "http://localhost:8081",
        "exp://localhost:8081", 
        "https://*.ngrok.io",
        "*"  # For development only. Remove in production.
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()