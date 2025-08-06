"""
Configuration management for VulnFixer
"""

from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # API Keys
    COPILOT_API_KEY: Optional[str] = None
    BITBUCKET_TOKEN: Optional[str] = None
    BITBUCKET_USERNAME: Optional[str] = None
    
    # Application Settings
    LOG_LEVEL: str = "INFO"
    ENVIRONMENT: str = "development"
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    
    # Agent Settings
    LLM_MODEL: str = "microsoft-copilot"
    LLM_TEMPERATURE: float = 0.1
    MAX_TOKENS: int = 4000
    COPILOT_ENDPOINT: str = "https://api.github.com/copilot"
    
    # Git Settings
    DEFAULT_BRANCH: str = "main"
    PR_BRANCH_PREFIX: str = "vulnfixer"
    SUPPORTED_REPOS: list = ["bitbucket", "github"]
    
    # Supported Formats
    SUPPORTED_FORMATS: list = [
        "application/json",
        "text/plain",
        "application/xml"
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Global settings instance
settings = Settings()

# Validation
def validate_settings():
    """Validate required settings"""
    errors = []
    
    if not settings.COPILOT_API_KEY:
        errors.append("COPILOT_API_KEY is required")
    
    if not settings.BITBUCKET_TOKEN:
        errors.append("BITBUCKET_TOKEN is required for Bitbucket operations")
    
    if not settings.BITBUCKET_USERNAME:
        errors.append("BITBUCKET_USERNAME is required for Bitbucket operations")
    
    if errors:
        raise ValueError(f"Configuration errors: {', '.join(errors)}")

# Validate on import
if os.getenv("SKIP_VALIDATION") != "true":
    validate_settings()