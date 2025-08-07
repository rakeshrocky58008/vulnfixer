"""
Configuration management for VulnFixer with Ollama Support
"""

from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # Ollama Configuration (Local AI - No API keys needed!)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "codellama:7b"  # Good for code generation
    OLLAMA_TIMEOUT: int = 120  # seconds
    USE_OLLAMA: bool = True    # Use local Ollama by default
    
    # Alternative AI APIs (Optional - use if Ollama not available)
    COPILOT_API_KEY: Optional[str] = None
    AZURE_OPENAI_KEY: Optional[str] = None
    AZURE_OPENAI_ENDPOINT: Optional[str] = None
    AZURE_OPENAI_MODEL: str = "gpt-4"
    
    # Bitbucket Configuration
    BITBUCKET_USERNAME: Optional[str] = None
    BITBUCKET_TOKEN: Optional[str] = None
    
    # Application Settings
    LOG_LEVEL: str = "INFO"
    ENVIRONMENT: str = "development"
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    
    # AI Settings
    LLM_MODEL: str = "ollama-codellama"  # Updated default
    LLM_TEMPERATURE: float = 0.1
    MAX_TOKENS: int = 4000
    
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
    
    # Ollama Model Options
    OLLAMA_MODELS: dict = {
        "codellama:7b": "Best for code generation (4GB RAM)",
        "codellama:13b": "Better quality, needs 8GB RAM", 
        "deepseek-coder:6.7b": "Fast and efficient for coding",
        "phind-codellama:34b": "Highest quality, needs 16GB+ RAM",
        "llama2:7b": "General purpose model",
        "mistral:7b": "Fast general purpose model"
    }
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Global settings instance
settings = Settings()

# Validation - Relaxed for Ollama (no API keys required)
def validate_settings():
    """Validate required settings"""
    errors = []
    warnings = []
    
    # Only require Bitbucket credentials if not using local-only mode
    if not settings.BITBUCKET_USERNAME:
        warnings.append("BITBUCKET_USERNAME not set - repository operations will be limited")
    
    if not settings.BITBUCKET_TOKEN:
        warnings.append("BITBUCKET_TOKEN not set - private repository access unavailable")
    
    # Check if using Ollama (preferred) or need API keys
    if settings.USE_OLLAMA:
        # No API keys needed for local Ollama!
        pass
    else:
        if not any([settings.COPILOT_API_KEY, settings.AZURE_OPENAI_KEY]):
            errors.append("Either COPILOT_API_KEY or AZURE_OPENAI_KEY is required when USE_OLLAMA=False")
    
    if errors:
        raise ValueError(f"Configuration errors: {', '.join(errors)}")
    
    if warnings and settings.ENVIRONMENT != "development":
        import logging
        logger = logging.getLogger(__name__)
        for warning in warnings:
            logger.warning(warning)

# Auto-detect best configuration
def auto_configure():
    """Auto-configure based on available resources"""
    import psutil
    
    # Check available RAM and suggest best Ollama model
    available_ram_gb = psutil.virtual_memory().available / (1024**3)
    
    if available_ram_gb >= 16:
        recommended_model = "phind-codellama:34b"
    elif available_ram_gb >= 8:
        recommended_model = "codellama:13b"
    elif available_ram_gb >= 4:
        recommended_model = "codellama:7b"
    else:
        recommended_model = "deepseek-coder:6.7b"  # Smallest efficient model
    
    if settings.OLLAMA_MODEL == "codellama:7b" and available_ram_gb >= 8:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Consider upgrading to {recommended_model} for better performance (you have {available_ram_gb:.1f}GB RAM)")
    
    return {
        "recommended_model": recommended_model,
        "available_ram_gb": available_ram_gb,
        "current_model": settings.OLLAMA_MODEL
    }

# Validate on import
if os.getenv("SKIP_VALIDATION") != "true":
    validate_settings()
