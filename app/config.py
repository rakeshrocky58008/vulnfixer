"""
Configuration management for VulnFixer with Universal Parser Support
"""

from pydantic_settings import BaseSettings
from typing import Optional, List
import os

class Settings(BaseSettings):
    """Application settings - UPDATED for Universal Parser"""
    
    # Ollama Configuration (Local AI - No API keys needed!)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "codellama:7b"
    OLLAMA_TIMEOUT: int = 120
    USE_OLLAMA: bool = True
    
    # Universal Parser Settings (NEW!)
    ENABLE_UNIVERSAL_PARSING: bool = True
    AUTO_DETECT_SCANNER: bool = True
    FUZZY_FIELD_MATCHING: bool = True
    CSV_DELIMITER_AUTO_DETECT: bool = True
    
    # Supported Scanners (NEW!)
    SUPPORTED_SCANNERS: List[str] = [
        "blackduck", "trivy", "xray", "jfrog", 
        "clair", "snyk", "anchore", "generic"
    ]
    SCANNER_DETECTION_CONFIDENCE_THRESHOLD: float = 0.5
    
    # Vulnerability Enhancement Settings
    ENABLE_FIXED_VERSION_RESOLUTION: bool = True
    ENHANCEMENT_TIMEOUT: int = 30
    ENHANCEMENT_CACHE_SIZE: int = 1000
    ENABLE_GITHUB_ADVISORY: bool = True
    ENABLE_OSV_API: bool = True
    ENABLE_PACKAGE_APIS: bool = True
    
    # Alternative AI APIs (Optional)
    COPILOT_API_KEY: Optional[str] = None
    COPILOT_ENDPOINT: str = "https://api.github.com/copilot"
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
    LLM_MODEL: str = "ollama-codellama"
    LLM_TEMPERATURE: float = 0.1
    MAX_TOKENS: int = 4000
    
    # Git Settings
    DEFAULT_BRANCH: str = "main"
    PR_BRANCH_PREFIX: str = "vulnfixer"
    SUPPORTED_REPOS: List[str] = ["bitbucket", "github"]
    
    # Enhanced Format Support (UPDATED)
    SUPPORTED_FORMATS: List[str] = [
        "application/json",
        "text/plain", 
        "application/xml",
        "text/csv",
        "text/html",
        "application/csv"
    ]
    
    # Enhanced Parsing Settings (NEW!)
    HTML_PARSER_ENABLED: bool = True
    XML_NAMESPACE_IGNORE: bool = True
    JSON_NESTED_PARSING: bool = True
    
    # Performance Settings (NEW!)
    PARSER_CACHE_SIZE: int = 1000
    PARALLEL_PROCESSING: bool = True
    MAX_CONCURRENT_ENHANCEMENTS: int = 5
    
    # Scanner-Specific Settings (NEW!)
    BLACKDUCK_SEVERITY_MAPPING: dict = {
        "CRITICAL": "CRITICAL", "HIGH": "HIGH", 
        "MEDIUM": "MEDIUM", "LOW": "LOW"
    }
    
    TRIVY_SEVERITY_MAPPING: dict = {
        "CRITICAL": "CRITICAL", "HIGH": "HIGH", 
        "MEDIUM": "MEDIUM", "LOW": "LOW", "UNKNOWN": "UNKNOWN"
    }
    
    # Ollama Model Options
    OLLAMA_MODELS: dict = {
        "codellama:7b": "Best for code generation (4GB RAM)",
        "codellama:13b": "Better quality, needs 8GB RAM", 
        "deepseek-coder:6.7b": "Fast and efficient for coding",
        "phind-codellama:34b": "Highest quality, needs 16GB+ RAM",
        "llama2:7b": "General purpose model",
        "mistral:7b": "Fast general purpose model"
    }
    
    # Enhancement API Endpoints
    GITHUB_API_BASE: str = "https://api.github.com"
    OSV_API_BASE: str = "https://api.osv.dev"
    NPM_REGISTRY_BASE: str = "https://registry.npmjs.org"
    PYPI_API_BASE: str = "https://pypi.org/pypi"
    MAVEN_SEARCH_BASE: str = "https://search.maven.org"
    
    # Rate Limiting for External APIs
    GITHUB_API_RATE_LIMIT: int = 5000
    OSV_API_RATE_LIMIT: int = 1000
    PACKAGE_API_RATE_LIMIT: int = 100
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Global settings instance
settings = Settings()

# Enhanced validation with universal parser support
def validate_settings():
    """Validate required settings with universal parser support"""
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
    
    # Validate universal parser settings
    if settings.ENABLE_UNIVERSAL_PARSING:
        if not settings.AUTO_DETECT_SCANNER:
            warnings.append("AUTO_DETECT_SCANNER disabled - scanner type must be specified manually")
        
        if settings.ENHANCEMENT_TIMEOUT < 5:
            warnings.append("ENHANCEMENT_TIMEOUT is very low, may cause timeouts")
        
        # Validate supported scanners list
        valid_scanners = ["blackduck", "trivy", "xray", "jfrog", "clair", "snyk", "anchore", "generic"]
        invalid_scanners = [s for s in settings.SUPPORTED_SCANNERS if s not in valid_scanners]
        if invalid_scanners:
            warnings.append(f"Invalid scanners in SUPPORTED_SCANNERS: {invalid_scanners}")
        
        # Check internet connectivity for external APIs
        if settings.ENABLE_FIXED_VERSION_RESOLUTION:
            if settings.ENABLE_GITHUB_ADVISORY or settings.ENABLE_OSV_API:
                try:
                    import socket
                    socket.create_connection(("8.8.8.8", 53), timeout=3)
                except OSError:
                    warnings.append("No internet connection detected - external API enhancement will be limited")
    
    if errors:
        raise ValueError(f"Configuration errors: {', '.join(errors)}")
    
    if warnings and settings.ENVIRONMENT != "development":
        import logging
        logger = logging.getLogger(__name__)
        for warning in warnings:
            logger.warning(warning)

# Auto-configure with universal parser support
def auto_configure():
    """Auto-configure based on available resources and scanner support"""
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
    
    # Check network connectivity for enhancement features
    network_available = False
    try:
        import socket
        socket.create_connection(("api.github.com", 443), timeout=5)
        network_available = True
    except OSError:
        pass
    
    # Check if universal parser is properly configured
    parser_config_valid = (
        settings.ENABLE_UNIVERSAL_PARSING and 
        settings.AUTO_DETECT_SCANNER and
        len(settings.SUPPORTED_SCANNERS) > 0
    )
    
    config_recommendations = {
        "recommended_model": recommended_model,
        "available_ram_gb": available_ram_gb,
        "current_model": settings.OLLAMA_MODEL,
        "network_available": network_available,
        "enhancement_enabled": settings.ENABLE_FIXED_VERSION_RESOLUTION,
        "universal_parser_enabled": settings.ENABLE_UNIVERSAL_PARSING,
        "parser_config_valid": parser_config_valid,
        "supported_scanners": settings.SUPPORTED_SCANNERS,
        "recommendations": []
    }
    
    # Add specific recommendations
    if not network_available and settings.ENABLE_FIXED_VERSION_RESOLUTION:
        config_recommendations["recommendations"].append(
            "Network unavailable - only local enhancement patterns will work"
        )
    
    if not parser_config_valid:
        config_recommendations["recommendations"].append(
            "Universal parser not properly configured - check SUPPORTED_SCANNERS setting"
        )
    
    if settings.OLLAMA_MODEL == "codellama:7b" and available_ram_gb >= 8:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Consider upgrading to {recommended_model} for better performance (you have {available_ram_gb:.1f}GB RAM)")
    
    return config_recommendations

# Environment-specific overrides with universal parser support
def setup_environment():
    """Setup environment-specific configurations"""
    if settings.ENVIRONMENT == "production":
        # Production settings
        settings.LOG_LEVEL = "WARNING"
        settings.ENHANCEMENT_TIMEOUT = 60
        settings.MAX_CONCURRENT_ENHANCEMENTS = 3  # Conservative for production
        
    elif settings.ENVIRONMENT == "development":
        # Development settings
        settings.LOG_LEVEL = "DEBUG"
        settings.ENHANCEMENT_TIMEOUT = 30
        settings.MAX_CONCURRENT_ENHANCEMENTS = 5
        
    elif settings.ENVIRONMENT == "testing":
        # Testing settings
        settings.ENABLE_FIXED_VERSION_RESOLUTION = False  # Disable external calls in tests
        settings.AUTO_DETECT_SCANNER = True  # Keep auto-detection for testing
        settings.LOG_LEVEL = "ERROR"

# Scanner configuration validation
def validate_scanner_support():
    """Validate scanner configurations"""
    required_scanners = ["blackduck", "trivy", "generic"]  # Minimum required
    
    missing_scanners = [s for s in required_scanners if s not in settings.SUPPORTED_SCANNERS]
    if missing_scanners:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Missing required scanner support: {missing_scanners}")

# Get scanner-specific configuration
def get_scanner_config(scanner_name: str) -> dict:
    """Get configuration for a specific scanner"""
    scanner_configs = {
        "blackduck": {
            "severity_mapping": settings.BLACKDUCK_SEVERITY_MAPPING,
            "default_type": "dependency",
            "enhancement_priority": "high"
        },
        "trivy": {
            "severity_mapping": settings.TRIVY_SEVERITY_MAPPING,
            "default_type": "dependency",
            "enhancement_priority": "high"
        },
        "generic": {
            "severity_mapping": {"UNKNOWN": "UNKNOWN"},
            "default_type": "dependency", 
            "enhancement_priority": "medium"
        }
    }
    
    return scanner_configs.get(scanner_name, scanner_configs["generic"])

# Migration helper for existing configurations
def migrate_legacy_config():
    """Migrate legacy configuration to universal parser format"""
    migrations = []
    
    # Check for legacy BlackDuck-specific settings
    legacy_settings = [
        "BLACKDUCK_ONLY_MODE",
        "ENABLE_BLACKDUCK_PARSING", 
        "BLACKDUCK_CSV_SUPPORT"
    ]
    
    for legacy_setting in legacy_settings:
        if os.getenv(legacy_setting):
            migrations.append(f"Legacy setting {legacy_setting} detected - now handled by universal parser")
    
    if migrations:
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Configuration migrations:")
        for migration in migrations:
            logger.info(f"  • {migration}")

# Validate on import (unless skipped)
if os.getenv("SKIP_VALIDATION") != "true":
    validate_settings()
    setup_environment()
    validate_scanner_support()
    migrate_legacy_config()
