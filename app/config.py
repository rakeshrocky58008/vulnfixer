"""
Configuration management for VulnFixer with Universal Parser Support
"""

from pydantic_settings import BaseSettings
from typing import Optional, List, Dict, Union
import os

class Settings(BaseSettings):
    """Application settings - Universal Parser Edition"""
    
    # ============================================================================
    # OLLAMA CONFIGURATION (Local AI - No API keys needed!)
    # ============================================================================
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "codellama:7b"
    OLLAMA_TIMEOUT: int = 120
    USE_OLLAMA: bool = True
    
    # ============================================================================
    # UNIVERSAL PARSER SETTINGS (NEW!)
    # ============================================================================
    ENABLE_UNIVERSAL_PARSING: bool = True
    AUTO_DETECT_SCANNER: bool = True
    FUZZY_FIELD_MATCHING: bool = True
    CSV_DELIMITER_AUTO_DETECT: bool = True
    
    # ============================================================================
    # SUPPORTED SCANNERS (NEW!)
    # ============================================================================
    SUPPORTED_SCANNERS: Union[str, List[str]] = "blackduck,trivy,xray,jfrog,clair,snyk,anchore,generic"
    SCANNER_DETECTION_CONFIDENCE_THRESHOLD: float = 0.5
    
    # ============================================================================
    # VULNERABILITY ENHANCEMENT SETTINGS
    # ============================================================================
    ENABLE_FIXED_VERSION_RESOLUTION: bool = True
    ENHANCEMENT_TIMEOUT: int = 30
    ENHANCEMENT_CACHE_SIZE: int = 1000
    ENABLE_GITHUB_ADVISORY: bool = True
    ENABLE_OSV_API: bool = True
    ENABLE_PACKAGE_APIS: bool = True
    
    # ============================================================================
    # ALTERNATIVE AI APIS (Optional)
    # ============================================================================
    COPILOT_API_KEY: Optional[str] = None
    COPILOT_ENDPOINT: str = "https://api.github.com/copilot"
    AZURE_OPENAI_KEY: Optional[str] = None
    AZURE_OPENAI_ENDPOINT: Optional[str] = None
    AZURE_OPENAI_MODEL: str = "gpt-4"
    
    # ============================================================================
    # BITBUCKET CONFIGURATION
    # ============================================================================
    BITBUCKET_USERNAME: Optional[str] = None
    BITBUCKET_TOKEN: Optional[str] = None
    
    # ============================================================================
    # APPLICATION SETTINGS
    # ============================================================================
    LOG_LEVEL: str = "INFO"
    ENVIRONMENT: str = "development"
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    
    # ============================================================================
    # AI SETTINGS
    # ============================================================================
    LLM_MODEL: str = "ollama-codellama"
    LLM_TEMPERATURE: float = 0.1
    MAX_TOKENS: int = 4000
    
    # ============================================================================
    # GIT SETTINGS
    # ============================================================================
    DEFAULT_BRANCH: str = "main"
    PR_BRANCH_PREFIX: str = "vulnfixer"
    SUPPORTED_REPOS: Union[str, List[str]] = "bitbucket,github"
    
    # ============================================================================
    # ENHANCED FORMAT SUPPORT
    # ============================================================================
    SUPPORTED_FORMATS: Union[str, List[str]] = "application/json,text/plain,application/xml,text/csv,text/html,application/csv"
    SUPPORTED_FILE_EXTENSIONS: Union[str, List[str]] = ".csv,.json,.xml,.html,.htm"
    SUPPORTED_MIME_TYPES: Union[str, List[str]] = "text/csv,application/json,application/xml,text/html"
    
    # ============================================================================
    # ENHANCED PARSING SETTINGS
    # ============================================================================
    HTML_PARSER_ENABLED: bool = True
    XML_NAMESPACE_IGNORE: bool = True
    JSON_NESTED_PARSING: bool = True
    STRICT_FIELD_MATCHING: bool = False
    CASE_SENSITIVE_HEADERS: bool = False
    ALLOW_PARTIAL_MATCHES: bool = True
    
    # ============================================================================
    # PERFORMANCE SETTINGS
    # ============================================================================
    PARSER_CACHE_SIZE: int = 1000
    PARALLEL_PROCESSING: bool = True
    MAX_CONCURRENT_ENHANCEMENTS: int = 5
    ENHANCEMENT_RETRY_COUNT: int = 3
    ENHANCEMENT_BATCH_SIZE: int = 10
    
    # ============================================================================
    # SECURITY SETTINGS
    # ============================================================================
    VALIDATE_FILE_CONTENT: bool = True
    MAX_VULNERABILITIES_PER_FILE: int = 10000
    SANITIZE_INPUT_DATA: bool = True
    
    # ============================================================================
    # LOGGING CONFIGURATION
    # ============================================================================
    ENABLE_PARSER_DEBUG_LOGS: bool = False
    ENABLE_ENHANCEMENT_DEBUG_LOGS: bool = False
    LOG_SCANNER_DETECTION_DETAILS: bool = True
    
    # ============================================================================
    # ADVANCED CONFIGURATION
    # ============================================================================
    SKIP_ENHANCEMENT_ON_ERROR: bool = False
    
    # Development settings
    DEV_MODE: bool = False
    MOCK_EXTERNAL_APIS: bool = False
    ENABLE_TEST_ENDPOINTS: bool = False
    BYPASS_BITBUCKET_AUTH: bool = False
    
    # Monitoring settings
    ENABLE_METRICS: bool = False
    METRICS_PORT: int = 8001
    HEALTH_CHECK_INTERVAL: int = 30
    
    # ============================================================================
    # ENHANCEMENT API ENDPOINTS
    # ============================================================================
    GITHUB_API_BASE: str = "https://api.github.com"
    OSV_API_BASE: str = "https://api.osv.dev"
    NPM_REGISTRY_BASE: str = "https://registry.npmjs.org"
    PYPI_API_BASE: str = "https://pypi.org/pypi"
    MAVEN_SEARCH_BASE: str = "https://search.maven.org"
    
    # ============================================================================
    # RATE LIMITING FOR EXTERNAL APIS
    # ============================================================================
    GITHUB_API_RATE_LIMIT: int = 5000
    OSV_API_RATE_LIMIT: int = 1000
    PACKAGE_API_RATE_LIMIT: int = 100
    
    class Config:
        env_file = ".env"
        case_sensitive = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Convert comma-separated strings to lists after initialization
        self._convert_string_lists()

    def _convert_string_lists(self):
        """Convert comma-separated strings to lists"""
        string_list_fields = [
            'SUPPORTED_SCANNERS',
            'SUPPORTED_REPOS', 
            'SUPPORTED_FORMATS',
            'SUPPORTED_FILE_EXTENSIONS',
            'SUPPORTED_MIME_TYPES'
        ]
        
        for field in string_list_fields:
            value = getattr(self, field)
            if isinstance(value, str):
                # Convert comma-separated string to list
                converted_list = [item.strip() for item in value.split(',') if item.strip()]
                setattr(self, field, converted_list)

    # ============================================================================
    # STATIC SEVERITY MAPPINGS
    # ============================================================================
    @property
    def BLACKDUCK_SEVERITY_MAPPING(self) -> Dict[str, str]:
        """BlackDuck severity mapping"""
        return {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW"
        }
    
    @property
    def TRIVY_SEVERITY_MAPPING(self) -> Dict[str, str]:
        """Trivy severity mapping"""
        return {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "UNKNOWN": "UNKNOWN"
        }

    @property
    def OLLAMA_MODELS(self) -> Dict[str, str]:
        """Available Ollama models"""
        return {
            "codellama:7b": "Best for code generation (4GB RAM)",
            "codellama:13b": "Better quality, needs 8GB RAM", 
            "deepseek-coder:6.7b": "Fast and efficient for coding",
            "phind-codellama:34b": "Highest quality, needs 16GB+ RAM",
            "llama2:7b": "General purpose model",
            "mistral:7b": "Fast general purpose model"
        }

# Global settings instance
settings = Settings()

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

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
        
        # Check minimum required scanners
        required_scanners = ["blackduck", "trivy", "generic"]
        missing_required = [s for s in required_scanners if s not in settings.SUPPORTED_SCANNERS]
        if missing_required:
            errors.append(f"Missing required scanners: {missing_required}")
    
    # Validate file size limits
    if settings.MAX_FILE_SIZE > 50 * 1024 * 1024:  # 50MB
        warnings.append("MAX_FILE_SIZE is very large, may cause memory issues")
    
    # Validate performance settings
    if settings.MAX_CONCURRENT_ENHANCEMENTS > 10:
        warnings.append("MAX_CONCURRENT_ENHANCEMENTS is high, may cause rate limiting")
    
    if errors:
        raise ValueError(f"Configuration errors: {', '.join(errors)}")
    
    if warnings and settings.ENVIRONMENT != "development":
        import logging
        logger = logging.getLogger(__name__)
        for warning in warnings:
            logger.warning(warning)

def auto_configure():
    """Auto-configure based on available resources and scanner support"""
    try:
        import psutil
        available_ram_gb = psutil.virtual_memory().available / (1024**3)
    except ImportError:
        available_ram_gb = 4  # Default assumption
    
    if available_ram_gb >= 16:
        recommended_model = "phind-codellama:34b"
    elif available_ram_gb >= 8:
        recommended_model = "codellama:13b"
    elif available_ram_gb >= 4:
        recommended_model = "codellama:7b"
    else:
        recommended_model = "deepseek-coder:6.7b"
    
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
    
    return config_recommendations

def setup_environment():
    """Setup environment-specific configurations"""
    # Simple environment setup without trying to modify immutable settings
    pass

def validate_scanner_support():
    """Validate scanner configurations"""
    required_scanners = ["blackduck", "trivy", "generic"]
    
    missing_scanners = [s for s in required_scanners if s not in settings.SUPPORTED_SCANNERS]
    if missing_scanners:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Missing required scanner support: {missing_scanners}")

def get_scanner_config(scanner_name: str) -> Dict:
    """Get configuration for a specific scanner"""
    scanner_configs = {
        "blackduck": {
            "severity_mapping": settings.BLACKDUCK_SEVERITY_MAPPING,
            "default_type": "dependency",
            "enhancement_priority": "high",
            "indicators": ["component name", "security risk", "vulnerability id"],
            "confidence_threshold": 0.8
        },
        "trivy": {
            "severity_mapping": settings.TRIVY_SEVERITY_MAPPING,
            "default_type": "dependency",
            "enhancement_priority": "high",
            "indicators": ["pkgname", "installedversion", "vulnerabilityid"],
            "confidence_threshold": 0.8
        },
        "xray": {
            "severity_mapping": {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"},
            "default_type": "dependency",
            "enhancement_priority": "high",
            "indicators": ["xray_id", "component", "violation_type"],
            "confidence_threshold": 0.7
        },
        "jfrog": {
            "severity_mapping": {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"},
            "default_type": "dependency",
            "enhancement_priority": "medium",
            "indicators": ["component_id", "impact_path", "provider"],
            "confidence_threshold": 0.7
        },
        "clair": {
            "severity_mapping": {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"},
            "default_type": "dependency",
            "enhancement_priority": "medium",
            "indicators": ["feature_name", "namespace_name", "fixed_by"],
            "confidence_threshold": 0.6
        },
        "snyk": {
            "severity_mapping": {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"},
            "default_type": "dependency",
            "enhancement_priority": "high",
            "indicators": ["snyk", "issue id", "package manager"],
            "confidence_threshold": 0.7
        },
        "anchore": {
            "severity_mapping": {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"},
            "default_type": "dependency",
            "enhancement_priority": "medium",
            "indicators": ["anchore", "vulnerability_id", "package_name"],
            "confidence_threshold": 0.6
        },
        "generic": {
            "severity_mapping": {"UNKNOWN": "UNKNOWN"},
            "default_type": "dependency", 
            "enhancement_priority": "low",
            "indicators": ["vulnerability", "component", "severity"],
            "confidence_threshold": 0.3
        }
    }
    
    return scanner_configs.get(scanner_name, scanner_configs["generic"])

def get_all_scanner_configs() -> Dict[str, Dict]:
    """Get all scanner configurations"""
    return {scanner: get_scanner_config(scanner) for scanner in settings.SUPPORTED_SCANNERS}

def migrate_legacy_config():
    """Migrate legacy configuration to universal parser format"""
    # Simple migration check
    pass

def check_compatibility():
    """Check compatibility with existing codebase"""
    compatibility_issues = []
    
    # Check if required modules are available
    try:
        import csv
        import json
        import xml.etree.ElementTree as ET
    except ImportError as e:
        compatibility_issues.append(f"Missing required module: {e}")
    
    if compatibility_issues:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning("Compatibility issues detected:")
        for issue in compatibility_issues:
            logger.warning(f"  • {issue}")

def get_effective_config() -> Dict:
    """Get the effective configuration after all overrides"""
    return {
        "ollama": {
            "base_url": settings.OLLAMA_BASE_URL,
            "model": settings.OLLAMA_MODEL,
            "timeout": settings.OLLAMA_TIMEOUT,
            "enabled": settings.USE_OLLAMA
        },
        "universal_parser": {
            "enabled": settings.ENABLE_UNIVERSAL_PARSING,
            "auto_detect": settings.AUTO_DETECT_SCANNER,
            "supported_scanners": settings.SUPPORTED_SCANNERS,
            "fuzzy_matching": settings.FUZZY_FIELD_MATCHING,
            "auto_delimiter": settings.CSV_DELIMITER_AUTO_DETECT
        },
        "enhancement": {
            "enabled": settings.ENABLE_FIXED_VERSION_RESOLUTION,
            "timeout": settings.ENHANCEMENT_TIMEOUT,
            "cache_size": settings.ENHANCEMENT_CACHE_SIZE,
            "github_advisory": settings.ENABLE_GITHUB_ADVISORY,
            "osv_api": settings.ENABLE_OSV_API,
            "package_apis": settings.ENABLE_PACKAGE_APIS
        }
    }

def get_scanner_statistics() -> Dict:
    """Get statistics about configured scanners"""
    total_scanners = len(settings.SUPPORTED_SCANNERS)
    enterprise_scanners = ["blackduck", "xray", "jfrog"]
    open_source_scanners = ["trivy", "clair", "snyk", "anchore"]
    
    enterprise_count = len([s for s in settings.SUPPORTED_SCANNERS if s in enterprise_scanners])
    open_source_count = len([s for s in settings.SUPPORTED_SCANNERS if s in open_source_scanners])
    
    return {
        "total_supported": total_scanners,
        "enterprise_scanners": enterprise_count,
        "open_source_scanners": open_source_count,
        "has_generic_fallback": "generic" in settings.SUPPORTED_SCANNERS,
        "auto_detection_enabled": settings.AUTO_DETECT_SCANNER,
        "enhancement_enabled": settings.ENABLE_FIXED_VERSION_RESOLUTION
    }

# ============================================================================
# INITIALIZATION
# ============================================================================

# Validate on import (unless skipped)
if os.getenv("SKIP_VALIDATION") != "true":
    try:
        validate_settings()
        setup_environment()
        validate_scanner_support()
        migrate_legacy_config()
        check_compatibility()
        
        # Log successful initialization
        import logging
        logger = logging.getLogger(__name__)
        logger.info("VulnFixer Universal Parser configuration loaded successfully")
        
        config_stats = get_scanner_statistics()
        logger.info(f"Universal parser configured with {config_stats['total_supported']} scanners")
        
        if settings.ENABLE_UNIVERSAL_PARSING:
            logger.info("Auto-detection enabled for all supported scanner types")
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Configuration initialization failed: {e}")
        # Don't raise in case of validation issues during import
        pass

# Export commonly used functions
__all__ = [
    'settings',
    'validate_settings', 
    'auto_configure',
    'setup_environment',
    'get_scanner_config',
    'get_all_scanner_configs',
    'get_effective_config',
    'get_scanner_statistics',
    'migrate_legacy_config',
    'check_compatibility'
]
