#!/usr/bin/env python3
"""
VulnFixer Project Setup Script
Run this script to create the complete project structure
"""

import os
import sys
from pathlib import Path

def create_directory_structure():
    """Create the project directory structure"""
    directories = [
        "vulnfixer",
        "vulnfixer/app",
        "vulnfixer/app/api",
        "vulnfixer/agents",
        "vulnfixer/agents/tools",
        "vulnfixer/web",
        "vulnfixer/tests",
        "vulnfixer/docs",
        "vulnfixer/examples"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def create_file(filepath, content):
    """Create a file with the given content"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✓ Created file: {filepath}")

def main():
    print("🛡️ VulnFixer Project Setup")
    print("=" * 40)
    
    # Create directory structure
    print("\n📁 Creating directory structure...")
    create_directory_structure()
    
    # Create __init__.py files
    init_files = [
        "vulnfixer/app/__init__.py",
        "vulnfixer/app/api/__init__.py",
        "vulnfixer/agents/__init__.py",
        "vulnfixer/agents/tools/__init__.py",
        "vulnfixer/tests/__init__.py"
    ]
    
    for init_file in init_files:
        create_file(init_file, "")
    
    print("\n📝 Creating main application files...")
    
    # Main FastAPI app
    main_app_content = '''"""
VulnFixer - Main FastAPI Application
Open Source Vulnerability Fix Automation Tool
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
from pathlib import Path

from app.config import settings
from app.api.routes import router as api_router

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="VulnFixer",
    description="Open Source Vulnerability Fix Automation Tool",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api")

# Serve static files (web frontend)
web_dir = Path(__file__).parent.parent / "web"
if web_dir.exists():
    app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main web interface"""
    web_file = web_dir / "index.html"
    if web_file.exists():
        return HTMLResponse(content=web_file.read_text(), status_code=200)
    
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnFixer</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 600px; margin: 0 auto; }
            .logo { text-align: center; margin-bottom: 40px; }
            .links a { margin: 10px; padding: 10px 20px; background: #007cba; color: white; text-decoration: none; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>🛡️ VulnFixer</h1>
                <p>Open Source Vulnerability Fix Automation</p>
            </div>
            <div class="links">
                <a href="/api/docs">API Documentation</a>
                <a href="https://github.com/yourusername/vulnfixer">GitHub Repository</a>
            </div>
            <div style="margin-top: 40px;">
                <h3>Quick Start:</h3>
                <ol>
                    <li>Upload your vulnerability report</li>
                    <li>Provide your Bitbucket repository URL</li>
                    <li>Get automated fixes via Pull Request</li>
                </ol>
            </div>
        </div>
    </body>
    </html>
    """)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "service": "vulnfixer"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True if os.getenv("ENVIRONMENT") == "development" else False
    )
'''
    create_file("vulnfixer/app/main.py", main_app_content)
    
    # Configuration file
    config_content = '''"""
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
'''
    create_file("vulnfixer/app/config.py", config_content)
    
    # Requirements.txt
    requirements_content = '''# Core FastAPI and web framework
fastapi==0.104.1
uvicorn==0.24.0
python-multipart==0.0.6

# HTTP client for API calls
aiohttp==3.8.5

# Configuration management
pydantic==2.5.0
pydantic-settings==2.1.0

# Git operations
GitPython==3.1.40

# File parsing
python-json-logger==2.0.7

# Environment variables
python-dotenv==1.0.0

# Optional: For enhanced JSON parsing
ujson==5.8.0

# Optional: For XML parsing (OWASP reports)
lxml==4.9.3

# Testing (optional)
pytest==7.4.3
pytest-asyncio==0.21.1

# Development dependencies (optional)
black==23.9.1
flake8==6.1.0
'''
    create_file("vulnfixer/requirements.txt", requirements_content)
    
    # .env.example
    env_example_content = '''# Microsoft Copilot API Configuration
COPILOT_API_KEY=your_copilot_api_key_here

# Bitbucket Configuration
BITBUCKET_USERNAME=your_bitbucket_username
BITBUCKET_TOKEN=your_bitbucket_app_password

# Application Settings
LOG_LEVEL=INFO
ENVIRONMENT=development
MAX_FILE_SIZE=10485760

# AI Settings
LLM_MODEL=microsoft-copilot
LLM_TEMPERATURE=0.1
MAX_TOKENS=4000
COPILOT_ENDPOINT=https://api.github.com/copilot

# Repository Settings
DEFAULT_BRANCH=main
PR_BRANCH_PREFIX=vulnfixer
SUPPORTED_REPOS=bitbucket,github

# Optional: Skip configuration validation during development
# SKIP_VALIDATION=true
'''
    create_file("vulnfixer/.env.example", env_example_content)
    
    # README.md (simplified)
    readme_content = '''# 🛡️ VulnFixer

**Open Source Automated Vulnerability Fixing with Microsoft Copilot & Bitbucket**

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. **Run the application:**
   ```bash
   python -m uvicorn app.main:app --reload --port 8000
   ```

4. **Access the web interface:**
   Open http://localhost:8000

## Configuration Required

- Microsoft Copilot API Key
- Bitbucket username and app password

## Features

- Upload vulnerability reports (BlackDuck, OWASP)
- Automated fix generation with Microsoft Copilot
- Bitbucket integration with automated PRs
- Web interface and REST API

For detailed documentation, see the complete README file.
'''
    create_file("vulnfixer/README.md", readme_content)
    
    print("\n🎉 Project setup completed successfully!")
    print("\nNext steps:")
    print("1. cd vulnfixer")
    print("2. pip install -r requirements.txt")
    print("3. cp .env.example .env")
    print("4. Edit .env with your API keys")
    print("5. python -m uvicorn app.main:app --reload")
    
    print("\n📖 Note: This script created the basic structure.")
    print("You'll need to copy the remaining files from the artifacts:")
    print("- app/api/routes.py")
    print("- app/models.py") 
    print("- agents/vulnerability_agent.py")
    print("- agents/tools/copilot_client.py")
    print("- agents/tools/bitbucket_helper.py")
    print("- agents/tools/parsers.py")
    print("- web/index.html")

if __name__ == "__main__":
    main()
