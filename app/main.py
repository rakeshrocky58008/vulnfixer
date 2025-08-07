"""
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
                <p>Open Source Vulnerability Fix Automation with Local AI</p>
            </div>
            <div class="links">
                <a href="/api/docs">API Documentation</a>
                <a href="https://github.com/yourusername/vulnfixer">GitHub Repository</a>
            </div>
            <div style="margin-top: 40px;">
                <h3>🦙 Powered by Local Ollama AI:</h3>
                <ul>
                    <li>Upload your vulnerability report</li>
                    <li>Provide your Bitbucket repository URL</li>
                    <li>Local AI generates secure fixes (no API keys needed!)</li>
                    <li>Automated pull request created</li>
                </ul>
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
