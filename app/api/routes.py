"""
API Routes for VulnFixer
"""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Optional
import tempfile
import os
import logging

from app.models import FixResponse, FixRequest
from agents.vulnerability_agent import VulnerabilityAgent

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize the AI agent
agent = VulnerabilityAgent()

@router.post("/fix-vulnerabilities", response_model=FixResponse)
async def fix_vulnerabilities(
    background_tasks: BackgroundTasks,
    report_file: UploadFile = File(..., description="Vulnerability report file"),
    repo_url: str = Form(..., description="Repository URL (GitHub or Bitbucket)"),
    repo_token: Optional[str] = Form(None, description="Repository token (optional if set in env)"),
    create_pr: bool = Form(True, description="Whether to create a pull request"),
    branch_name: Optional[str] = Form(None, description="Custom branch name")
):
    """
    Fix vulnerabilities in a repository based on the uploaded report
    """
    try:
        # Validate file type
        if not report_file.content_type.startswith(('application/json', 'text/', 'application/xml')):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: {report_file.content_type}"
            )
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            content = await report_file.read()
            tmp_file.write(content)
            report_path = tmp_file.name
        
        logger.info(f"Processing vulnerability report for repo: {repo_url}")
        
        # Process with AI agent
        result = await agent.process_vulnerability_fix(
            report_path=report_path,
            repo_url=repo_url,
            repo_token=repo_token,
            create_pr=create_pr,
            branch_name=branch_name
        )
        
        # Clean up temporary file
        background_tasks.add_task(os.unlink, report_path)
        
        return FixResponse(
            status="success",
            message=result.get("message", "Vulnerabilities processed successfully"),
            fixes_applied=result.get("fixes_applied", 0),
            pr_url=result.get("pr_url"),
            branch_name=result.get("branch_name"),
            vulnerabilities_found=result.get("vulnerabilities_found", 0)
        )
        
    except Exception as e:
        logger.error(f"Error processing vulnerability fix: {str(e)}")
        # Clean up on error
        if 'report_path' in locals():
            background_tasks.add_task(os.unlink, report_path)
        
        raise HTTPException(
            status_code=500,
            detail=f"Error processing vulnerability fix: {str(e)}"
        )

@router.post("/analyze-report")
async def analyze_report(
    report_file: UploadFile = File(..., description="Vulnerability report file")
):
    """
    Analyze vulnerability report without making fixes
    """
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            content = await report_file.read()
            tmp_file.write(content)
            report_path = tmp_file.name
        
        # Parse and analyze the report
        vulnerabilities = await agent.analyze_report(report_path)
        
        # Clean up
        os.unlink(report_path)
        
        return {
            "status": "success",
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities[:10],  # Return first 10 for preview
            "summary": {
                "critical": len([v for v in vulnerabilities if v.get("severity") == "CRITICAL"]),
                "high": len([v for v in vulnerabilities if v.get("severity") == "HIGH"]),
                "medium": len([v for v in vulnerabilities if v.get("severity") == "MEDIUM"]),
                "low": len([v for v in vulnerabilities if v.get("severity") == "LOW"])
            }
        }
        
    except Exception as e:
        logger.error(f"Error analyzing report: {str(e)}")
        if 'report_path' in locals():
            os.unlink(report_path)
        
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing report: {str(e)}"
        )

@router.get("/supported-formats")
async def get_supported_formats():
    """
    Get list of supported vulnerability report formats
    """
    return {
        "formats": [
            {
                "name": "BlackDuck",
                "description": "BlackDuck security scan reports",
                "mime_types": ["application/json"],
                "extensions": [".json"]
            },
            {
                "name": "OWASP Dependency Check",
                "description": "OWASP dependency vulnerability reports",
                "mime_types": ["application/json", "application/xml"],
                "extensions": [".json", ".xml"]
            },
            {
                "name": "Snyk",
                "description": "Snyk vulnerability reports",
                "mime_types": ["application/json"],
                "extensions": [".json"]
            },
            {
                "name": "Generic JSON",
                "description": "Generic vulnerability report in JSON format",
                "mime_types": ["application/json"],
                "extensions": [".json"]
            }
        ],
        "ai_engine": "Local Ollama - No API keys required",
        "privacy": "100% local processing"
    }

@router.get("/agent-status")
async def get_agent_status():
    """
    Get current agent status and capabilities
    """
    # Check Ollama availability
    ollama_status = await agent.ollama_client.check_model_availability()
    
    return {
        "status": "active" if ollama_status.get("ollama_running") else "ollama_not_running",
        "ai_engine": "Local Ollama",
        "model": agent.get_model_info(),
        "ollama_status": ollama_status,
        "capabilities": [
            "Vulnerability report parsing",
            "Local AI-powered code fixing",
            "Bitbucket integration",
            "Pull request creation",
            "Offline processing"
        ],
        "supported_languages": [
            "Java (Maven)",
            "Python", 
            "JavaScript/Node.js",
            "C#/.NET",
            "Go",
            "PHP"
        ],
        "privacy": "100% local processing - code never leaves your machine"
    }
