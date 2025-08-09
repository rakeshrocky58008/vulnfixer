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


@app.post("/api/fix-vulnerabilities")
async def fix_vulnerabilities(
    report_file: UploadFile = File(...),
    repo_url: str = Form(...),
    repo_token: str = Form(...),
    create_pr: bool = Form(True)
):
    try:
        # Your existing file saving logic
        report_path = await save_uploaded_file(report_file)
        
        # NEW: Use enhanced parser
        parser = VulnerabilityParser()
        vulnerabilities = await parser.parse_with_enhancements(report_path)  # ENHANCED
        
        # Log enhancement results
        fixes_available = len([v for v in vulnerabilities if v.get('fixed_version')])
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities, {fixes_available} with fixes")
        
        # Your existing Ollama AI processing
        fixes_applied = 0
        for vuln in vulnerabilities:
            if vuln.get('fixed_version'):
                # Enhanced prompt with fix information
                fix_prompt = f"""
                Fix this vulnerability:
                - Component: {vuln.get('component')}
                - Current Version: {vuln.get('current_version')}
                - Vulnerability: {vuln.get('name')}
                - Recommended Fix: Upgrade to version {vuln.get('fixed_version')}
                - Description: {vuln.get('description')}
                
                Generate the necessary code changes to upgrade this dependency.
                """
            else:
                # Your existing prompt for vulnerabilities without known fixes
                fix_prompt = f"""
                Fix this vulnerability (no known version fix available):
                - Component: {vuln.get('component')}
                - Vulnerability: {vuln.get('name')}
                - Description: {vuln.get('description')}
                
                Suggest alternative mitigation strategies.
                """
            
            # Your existing Ollama AI call
            fix_result = await ollama_client.generate_fix(fix_prompt)
            if fix_result:
                fixes_applied += 1
        
        # Your existing Bitbucket integration
        pr_url = await create_bitbucket_pr(repo_url, repo_token, fixes_applied)
        
        return {
            "status": "success",
            "message": f"Successfully processed {fixes_applied}/{len(vulnerabilities)} vulnerabilities",
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities_with_fixes": fixes_available,  # NEW metric
            "fixes_applied": fixes_applied,
            "pr_url": pr_url,
            "processing_time": time.time() - start_time,
            "model_used": "codellama:7b"
        }
        
    except Exception as e:
        logger.error(f"Error processing vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))




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
