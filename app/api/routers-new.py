"""
Enhanced API Routes with Selective Vulnerability Fixing
Supports user-selected vulnerabilities and proper authentication
"""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Body
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict
import tempfile
import os
import logging
import time
import json
import uuid
from datetime import datetime

from app.models import FixResponse, FixRequest
from agents.vulnerability_agent import VulnerabilityAgent
from agents.tools.parsers import VulnerabilityParser

logger = logging.getLogger(__name__)
router = APIRouter()

# Store user sessions temporarily (in production, use Redis or database)
user_sessions = {}

@router.post("/fix-vulnerabilities-selective")
async def fix_vulnerabilities_selective(
    background_tasks: BackgroundTasks,
    report_file: UploadFile = File(...),
    bitbucket_username: str = Form(...),
    bitbucket_token: str = Form(...),
    repo_url: str = Form(...),
    selected_vulnerabilities: str = Form(...),  # JSON string of selected vulns
    branch_name: Optional[str] = Form(None),
    validation: str = Form("test"),  # compile, test, or none
    async_processing: bool = Form(True)
):
    """
    Fix only selected vulnerabilities with proper credentials
    """
    request_id = str(uuid.uuid4())
    logger.info(f"Request {request_id}: Selective fix for {repo_url}")
    
    try:
        # Parse selected vulnerabilities
        selected_vulns = json.loads(selected_vulnerabilities)
        logger.info(f"Request {request_id}: {len(selected_vulns)} vulnerabilities selected")
        
        # Save uploaded file
        report_path = await save_uploaded_file(report_file, request_id)
        
        # Store credentials temporarily for this request
        user_sessions[request_id] = {
            "bitbucket_username": bitbucket_username,
            "bitbucket_token": bitbucket_token,
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Configure validation level
        validate_builds = validation != "none"
        run_tests = validation == "test"
        
        if async_processing:
            # Create job for async processing
            job_id = await create_job(request_id)
            
            # Add to background tasks
            background_tasks.add_task(
                process_selective_vulnerabilities,
                job_id,
                request_id,
                report_path,
                repo_url,
                selected_vulns,
                branch_name,
                validate_builds,
                run_tests
            )
            
            return {
                "status": "accepted",
                "job_id": job_id,
                "message": f"Processing {len(selected_vulns)} selected vulnerabilities",
                "check_status_url": f"/api/job-status/{job_id}"
            }
        else:
            # Synchronous processing
            result = await process_selective_vulnerabilities_sync(
                request_id,
                report_path,
                repo_url,
                selected_vulns,
                branch_name,
                validate_builds,
                run_tests
            )
            
            # Cleanup
            cleanup_session(request_id, report_path)
            
            return result
            
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid selected vulnerabilities format")
    except Exception as e:
        logger.error(f"Request {request_id}: Error: {e}")
        cleanup_session(request_id)
        raise HTTPException(status_code=500, detail=str(e))

async def process_selective_vulnerabilities(
    job_id: str,
    request_id: str,
    report_path: str,
    repo_url: str,
    selected_vulns: List[Dict],
    branch_name: Optional[str],
    validate_builds: bool,
    run_tests: bool
):
    """
    Async processing of selected vulnerabilities
    """
    try:
        # Get credentials from session
        session = user_sessions.get(request_id)
        if not session:
            raise Exception("Session expired or not found")
        
        # Create custom agent with user credentials
        agent = create_authenticated_agent(
            session["bitbucket_username"],
            session["bitbucket_token"]
        )
        
        # Process only selected vulnerabilities
        result = await agent.process_selected_vulnerabilities(
            vulnerabilities=selected_vulns,
            repo_url=repo_url,
            branch_name=branch_name,
            validate_builds=validate_builds,
            run_tests=run_tests
        )
        
        # Store result
        await update_job_result(job_id, result)
        
    except Exception as e:
        logger.error(f"Job {job_id}: Failed: {e}")
        await update_job_result(job_id, {
            "success": False,
            "error": str(e)
        })
    finally:
        # Cleanup
        cleanup_session(request_id, report_path)

async def process_selective_vulnerabilities_sync(
    request_id: str,
    report_path: str,
    repo_url: str,
    selected_vulns: List[Dict],
    branch_name: Optional[str],
    validate_builds: bool,
    run_tests: bool
) -> Dict:
    """
    Synchronous processing of selected vulnerabilities
    """
    session = user_sessions.get(request_id)
    if not session:
        raise Exception("Session not found")
    
    agent = create_authenticated_agent(
        session["bitbucket_username"],
        session["bitbucket_token"]
    )
    
    return await agent.process_selected_vulnerabilities(
        vulnerabilities=selected_vulns,
        repo_url=repo_url,
        branch_name=branch_name,
        validate_builds=validate_builds,
        run_tests=run_tests
    )

def create_authenticated_agent(username: str, token: str):
    """
    Create agent with user-specific credentials
    """
    from agents.vulnerability_agent import VulnerabilityAgent
    from agents.tools.bitbucket_helper import BitbucketHelper
    
    # Create new agent instance
    agent = VulnerabilityAgent()
    
    # Override Bitbucket helper with user credentials
    agent.bitbucket_helper = BitbucketHelper()
    agent.bitbucket_helper.username = username
    agent.bitbucket_helper.token = token
    
    # Create auth header
    import base64
    auth_string = f"{username}:{token}"
    agent.bitbucket_helper.auth_header = base64.b64encode(auth_string.encode()).decode()
    
    return agent

@router.post("/analyze-report-detailed")
async def analyze_report_detailed(
    report_file: UploadFile = File(..., description="Vulnerability report file")
):
    """
    Detailed analysis with dependency type detection
    """
    request_id = str(uuid.uuid4())
    report_path = None
    
    try:
        report_path = await save_uploaded_file(report_file, request_id)
        
        parser = VulnerabilityParser()
        vulnerabilities = await parser.parse_with_enhancements(report_path)
        
        # Analyze dependency types (this would need repo context for accuracy)
        for vuln in vulnerabilities:
            # Simple heuristic for demo
            vuln['type'] = classify_dependency_type(vuln)
        
        # Group by severity
        summary = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").lower()
            if severity in summary:
                summary[severity].append(vuln)
        
        return {
            "status": "success",
            "request_id": request_id,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "summary": {
                "critical": len(summary["critical"]),
                "high": len(summary["high"]),
                "medium": len(summary["medium"]),
                "low": len(summary["low"]),
                "fixable": len([v for v in vulnerabilities if v.get("fixed_version")]),
                "direct_dependencies": len([v for v in vulnerabilities if v.get("type") == "direct"]),
                "transitive_dependencies": len([v for v in vulnerabilities if v.get("type") == "transitive"])
            },
            "detected_scanner": detect_scanner_type(vulnerabilities),
            "auto_fixable": len([v for v in vulnerabilities if v.get("fixed_version") and v.get("type") == "direct"])
        }
        
    except Exception as e:
        logger.error(f"Request {request_id}: Error analyzing report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if report_path and os.path.exists(report_path):
            os.unlink(report_path)

@router.post("/validate-credentials")
async def validate_bitbucket_credentials(
    username: str = Form(...),
    token: str = Form(...)
):
    """
    Validate Bitbucket credentials before processing
    """
    try:
        import aiohttp
        import base64
        
        auth_string = f"{username}:{token}"
        auth_header = base64.b64encode(auth_string.encode()).decode()
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.bitbucket.org/2.0/user",
                headers={"Authorization": f"Basic {auth_header}"}
            ) as response:
                if response.status == 200:
                    user_data = await response.json()
                    return {
                        "valid": True,
                        "username": user_data.get("username"),
                        "display_name": user_data.get("display_name")
                    }
                elif response.status == 401:
                    return {
                        "valid": False,
                        "error": "Invalid credentials"
                    }
                else:
                    return {
                        "valid": False,
                        "error": f"Validation failed: {response.status}"
                    }
    
    except Exception as e:
        logger.error(f"Error validating credentials: {e}")
        return {
            "valid": False,
            "error": str(e)
        }

@router.get("/recommended-fixes/{repo_url}")
async def get_recommended_fixes(
    repo_url: str,
    vulnerabilities: List[Dict] = Body(...)
):
    """
    Get AI recommendations for which vulnerabilities to fix
    """
    try:
        recommendations = []
        
        for vuln in vulnerabilities:
            score = calculate_fix_priority(vuln)
            
            recommendation = {
                "vulnerability": vuln,
                "priority_score": score,
                "recommended": score >= 70,
                "reason": get_recommendation_reason(vuln, score),
                "risk_assessment": assess_fix_risk(vuln)
            }
            
            recommendations.append(recommendation)
        
        # Sort by priority score
        recommendations.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return {
            "recommendations": recommendations,
            "summary": {
                "total": len(vulnerabilities),
                "recommended": len([r for r in recommendations if r["recommended"]]),
                "high_priority": len([r for r in recommendations if r["priority_score"] >= 80]),
                "low_risk_fixes": len([r for r in recommendations if r["risk_assessment"] == "low"])
            }
        }
    
    except Exception as e:
        logger.error(f"Error generating recommendations: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Helper functions

async def save_uploaded_file(file: UploadFile, request_id: str) -> str:
    """Save uploaded file with request isolation"""
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=f"_{request_id}{suffix}",
        prefix="vulnfix_"
    ) as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        return tmp_file.name

def classify_dependency_type(vulnerability: Dict) -> str:
    """
    Classify if dependency is direct or transitive
    (Simplified - in reality would need POM analysis)
    """
    component = vulnerability.get("component", "").lower()
    
    # Common direct dependencies
    direct_indicators = ["spring-boot-starter", "junit", "lombok", "slf4j-api"]
    
    # Common transitive dependencies
    transitive_indicators = ["netty", "jackson-databind", "commons-", "asm"]
    
    for indicator in direct_indicators:
        if indicator in component:
            return "direct"
    
    for indicator in transitive_indicators:
        if indicator in component:
            return "transitive"
    
    # Default based on presence of group ID
    if ":" in vulnerability.get("component", ""):
        return "direct"
    
    return "transitive"

def detect_scanner_type(vulnerabilities: List[Dict]) -> str:
    """Detect scanner type from vulnerability data"""
    if vulnerabilities:
        source = vulnerabilities[0].get("source", "")
        if "BlackDuck" in source:
            return "BlackDuck"
        elif "Trivy" in source:
            return "Trivy"
        elif "Xray" in source or "JFrog" in source:
            return "JFrog Xray"
        elif "Snyk" in source:
            return "Snyk"
    
    return "Unknown"

def calculate_fix_priority(vulnerability: Dict) -> int:
    """
    Calculate priority score (0-100) for fixing a vulnerability
    """
    score = 0
    
    # Severity weight (40 points)
    severity_scores = {
        "CRITICAL": 40,
        "HIGH": 30,
        "MEDIUM": 20,
        "LOW": 10,
        "INFO": 5
    }
    score += severity_scores.get(vulnerability.get("severity", "").upper(), 0)
    
    # Has fix available (30 points)
    if vulnerability.get("fixed_version"):
        score += 30
    
    # Direct dependency (20 points)
    if vulnerability.get("type") == "direct":
        score += 20
    
    # Has CVE (10 points)
    if vulnerability.get("cve_id"):
        score += 10
    
    return score

def get_recommendation_reason(vulnerability: Dict, score: int) -> str:
    """Get human-readable recommendation reason"""
    reasons = []
    
    if vulnerability.get("severity") in ["CRITICAL", "HIGH"]:
        reasons.append(f"{vulnerability.get('severity')} severity")
    
    if vulnerability.get("type") == "direct":
        reasons.append("direct dependency")
    
    if vulnerability.get("fixed_version"):
        reasons.append("fix available")
    
    if not reasons:
        reasons.append("low priority")
    
    return f"Recommended: {', '.join(reasons)} (score: {score}/100)"

def assess_fix_risk(vulnerability: Dict) -> str:
    """Assess risk of applying fix"""
    # Simple heuristic
    if vulnerability.get("type") == "direct":
        current = vulnerability.get("current_version", "")
        fixed = vulnerability.get("fixed_version", "")
        
        # Check for major version change
        if current and fixed:
            current_major = current.split(".")[0]
            fixed_major = fixed.split(".")[0]
            
            if current_major != fixed_major:
                return "high"  # Major version change
        
        return "low"  # Minor/patch version change
    
    return "medium"  # Transitive dependencies are medium risk

def cleanup_session(request_id: str, report_path: str = None):
    """Clean up session data and files"""
    if request_id in user_sessions:
        del user_sessions[request_id]
    
    if report_path and os.path.exists(report_path):
        try:
            os.unlink(report_path)
        except:
            pass

# Job management functions (simplified)
job_storage = {}

async def create_job(request_id: str) -> str:
    job_id = str(uuid.uuid4())
    job_storage[job_id] = {
        "status": "pending",
        "request_id": request_id,
        "created_at": datetime.utcnow().isoformat()
    }
    return job_id

async def update_job_result(job_id: str, result: Dict):
    if job_id in job_storage:
        job_storage[job_id]["status"] = "completed"
        job_storage[job_id]["result"] = result

@router.get("/job-status/{job_id}")
async def get_job_status(job_id: str):
    if job_id not in job_storage:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return job_storage[job_id]
