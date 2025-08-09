"""
Updated API Routes for VulnFixer with Universal Parser Support
"""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Optional
import tempfile
import os
import logging
import time

from app.models import FixResponse, FixRequest
from agents.vulnerability_agent import VulnerabilityAgent
from agents.tools.parsers import VulnerabilityParser  # Now universal!

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize the AI agent
agent = VulnerabilityAgent()

async def save_uploaded_file(file: UploadFile) -> str:
    """Save uploaded file to temporary location"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        return tmp_file.name

@router.post("/fix-vulnerabilities")
async def fix_vulnerabilities(
    report_file: UploadFile = File(...),
    repo_url: str = Form(...),
    repo_token: Optional[str] = Form(None),
    create_pr: bool = Form(True),
    branch_name: Optional[str] = Form(None)
):
    """
    Main endpoint to fix vulnerabilities using universal parser
    """
    start_time = time.time()
    report_path = None
    
    try:
        logger.info(f"Starting vulnerability fix process for {repo_url}")
        
        # Save uploaded file
        report_path = await save_uploaded_file(report_file)
        logger.info(f"Saved report file to {report_path}")
        
        # Use the main agent with universal parsing
        result = await agent.process_vulnerability_fix(
            report_path=report_path,
            repo_url=repo_url,
            repo_token=repo_token,
            create_pr=create_pr,
            branch_name=branch_name
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Error processing vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        # Clean up uploaded file
        if report_path and os.path.exists(report_path):
            os.unlink(report_path)

@router.post("/analyze-report")
async def analyze_report(
    report_file: UploadFile = File(..., description="Vulnerability report file")
):
    """
    Analyze vulnerability report with universal parser and enhancement
    """
    report_path = None
    try:
        # Save uploaded file
        report_path = await save_uploaded_file(report_file)
        
        # Use universal parser directly
        parser = VulnerabilityParser()
        vulnerabilities = await parser.parse_with_enhancements(report_path)
        
        # Calculate statistics
        fixes_available = len([v for v in vulnerabilities if v.get('fixed_version')])
        auto_fixable = len([v for v in vulnerabilities if v.get('type') == 'dependency' and v.get('fixed_version')])
        
        # Detect scanner type from results
        detected_scanner = "Unknown"
        if vulnerabilities:
            source = vulnerabilities[0].get('source', '')
            detected_scanner = source.replace(' CSV', '').replace(' JSON', '')
        
        return {
            "status": "success",
            "detected_scanner": detected_scanner,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities_with_fixes": fixes_available,
            "auto_fixable": auto_fixable,
            "vulnerabilities": vulnerabilities[:20],  # Return first 20 for preview
            "summary": {
                "critical": len([v for v in vulnerabilities if v.get("severity") == "CRITICAL"]),
                "high": len([v for v in vulnerabilities if v.get("severity") == "HIGH"]),
                "medium": len([v for v in vulnerabilities if v.get("severity") == "MEDIUM"]),
                "low": len([v for v in vulnerabilities if v.get("severity") == "LOW"]),
                "fixable": fixes_available
            },
            "enhancement_info": {
                "enhanced_vulnerabilities": fixes_available,
                "original_fixes": len([v for v in vulnerabilities if not v.get('fixed_version_source')]),
                "auto_resolved_fixes": len([v for v in vulnerabilities if v.get('fixed_version_source') == 'auto-resolved'])
            }
        }
        
    except Exception as e:
        logger.error(f"Error analyzing report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing report: {str(e)}")
    
    finally:
        if report_path and os.path.exists(report_path):
            os.unlink(report_path)

@router.get("/supported-formats")
async def get_supported_formats():
    """
    Get list of supported vulnerability report formats (UPDATED)
    """
    parser = VulnerabilityParser()
    supported_scanners = parser.get_supported_scanners()
    
    return {
        "formats": [
            {
                "name": "BlackDuck",
                "description": "Synopsys BlackDuck security scan reports",
                "mime_types": ["text/csv", "application/json"],
                "extensions": [".csv", ".json"],
                "features": ["Auto-detection", "Fix version resolution", "Component mapping"],
                "status": "✅ Fully Supported"
            },
            {
                "name": "Trivy", 
                "description": "Aqua Security Trivy vulnerability scanner",
                "mime_types": ["text/csv", "application/json"],
                "extensions": [".csv", ".json"],
                "features": ["Auto-detection", "Container & package scanning", "Fix versions"],
                "status": "✅ Fully Supported"
            },
            {
                "name": "JFrog Xray",
                "description": "JFrog Xray security and compliance scanner",
                "mime_types": ["text/csv", "application/json"],
                "extensions": [".csv", ".json"],
                "features": ["Auto-detection", "Policy violations", "Impact paths"],
                "status": "✅ Fully Supported"
            },
            {
                "name": "JFrog Artifactory",
                "description": "JFrog Artifactory vulnerability reports",
                "mime_types": ["text/csv", "application/json"],
                "extensions": [".csv", ".json"],
                "features": ["Auto-detection", "Dependency analysis", "Fix recommendations"],
                "status": "✅ Fully Supported"
            },
            {
                "name": "Clair",
                "description": "CoreOS Clair container vulnerability scanner",
                "mime_types": ["text/csv", "application/json"],
                "extensions": [".csv", ".json"],
                "features": ["Auto-detection", "Container layer analysis", "Namespace support"],
                "status": "✅ Fully Supported"
            },
            {
                "name": "Snyk",
                "description": "Snyk vulnerability scanner",
                "mime_types": ["text/csv", "application/json"],
                "extensions": [".csv", ".json"],
                "features": ["Auto-detection", "Package manager support", "Fix recommendations"],
                "status": "✅ Fully Supported"
            },
            {
                "name": "Anchore",
                "description": "Anchore container security scanner",
                "mime_types": ["text/csv", "application/json"],
                "extensions": [".csv", ".json"],
                "features": ["Auto-detection", "Container analysis", "Policy evaluation"],
                "status": "✅ Fully Supported"
            },
            {
                "name": "OWASP Dependency Check",
                "description": "OWASP dependency vulnerability reports",
                "mime_types": ["application/json", "application/xml"],
                "extensions": [".json", ".xml"],
                "features": ["CVE mapping", "Fix resolution"],
                "status": "✅ Supported"
            },
            {
                "name": "Generic",
                "description": "Generic vulnerability report format",
                "mime_types": ["text/csv", "application/json"],
                "extensions": [".csv", ".json"],
                "features": ["Fallback support", "Flexible field mapping"],
                "status": "✅ Fallback Support"
            }
        ],
        "auto_detection": {
            "enabled": True,
            "supported_scanners": supported_scanners,
            "detection_method": "Header pattern matching + content analysis"
        },
        "ai_engine": "Local Ollama - No API keys required",
        "privacy": "100% local processing",
        "enhancement_features": [
            "Automatic scanner type detection",
            "Intelligent field mapping", 
            "Fixed version extraction from descriptions",
            "GitHub Advisory Database lookup",
            "OSV API integration",
            "Package registry queries",
            "Severity normalization"
        ]
    }

@router.get("/agent-status")
async def get_agent_status():
    """
    Get current agent status and capabilities (UPDATED)
    """
    # Check Ollama availability
    ollama_status = await agent.ollama_client.check_model_availability()
    
    # Get parser info
    parser = VulnerabilityParser()
    supported_scanners = parser.get_supported_scanners()
    
    return {
        "status": "active" if ollama_status.get("ollama_running") else "ollama_not_running",
        "ai_engine": "Local Ollama",
        "model": agent.get_model_info(),
        "ollama_status": ollama_status,
        "parser_info": {
            "type": "Universal Parser",
            "supported_scanners": supported_scanners,
            "auto_detection": True,
            "format_support": ["CSV", "JSON", "XML", "HTML"]
        },
        "capabilities": [
            "Universal vulnerability report parsing",
            "Automatic scanner type detection", 
            "Intelligent field mapping",
            "Fixed version auto-resolution",
            "Local AI-powered code fixing",
            "Bitbucket integration",
            "Pull request creation",
            "Offline processing"
        ],
        "supported_languages": [
            "Java (Maven, Gradle)",
            "Python (pip, pipenv)", 
            "JavaScript/Node.js (npm, yarn)",
            "C#/.NET (NuGet)",
            "Go (go.mod)",
            "PHP (Composer)",
            "Ruby (Bundler)",
            "Rust (Cargo)"
        ],
        "privacy": "100% local processing - code never leaves your machine",
        "enhancement_services": {
            "github_advisory": "Available",
            "osv_api": "Available", 
            "pattern_matching": "Active",
            "cve_lookup": "Active",
            "scanner_detection": "Active"
        }
    }

@router.post("/test-enhancement")
async def test_enhancement(
    report_file: UploadFile = File(..., description="Test vulnerability report enhancement")
):
    """
    Test endpoint to show enhancement capabilities with universal parser
    """
    report_path = None
    try:
        report_path = await save_uploaded_file(report_file)
        
        # Parse without enhancement first
        parser = VulnerabilityParser()
        original_vulns = await parser.parse_report(report_path)
        
        # Parse with enhancement
        enhanced_vulns = await parser.parse_with_enhancements(report_path)
        
        # Compare results
        original_fixes = len([v for v in original_vulns if v.get('fixed_version')])
        enhanced_fixes = len([v for v in enhanced_vulns if v.get('fixed_version')])
        new_fixes = enhanced_fixes - original_fixes
        
        # Detect scanner type
        detected_scanner = "Unknown"
        if enhanced_vulns:
            source = enhanced_vulns[0].get('source', '')
            detected_scanner = source.replace(' CSV', '').replace(' JSON', '')
        
        return {
            "status": "success",
            "detected_scanner": detected_scanner,
            "original": {
                "total_vulnerabilities": len(original_vulns),
                "vulnerabilities_with_fixes": original_fixes
            },
            "enhanced": {
                "total_vulnerabilities": len(enhanced_vulns),
                "vulnerabilities_with_fixes": enhanced_fixes,
                "new_fixes_found": new_fixes
            },
            "improvement": {
                "additional_fixes": new_fixes,
                "improvement_percentage": (new_fixes / max(len(enhanced_vulns), 1)) * 100
            },
            "sample_enhanced": [
                {
                    "name": v.get('name'),
                    "component": v.get('component'),
                    "current_version": v.get('current_version'),
                    "fixed_version": v.get('fixed_version'),
                    "source": v.get('fixed_version_source', 'original'),
                    "severity": v.get('severity')
                }
                for v in enhanced_vulns[:5] if v.get('fixed_version')
            ]
        }
        
    except Exception as e:
        logger.error(f"Error testing enhancement: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if report_path and os.path.exists(report_path):
            os.unlink(report_path)

@router.post("/add-scanner")
async def add_scanner_support(
    scanner_id: str = Form(...),
    scanner_name: str = Form(...),
    indicators: str = Form(..., description="Comma-separated list of unique headers"),
    field_mappings: str = Form(..., description="JSON string of field mappings")
):
    """
    Dynamically add support for a new scanner
    """
    try:
        import json
        
        # Parse inputs
        indicators_list = [i.strip() for i in indicators.split(',')]
        mappings_dict = json.loads(field_mappings)
        
        # Add to parser
        parser = VulnerabilityParser()
        parser.add_scanner_support(scanner_id, indicators_list, mappings_dict)
        
        return {
            "status": "success",
            "message": f"Added support for {scanner_name} scanner",
            "scanner_id": scanner_id,
            "indicators": indicators_list,
            "supported_scanners": parser.get_supported_scanners()
        }
        
    except Exception as e:
        logger.error(f"Error adding scanner support: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scanner-detection-test")
async def test_scanner_detection(
    sample_text: str = Form(..., description="Sample CSV headers or content")
):
    """
    Test scanner auto-detection with sample content
    """
    try:
        parser = VulnerabilityParser()
        
        # Test detection
        detected_scanner = parser._detect_scanner_type(sample_text)
        detected_delimiter = parser._detect_delimiter(sample_text)
        
        # Get scanner config
        scanner_config = parser.scanner_configs.get(detected_scanner, {})
        
        return {
            "detected_scanner": detected_scanner,
            "detected_delimiter": detected_delimiter,
            "confidence": "high" if detected_scanner != "generic" else "low",
            "scanner_config": {
                "indicators": scanner_config.get('indicators', []),
                "field_mappings": list(scanner_config.get('fields', {}).keys())
            }
        }
        
    except Exception as e:
        logger.error(f"Error in scanner detection test: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
