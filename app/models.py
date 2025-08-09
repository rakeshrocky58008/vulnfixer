"""
Pydantic models for VulnFixer API
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Dict, Any
from enum import Enum

class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityType(str, Enum):
    """Types of vulnerabilities"""
    DEPENDENCY = "dependency"
    CODE = "code"
    CONFIGURATION = "configuration"
    INFRASTRUCTURE = "infrastructure"

class Vulnerability(BaseModel):
    """Individual vulnerability model"""
    id: str = Field(..., description="Unique vulnerability identifier")
    name: str = Field(..., description="Vulnerability name")
    severity: SeverityLevel = Field(..., description="Severity level")
    type: VulnerabilityType = Field(..., description="Type of vulnerability")
    component: Optional[str] = Field(None, description="Affected component")
    current_version: Optional[str] = Field(None, description="Current version")
    fixed_version: Optional[str] = Field(None, description="Version that fixes the vulnerability")
    description: Optional[str] = Field(None, description="Vulnerability description")
    cve_id: Optional[str] = Field(None, description="CVE identifier if available")
    
class FixRequest(BaseModel):
    """Request model for vulnerability fixing"""
    repo_url: HttpUrl = Field(..., description="Repository URL (GitHub or Bitbucket)")
    repo_token: Optional[str] = Field(None, description="Repository token")
    create_pr: bool = Field(True, description="Whether to create a pull request")
    branch_name: Optional[str] = Field(None, description="Custom branch name")
    auto_merge: bool = Field(False, description="Auto-merge if tests pass")

class FixResponse(BaseModel):
    """Response model for vulnerability fixing"""
    status: str = Field(..., description="Operation status")
    message: str = Field(..., description="Human-readable message")
    fixes_applied: int = Field(..., description="Number of fixes applied")
    vulnerabilities_found: int = Field(..., description="Total vulnerabilities found")
    pr_url: Optional[str] = Field(None, description="Pull request URL if created")
    branch_name: Optional[str] = Field(None, description="Branch name used")
    processing_time: Optional[float] = Field(None, description="Processing time in seconds")

class ReportAnalysis(BaseModel):
    """Analysis results of a vulnerability report"""
    total_vulnerabilities: int = Field(..., description="Total number of vulnerabilities")
    by_severity: Dict[str, int] = Field(..., description="Count by severity level")
    by_type: Dict[str, int] = Field(..., description="Count by vulnerability type")
    fixable_count: int = Field(..., description="Number of automatically fixable vulnerabilities")
    vulnerabilities: List[Vulnerability] = Field(..., description="List of vulnerabilities")

class AgentStatus(BaseModel):
    """AI agent status information"""
    status: str = Field(..., description="Agent status")
    model: str = Field(..., description="LLM model being used")
    capabilities: List[str] = Field(..., description="Agent capabilities")
    supported_languages: List[str] = Field(..., description="Supported programming languages")
    last_updated: Optional[str] = Field(None, description="Last update timestamp")

class ProcessingStats(BaseModel):
    """Processing statistics"""
    total_reports_processed: int = Field(0, description="Total reports processed")
    total_fixes_applied: int = Field(0, description="Total fixes applied")
    success_rate: float = Field(0.0, description="Success rate percentage")
    average_processing_time: float = Field(0.0, description="Average processing time")

class ErrorResponse(BaseModel):
    """Error response model"""
    status: str = Field("error", description="Status indicator")
    error_code: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    
class HealthCheck(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="Application version")
    service: str = Field(..., description="Service name")
    timestamp: Optional[str] = Field(None, description="Timestamp of health check")