"""
Report Generator Service for VulnFixer
Generates HTML, PDF, and email reports
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
import json
import base64

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate various types of reports for vulnerability fixes and diffs"""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Load report templates"""
        return {
            "html_report": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnFixer Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f7fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .content { padding: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }
        .stat-number { font-size: 2.5em; font-weight: bold; color: #2d3748; margin-bottom: 5px; }
        .stat-label { color: #718096; font-size: 0.9em; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2d3748; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .vulnerability-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .vulnerability-table th { background: #f7fafc; padding: 12px; text-align: left; border: 1px solid #e2e8f0; }
        .vulnerability-table td { padding: 12px; border: 1px solid #e2e8f0; }
        .vulnerability-table tr:nth-child(even) { background: #f8f9fa; }
        .severity-critical { background: #fed7d7; color: #c53030; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .severity-high { background: #feebc8; color: #c05621; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .severity-medium { background: #fef5e7; color: #d69e2e; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .severity-low { background: #e6fffa; color: #0e7490; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .alert { padding: 15px; border-radius: 8px; margin: 15px 0; }
        .alert-success { background: #c6f6d5; color: #22543d; border-left: 4px solid #48bb78; }
        .alert-warning { background: #feebc8; color: #7c2d12; border-left: 4px solid #dd6b20; }
        .alert-info { background: #bee3f8; color: #2c5282; border-left: 4px solid #3182ce; }
        .footer { background: #f8f9fa; padding: 20px; border-radius: 0 0 10px 10px; text-align: center; color: #718096; font-size: 0.9em; }
        .ai-usage { background: #e6fffa; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #38b2ac; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VulnFixer Report</h1>
            <p>Generated on {timestamp}</p>
        </div>
        
        <div class="content">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{total_vulnerabilities}</div>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{successfully_fixed}</div>
                    <div class="stat-label">Successfully Fixed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{failed_to_fix}</div>
                    <div class="stat-label">Failed to Fix</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{skipped_no_fix}</div>
                    <div class="stat-label">Skipped (No Fix)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{success_rate}%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
            </div>
            
            <div class="ai-usage">
                <h3>🤖 AI Usage Statistics</h3>
                <p><strong>Template-based fixes:</strong> {simple_fixes} ({simple_percentage}%)</p>
                <p><strong>AI-enhanced fixes:</strong> {ai_enhanced_fixes} ({ai_percentage}%)</p>
                <p>Our smart approach uses simple templates for 90% of cases, reserving AI for complex scenarios.</p>
            </div>
            
            {successful_fixes_section}
            {failed_fixes_section}
            {skipped_fixes_section}
            
            <div class="section">
                <h2>📊 Severity Breakdown</h2>
                {severity_breakdown}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by VulnFixer - Smart Vulnerability Management with Local AI</p>
            <p>🏢 VAA Company Internal Tool</p>
        </div>
    </div>
</body>
</html>
            """,
            
            "email_template": """
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center;">
        <h1 style="margin: 0;">🛡️ VulnFixer Report</h1>
        <p style="margin: 10px 0 0 0;">Vulnerability Fix Summary</p>
    </div>
    
    <div style="padding: 20px; background: white;">
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h2 style="margin-top: 0; color: #2d3748;">📈 Summary</h2>
            <ul style="list-style: none; padding: 0;">
                <li style="margin: 5px 0;"><strong>Total Vulnerabilities:</strong> {total_vulnerabilities}</li>
                <li style="margin: 5px 0;"><strong>Successfully Fixed:</strong> {successfully_fixed}</li>
                <li style="margin: 5px 0;"><strong>Failed to Fix:</strong> {failed_to_fix}</li>
                <li style="margin: 5px 0;"><strong>Skipped (No Fix Available):</strong> {skipped_no_fix}</li>
                <li style="margin: 5px 0;"><strong>Success Rate:</strong> {success_rate}%</li>
            </ul>
        </div>
        
        <div style="background: #e6fffa; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #38b2ac;">
            <h3 style="margin-top: 0;">🤖 AI Efficiency</h3>
            <p><strong>{simple_fixes}</strong> vulnerabilities fixed with simple templates ({simple_percentage}%)</p>
            <p><strong>{ai_enhanced_fixes}</strong> vulnerabilities required AI assistance ({ai_percentage}%)</p>
        </div>
        
        {successful_fixes_email}
        {pr_link}
        
        <div style="background: #f1f5f9; padding: 15px; border-radius: 8px; margin-top: 20px; text-align: center;">
            <p style="margin: 0; color: #64748b; font-size: 0.9em;">
                Generated by VulnFixer on {timestamp}<br>
                VAA Company Internal Security Tool
            </p>
        </div>
    </div>
</div>
            """,
            
            "diff_report_template": """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Diff Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f7fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }
        .content { padding: 30px; }
        .diff-section { margin-bottom: 30px; }
        .diff-fixed { background: #c6f6d5; border-left: 4px solid #48bb78; padding: 15px; border-radius: 8px; }
        .diff-new { background: #fed7d7; border-left: 4px solid #e53e3e; padding: 15px; border-radius: 8px; }
        .diff-persistent { background: #feebc8; border-left: 4px solid #dd6b20; padding: 15px; border-radius: 8px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }
        .stat-number { font-size: 2em; font-weight: bold; color: #2d3748; }
        .stat-label { color: #718096; font-size: 0.9em; }
        .vulnerability-list { margin: 15px 0; }
        .vulnerability-item { background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 3px solid #e2e8f0; }
        .severity-critical { border-left-color: #e53e3e !important; }
        .severity-high { border-left-color: #dd6b20 !important; }
        .severity-medium { border-left-color: #d69e2e !important; }
        .severity-low { border-left-color: #38b2ac !important; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Vulnerability Diff Report</h1>
            <p>Comparison between scan reports - Generated on {timestamp}</p>
        </div>
        
        <div class="content">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{total_old}</div>
                    <div class="stat-label">Previous Scan</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_new}</div>
                    <div class="stat-label">Current Scan</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #48bb78;">{fixed_count}</div>
                    <div class="stat-label">Fixed Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #e53e3e;">{new_count}</div>
                    <div class="stat-label">New Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #dd6b20;">{persistent_count}</div>
                    <div class="stat-label">Still Present</div>
                </div>
            </div>
            
            {fixed_vulnerabilities_section}
            {new_vulnerabilities_section}
            {persistent_vulnerabilities_section}
            
            <div class="diff-section">
                <h2>🎯 Action Required</h2>
                <div style="background: #bee3f8; padding: 15px; border-radius: 8px; border-left: 4px solid #3182ce;">
                    <p><strong>Priority:</strong> Focus on {new_count} new vulnerabilities and {persistent_count} persistent issues.</p>
                    <p><strong>Recommendation:</strong> Use VulnFixer to automatically fix vulnerabilities with available patches.</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
            """
        }
    
    async def generate_fix_report(self, report_data: Dict, output_format: str = "html") -> str:
        """Generate fix report in specified format"""
        if output_format == "html":
            return self._generate_html_fix_report(report_data)
        elif output_format == "json":
            return json.dumps(report_data, indent=2)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_html_fix_report(self, report_data: Dict) -> str:
        """Generate HTML fix report"""
        template = self.templates["html_report"]
        
        # Prepare data
        summary = report_data["summary"]
        ai_stats = report_data["ai_usage_stats"]
        
        # Generate sections
        successful_fixes_section = self._generate_successful_fixes_section(
            report_data["vulnerabilities"]["successful_fixes"]
        )
        failed_fixes_section = self._generate_failed_fixes_section(
            report_data["vulnerabilities"]["failed_fixes"]
        )
        skipped_fixes_section = self._generate_skipped_fixes_section(
            report_data["vulnerabilities"]["skipped_fixes"]
        )
        severity_breakdown = self._generate_severity_breakdown_html(
            report_data["severity_breakdown"]
        )
        
        # Calculate percentages
        total_fixes = max(1, summary["successfully_fixed"])
        simple_percentage = round((ai_stats["simple_fixes"] / total_fixes) * 100, 1)
        ai_percentage = round((ai_stats["ai_enhanced_fixes"] / total_fixes) * 100, 1)
        
        return template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulnerabilities=summary["total_vulnerabilities"],
            successfully_fixed=summary["successfully_fixed"],
            failed_to_fix=summary["failed_to_fix"],
            skipped_no_fix=summary["skipped_no_fix"],
            success_rate=summary["success_rate"],
            simple_fixes=ai_stats["simple_fixes"],
            ai_enhanced_fixes=ai_stats["ai_enhanced_fixes"],
            simple_percentage=simple_percentage,
            ai_percentage=ai_percentage,
            successful_fixes_section=successful_fixes_section,
            failed_fixes_section=failed_fixes_section,
            skipped_fixes_section=skipped_fixes_section,
            severity_breakdown=severity_breakdown
        )
    
    async def generate_email_report(self, report_data: Dict, pr_url: Optional[str] = None) -> str:
        """Generate email-friendly report"""
        template = self.templates["email_template"]
        
        summary = report_data["summary"]
        ai_stats = report_data["ai_usage_stats"]
        
        # Calculate percentages
        total_fixes = max(1, summary["successfully_fixed"])
        simple_percentage = round((ai_stats["simple_fixes"] / total_fixes) * 100, 1)
        ai_percentage = round((ai_stats["ai_enhanced_fixes"] / total_fixes) * 100, 1)
        
        # Generate successful fixes email section
        successful_fixes_email = self._generate_successful_fixes_email(
            report_data["vulnerabilities"]["successful_fixes"]
        )
        
        # Generate PR link section
        pr_link = ""
        if pr_url:
            pr_link = f"""
            <div style="background: #c6f6d5; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #48bb78;">
                <h3 style="margin-top: 0;">🔗 Pull Request Created</h3>
                <p>A pull request has been created with all successful fixes:</p>
                <p><a href="{pr_url}" style="color: #2b6cb0; text-decoration: none; font-weight: bold;">{pr_url}</a></p>
            </div>
            """
        
        return template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulnerabilities=summary["total_vulnerabilities"],
            successfully_fixed=summary["successfully_fixed"],
            failed_to_fix=summary["failed_to_fix"],
            skipped_no_fix=summary["skipped_no_fix"],
            success_rate=summary["success_rate"],
            simple_fixes=ai_stats["simple_fixes"],
            ai_enhanced_fixes=ai_stats["ai_enhanced_fixes"],
            simple_percentage=simple_percentage,
            ai_percentage=ai_percentage,
            successful_fixes_email=successful_fixes_email,
            pr_link=pr_link
        )
    
    async def generate_diff_report(self, diff_result: Dict, output_format: str = "html") -> str:
        """Generate vulnerability diff report"""
        if output_format == "html":
            return self._generate_html_diff_report(diff_result)
        elif output_format == "json":
            return json.dumps(diff_result, indent=2)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_html_diff_report(self, diff_result: Dict) -> str:
        """Generate HTML diff report"""
        template = self.templates["diff_report_template"]
        
        # Generate sections
        fixed_section = self._generate_diff_section(
            "Fixed Vulnerabilities", 
            diff_result["fixed"], 
            "diff-fixed",
            "✅ These vulnerabilities have been resolved since the previous scan:"
        )
        
        new_section = self._generate_diff_section(
            "New Vulnerabilities", 
            diff_result["new"], 
            "diff-new",
            "🚨 These vulnerabilities are new in the current scan:"
        )
        
        persistent_section = self._generate_diff_section(
            "Persistent Vulnerabilities", 
            diff_result["persistent"], 
            "diff-persistent",
            "⚠️ These vulnerabilities are still present:"
        )
        
        return template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_old=len(diff_result["old_vulnerabilities"]),
            total_new=len(diff_result["new_vulnerabilities"]),
            fixed_count=len(diff_result["fixed"]),
            new_count=len(diff_result["new"]),
            persistent_count=len(diff_result["persistent"]),
            fixed_vulnerabilities_section=fixed_section,
            new_vulnerabilities_section=new_section,
            persistent_vulnerabilities_section=persistent_section
        )
    
    async def generate_diff_email(self, diff_result: Dict) -> str:
        """Generate email content for diff report"""
        summary = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0;">📊 Vulnerability Diff Report</h1>
                <p style="margin: 10px 0 0 0;">Scan Comparison Results</p>
            </div>
            
            <div style="padding: 20px; background: white;">
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h2 style="margin-top: 0;">📈 Summary</h2>
                    <ul style="list-style: none; padding: 0;">
                        <li style="margin: 5px 0; color: #48bb78;"><strong>✅ Fixed:</strong> {len(diff_result["fixed"])} vulnerabilities</li>
                        <li style="margin: 5px 0; color: #e53e3e;"><strong>🚨 New:</strong> {len(diff_result["new"])} vulnerabilities</li>
                        <li style="margin: 5px 0; color: #dd6b20;"><strong>⚠️ Persistent:</strong> {len(diff_result["persistent"])} vulnerabilities</li>
                    </ul>
                </div>
                
                <div style="background: #bee3f8; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #3182ce;">
                    <h3 style="margin-top: 0;">🎯 Action Required</h3>
                    <p><strong>Priority:</strong> {len(diff_result["new"]) + len(diff_result["persistent"])} vulnerabilities need attention.</p>
                    <p><strong>Recommendation:</strong> Use VulnFixer to automatically address vulnerabilities with available fixes.</p>
                </div>
                
                <div style="background: #f1f5f9; padding: 15px; border-radius: 8px; text-align: center;">
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">
                        Generated by VulnFixer on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
                        VAA Company Internal Security Tool
                    </p>
                </div>
            </div>
        </div>
        """
        return summary
    
    def _generate_successful_fixes_section(self, successful_fixes: List[Dict]) -> str:
        """Generate successful fixes section for HTML report"""
        if not successful_fixes:
            return ""
        
        section = """
        <div class="section">
            <h2>✅ Successfully Fixed Vulnerabilities</h2>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>Component</th>
                        <th>Version Change</th>
                        <th>Severity</th>
                        <th>CVE</th>
                        <th>Fix Method</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for vuln in successful_fixes:
            fix_method = "🤖 AI-Enhanced" if vuln.get('fix_method') == 'ai_enhanced' else "⚡ Template-Based"
            severity_class = f"severity-{vuln.get('severity', 'unknown').lower()}"
            
            section += f"""
                    <tr>
                        <td><strong>{vuln.get('component', 'Unknown')}</strong></td>
                        <td>{vuln.get('current_version', 'Unknown')} → {vuln.get('fixed_version', 'Unknown')}</td>
                        <td><span class="{severity_class}">{vuln.get('severity', 'Unknown')}</span></td>
                        <td>{vuln.get('cve_id', 'N/A')}</td>
                        <td>{fix_method}</td>
                    </tr>
            """
        
        section += """
                </tbody>
            </table>
        </div>
        """
        return section
    
    def _generate_failed_fixes_section(self, failed_fixes: List[Dict]) -> str:
        """Generate failed fixes section"""
        if not failed_fixes:
            return ""
        
        section = """
        <div class="section">
            <h2>❌ Failed to Fix</h2>
            <div class="alert alert-warning">
                <strong>Manual intervention required for these vulnerabilities:</strong>
            </div>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>Component</th>
                        <th>Current Version</th>
                        <th>Target Version</th>
                        <th>Severity</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for vuln in failed_fixes:
            severity_class = f"severity-{vuln.get('severity', 'unknown').lower()}"
            section += f"""
                    <tr>
                        <td><strong>{vuln.get('component', 'Unknown')}</strong></td>
                        <td>{vuln.get('current_version', 'Unknown')}</td>
                        <td>{vuln.get('fixed_version', 'Unknown')}</td>
                        <td><span class="{severity_class}">{vuln.get('severity', 'Unknown')}</span></td>
                        <td>Build validation failed</td>
                    </tr>
            """
        
        section += """
                </tbody>
            </table>
        </div>
        """
        return section
    
    def _generate_skipped_fixes_section(self, skipped_fixes: List[Dict]) -> str:
        """Generate skipped fixes section"""
        if not skipped_fixes:
            return ""
        
        section = """
        <div class="section">
            <h2>⏭️ Skipped Vulnerabilities</h2>
            <div class="alert alert-info">
                <strong>These vulnerabilities were skipped because no fixed version is available:</strong>
            </div>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>Component</th>
                        <th>Current Version</th>
                        <th>Severity</th>
                        <th>CVE</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for vuln in skipped_fixes:
            severity_class = f"severity-{vuln.get('severity', 'unknown').lower()}"
            section += f"""
                    <tr>
                        <td><strong>{vuln.get('component', 'Unknown')}</strong></td>
                        <td>{vuln.get('current_version', 'Unknown')}</td>
                        <td><span class="{severity_class}">{vuln.get('severity', 'Unknown')}</span></td>
                        <td>{vuln.get('cve_id', 'N/A')}</td>
                        <td>{vuln.get('skip_reason', 'No fix available')}</td>
                    </tr>
            """
        
        section += """
                </tbody>
            </table>
        </div>
        """
        return section
    
    def _generate_severity_breakdown_html(self, severity_breakdown: Dict) -> str:
        """Generate severity breakdown HTML"""
        section = '<div class="stats-grid">'
        
        severity_colors = {
            'CRITICAL': '#e53e3e',
            'HIGH': '#dd6b20', 
            'MEDIUM': '#d69e2e',
            'LOW': '#38b2ac',
            'INFO': '#3182ce',
            'UNKNOWN': '#718096'
        }
        
        for severity, count in severity_breakdown.items():
            color = severity_colors.get(severity, '#718096')
            section += f"""
                <div class="stat-card">
                    <div class="stat-number" style="color: {color};">{count}</div>
                    <div class="stat-label">{severity.title()}</div>
                </div>
            """
        
        section += '</div>'
        return section
    
    def _generate_successful_fixes_email(self, successful_fixes: List[Dict]) -> str:
        """Generate successful fixes section for email"""
        if not successful_fixes:
            return ""
        
        section = """
        <div style="background: #c6f6d5; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #48bb78;">
            <h3 style="margin-top: 0;">✅ Successfully Fixed</h3>
            <ul style="margin: 0; padding-left: 20px;">
        """
        
        for vuln in successful_fixes[:10]:  # Limit to first 10 for email
            fix_method = "🤖" if vuln.get('fix_method') == 'ai_enhanced' else "⚡"
            section += f"""
                <li style="margin: 5px 0;">
                    <strong>{vuln.get('component', 'Unknown')}</strong> {fix_method}<br>
                    <small>{vuln.get('current_version', 'Unknown')} → {vuln.get('fixed_version', 'Unknown')} ({vuln.get('severity', 'Unknown')})</small>
                </li>
            """
        
        if len(successful_fixes) > 10:
            section += f"<li><em>... and {len(successful_fixes) - 10} more</em></li>"
        
        section += "</ul></div>"
        return section
    
    def _generate_diff_section(self, title: str, vulnerabilities: List[Dict], css_class: str, description: str) -> str:
        """Generate diff section for HTML report"""
        if not vulnerabilities:
            return ""
        
        section = f"""
        <div class="diff-section">
            <h2>{title}</h2>
            <div class="{css_class}">
                <p>{description}</p>
                <div class="vulnerability-list">
        """
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            section += f"""
                <div class="vulnerability-item severity-{severity}">
                    <strong>{vuln.get('component', 'Unknown')}</strong> - {vuln.get('severity', 'Unknown')}<br>
                    <small>Version: {vuln.get('current_version', 'Unknown')} | CVE: {vuln.get('cve_id', 'N/A')}</small>
                </div>
            """
        
        section += """
                </div>
            </div>
        </div>
        """
        return section
