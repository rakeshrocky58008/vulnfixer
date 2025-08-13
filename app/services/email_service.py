"""
Email Service for VulnFixer
Handles sending reports and notifications via email
"""

import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List, Optional
from pathlib import Path
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class EmailService:
    """
    Email service for sending vulnerability reports and notifications
    """
    
    def __init__(self):
        # Email configuration - can be moved to settings
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.vaa.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_username = os.getenv('SMTP_USERNAME', 'vulnfixer@vaa.com')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        self.from_email = os.getenv('FROM_EMAIL', 'vulnfixer@vaa.com')
        self.use_tls = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
        
        # For development/testing - use console output if no SMTP configured
        self.dev_mode = not self.smtp_password
        
        if self.dev_mode:
            logger.warning("Email service running in development mode - emails will be logged instead of sent")
    
    async def send_fix_report_email(
        self, 
        to_email: str, 
        subject: str, 
        content: str, 
        attachments: List[str] = None
    ) -> Dict:
        """
        Send vulnerability fix report via email
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add HTML content
            html_part = MIMEText(content, 'html')
            msg.attach(html_part)
            
            # Add attachments if any
            if attachments:
                for attachment_path in attachments:
                    if os.path.exists(attachment_path):
                        self._add_attachment(msg, attachment_path)
            
            # Send email
            if self.dev_mode:
                return self._log_email_for_dev(to_email, subject, content)
            else:
                return await self._send_email_smtp(msg, to_email)
                
        except Exception as e:
            logger.error(f"Failed to send notification email: {e}")
            return {"success": False, "error": str(e)}
    
    def _add_attachment(self, msg: MIMEMultipart, file_path: str):
        """Add file attachment to email message"""
        try:
            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            
            # Add header
            filename = Path(file_path).name
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {filename}'
            )
            
            msg.attach(part)
            
        except Exception as e:
            logger.error(f"Failed to add attachment {file_path}: {e}")
    
    async def _send_email_smtp(self, msg: MIMEMultipart, to_email: str) -> Dict:
        """Send email via SMTP"""
        try:
            # Create SMTP session
            if self.use_tls:
                context = ssl.create_default_context()
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls(context=context)
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            
            # Login and send
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            
            text = msg.as_string()
            server.sendmail(self.from_email, to_email, text)
            server.quit()
            
            logger.info(f"Email sent successfully to {to_email}")
            return {"success": True, "message": f"Email sent to {to_email}"}
            
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            return {"success": False, "error": str(e)}
    
    def _log_email_for_dev(self, to_email: str, subject: str, content: str) -> Dict:
        """Log email content for development mode"""
        logger.info("=" * 60)
        logger.info("EMAIL (Development Mode)")
        logger.info("=" * 60)
        logger.info(f"To: {to_email}")
        logger.info(f"Subject: {subject}")
        logger.info("-" * 60)
        logger.info("Content:")
        # Log first 500 chars of content for brevity
        logger.info(content[:500] + "..." if len(content) > 500 else content)
        logger.info("=" * 60)
        
        return {"success": True, "message": f"Email logged for development (to: {to_email})"}
    
    def _generate_notification_content(self, notification_type: str, data: Dict) -> tuple:
        """Generate notification email subject and content"""
        
        if notification_type == "pr_created":
            subject = f"🛡️ VulnFixer: Pull Request Created - {data.get('fixes_count', 0)} fixes applied"
            content = self._generate_pr_notification(data)
            
        elif notification_type == "fixes_completed":
            subject = f"✅ VulnFixer: Fix Process Completed - {data.get('success_count', 0)} successful"
            content = self._generate_completion_notification(data)
            
        elif notification_type == "fixes_failed":
            subject = f"❌ VulnFixer: Fix Process Failed - Manual intervention required"
            content = self._generate_failure_notification(data)
            
        elif notification_type == "diff_analysis":
            subject = f"📊 VulnFixer: Diff Analysis Complete - {data.get('new_vulns', 0)} new vulnerabilities"
            content = self._generate_diff_notification(data)
            
        else:
            subject = "🛡️ VulnFixer Notification"
            content = self._generate_generic_notification(data)
        
        return subject, content
    
    def _generate_pr_notification(self, data: Dict) -> str:
        """Generate PR creation notification"""
        return f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0;">🛡️ Pull Request Created</h1>
                <p style="margin: 10px 0 0 0;">VulnFixer has successfully applied security fixes</p>
            </div>
            
            <div style="padding: 20px; background: white;">
                <div style="background: #c6f6d5; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #48bb78;">
                    <h2 style="margin-top: 0;">✅ Fixes Applied</h2>
                    <ul style="margin: 0; padding-left: 20px;">
                        <li><strong>{data.get('fixes_count', 0)}</strong> vulnerabilities fixed</li>
                        <li><strong>{data.get('branch_name', 'vulnfixer-branch')}</strong> branch created</li>
                        <li>All fixes validated with Maven build</li>
                    </ul>
                </div>
                
                <div style="background: #bee3f8; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #3182ce;">
                    <h3 style="margin-top: 0;">🔗 Action Required</h3>
                    <p>Review and merge the pull request:</p>
                    <p><a href="{data.get('pr_url', '#')}" style="color: #2b6cb0; text-decoration: none; font-weight: bold; background: #e6f3ff; padding: 8px 16px; border-radius: 4px; display: inline-block;">View Pull Request</a></p>
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
    
    def _generate_completion_notification(self, data: Dict) -> str:
        """Generate completion notification"""
        return f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #48bb78 0%, #38a169 100%); color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0;">✅ Fix Process Completed</h1>
                <p style="margin: 10px 0 0 0;">VulnFixer has finished processing vulnerabilities</p>
            </div>
            
            <div style="padding: 20px; background: white;">
                <div style="background: #c6f6d5; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #48bb78;">
                    <h2 style="margin-top: 0;">📊 Results Summary</h2>
                    <ul style="margin: 0; padding-left: 20px;">
                        <li><strong>{data.get('success_count', 0)}</strong> vulnerabilities successfully fixed</li>
                        <li><strong>{data.get('failed_count', 0)}</strong> vulnerabilities failed to fix</li>
                        <li><strong>{data.get('skipped_count', 0)}</strong> vulnerabilities skipped (no fix available)</li>
                        <li><strong>{data.get('success_rate', 0)}%</strong> success rate</li>
                    </ul>
                </div>
                
                <div style="background: #e6fffa; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #38b2ac;">
                    <h3 style="margin-top: 0;">🤖 AI Efficiency</h3>
                    <p><strong>{data.get('template_fixes', 0)}</strong> fixes applied using templates (fast)</p>
                    <p><strong>{data.get('ai_fixes', 0)}</strong> fixes required AI assistance (complex cases)</p>
                </div>
                
                {f'<div style="background: #feebc8; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #dd6b20;"><h3 style="margin-top: 0;">⚠️ Manual Review Required</h3><p>{data.get("failed_count", 0)} vulnerabilities could not be fixed automatically and require manual intervention.</p></div>' if data.get('failed_count', 0) > 0 else ''}
                
                <div style="background: #f1f5f9; padding: 15px; border-radius: 8px; text-align: center;">
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">
                        Processing completed in {data.get('processing_time', 0):.1f} seconds<br>
                        VAA Company Internal Security Tool
                    </p>
                </div>
            </div>
        </div>
        """
    
    def _generate_failure_notification(self, data: Dict) -> str:
        """Generate failure notification"""
        return f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%); color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0;">❌ Fix Process Failed</h1>
                <p style="margin: 10px 0 0 0;">Manual intervention required</p>
            </div>
            
            <div style="padding: 20px; background: white;">
                <div style="background: #fed7d7; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #e53e3e;">
                    <h2 style="margin-top: 0;">🚨 Issues Encountered</h2>
                    <p><strong>Error:</strong> {data.get('error_message', 'Unknown error occurred')}</p>
                    <p><strong>Repository:</strong> {data.get('repo_url', 'Unknown')}</p>
                    <p><strong>Report:</strong> {data.get('report_name', 'Unknown')}</p>
                </div>
                
                <div style="background: #bee3f8; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #3182ce;">
                    <h3 style="margin-top: 0;">🔧 Recommended Actions</h3>
                    <ul style="margin: 0; padding-left: 20px;">
                        <li>Check repository access permissions</li>
                        <li>Verify vulnerability report format</li>
                        <li>Ensure Maven build is working locally</li>
                        <li>Review VulnFixer logs for detailed error information</li>
                    </ul>
                </div>
                
                <div style="background: #f1f5f9; padding: 15px; border-radius: 8px; text-align: center;">
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">
                        Failed at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
                        Contact DevSecOps team if issues persist
                    </p>
                </div>
            </div>
        </div>
        """
    
    def _generate_diff_notification(self, data: Dict) -> str:
        """Generate diff analysis notification"""
        return f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0;">📊 Diff Analysis Complete</h1>
                <p style="margin: 10px 0 0 0;">Vulnerability scan comparison results</p>
            </div>
            
            <div style="padding: 20px; background: white;">
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h2 style="margin-top: 0;">📈 Change Summary</h2>
                    <ul style="list-style: none; padding: 0;">
                        <li style="margin: 5px 0; color: #48bb78;"><strong>✅ Fixed:</strong> {data.get('fixed_vulns', 0)} vulnerabilities</li>
                        <li style="margin: 5px 0; color: #e53e3e;"><strong>🚨 New:</strong> {data.get('new_vulns', 0)} vulnerabilities</li>
                        <li style="margin: 5px 0; color: #dd6b20;"><strong>⚠️ Persistent:</strong> {data.get('persistent_vulns', 0)} vulnerabilities</li>
                    </ul>
                </div>
                
                <div style="background: #bee3f8; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #3182ce;">
                    <h3 style="margin-top: 0;">🎯 Action Required</h3>
                    <p><strong>{data.get('actionable_count', 0)}</strong> vulnerabilities need attention ({data.get('auto_fixable', 0)} can be auto-fixed)</p>
                    <p>Download the detailed report for complete analysis and recommendations.</p>
                </div>
                
                <div style="background: #f1f5f9; padding: 15px; border-radius: 8px; text-align: center;">
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">
                        Analysis completed on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
                        VAA Company Internal Security Tool
                    </p>
                </div>
            </div>
        </div>
        """
    
    def _generate_generic_notification(self, data: Dict) -> str:
        """Generate generic notification"""
        return f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0;">🛡️ VulnFixer Notification</h1>
                <p style="margin: 10px 0 0 0;">Security tool update</p>
            </div>
            
            <div style="padding: 20px; background: white;">
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h2 style="margin-top: 0;">ℹ️ Information</h2>
                    <p>{data.get('message', 'VulnFixer has completed a security operation.')}</p>
                </div>
                
                <div style="background: #f1f5f9; padding: 15px; border-radius: 8px; text-align: center;">
                    <p style="margin: 0; color: #64748b; font-size: 0.9em;">
                        Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
                        VAA Company Internal Security Tool
                    </p>
                </div>
            </div>
        </div>
        """
    
    def validate_email_config(self) -> Dict:
        """Validate email configuration"""
        issues = []
        
        if not self.smtp_server:
            issues.append("SMTP server not configured")
        
        if not self.smtp_username:
            issues.append("SMTP username not configured")
        
        if not self.smtp_password and not self.dev_mode:
            issues.append("SMTP password not configured")
        
        if not self.from_email:
            issues.append("From email not configured")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "dev_mode": self.dev_mode,
            "smtp_server": self.smtp_server,
            "smtp_port": self.smtp_port
        }
    
    async def test_email_connection(self) -> Dict:
        """Test email connection"""
        if self.dev_mode:
            return {"success": True, "message": "Running in development mode - no SMTP connection needed"}
        
        try:
            if self.use_tls:
                context = ssl.create_default_context()
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls(context=context)
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            
            server.quit()
            
            return {"success": True, "message": "Email connection successful"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}_email)
                
        except Exception as e:
            logger.error(f"Failed to send fix report email: {e}")
            return {"success": False, "error": str(e)}
    
    async def send_diff_report_email(
        self, 
        to_email: str, 
        subject: str, 
        content: str, 
        attachments: List[str] = None
    ) -> Dict:
        """
        Send vulnerability diff report via email
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add HTML content
            html_part = MIMEText(content, 'html')
            msg.attach(html_part)
            
            # Add attachments
            if attachments:
                for attachment_path in attachments:
                    if os.path.exists(attachment_path):
                        self._add_attachment(msg, attachment_path)
            
            # Send email
            if self.dev_mode:
                return self._log_email_for_dev(to_email, subject, content)
            else:
                return await self._send_email_smtp(msg, to_email)
                
        except Exception as e:
            logger.error(f"Failed to send diff report email: {e}")
            return {"success": False, "error": str(e)}
    
    async def send_notification_email(
        self, 
        to_email: str, 
        notification_type: str, 
        data: Dict
    ) -> Dict:
        """
        Send notification email (PR created, fixes failed, etc.)
        """
        try:
            # Generate notification content based on type
            subject, content = self._generate_notification_content(notification_type, data)
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add HTML content
            html_part = MIMEText(content, 'html')
            msg.attach(html_part)
            
            # Send email
            if self.dev_mode:
                return self._log_email_for_dev(to_email, subject, content)
            else:
                return await self._send_email_smtp(msg, to
