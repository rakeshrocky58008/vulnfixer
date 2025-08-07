"""
Main Vulnerability Fixing AI Agent using Local Ollama
Completely local AI processing - no API keys needed!
"""

import logging
import tempfile
import time
import os
from typing import Dict, List, Optional

from app.config import settings
from agents.tools.parsers import VulnerabilityParser
from agents.tools.bitbucket_helper import BitbucketHelper
from agents.tools.ollama_client import OllamaClient

logger = logging.getLogger(__name__)

class VulnerabilityAgent:
    """Main agent that coordinates vulnerability fixing process using local Ollama"""
    
    def __init__(self):
        """Initialize the vulnerability fixing agent"""
        self.parser = VulnerabilityParser()
        self.bitbucket_helper = BitbucketHelper()
        self.ollama_client = OllamaClient()
    
    async def process_vulnerability_fix(
        self,
        report_path: str,
        repo_url: str,
        repo_token: Optional[str] = None,
        create_pr: bool = True,
        branch_name: Optional[str] = None
    ) -> Dict:
        """
        Main method to process vulnerability fixes using local Ollama
        """
        start_time = time.time()
        
        try:
            logger.info(f"Starting vulnerability fix process for {repo_url}")
            
            # Step 1: Check Ollama availability
            ollama_status = await self.ollama_client.check_model_availability()
            if not ollama_status.get("ollama_running"):
                return {
                    "message": "Ollama is not running. Please start Ollama first.",
                    "fixes_applied": 0,
                    "vulnerabilities_found": 0,
                    "error": "Ollama not available",
                    "instructions": [
                        "1. Install Ollama: https://ollama.ai",
                        "2. Run: ollama serve",
                        f"3. Pull model: ollama pull {settings.OLLAMA_MODEL}"
                    ]
                }
            
            if not ollama_status.get("model_available"):
                logger.info(f"Pulling model {settings.OLLAMA_MODEL}...")
                pull_result = await self.ollama_client.pull_model()
                if not pull_result.get("success"):
                    return {
                        "message": f"Failed to pull model {settings.OLLAMA_MODEL}",
                        "fixes_applied": 0,
                        "vulnerabilities_found": 0,
                        "error": pull_result.get("error")
                    }
            
            # Step 2: Parse vulnerability report
            logger.info("Parsing vulnerability report...")
            vulnerabilities = await self.analyze_report(report_path)
            
            if not vulnerabilities:
                return {
                    "message": "No vulnerabilities found in the report",
                    "fixes_applied": 0,
                    "vulnerabilities_found": 0
                }
            
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
            
            # Step 3: Determine repository type and clone
            repo_type = self._determine_repo_type(repo_url)
            logger.info(f"Detected repository type: {repo_type}")
            
            logger.info(f"Cloning repository {repo_url}...")
            with tempfile.TemporaryDirectory() as temp_dir:
                if repo_type == "bitbucket":
                    repo_info = await self.bitbucket_helper.clone_repository(repo_url, temp_dir)
                    workspace = repo_info["workspace"]
                    repo_name = repo_info["repo_name"]
                else:
                    # GitHub support can be added later
                    raise NotImplementedError("GitHub support not implemented yet")
                
                # Step 4: Generate and apply fixes using local Ollama
                fixes_applied = 0
                successful_fixes = []
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    try:
                        logger.info(f"Processing vulnerability {i}/{len(vulnerabilities)}: {vuln.get('name', vuln.get('id'))}")
                        
                        fix_result = await self._apply_vulnerability_fix(vuln, temp_dir)
                        
                        if fix_result['success']:
                            fixes_applied += 1
                            successful_fixes.append({
                                'vulnerability': vuln,
                                'fix': fix_result
                            })
                            logger.info(f"✅ Fixed: {vuln.get('name', vuln.get('id'))}")
                        else:
                            logger.warning(f"❌ Could not fix: {vuln.get('name', vuln.get('id'))} - {fix_result.get('reason')}")
                    
                    except Exception as e:
                        logger.error(f"Error processing vulnerability {vuln.get('id')}: {str(e)}")
                        continue
                
                # Step 5: Create pull request if fixes were applied
                pr_url = None
                final_branch_name = None
                
                if fixes_applied > 0 and create_pr:
                    logger.info(f"Creating pull request with {fixes_applied} fixes...")
                    
                    if not branch_name:
                        branch_name = f"{settings.PR_BRANCH_PREFIX}-{int(time.time())}"
                    
                    # Push changes to Bitbucket
                    files_changed = [fix['file_path'] for fix in successful_fixes if 'file_path' in fix]
                    
                    push_result = await self.bitbucket_helper.push_changes(
                        temp_dir,
                        branch_name,
                        f"🛡️ Fix {fixes_applied} security vulnerabilities\n\nAutomated fixes generated by VulnFixer using local Ollama AI ({settings.OLLAMA_MODEL})",
                        files_changed
                    )
                    
                    if push_result["success"]:
                        pr_result = await self.bitbucket_helper.create_pull_request(
                            workspace,
                            repo_name,
                            branch_name,
                            target_branch="main",
                            title=f"🛡️ Fix {fixes_applied} Security Vulnerabilities (Ollama AI)",
                            description=self._generate_pr_description(successful_fixes),
                            fixes_applied=successful_fixes
                        )
                        pr_url = pr_result.get('pr_url')
                        final_branch_name = branch_name
                
                processing_time = time.time() - start_time
                
                return {
                    "message": f"Successfully processed {fixes_applied}/{len(vulnerabilities)} vulnerabilities using local Ollama",
                    "fixes_applied": fixes_applied,
                    "vulnerabilities_found": len(vulnerabilities),
                    "pr_url": pr_url,
                    "branch_name": final_branch_name,
                    "processing_time": processing_time,
                    "successful_fixes": [f['vulnerability']['name'] for f in successful_fixes],
                    "model_used": settings.OLLAMA_MODEL
                }
        
        except Exception as e:
            logger.error(f"Error in vulnerability fix process: {str(e)}")
            raise
    
    async def analyze_report(self, report_path: str) -> List[Dict]:
        """
        Analyze vulnerability report and extract structured data
        """
        try:
            return await self.parser.parse_report(report_path)
        except Exception as e:
            logger.error(f"Error parsing vulnerability report: {str(e)}")
            raise
    
    async def _apply_vulnerability_fix(self, vulnerability: Dict, repo_path: str) -> Dict:
        """
        Apply fix for a single vulnerability using local Ollama
        """
        try:
            vuln_type = vulnerability.get('type', 'unknown')
            
            if vuln_type == 'dependency':
                return await self._fix_dependency_vulnerability(vulnerability, repo_path)
            elif vuln_type == 'code':
                return await self._fix_code_vulnerability(vulnerability, repo_path)
            elif vuln_type == 'configuration':
                return await self._fix_configuration_vulnerability(vulnerability, repo_path)
            else:
                return {
                    'success': False,
                    'reason': f'Unsupported vulnerability type: {vuln_type}'
                }
        
        except Exception as e:
            logger.error(f"Error applying fix for vulnerability {vulnerability.get('id')}: {str(e)}")
            return {
                'success': False,
                'reason': f'Error applying fix: {str(e)}'
            }
    
    async def _fix_dependency_vulnerability(self, vulnerability: Dict, repo_path: str) -> Dict:
        """
        Fix dependency-related vulnerabilities using local Ollama
        """
        try:
            # Find dependency files (pom.xml, package.json, requirements.txt, etc.)
            dep_files = self._find_dependency_files(repo_path)
            
            if not dep_files:
                return {
                    'success': False,
                    'reason': 'No dependency files found'
                }
            
            for dep_file in dep_files:
                file_path = os.path.join(repo_path, dep_file)
                
                if not os.path.exists(file_path):
                    continue
                
                # Read current file content
                with open(file_path, 'r', encoding='utf-8') as f:
                    current_content = f.read()
                
                # Check if this file contains the vulnerable dependency
                component_name = vulnerability.get('component', '')
                if component_name.lower() not in current_content.lower():
                    continue
                
                # Determine build file type
                build_type = self._get_build_file_type(dep_file)
                
                # Generate fix using local Ollama
                logger.info(f"Using Ollama model {settings.OLLAMA_MODEL} to fix dependency vulnerability...")
                fix_result = await self.ollama_client.generate_dependency_update(
                    vulnerability,
                    current_content,
                    build_type
                )
                
                if fix_result["success"]:
                    # Apply the fix
                    updated_content = fix_result["updated_content"]
                    
                    # Clean up the content (remove markdown formatting if present)
                    updated_content = self._clean_generated_content(updated_content)
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(updated_content)
                    
                    return {
                        'success': True,
                        'file_path': dep_file,
                        'fix_type': 'dependency_update',
                        'reasoning': fix_result["reasoning"],
                        'old_version': fix_result.get("old_version"),
                        'new_version': fix_result.get("new_version"),
                        'model_used': fix_result.get("model_used")
                    }
            
            return {
                'success': False,
                'reason': f'Could not find vulnerable dependency {vulnerability.get("component")} in dependency files'
            }
            
        except Exception as e:
            logger.error(f"Error fixing dependency vulnerability: {str(e)}")
            return {'success': False, 'reason': str(e)}
    
    async def _fix_code_vulnerability(self, vulnerability: Dict, repo_path: str) -> Dict:
        """
        Fix code-level vulnerabilities using local Ollama
        """
        try:
            # Find relevant source files
            source_files = self._find_source_files(repo_path)
            
            # Process first 3 files to avoid excessive processing
            for source_file in source_files[:3]:
                file_path = os.path.join(repo_path, source_file)
                
                if not os.path.exists(file_path):
                    continue
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    code_content = f.read()
                
                # Check if this file might contain the vulnerability
                vuln_keywords = [
                    vulnerability.get('name', '').lower(),
                    vulnerability.get('type', '').lower(),
                    'sql', 'injection', 'xss', 'csrf'  # Common vulnerability patterns
                ]
                
                if not any(keyword in code_content.lower() for keyword in vuln_keywords if keyword):
                    continue
                
                # Get file type
                file_extension = os.path.splitext(source_file)[1].lstrip('.')
                
                # Use local Ollama for code fix generation
                logger.info(f"Using Ollama model {settings.OLLAMA_MODEL} to fix code vulnerability...")
                fix_result = await self.ollama_client.generate_vulnerability_fix(
                    vulnerability,
                    code_content,
                    file_extension
                )
                
                if fix_result["success"]:
                    # Parse and clean the response
                    fixed_code = self._extract_code_from_response(fix_result["fix_content"])
                    
                    if fixed_code and len(fixed_code.strip()) > 10:  # Ensure we got actual code
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(fixed_code)
                        
                        return {
                            'success': True,
                            'file_path': source_file,
                            'fix_type': 'code_fix',
                            'reasoning': fix_result["reasoning"],
                            'model_used': fix_result.get("model_used"),
                            'confidence': fix_result.get("confidence")
                        }
            
            return {
                'success': False,
                'reason': 'Could not generate code fix for vulnerability'
            }
            
        except Exception as e:
            logger.error(f"Error fixing code vulnerability: {str(e)}")
            return {'success': False, 'reason': str(e)}
    
    async def _fix_configuration_vulnerability(self, vulnerability: Dict, repo_path: str) -> Dict:
        """
        Fix configuration vulnerabilities
        """
        # Implementation for configuration vulnerabilities
        return {
            'success': False,
            'reason': 'Configuration vulnerability fixes not implemented yet'
        }
    
    def _clean_generated_content(self, content: str) -> str:
        """
        Clean up AI-generated content by removing markdown formatting
        """
        lines = content.split('\n')
        cleaned_lines = []
        in_code_block = False
        
        for line in lines:
            # Skip markdown code block markers
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue
            
            # If we're in a code block or this looks like actual code/config content
            if in_code_block or self._looks_like_code(line):
                cleaned_lines.append(line)
            elif not in_code_block and line.strip():
                # Outside code blocks, only keep lines that look like file content
                if any(marker in line.lower() for marker in ['<', '>', '{', '}', '=', ':']):
                    cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def _looks_like_code(self, line: str) -> bool:
        """
        Check if a line looks like code/configuration content
        """
        code_indicators = [
            '<', '>', '{', '}', '[', ']', '=', ':', ';',
            'import ', 'public ', 'private ', 'class ',
            'def ', 'function ', 'var ', 'let ', 'const ',
            '<?xml', '<!DOCTYPE', '<dependency>', '<version>'
        ]
        
        return any(indicator in line for indicator in code_indicators)
    
    def _extract_code_from_response(self, response: str) -> Optional[str]:
        """
        Extract code from AI response, handling various formats
        """
        try:
            lines = response.split('\n')
            code_lines = []
            in_code_block = False
            
            for line in lines:
                if line.strip().startswith('```'):
                    in_code_block = not in_code_block
                    continue
                
                if in_code_block or self._looks_like_code(line):
                    code_lines.append(line)
            
            if code_lines:
                return '\n'.join(code_lines)
            
            # If no code blocks found, return the entire response if it looks like code
            if self._looks_like_code(response):
                return response
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting code from response: {str(e)}")
            return None
    
    def _determine_repo_type(self, repo_url: str) -> str:
        """
        Determine if repository is from Bitbucket or GitHub
        """
        if "bitbucket.org" in repo_url:
            return "bitbucket"
        elif "github.com" in repo_url:
            return "github"
        else:
            return "unknown"
    
    def _find_dependency_files(self, repo_path: str) -> List[str]:
        """
        Find dependency management files in repository
        """
        dep_files = []
        common_files = [
            'pom.xml',          # Maven
            'package.json',     # npm
            'requirements.txt', # pip
            'Pipfile',          # pipenv
            'build.gradle',     # Gradle
            'composer.json',    # Composer
            'Gemfile',          # Bundle
            'go.mod',           # Go modules
        ]
        
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file in common_files:
                    rel_path = os.path.relpath(os.path.join(root, file), repo_path)
                    dep_files.append(rel_path)
        
        return dep_files
    
    def _find_source_files(self, repo_path: str) -> List[str]:
        """
        Find source code files in repository
        """
        source_files = []
        source_extensions = ['.java', '.py', '.js', '.ts', '.cs', '.cpp', '.c', '.go', '.php', '.rb']
        
        for root, dirs, files in os.walk(repo_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'target', 'build', '__pycache__']]
            
            for file in files:
                if any(file.endswith(ext) for ext in source_extensions):
                    rel_path = os.path.relpath(os.path.join(root, file), repo_path)
                    source_files.append(rel_path)
        
        return source_files
    
    def _get_build_file_type(self, file_name: str) -> str:
        """
        Determine build file type from filename
        """
        type_mapping = {
            'pom.xml': 'maven',
            'package.json': 'npm',
            'requirements.txt': 'pip',
            'Pipfile': 'pipenv',
            'build.gradle': 'gradle',
            'composer.json': 'composer',
            'Gemfile': 'bundler',
            'go.mod': 'go'
        }
        
        return type_mapping.get(os.path.basename(file_name), 'unknown')
    
    def _generate_pr_description(self, successful_fixes: List[Dict]) -> str:
        """
        Generate detailed pull request description
        """
        description = f"""# 🛡️ Automated Security Vulnerability Fixes (Ollama AI)

This pull request contains automated fixes for security vulnerabilities generated by VulnFixer using local Ollama AI model: **{settings.OLLAMA_MODEL}**.

## 📋 Summary of Changes

"""
        
        for fix in successful_fixes:
            vuln = fix.get('vulnerability', {})
            fix_info = fix.get('fix', {})
            description += f"""### {vuln.get('name', 'Unknown Vulnerability')}
- **Severity**: {vuln.get('severity', 'Unknown')}
- **Type**: {vuln.get('type', 'Unknown')}
- **File**: `{fix_info.get('file_path', 'Unknown')}`
- **Fix**: {fix_info.get('reasoning', 'Applied security fix')}
- **Model Used**: {fix_info.get('model_used', settings.OLLAMA_MODEL)}

"""
        
        description += f"""## 🔍 Verification

Please review the changes and ensure they don't break existing functionality. Consider running:
- Unit tests
- Integration tests
- Security scans
- Manual testing of affected features

## 🤖 Generated by VulnFixer
- **AI Model**: {settings.OLLAMA_MODEL} (local Ollama)
- **Processing**: Completely local - no external API calls
- **Privacy**: Your code never left your environment
- **Cost**: Free - no API fees incurred

## 🦙 About Local AI Processing
This PR was generated using local Ollama AI, ensuring:
- ✅ Complete privacy and security
- ✅ No API rate limits or costs
- ✅ Offline processing capabilities
- ✅ Full control over the AI model
"""
        
        return description
    
    def get_model_info(self) -> str:
        """Get information about the AI model being used"""
        return f"Local Ollama: {settings.OLLAMA_MODEL} (temperature: {settings.LLM_TEMPERATURE})"
