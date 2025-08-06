"""
Microsoft Copilot API Client for Code Generation
"""

import aiohttp
import logging
from typing import Dict, List, Optional, Any
import json

from app.config import settings

logger = logging.getLogger(__name__)

class CopilotClient:
    """Client for Microsoft Copilot API"""
    
    def __init__(self):
        self.api_key = settings.COPILOT_API_KEY
        self.endpoint = settings.COPILOT_ENDPOINT
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "VulnFixer/1.0"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def generate_vulnerability_fix(
        self,
        vulnerability: Dict,
        code_context: str,
        file_type: str = "java"
    ) -> Dict:
        """
        Generate a vulnerability fix using Copilot
        
        Args:
            vulnerability: Vulnerability details
            code_context: Current code that needs fixing
            file_type: Type of file (java, python, javascript, etc.)
        
        Returns:
            Dictionary with generated fix
        """
        try:
            prompt = self._create_fix_prompt(vulnerability, code_context, file_type)
            
            # Use Copilot Completions API
            response = await self._make_copilot_request(prompt)
            
            return {
                "success": True,
                "fix_content": response.get("choices", [{}])[0].get("text", ""),
                "reasoning": f"Fixed {vulnerability.get('name')} vulnerability",
                "confidence": response.get("confidence", 0.8)
            }
            
        except Exception as e:
            logger.error(f"Error generating fix with Copilot: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def generate_dependency_update(
        self,
        vulnerability: Dict,
        current_file_content: str,
        build_file_type: str = "maven"
    ) -> Dict:
        """
        Generate dependency update fix using Copilot
        
        Args:
            vulnerability: Vulnerability details
            current_file_content: Current build file content (pom.xml, package.json, etc.)
            build_file_type: Type of build file (maven, npm, pip, etc.)
        
        Returns:
            Dictionary with dependency update fix
        """
        try:
            prompt = self._create_dependency_prompt(vulnerability, current_file_content, build_file_type)
            
            response = await self._make_copilot_request(prompt)
            
            return {
                "success": True,
                "updated_content": response.get("choices", [{}])[0].get("text", ""),
                "reasoning": f"Updated {vulnerability.get('component')} to fix vulnerability",
                "old_version": vulnerability.get("current_version"),
                "new_version": vulnerability.get("fixed_version")
            }
            
        except Exception as e:
            logger.error(f"Error generating dependency update with Copilot: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _make_copilot_request(self, prompt: str) -> Dict:
        """
        Make request to Copilot API
        """
        payload = {
            "prompt": prompt,
            "max_tokens": settings.MAX_TOKENS,
            "temperature": settings.LLM_TEMPERATURE,
            "model": "copilot-codex",
            "stream": False
        }
        
        async with self.session.post(
            f"{self.endpoint}/completions",
            json=payload
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                error_text = await response.text()
                raise Exception(f"Copilot API error {response.status}: {error_text}")
    
    def _create_fix_prompt(self, vulnerability: Dict, code_context: str, file_type: str) -> str:
        """
        Create prompt for vulnerability fixing
        """
        return f"""
# Vulnerability Fix Request

## Vulnerability Details:
- Name: {vulnerability.get('name', 'Unknown')}
- Type: {vulnerability.get('type', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- Description: {vulnerability.get('description', 'No description available')}
- CVE ID: {vulnerability.get('cve_id', 'N/A')}

## Current Code ({file_type}):
```{file_type}
{code_context}
```

## Task:
Generate a secure fix for the vulnerability above. Follow these guidelines:
1. Make minimal changes to preserve functionality
2. Follow security best practices for {file_type}
3. Add comments explaining the fix
4. Ensure the fix is production-ready
5. Consider edge cases and error handling

## Output Format:
Provide only the corrected code without additional explanations.

Fixed Code:
"""
    
    def _create_dependency_prompt(self, vulnerability: Dict, file_content: str, build_type: str) -> str:
        """
        Create prompt for dependency updates
        """
        return f"""
# Dependency Vulnerability Fix

## Vulnerability Details:
- Component: {vulnerability.get('component', 'Unknown')}
- Current Version: {vulnerability.get('current_version', 'Unknown')}
- Fixed Version: {vulnerability.get('fixed_version', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}

## Current Build File ({build_type}):
```
{file_content}
```

## Task:
Update the vulnerable dependency to the fixed version. Guidelines:
1. Update only the vulnerable dependency
2. Maintain compatibility with other dependencies
3. Follow {build_type} best practices
4. Preserve formatting and comments
5. Ensure version constraints are appropriate

## Output Format:
Provide the complete updated build file content.

Updated Build File:
"""

# Alternative implementation using GitHub Copilot Chat API
class CopilotChatClient:
    """Alternative client using Copilot Chat API"""
    
    def __init__(self):
        self.api_key = settings.COPILOT_API_KEY
        self.base_url = "https://api.github.com"
    
    async def chat_completion(self, messages: List[Dict], model: str = "gpt-4") -> str:
        """
        Use Copilot Chat API for more conversational fixes
        """
        headers = {
            "Authorization": f"token {self.api_key}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        payload = {
            "messages": messages,
            "model": model,
            "stream": False
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/copilot/chat/completions",
                headers=headers,
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("choices", [{}])[0].get("message", {}).get("content", "")
                else:
                    error_text = await response.text()
                    raise Exception(f"Copilot Chat API error {response.status}: {error_text}")
    
    async def generate_fix_with_chat(self, vulnerability: Dict, code_context: str) -> Dict:
        """
        Generate fix using chat-based approach
        """
        try:
            messages = [
                {
                    "role": "system",
                    "content": "You are a senior security engineer expert in fixing code vulnerabilities. Provide secure, minimal fixes that maintain functionality."
                },
                {
                    "role": "user",
                    "content": f"""
                    Please fix this security vulnerability:
                    
                    Vulnerability: {vulnerability.get('name')}
                    Severity: {vulnerability.get('severity')}
                    Description: {vulnerability.get('description', 'N/A')}
                    
                    Current code:
                    ```
                    {code_context}
                    ```
                    
                    Please provide:
                    1. The fixed code
                    2. Brief explanation of the fix
                    3. Any important considerations
                    """
                }
            ]
            
            response = await self.chat_completion(messages)
            
            return {
                "success": True,
                "response": response,
                "method": "copilot_chat"
            }
            
        except Exception as e:
            logger.error(f"Error with Copilot Chat API: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }