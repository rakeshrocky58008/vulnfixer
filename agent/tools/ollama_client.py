"""
Ollama Local AI Client for Vulnerability Fixing
"""

import aiohttp
import logging
from typing import Dict, List, Optional
import json

from app.config import settings

logger = logging.getLogger(__name__)

class OllamaClient:
    """Client for local Ollama API"""
    
    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL
        self.timeout = settings.OLLAMA_TIMEOUT
    
    async def generate_vulnerability_fix(
        self,
        vulnerability: Dict,
        code_context: str,
        file_type: str = "java"
    ) -> Dict:
        """Generate a vulnerability fix using local Ollama"""
        try:
            prompt = self._create_fix_prompt(vulnerability, code_context, file_type)
            
            response_text = await self._chat_with_ollama([
                {
                    "role": "system",
                    "content": "You are a senior security engineer. Fix vulnerabilities with minimal, secure changes."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ])
            
            return {
                "success": True,
                "fix_content": response_text,
                "reasoning": f"Fixed {vulnerability.get('name')} using Ollama",
                "model_used": self.model
            }
            
        except Exception as e:
            logger.error(f"Error generating fix with Ollama: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def generate_dependency_update(
        self,
        vulnerability: Dict,
        current_file_content: str,
        build_file_type: str = "maven"
    ) -> Dict:
        """Generate dependency update fix using local Ollama"""
        try:
            prompt = self._create_dependency_prompt(vulnerability, current_file_content, build_file_type)
            
            response_text = await self._chat_with_ollama([
                {
                    "role": "system",
                    "content": "You are an expert in dependency management. Update vulnerable dependencies safely."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ])
            
            return {
                "success": True,
                "updated_content": response_text,
                "reasoning": f"Updated {vulnerability.get('component')} to fix vulnerability",
                "model_used": self.model
            }
            
        except Exception as e:
            logger.error(f"Error generating dependency update: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _chat_with_ollama(self, messages: List[Dict]) -> str:
        """Send chat request to local Ollama instance"""
        prompt = self._messages_to_prompt(messages)
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": settings.LLM_TEMPERATURE,
                "num_ctx": 4096,
                "num_predict": settings.MAX_TOKENS
            }
        }
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("response", "")
                else:
                    error_text = await response.text()
                    raise Exception(f"Ollama error: {error_text}")
    
    def _messages_to_prompt(self, messages: List[Dict]) -> str:
        """Convert chat messages to prompt for Ollama"""
        prompt_parts = []
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            
            if role == "system":
                prompt_parts.append(f"System: {content}")
            elif role == "user":
                prompt_parts.append(f"User: {content}")
        
        prompt_parts.append("Assistant:")
        return "\n\n".join(prompt_parts)
    
    def _create_fix_prompt(self, vulnerability: Dict, code_context: str, file_type: str) -> str:
        """Create prompt for vulnerability fixing"""
        return f"""Fix this security vulnerability in the {file_type} code:

VULNERABILITY:
- Name: {vulnerability.get('name', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- Description: {vulnerability.get('description', 'No description')}

CURRENT CODE:
```{file_type}
{code_context}
