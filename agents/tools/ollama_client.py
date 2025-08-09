"""
Ollama Local AI Client for Vulnerability Fixing
No API keys needed - runs completely local!
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
        self.base_url = settings.OLLAMA_BASE_URL  # Default: http://localhost:11434
        self.model = settings.OLLAMA_MODEL        # Default: codellama:7b
        self.timeout = settings.OLLAMA_TIMEOUT    # Default: 120 seconds
    
    async def generate_vulnerability_fix(
        self,
        vulnerability: Dict,
        code_context: str,
        file_type: str = "java"
    ) -> Dict:
        """
        Generate a vulnerability fix using local Ollama
        """
        try:
            prompt = self._create_fix_prompt(vulnerability, code_context, file_type)
            
            response_text = await self._chat_with_ollama([
                {
                    "role": "system",
                    "content": "You are a senior security engineer expert in fixing code vulnerabilities. Provide secure, minimal fixes that maintain functionality. Focus on practical, production-ready solutions."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ])
            
            return {
                "success": True,
                "fix_content": response_text,
                "reasoning": f"Fixed {vulnerability.get('name')} vulnerability using local Ollama ({self.model})",
                "confidence": 0.8,
                "model_used": self.model
            }
            
        except Exception as e:
            logger.error(f"Error generating fix with Ollama: {str(e)}")
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
        Generate dependency update fix using local Ollama
        """
        try:
            prompt = self._create_dependency_prompt(vulnerability, current_file_content, build_file_type)
            
            response_text = await self._chat_with_ollama([
                {
                    "role": "system",
                    "content": "You are an expert in dependency management and security vulnerabilities. Update vulnerable dependencies while maintaining compatibility and following best practices."
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
                "old_version": vulnerability.get("current_version"),
                "new_version": vulnerability.get("fixed_version"),
                "model_used": self.model
            }
            
        except Exception as e:
            logger.error(f"Error generating dependency update: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _chat_with_ollama(self, messages: List[Dict]) -> str:
        """
        Send chat request to local Ollama instance
        """
        # Convert messages to a single prompt for Ollama
        prompt = self._messages_to_prompt(messages)
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": settings.LLM_TEMPERATURE,
                "top_p": 0.9,
                "top_k": 40,
                "num_ctx": 8192,  # Context window
                "num_predict": settings.MAX_TOKENS
            }
        }
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("response", "")
                else:
                    error_text = await response.text()
                    raise Exception(f"Ollama API error {response.status}: {error_text}")
    
    async def _generate_with_ollama(self, prompt: str) -> str:
        """
        Simple generation request to Ollama
        """
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
        """
        Convert chat messages to a single prompt for Ollama
        """
        prompt_parts = []
        
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            
            if role == "system":
                prompt_parts.append(f"System: {content}")
            elif role == "user":
                prompt_parts.append(f"User: {content}")
            elif role == "assistant":
                prompt_parts.append(f"Assistant: {content}")
        
        prompt_parts.append("Assistant:")  # Prompt for response
        return "\n\n".join(prompt_parts)
    
    def _create_fix_prompt(self, vulnerability: Dict, code_context: str, file_type: str) -> str:
        """Create prompt for vulnerability fixing"""
        return f"""Fix this security vulnerability in the {file_type} code below.

VULNERABILITY DETAILS:
- Name: {vulnerability.get('name', 'Unknown')}
- Type: {vulnerability.get('type', 'Unknown')}  
- Severity: {vulnerability.get('severity', 'Unknown')}
- Description: {vulnerability.get('description', 'No description')}

CURRENT CODE:
```{file_type}
{code_context}
```

REQUIREMENTS:
1. Fix the security vulnerability completely
2. Make minimal changes to preserve existing functionality
3. Follow security best practices for {file_type}
4. Add brief comments explaining the changes
5. Return only the corrected code

FIXED CODE:"""
    
    def _create_dependency_prompt(self, vulnerability: Dict, file_content: str, build_type: str) -> str:
        """Create prompt for dependency updates"""
        return f"""Update the vulnerable dependency in this {build_type} build file.

VULNERABILITY DETAILS:
- Component: {vulnerability.get('component', 'Unknown')}
- Current Version: {vulnerability.get('current_version', 'Unknown')}
- Fixed Version: {vulnerability.get('fixed_version', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}

CURRENT BUILD FILE:
```
{file_content}
```

REQUIREMENTS:
1. Update ONLY the vulnerable dependency to the fixed version
2. Keep all other dependencies unchanged
3. Maintain proper {build_type} syntax and formatting
4. Preserve all comments and structure
5. Return the complete updated file

UPDATED BUILD FILE:"""
    
    async def check_model_availability(self) -> Dict:
        """
        Check if Ollama is running and model is available
        """
        try:
            # Check if Ollama is running
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/api/tags") as response:
                    if response.status == 200:
                        data = await response.json()
                        models = [model["name"] for model in data.get("models", [])]
                        
                        return {
                            "ollama_running": True,
                            "model_available": self.model in models,
                            "available_models": models,
                            "current_model": self.model
                        }
                    else:
                        return {
                            "ollama_running": False,
                            "error": f"Ollama not responding: {response.status}"
                        }
        
        except Exception as e:
            return {
                "ollama_running": False,
                "error": str(e)
            }
    
    async def pull_model(self, model_name: str = None) -> Dict:
        """
        Pull/download a model in Ollama
        """
        model = model_name or self.model
        
        try:
            payload = {"name": model}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/pull",
                    json=payload
                ) as response:
                    if response.status == 200:
                        return {
                            "success": True,
                            "message": f"Model {model} pulled successfully"
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "success": False,
                            "error": error_text
                        }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

# Utility functions for Ollama setup
async def setup_ollama_model(model_name: str = "codellama:7b") -> Dict:
    """
    Setup and verify Ollama model
    """
    client = OllamaClient()
    
    # Check if Ollama is running
    status = await client.check_model_availability()
    
    if not status.get("ollama_running"):
        return {
            "success": False,
            "message": "Ollama is not running. Please start Ollama first.",
            "instructions": [
                "1. Install Ollama: https://ollama.ai",
                "2. Run: ollama serve",
                "3. Pull model: ollama pull codellama:7b"
            ]
        }
    
    if not status.get("model_available"):
        logger.info(f"Pulling model {model_name}...")
        pull_result = await client.pull_model(model_name)
        
        if not pull_result.get("success"):
            return {
                "success": False,
                "message": f"Failed to pull model {model_name}",
                "error": pull_result.get("error")
            }
    
    return {
        "success": True,
        "message": f"Ollama setup complete with model {model_name}",
        "available_models": status.get("available_models", [])
    }
