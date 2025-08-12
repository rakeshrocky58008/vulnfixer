"""
Targeted Ollama Client - Generates specific fixes without processing entire POM
"""

import aiohttp
import logging
import re
from typing import Dict, Optional, List
import json

logger = logging.getLogger(__name__)

class TargetedOllamaClient:
    """
    Ollama client that generates targeted fixes without processing entire files
    """
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "codellama:7b"):
        self.base_url = base_url
        self.model = model
        self.timeout = 30  # Shorter timeout since we're not processing large files
    
    async def generate_fix_snippet(
        self,
        vulnerability: Dict,
        dependency_type: str = "direct",
        parent_info: Optional[Dict] = None
    ) -> Dict:
        """
        Generate just the fix snippet, not the entire file
        """
        try:
            component = vulnerability.get('component', '')
            current_version = vulnerability.get('current_version', '')
            fixed_version = vulnerability.get('fixed_version', '')
            
            if dependency_type == "direct":
                # For direct dependencies, we just need the version update
                return {
                    "success": True,
                    "fix_type": "version_update",
                    "search_pattern": f"<version>{current_version}</version>",
                    "replacement": f"<version>{fixed_version}</version>",
                    "context": component
                }
            else:
                # For transitive, generate the dependency block
                dependency_block = await self._generate_dependency_block(
                    component, fixed_version
                )
                
                return {
                    "success": True,
                    "fix_type": "add_explicit_dependency",
                    "dependency_block": dependency_block,
                    "location": "dependencies_section"
                }
                
        except Exception as e:
            logger.error(f"Error generating fix snippet: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _generate_dependency_block(
        self,
        component: str,
        fixed_version: str
    ) -> str:
        """
        Generate a Maven dependency block using Ollama
        """
        # Parse component
        if ':' in component:
            group_id, artifact_id = component.rsplit(':', 1)
        else:
            artifact_id = component
            group_id = await self._infer_group_id_with_ollama(artifact_id)
        
        prompt = f"""Generate a Maven dependency XML block for:
- Group ID: {group_id}
- Artifact ID: {artifact_id}
- Version: {fixed_version}

Return ONLY the XML dependency block, no explanations:"""
        
        response = await self._query_ollama(prompt)
        
        # Extract and clean the dependency block
        dependency = self._extract_xml_block(response)
        
        if not dependency:
            # Fallback to template
            dependency = f"""    <dependency>
        <groupId>{group_id}</groupId>
        <artifactId>{artifact_id}</artifactId>
        <version>{fixed_version}</version>
    </dependency>"""
        
        return dependency
    
    async def suggest_exclusion_strategy(
        self,
        parent_dependency: str,
        transitive_dependency: str,
        fixed_version: str
    ) -> Dict:
        """
        Generate exclusion strategy for transitive dependencies
        """
        prompt = f"""Generate a Maven exclusion for:
Parent dependency: {parent_dependency}
Transitive dependency to exclude: {transitive_dependency}
Then add explicit dependency with version: {fixed_version}

Return the strategy as JSON with 'exclusion' and 'explicit_dependency' fields:"""
        
        response = await self._query_ollama(prompt)
        
        try:
            # Try to parse JSON response
            strategy = self._extract_json(response)
            
            if not strategy:
                # Fallback strategy
                if ':' in transitive_dependency:
                    group_id, artifact_id = transitive_dependency.rsplit(':', 1)
                else:
                    artifact_id = transitive_dependency
                    group_id = "unknown"
                
                strategy = {
                    "exclusion": f"""        <exclusion>
            <groupId>{group_id}</groupId>
            <artifactId>{artifact_id}</artifactId>
        </exclusion>""",
                    "explicit_dependency": f"""    <dependency>
        <groupId>{group_id}</groupId>
        <artifactId>{artifact_id}</artifactId>
        <version>{fixed_version}</version>
    </dependency>"""
                }
            
            return {
                "success": True,
                "strategy": strategy
            }
            
        except Exception as e:
            logger.error(f"Error generating exclusion strategy: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def validate_version_compatibility(
        self,
        component: str,
        current_version: str,
        target_version: str
    ) -> Dict:
        """
        Check if version upgrade is likely to be compatible
        """
        prompt = f"""Is upgrading {component} from {current_version} to {target_version} likely to be compatible?
Consider:
1. Major version changes
2. Known breaking changes
3. API compatibility

Answer with YES or NO and brief reason:"""
        
        response = await self._query_ollama(prompt)
        
        # Parse response
        response_lower = response.lower()
        is_compatible = "yes" in response_lower[:20]  # Check first 20 chars
        
        return {
            "compatible": is_compatible,
            "reason": response[:200]  # First 200 chars of explanation
        }
    
    async def _query_ollama(self, prompt: str) -> str:
        """
        Query Ollama with a simple prompt
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 500,  # Smaller response size
                "stop": ["```", "EXPLANATION:", "Note:"]
            }
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("response", "")
                    else:
                        logger.error(f"Ollama returned status {response.status}")
                        return ""
        except Exception as e:
            logger.error(f"Error querying Ollama: {e}")
            return ""
    
    async def _infer_group_id_with_ollama(self, artifact_id: str) -> str:
        """
        Use Ollama to infer group ID
        """
        prompt = f"What is the Maven group ID for artifact '{artifact_id}'? Return only the group ID:"
        
        response = await self._query_ollama(prompt)
        
        # Clean response
        group_id = response.strip().split('\n')[0].strip()
        
        # Validate it looks like a group ID
        if '.' in group_id and len(group_id) < 50:
            return group_id
        else:
            # Fallback to common patterns
            return self._infer_group_id_fallback(artifact_id)
    
    def _infer_group_id_fallback(self, artifact_id: str) -> str:
        """
        Fallback group ID inference
        """
        patterns = {
            'netty': 'io.netty',
            'spring': 'org.springframework',
            'jackson': 'com.fasterxml.jackson.core',
            'log4j': 'org.apache.logging.log4j',
            'commons': 'org.apache.commons'
        }
        
        for key, group in patterns.items():
            if key in artifact_id.lower():
                return group
        
        return "unknown.group"
    
    def _extract_xml_block(self, text: str) -> Optional[str]:
        """
        Extract XML dependency block from response
        """
        # Look for <dependency> block
        match = re.search(r'<dependency>.*?</dependency>', text, re.DOTALL)
        if match:
            return match.group(0)
        
        return None
    
    def _extract_json(self, text: str) -> Optional[Dict]:
        """
        Extract JSON from response
        """
        try:
            # Find JSON object
            start = text.find('{')
            end = text.rfind('}')
            
            if start != -1 and end != -1:
                json_str = text[start:end+1]
                return json.loads(json_str)
        except:
            pass
        
        return None
    
    async def check_availability(self) -> Dict:
        """
        Check if Ollama is available
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/tags",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        models = [m["name"] for m in data.get("models", [])]
                        
                        return {
                            "available": True,
                            "model_ready": any(self.model in m for m in models),
                            "models": models
                        }
        except:
            pass
        
        return {
            "available": False,
            "error": "Cannot connect to Ollama"
        }
