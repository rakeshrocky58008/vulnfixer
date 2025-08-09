import aiohttp
import asyncio
import re
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class FixedVersionResolver:
    """Lightweight fixed version resolver for VulnFixer"""
    
    def __init__(self):
        self.session = None
        self.cache = {}
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def enhance_vulnerability(self, vulnerability: Dict) -> Dict:
        """Enhance a single vulnerability with fixed version info"""
        
        if vulnerability.get('fixed_version'):
            return vulnerability  # Already has fix info
        
        # Try to resolve fixed version
        fixed_version = await self._resolve_fixed_version(vulnerability)
        
        if fixed_version:
            vulnerability['fixed_version'] = fixed_version
            vulnerability['fixed_version_source'] = 'auto-resolved'
            
        return vulnerability
    
    async def _resolve_fixed_version(self, vuln: Dict) -> Optional[str]:
        """Resolve fixed version using multiple strategies"""
        
        cve_id = vuln.get('cve_id') or vuln.get('name', '')
        component = vuln.get('component', '')
        description = vuln.get('description', '')
        
        # Strategy 1: Extract from description
        fixed_version = self._extract_from_description(description)
        if fixed_version:
            return fixed_version
        
        # Strategy 2: Try GitHub Advisory (if configured)
        if cve_id and cve_id.startswith('CVE-'):
            fixed_version = await self._try_github_advisory(cve_id, component)
            if fixed_version:
                return fixed_version
        
        # Strategy 3: Try OSV API
        if component:
            fixed_version = await self._try_osv_api(component, cve_id)
            if fixed_version:
                return fixed_version
        
        return None
    
    def _extract_from_description(self, description: str) -> Optional[str]:
        """Extract fixed version from description text"""
        if not description:
            return None
            
        patterns = [
            r'fixed?\s+in\s+version\s+([0-9][0-9a-zA-Z\.\-_]*)',
            r'upgrade\s+to\s+([0-9][0-9a-zA-Z\.\-_]*)',
            r'>=\s*([0-9][0-9a-zA-Z\.\-_]*)',
            r'version\s+([0-9][0-9a-zA-Z\.\-_]*)\s+(?:fixes|resolves)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    async def _try_github_advisory(self, cve_id: str, component: str) -> Optional[str]:
        """Try GitHub Advisory Database"""
        try:
            # Simple REST API call (no GraphQL needed)
            url = "https://api.github.com/advisories"
            params = {"cve_id": cve_id}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for advisory in data:
                        for vuln in advisory.get('vulnerabilities', []):
                            pkg_name = vuln.get('package', {}).get('name', '')
                            if component.lower() in pkg_name.lower():
                                first_patched = vuln.get('first_patched_version', {})
                                if first_patched:
                                    return first_patched.get('identifier')
                                    
        except Exception as e:
            logger.debug(f"GitHub Advisory lookup failed for {cve_id}: {e}")
            
        return None
    
    async def _try_osv_api(self, component: str, cve_id: str = None) -> Optional[str]:
        """Try OSV (Open Source Vulnerabilities) API"""
        try:
            url = "https://api.osv.dev/v1/query"
            
            if cve_id:
                payload = {"cve": cve_id}
            else:
                payload = {"package": {"name": component}}
            
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for vuln in data.get('vulns', []):
                        for affected in vuln.get('affected', []):
                            for range_info in affected.get('ranges', []):
                                for event in range_info.get('events', []):
                                    if 'fixed' in event:
                                        return event['fixed']
                                        
        except Exception as e:
            logger.debug(f"OSV lookup failed for {component}: {e}")
            
        return None
