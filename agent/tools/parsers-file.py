"""
Vulnerability Report Parsers for different formats
"""

import json
import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Optional
import os

logger = logging.getLogger(__name__)

class VulnerabilityParser:
    """Parser for various vulnerability report formats"""
    
    async def parse_report(self, report_path: str) -> List[Dict]:
        """
        Parse vulnerability report and return structured data
        """
        try:
            file_extension = os.path.splitext(report_path)[1].lower()
            
            if file_extension == '.json':
                return await self._parse_json_report(report_path)
            elif file_extension == '.xml':
                return await self._parse_xml_report(report_path)
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")
                
        except Exception as e:
            logger.error(f"Error parsing vulnerability report: {str(e)}")
            raise
    
    async def _parse_json_report(self, report_path: str) -> List[Dict]:
        """Parse JSON vulnerability reports (BlackDuck, Snyk, etc.)"""
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        vulnerabilities = []
        
        # BlackDuck format
        if 'components' in data:
            vulnerabilities.extend(await self._parse_blackduck_format(data))
        
        # OWASP Dependency Check JSON format
        elif 'dependencies' in data:
            vulnerabilities.extend(await self._parse_owasp_json_format(data))
        
        # Snyk format
        elif 'vulnerabilities' in data:
            vulnerabilities.extend(await self._parse_snyk_format(data))
        
        # Generic format
        elif isinstance(data, list):
            vulnerabilities.extend(await self._parse_generic_format(data))
        
        else:
            logger.warning("Unknown JSON report format, attempting generic parsing")
            vulnerabilities.extend(await self._parse_generic_format([data]))
        
        return vulnerabilities
    
    async def _parse_xml_report(self, report_path: str) -> List[Dict]:
        """Parse XML vulnerability reports (OWASP Dependency Check)"""
        tree = ET.parse(report_path)
        root = tree.getroot()
        
        vulnerabilities = []
        
        # OWASP Dependency Check XML format
        if root.tag == 'analysis' or 'dependency-check' in str(root.tag):
            vulnerabilities.extend(await self._parse_owasp_xml_format(root))
        
        return vulnerabilities
    
    async def _parse_blackduck_format(self, data: Dict) -> List[Dict]:
        """Parse BlackDuck format"""
        vulnerabilities = []
        
        for component in data.get('components', []):
            component_name = component.get('componentName', 'Unknown')
            component_version = component.get('componentVersion', 'Unknown')
            
            for vuln in component.get('vulnerabilities', []):
                vulnerabilities.append({
                    'id': vuln.get('vulnerabilityName', f"{component_name}-vuln"),
                    'name': vuln.get('vulnerabilityName', 'Unknown Vulnerability'),
                    'severity': vuln.get('severity', 'UNKNOWN').upper(),
                    'type': 'dependency',
                    'component': component_name,
                    'current_version': component_version,
                    'fixed_version': vuln.get('remediationTargetVersion'),
                    'description': vuln.get('description', ''),
                    'cve_id': vuln.get('vulnerabilityName') if vuln.get('vulnerabilityName', '').startswith('CVE-') else None,
                    'source': 'BlackDuck'
                })
        
        return vulnerabilities
    
    async def _parse_owasp_json_format(self, data: Dict) -> List[Dict]:
        """Parse OWASP Dependency Check JSON format"""
        vulnerabilities = []
        
        for dependency in data.get('dependencies', []):
            file_name = dependency.get('fileName', 'Unknown')
            
            for vuln in dependency.get('vulnerabilities', []):
                vulnerabilities.append({
                    'id': vuln.get('name', f"{file_name}-vuln"),
                    'name': vuln.get('name', 'Unknown Vulnerability'),
                    'severity': vuln.get('severity', 'UNKNOWN').upper(),
                    'type': 'dependency',
                    'component': file_name,
                    'current_version': dependency.get('evidenceCollected', {}).get('versionEvidence', [{}])[0].get('value', 'Unknown'),
                    'fixed_version': None,  # OWASP doesn't always provide fix versions
                    'description': vuln.get('description', ''),
                    'cve_id': vuln.get('name') if vuln.get('name', '').startswith('CVE-') else None,
                    'source': 'OWASP Dependency Check',
                    'cwes': [cwe.get('cweId') for cwe in vuln.get('cwes', [])],
                    'references': [ref.get('url') for ref in vuln.get('references', [])]
                })
        
        return vulnerabilities
    
    async def _parse_owasp_xml_format(self, root) -> List[Dict]:
        """Parse OWASP Dependency Check XML format"""
        vulnerabilities = []
        
        for dependency in root.findall('.//dependency'):
            file_name = dependency.get('fileName', 'Unknown')
            
            for vuln in dependency.findall('.//vulnerability'):
                name = vuln.find('name')
                severity = vuln.find('severity')
                description = vuln.find('description')
                
                vulnerabilities.append({
                    'id': name.text if name is not None else f"{file_name}-vuln",
                    'name': name.text if name is not None else 'Unknown Vulnerability',
                    'severity': severity.text.upper() if severity is not None else 'UNKNOWN',
                    'type': 'dependency',
                    'component': file_name,
                    'current_version': 'Unknown',
                    'fixed_version': None,
                    'description': description.text if description is not None else '',
                    'cve_id': name.text if name is not None and name.text.startswith('CVE-') else None,
                    'source': 'OWASP Dependency Check'
                })
        
        return vulnerabilities
    
    async def _parse_snyk_format(self, data: Dict) -> List[Dict]:
        """Parse Snyk format"""
        vulnerabilities = []
        
        for vuln in data.get('vulnerabilities', []):
            vulnerabilities.append({
                'id': vuln.get('id', 'unknown'),
                'name': vuln.get('title', 'Unknown Vulnerability'),
                'severity': vuln.get('severity', 'unknown').upper(),
                'type': 'dependency',
                'component': vuln.get('packageName', 'Unknown'),
                'current_version': vuln.get('version', 'Unknown'),
                'fixed_version': vuln.get('fixedIn', [None])[0] if vuln.get('fixedIn') else None,
                'description': vuln.get('description', ''),
                'cve_id': vuln.get('identifiers', {}).get('CVE', [None])[0],
                'source': 'Snyk'
            })
        
        return vulnerabilities
    
    async def _parse_generic_format(self, data: List[Dict]) -> List[Dict]:
        """Parse generic vulnerability format"""
        vulnerabilities = []
        
        for item in data:
            if isinstance(item, dict):
                # Try to extract common fields
                vuln_id = item.get('id') or item.get('vulnerability_id') or item.get('name', 'unknown')
                name = item.get('name') or item.get('title') or item.get('vulnerability_name', 'Unknown Vulnerability')
                severity = str(item.get('severity', 'unknown')).upper()
                
                vulnerabilities.append({
                    'id': vuln_id,
                    'name': name,
                    'severity': severity,
                    'type': item.get('type', 'dependency'),
                    'component': item.get('component') or item.get('package') or item.get('dependency', 'Unknown'),
                    'current_version': item.get('current_version') or item.get('version', 'Unknown'),
                    'fixed_version': item.get('fixed_version') or item.get('fixed_in'),
                    'description': item.get('description', ''),
                    'cve_id': item.get('cve_id') or item.get('cve'),
                    'source': 'Generic'
                })
        
        return vulnerabilities
    
    def validate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Validate and clean vulnerability data"""
        cleaned_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # Ensure required fields exist
            if not vuln.get('id') or not vuln.get('name'):
                logger.warning(f"Skipping invalid vulnerability: {vuln}")
                continue
            
            # Normalize severity levels
            severity = vuln.get('severity', 'UNKNOWN').upper()
            if severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']:
                # Map common variations
                severity_mapping = {
                    'SEVERE': 'CRITICAL',
                    'MAJOR': 'HIGH',
                    'MINOR': 'LOW',
                    'INFORMATIONAL': 'INFO'
                }
                severity = severity_mapping.get(severity, 'UNKNOWN')
            
            vuln['severity'] = severity
            
            # Ensure type is valid
            if vuln.get('type') not in ['dependency', 'code', 'configuration', 'infrastructure']:
                vuln['type'] = 'dependency'  # Default to dependency
            
            # Clean up version strings
            if vuln.get('current_version'):
                vuln['current_version'] = str(vuln['current_version']).strip()
            
            if vuln.get('fixed_version'):
                vuln['fixed_version'] = str(vuln['fixed_version']).strip()
            
            cleaned_vulnerabilities.append(vuln)
        
        return cleaned_vulnerabilities
    
    def get_vulnerability_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Get summary statistics of vulnerabilities"""
        summary = {
            'total': len(vulnerabilities),
            'by_severity': {},
            'by_type': {},
            'fixable': 0,
            'critical_count': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            vuln_type = vuln.get('type', 'unknown')
            
            # Count by severity
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            # Count fixable vulnerabilities
            if vuln.get('fixed_version'):
                summary['fixable'] += 1
            
            # Count critical vulnerabilities
            if severity == 'CRITICAL':
                summary['critical_count'] += 1
        
        return summary