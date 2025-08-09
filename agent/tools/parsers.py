"""
Universal Vulnerability Report Parsers - UPDATED VERSION
Supports: BlackDuck, Trivy, Xray, JFrog, Clair, Snyk, Anchore, and generic formats
"""

import csv
import json
import xml.etree.ElementTree as ET
import logging
import os
import re
from typing import Dict, List, Optional, Any
from html.parser import HTMLParser

logger = logging.getLogger(__name__)

class VulnerabilityParser:
    """
    Universal parser that auto-detects and handles multiple vulnerability scanner formats
    Drop-in replacement for your existing VulnerabilityParser
    """
    
    def __init__(self):
        self.scanner_configs = self._get_scanner_configs()
        self.severity_normalizer = self._get_severity_normalizer()
    
    def _get_scanner_configs(self) -> Dict[str, Dict]:
        """Get scanner configurations"""
        return {
            'blackduck': {
                'indicators': ['component name', 'security risk', 'vulnerability id', 'base score'],
                'fields': {
                    'component': ['component name', 'component_name', 'componentname'],
                    'version': ['component version name', 'component version', 'version'],
                    'vulnerability': ['vulnerability id', 'vulnerability_id', 'vuln_id'],
                    'severity': ['security risk', 'severity', 'risk'],
                    'description': ['description', 'summary'],
                    'fixed_version': ['fixed version', 'remediation version'],
                    'cve': ['cve', 'cve_id']
                }
            },
            'trivy': {
                'indicators': ['pkgname', 'installedversion', 'vulnerabilityid', 'class'],
                'fields': {
                    'component': ['pkgname', 'pkg_name', 'package'],
                    'version': ['installedversion', 'installed_version'],
                    'vulnerability': ['vulnerabilityid', 'vulnerability_id'],
                    'severity': ['severity', 'level'],
                    'description': ['description', 'title'],
                    'fixed_version': ['fixedversion', 'fixed_version'],
                    'cve': ['vulnerabilityid', 'cve']
                }
            },
            'xray': {
                'indicators': ['xray_id', 'component', 'violation_type', 'watch_name'],
                'fields': {
                    'component': ['component', 'artifact', 'package_name'],
                    'version': ['version', 'component_version'],
                    'vulnerability': ['xray_id', 'cve', 'issue_id'],
                    'severity': ['severity', 'level'],
                    'description': ['summary', 'description'],
                    'fixed_version': ['fixed_versions', 'fix_version'],
                    'cve': ['cve', 'cve_id']
                }
            },
            'jfrog': {
                'indicators': ['component_id', 'impact_path', 'provider'],
                'fields': {
                    'component': ['component_id', 'artifact_id', 'component'],
                    'version': ['version', 'component_version'],
                    'vulnerability': ['cve', 'xray_id', 'issue_id'],
                    'severity': ['severity', 'level'],
                    'description': ['description', 'summary'],
                    'fixed_version': ['fixed_versions', 'fix_version'],
                    'cve': ['cve', 'cve_id']
                }
            },
            'clair': {
                'indicators': ['feature_name', 'namespace_name', 'fixed_by'],
                'fields': {
                    'component': ['feature_name', 'name', 'package'],
                    'version': ['version', 'version_format'],
                    'vulnerability': ['name', 'vulnerability', 'cve'],
                    'severity': ['severity', 'normalized_severity'],
                    'description': ['description', 'summary'],
                    'fixed_version': ['fixed_by', 'fixed_in_version'],
                    'cve': ['name', 'cve']
                }
            },
            'snyk': {
                'indicators': ['snyk', 'issue id', 'package manager'],
                'fields': {
                    'component': ['package name', 'package', 'library'],
                    'version': ['version', 'package version'],
                    'vulnerability': ['issue id', 'cve', 'snyk id'],
                    'severity': ['issue severity', 'severity'],
                    'description': ['issue title', 'title', 'description'],
                    'fixed_version': ['fix version', 'remediation'],
                    'cve': ['cve', 'identifiers']
                }
            },
            'anchore': {
                'indicators': ['anchore', 'vulnerability_id', 'package_name'],
                'fields': {
                    'component': ['package_name', 'package', 'name'],
                    'version': ['package_version', 'version'],
                    'vulnerability': ['vulnerability_id', 'vuln_id'],
                    'severity': ['severity', 'level'],
                    'description': ['description', 'summary'],
                    'fixed_version': ['fix', 'fixed_version'],
                    'cve': ['vulnerability_id', 'cve']
                }
            }
        }
    
    def _get_severity_normalizer(self) -> Dict[str, str]:
        """Get severity level mappings"""
        return {
            # Standard levels
            'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW', 'INFO': 'INFO',
            # Case variations
            'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW', 'info': 'INFO',
            # Alternative naming
            'severe': 'CRITICAL', 'major': 'HIGH', 'moderate': 'MEDIUM', 'minor': 'LOW',
            'negligible': 'LOW', 'informational': 'INFO',
            # Scanner-specific
            'very high': 'CRITICAL', 'very low': 'LOW',
            # Numeric (some scanners)
            '5': 'CRITICAL', '4': 'HIGH', '3': 'MEDIUM', '2': 'LOW', '1': 'INFO',
            # Fallback
            'unknown': 'UNKNOWN', 'unspecified': 'UNKNOWN'
        }
    
    async def parse_report(self, report_path: str) -> List[Dict]:
        """
        Universal parse method - auto-detects format and scanner type
        """
        try:
            file_extension = os.path.splitext(report_path)[1].lower()
            
            if file_extension == '.csv':
                return await self._parse_csv_universal(report_path)
            elif file_extension == '.json':
                return await self._parse_json_universal(report_path)
            elif file_extension == '.xml':
                return await self._parse_xml_report(report_path)
            elif file_extension in ['.html', '.htm']:
                return await self._parse_html_report(report_path)
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")
                
        except Exception as e:
            logger.error(f"Error parsing vulnerability report: {str(e)}")
            raise
    
    async def _parse_csv_universal(self, report_path: str) -> List[Dict]:
        """Universal CSV parser with auto-detection"""
        vulnerabilities = []
        
        try:
            # Read sample to detect format
            with open(report_path, 'r', encoding='utf-8') as f:
                sample = f.read(2048)
            
            # Detect delimiter
            delimiter = self._detect_delimiter(sample)
            
            # Detect scanner type
            scanner_type = self._detect_scanner_type(sample)
            logger.info(f"Detected: {scanner_type} scanner, delimiter: '{delimiter}'")
            
            # Parse with detected configuration
            with open(report_path, 'r', encoding='utf-8', newline='') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=delimiter)
                headers = list(reader.fieldnames) if reader.fieldnames else []
                
                scanner_config = self.scanner_configs.get(scanner_type, {})
                field_mappings = scanner_config.get('fields', {})
                
                for row_num, row in enumerate(reader, start=1):
                    try:
                        vulnerability = self._parse_row_universal(row, field_mappings, scanner_type)
                        if vulnerability:
                            vulnerabilities.append(vulnerability)
                    except Exception as e:
                        logger.warning(f"Error parsing row {row_num}: {str(e)}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error reading CSV file: {str(e)}")
            raise
            
        logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from {scanner_type} CSV")
        return vulnerabilities
    
    def _detect_delimiter(self, sample: str) -> str:
        """Auto-detect CSV delimiter"""
        delimiters = [',', ';', '\t', '|']
        delimiter_counts = {d: sample.count(d) for d in delimiters}
        
        # Return delimiter with highest count (minimum 2 occurrences)
        for delimiter, count in sorted(delimiter_counts.items(), key=lambda x: x[1], reverse=True):
            if count >= 2:
                return delimiter
        
        return ','  # Default
    
    def _detect_scanner_type(self, sample: str) -> str:
        """Auto-detect scanner type from content"""
        sample_lower = sample.lower()
        
        # Score each scanner based on indicator presence
        scores = {}
        for scanner_id, config in self.scanner_configs.items():
            indicators = config.get('indicators', [])
            score = sum(1 for indicator in indicators if indicator.lower() in sample_lower)
            if score > 0:
                scores[scanner_id] = score
        
        # Return scanner with highest score
        if scores:
            detected = max(scores.items(), key=lambda x: x[1])[0]
            logger.debug(f"Scanner detection scores: {scores}")
            return detected
        
        return 'generic'
    
    def _parse_row_universal(self, row: Dict, field_mappings: Dict, scanner_type: str) -> Optional[Dict]:
        """Universal row parser"""
        try:
            # Extract core fields using field mappings
            component = self._extract_field(row, field_mappings.get('component', []))
            version = self._extract_field(row, field_mappings.get('version', []))
            vulnerability_id = self._extract_field(row, field_mappings.get('vulnerability', []))
            severity = self._extract_field(row, field_mappings.get('severity', []))
            description = self._extract_field(row, field_mappings.get('description', []))
            fixed_version = self._extract_field(row, field_mappings.get('fixed_version', []))
            cve_id = self._extract_field(row, field_mappings.get('cve', []))
            
            # Skip if missing essential fields
            if not component or not vulnerability_id:
                return None
            
            # Enhanced CVE extraction
            if not cve_id:
                cve_id = self._extract_cve_from_text(vulnerability_id) or \
                         self._extract_cve_from_text(description or '')
            
            # Normalize severity
            normalized_severity = self._normalize_severity(severity)
            
            # Extract fixed version from description if not found
            if not fixed_version and description:
                fixed_version = self._extract_fixed_version_from_description(description)
            
            # Create standardized vulnerability object
            vulnerability = {
                'id': vulnerability_id,
                'name': vulnerability_id,
                'severity': normalized_severity,
                'type': 'dependency',  # Can be enhanced later
                'component': component,
                'current_version': version or 'Unknown',
                'fixed_version': fixed_version,
                'description': description or f'Vulnerability in {component}',
                'cve_id': cve_id,
                'source': f'{scanner_type.title()} CSV',
                'raw_data': dict(row)  # Preserve original data
            }
            
            return vulnerability
                
        except Exception as e:
            logger.error(f"Error parsing row: {str(e)}")
            return None
    
    def _extract_field(self, row: Dict, possible_headers: List[str]) -> Optional[str]:
        """Extract field value using fuzzy header matching"""
        # Direct matches first
        for header in possible_headers:
            if header in row and row[header] and str(row[header]).strip():
                return str(row[header]).strip()
        
        # Case-insensitive matches
        for header in possible_headers:
            for row_header in row.keys():
                if row_header.lower() == header.lower():
                    value = row[row_header]
                    if value and str(value).strip():
                        return str(value).strip()
        
        # Fuzzy matches (contains)
        for header in possible_headers:
            for row_header in row.keys():
                if header.lower() in row_header.lower() or row_header.lower() in header.lower():
                    value = row[row_header]
                    if value and str(value).strip():
                        return str(value).strip()
        
        return None
    
    def _extract_cve_from_text(self, text: str) -> Optional[str]:
        """Extract CVE ID from text"""
        if not text:
            return None
        
        cve_pattern = r'(CVE-\d{4}-\d+)'
        match = re.search(cve_pattern, text, re.IGNORECASE)
        return match.group(1) if match else None
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels"""
        if not severity:
            return 'UNKNOWN'
        
        severity_clean = str(severity).strip()
        return self.severity_normalizer.get(severity_clean.lower(), 'UNKNOWN')
    
    def _extract_fixed_version_from_description(self, description: str) -> Optional[str]:
        """Extract fixed version from description"""
        if not description:
            return None
        
        # Comprehensive patterns for version extraction
        patterns = [
            r'fixed?\s+in\s+(?:version\s+)?([0-9][0-9a-zA-Z\.\-_+]*)',
            r'upgrade\s+to\s+(?:version\s+)?([0-9][0-9a-zA-Z\.\-_+]*)',
            r'update\s+to\s+(?:version\s+)?([0-9][0-9a-zA-Z\.\-_+]*)',
            r'version\s+([0-9][0-9a-zA-Z\.\-_+]*)\s+(?:and\s+)?(?:above|higher|later)',
            r'>=\s*([0-9][0-9a-zA-Z\.\-_+]*)',
            r'>\s*([0-9][0-9a-zA-Z\.\-_+]*)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                version = match.group(1)
                if self._is_valid_version(version):
                    return version
        
        return None
    
    def _is_valid_version(self, version: str) -> bool:
        """Validate version format"""
        if not version or len(version) < 1:
            return False
        
        # Must start with digit
        if not version[0].isdigit():
            return False
        
        # Common version patterns
        patterns = [
            r'^\d+(\.\d+)*(-\w+)?(\+\w+)?$',  # 1.2.3, 1.2.3-SNAPSHOT
            r'^\d+(\.\d+)*[a-zA-Z]\d*$',      # 1.2.3a1
            r'^\d+(\.\d+)*-[a-zA-Z]+$',       # 1.2.3-alpha
        ]
        
        return any(re.match(pattern, version) for pattern in patterns)
    
    async def _parse_json_universal(self, report_path: str) -> List[Dict]:
        """Universal JSON parser"""
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        vulnerabilities = []
        
        # Simple JSON structure detection and parsing
        if 'Results' in data or 'results' in data:
            # Trivy format
            vulnerabilities = await self._parse_trivy_json(data)
        elif 'components' in data:
            # BlackDuck format
            vulnerabilities = await self._parse_blackduck_json(data)
        elif 'vulnerabilities' in data:
            # Generic vulnerabilities array
            vulnerabilities = await self._parse_generic_json(data)
        else:
            logger.warning("Unknown JSON format, attempting generic parsing")
            vulnerabilities = await self._parse_generic_json(data)
        
        return vulnerabilities
    
    async def _parse_trivy_json(self, data: Dict) -> List[Dict]:
        """Parse Trivy JSON format"""
        vulnerabilities = []
        results = data.get('Results', data.get('results', []))
        
        for result in results:
            target = result.get('Target', 'Unknown')
            vulns = result.get('Vulnerabilities', result.get('vulnerabilities', []))
            
            for vuln in vulns:
                vulnerability = {
                    'id': vuln.get('VulnerabilityID', 'Unknown'),
                    'name': vuln.get('VulnerabilityID', 'Unknown'),
                    'severity': self._normalize_severity(vuln.get('Severity', 'UNKNOWN')),
                    'type': 'dependency',
                    'component': vuln.get('PkgName', target),
                    'current_version': vuln.get('InstalledVersion', 'Unknown'),
                    'fixed_version': vuln.get('FixedVersion'),
                    'description': vuln.get('Description', ''),
                    'cve_id': vuln.get('VulnerabilityID') if 'CVE-' in str(vuln.get('VulnerabilityID', '')) else None,
                    'source': 'Trivy JSON'
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _parse_blackduck_json(self, data: Dict) -> List[Dict]:
        """Parse BlackDuck JSON format"""
        vulnerabilities = []
        
        for component in data.get('components', []):
            component_name = component.get('componentName', 'Unknown')
            component_version = component.get('componentVersion', 'Unknown')
            
            for vuln in component.get('vulnerabilities', []):
                vulnerability = {
                    'id': vuln.get('vulnerabilityName', 'Unknown'),
                    'name': vuln.get('vulnerabilityName', 'Unknown'),
                    'severity': self._normalize_severity(vuln.get('severity', 'UNKNOWN')),
                    'type': 'dependency',
                    'component': component_name,
                    'current_version': component_version,
                    'fixed_version': vuln.get('remediationTargetVersion'),
                    'description': vuln.get('description', ''),
                    'cve_id': vuln.get('vulnerabilityName') if 'CVE-' in str(vuln.get('vulnerabilityName', '')) else None,
                    'source': 'BlackDuck JSON'
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _parse_generic_json(self, data: Dict) -> List[Dict]:
        """Parse generic JSON format"""
        vulnerabilities = []
        
        # Try to find vulnerabilities array
        vuln_arrays = []
        if 'vulnerabilities' in data:
            vuln_arrays.append(data['vulnerabilities'])
        if 'issues' in data:
            vuln_arrays.append(data['issues'])
        if isinstance(data, list):
            vuln_arrays.append(data)
        
        for vuln_array in vuln_arrays:
            if isinstance(vuln_array, list):
                for item in vuln_array:
                    if isinstance(item, dict):
                        vulnerability = {
                            'id': item.get('id', item.get('vulnerability_id', 'Unknown')),
                            'name': item.get('name', item.get('title', 'Unknown')),
                            'severity': self._normalize_severity(item.get('severity', 'UNKNOWN')),
                            'type': 'dependency',
                            'component': item.get('component', item.get('package', 'Unknown')),
                            'current_version': item.get('version', item.get('current_version', 'Unknown')),
                            'fixed_version': item.get('fixed_version', item.get('fix_version')),
                            'description': item.get('description', item.get('summary', '')),
                            'cve_id': item.get('cve_id', item.get('cve')),
                            'source': 'Generic JSON'
                        }
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    # Keep your existing XML and HTML parsing methods
    async def _parse_xml_report(self, report_path: str) -> List[Dict]:
        """Parse XML reports (OWASP Dependency Check, etc.)"""
        tree = ET.parse(report_path)
        root = tree.getroot()
        
        vulnerabilities = []
        
        # OWASP Dependency Check XML format
        if root.tag == 'analysis' or 'dependency-check' in str(root.tag):
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
                        'source': 'OWASP Dependency Check XML'
                    })
        
        return vulnerabilities
    
    async def _parse_html_report(self, report_path: str) -> List[Dict]:
        """Parse HTML reports"""
        # Implementation for HTML parsing (keep your existing logic)
        return []
    
    async def parse_with_enhancements(self, report_path: str) -> List[Dict]:
        """Parse with automatic fixed version resolution"""
        vulnerabilities = await self.parse_report(report_path)
        
        # Apply enhancements if enabled
        if os.getenv('ENABLE_FIXED_VERSION_RESOLUTION', 'true').lower() == 'true':
            logger.info(f"Enhancing {len(vulnerabilities)} vulnerabilities")
            
            try:
                from app.services.vulnerability_enhancer import VulnerabilityEnhancer
                enhancer = VulnerabilityEnhancer()
                vulnerabilities = await enhancer.enhance_vulnerabilities(vulnerabilities)
            except ImportError:
                logger.warning("VulnerabilityEnhancer not available")
            except Exception as e:
                logger.error(f"Enhancement error: {e}")
        
        return vulnerabilities
    
    def add_scanner_support(self, scanner_id: str, indicators: List[str], field_mappings: Dict[str, List[str]]):
        """Dynamically add support for a new scanner"""
        self.scanner_configs[scanner_id] = {
            'indicators': indicators,
            'fields': field_mappings
        }
        logger.info(f"Added support for {scanner_id} scanner")
    
    def get_supported_scanners(self) -> List[str]:
        """Get list of supported scanners"""
        return list(self.scanner_configs.keys()) + ['generic']
    
    # Keep backward compatibility methods
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
                vuln['type'] = 'dependency'
            
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
            'by_source': {},
            'fixable': 0,
            'critical_count': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            vuln_type = vuln.get('type', 'unknown')
            source = vuln.get('source', 'unknown')
            
            # Count by severity
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            # Count by source
            summary['by_source'][source] = summary['by_source'].get(source, 0) + 1
            
            # Count fixable vulnerabilities
            if vuln.get('fixed_version'):
                summary['fixable'] += 1
            
            # Count critical vulnerabilities
            if severity == 'CRITICAL':
                summary['critical_count'] += 1
        
        return summary
