"""
Vulnerability Report Parsers for different formats
Updated with BlackDuck CSV and HTML support
"""

import json
import xml.etree.ElementTree as ET
import csv
import logging
from typing import Dict, List, Optional
import os
import re
from html.parser import HTMLParser
import io

logger = logging.getLogger(__name__)

class BlackDuckHTMLParser(HTMLParser):
    """Custom HTML parser for BlackDuck HTML reports"""
    
    def __init__(self):
        super().__init__()
        self.vulnerabilities = []
        self.current_vulnerability = {}
        self.current_tag = None
        self.current_data = ""
        self.in_vulnerability_section = False
        self.in_table_row = False
        self.current_cell_index = 0
        self.table_headers = []
        
    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        
        # Look for vulnerability table or section
        if tag == 'table':
            # Check if this is a vulnerability table
            for attr_name, attr_value in attrs:
                if 'vulnerab' in attr_value.lower() or 'security' in attr_value.lower():
                    self.in_vulnerability_section = True
        
        elif tag == 'tr' and self.in_vulnerability_section:
            self.in_table_row = True
            self.current_cell_index = 0
            self.current_vulnerability = {}
            
    def handle_endtag(self, tag):
        if tag == 'table' and self.in_vulnerability_section:
            self.in_vulnerability_section = False
            
        elif tag == 'tr' and self.in_table_row:
            self.in_table_row = False
            if self.current_vulnerability:
                self.vulnerabilities.append(self.current_vulnerability)
                
        self.current_tag = None
        self.current_data = ""
        
    def handle_data(self, data):
        if self.in_table_row and self.current_tag == 'td':
            data = data.strip()
            if data:
                # Map table cell data to vulnerability fields based on position
                if self.current_cell_index == 0:
                    self.current_vulnerability['component'] = data
                elif self.current_cell_index == 1:
                    self.current_vulnerability['current_version'] = data
                elif self.current_cell_index == 2:
                    self.current_vulnerability['name'] = data
                elif self.current_cell_index == 3:
                    self.current_vulnerability['severity'] = data.upper()
                elif self.current_cell_index == 4:
                    self.current_vulnerability['description'] = data
                elif self.current_cell_index == 5:
                    self.current_vulnerability['fixed_version'] = data
                
                self.current_cell_index += 1

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
            elif file_extension == '.csv':
                return await self._parse_csv_report(report_path)
            elif file_extension == '.html' or file_extension == '.htm':
                return await self._parse_html_report(report_path)
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")
                
        except Exception as e:
            logger.error(f"Error parsing vulnerability report: {str(e)}")
            raise
    
    async def _parse_csv_report(self, report_path: str) -> List[Dict]:
        """Parse CSV vulnerability reports (BlackDuck CSV format)"""
        vulnerabilities = []
        
        try:
            with open(report_path, 'r', encoding='utf-8', newline='') as csvfile:
                # Try to detect delimiter
                sample = csvfile.read(1024)
                csvfile.seek(0)
                
                # Common delimiters in BlackDuck CSV files
                delimiter = ','
                if ';' in sample and sample.count(';') > sample.count(','):
                    delimiter = ';'
                elif '\t' in sample:
                    delimiter = '\t'
                
                csv_reader = csv.DictReader(csvfile, delimiter=delimiter)
                
                # Normalize headers (remove whitespace, make lowercase for matching)
                fieldnames = [field.strip().lower() if field else '' for field in csv_reader.fieldnames]
                
                for row_num, row in enumerate(csv_reader, start=1):
                    try:
                        vulnerability = self._parse_csv_row(row, fieldnames)
                        if vulnerability:
                            vulnerabilities.append(vulnerability)
                    except Exception as e:
                        logger.warning(f"Error parsing CSV row {row_num}: {str(e)}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error reading CSV file: {str(e)}")
            raise
            
        return vulnerabilities
    
    def _parse_csv_row(self, row: Dict, fieldnames: List[str]) -> Optional[Dict]:
        """Parse a single CSV row into vulnerability format"""
        try:
            # Create a normalized row with lowercase keys
            normalized_row = {}
            for i, field in enumerate(fieldnames):
                if field and i < len(list(row.values())):
                    value = list(row.values())[i]
                    normalized_row[field] = value.strip() if value else ''
            
            # Map BlackDuck CSV fields to our vulnerability format
            vulnerability = {}
            
            # Component name mapping
            component = self._get_csv_field(normalized_row, [
                'component', 'component name', 'componentname', 'package', 'library', 'dependency'
            ])
            
            # Version mapping
            current_version = self._get_csv_field(normalized_row, [
                'version', 'component version', 'componentversion', 'current version', 'installed version'
            ])
            
            # Vulnerability name mapping
            vuln_name = self._get_csv_field(normalized_row, [
                'vulnerability', 'vulnerability name', 'vulnerabilityname', 'cve', 'cve id', 'issue'
            ])
            
            # Severity mapping
            severity = self._get_csv_field(normalized_row, [
                'severity', 'risk', 'priority', 'criticality', 'impact'
            ])
            
            # Description mapping
            description = self._get_csv_field(normalized_row, [
                'description', 'summary', 'details', 'vulnerability description'
            ])
            
            # Fixed version mapping
            fixed_version = self._get_csv_field(normalized_row, [
                'fixed version', 'fixedversion', 'remediation version', 'target version', 'solution version'
            ])
            
            # Base URL or source mapping
            source_url = self._get_csv_field(normalized_row, [
                'url', 'source', 'link', 'reference', 'more info'
            ])
            
            # Only create vulnerability if we have essential fields
            if component and vuln_name:
                vulnerability = {
                    'id': vuln_name or f"{component}-vuln",
                    'name': vuln_name or 'Unknown Vulnerability',
                    'severity': severity.upper() if severity else 'UNKNOWN',
                    'type': 'dependency',  # CSV reports are typically for dependencies
                    'component': component,
                    'current_version': current_version or 'Unknown',
                    'fixed_version': fixed_version,
                    'description': description or '',
                    'cve_id': vuln_name if vuln_name and vuln_name.startswith('CVE-') else None,
                    'source': 'BlackDuck CSV',
                    'source_url': source_url
                }
                
                return vulnerability
                
        except Exception as e:
            logger.error(f"Error parsing CSV row: {str(e)}")
            
        return None
    
    def _get_csv_field(self, row: Dict, possible_fields: List[str]) -> Optional[str]:
        """Get field value from CSV row using multiple possible field names"""
        for field in possible_fields:
            if field in row and row[field]:
                return row[field].strip()
        return None
    
    async def _parse_html_report(self, report_path: str) -> List[Dict]:
        """Parse HTML vulnerability reports (BlackDuck HTML format)"""
        vulnerabilities = []
        
        try:
            with open(report_path, 'r', encoding='utf-8') as htmlfile:
                html_content = htmlfile.read()
                
            # Method 1: Try custom HTML parser
            vulnerabilities.extend(self._parse_html_with_custom_parser(html_content))
            
            # Method 2: Try regex pattern matching if custom parser didn't find much
            if len(vulnerabilities) < 5:  # Fallback if we didn't find many vulnerabilities
                regex_vulns = self._parse_html_with_regex(html_content)
                vulnerabilities.extend(regex_vulns)
                
        except Exception as e:
            logger.error(f"Error reading HTML file: {str(e)}")
            raise
            
        return vulnerabilities
    
    def _parse_html_with_custom_parser(self, html_content: str) -> List[Dict]:
        """Parse HTML using custom HTML parser"""
        try:
            parser = BlackDuckHTMLParser()
            parser.feed(html_content)
            
            # Convert parsed data to our vulnerability format
            vulnerabilities = []
            for vuln_data in parser.vulnerabilities:
                if vuln_data.get('component') and vuln_data.get('name'):
                    vulnerability = {
                        'id': vuln_data.get('name', f"{vuln_data.get('component')}-vuln"),
                        'name': vuln_data.get('name', 'Unknown Vulnerability'),
                        'severity': vuln_data.get('severity', 'UNKNOWN').upper(),
                        'type': 'dependency',
                        'component': vuln_data.get('component', 'Unknown'),
                        'current_version': vuln_data.get('current_version', 'Unknown'),
                        'fixed_version': vuln_data.get('fixed_version'),
                        'description': vuln_data.get('description', ''),
                        'cve_id': vuln_data.get('name') if vuln_data.get('name', '').startswith('CVE-') else None,
                        'source': 'BlackDuck HTML'
                    }
                    vulnerabilities.append(vulnerability)
                    
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error with custom HTML parser: {str(e)}")
            return []
    
    def _parse_html_with_regex(self, html_content: str) -> List[Dict]:
        """Parse HTML using regex patterns for BlackDuck reports"""
        vulnerabilities = []
        
        try:
            # Remove HTML tags for easier text processing
            import re
            text_content = re.sub(r'<[^>]+>', ' ', html_content)
            text_content = re.sub(r'\s+', ' ', text_content)
            
            # Common patterns in BlackDuck HTML reports
            patterns = [
                # Pattern for CVE listings
                r'(CVE-\d{4}-\d+).*?(?:severity|risk).*?(critical|high|medium|low)',
                # Pattern for component listings
                r'component[:\s]+([^\s]+).*?version[:\s]+([^\s]+).*?(CVE-\d{4}-\d+)',
                # Pattern for vulnerability tables
                r'(CVE-\d{4}-\d+)[^<]*([A-Za-z-_]+)[^<]*(\d+\.\d+[^<]*)(Critical|High|Medium|Low)'
            ]
            
            vuln_counter = 0
            for pattern in patterns:
                matches = re.finditer(pattern, text_content, re.IGNORECASE)
                
                for match in matches:
                    groups = match.groups()
                    if len(groups) >= 2:
                        vuln_counter += 1
                        
                        # Extract data based on pattern structure
                        if 'CVE-' in groups[0]:
                            cve_id = groups[0]
                            severity = groups[1] if len(groups) > 1 else 'UNKNOWN'
                            component = groups[2] if len(groups) > 2 else 'Unknown'
                            version = groups[3] if len(groups) > 3 else 'Unknown'
                        else:
                            component = groups[0]
                            version = groups[1] if len(groups) > 1 else 'Unknown'
                            cve_id = groups[2] if len(groups) > 2 else f'HTML-VULN-{vuln_counter}'
                            severity = groups[3] if len(groups) > 3 else 'UNKNOWN'
                        
                        vulnerability = {
                            'id': cve_id,
                            'name': cve_id,
                            'severity': severity.upper(),
                            'type': 'dependency',
                            'component': component,
                            'current_version': version,
                            'fixed_version': None,
                            'description': f'Vulnerability found in {component}',
                            'cve_id': cve_id if cve_id.startswith('CVE-') else None,
                            'source': 'BlackDuck HTML (Regex)'
                        }
                        
                        vulnerabilities.append(vulnerability)
                        
                        # Limit to avoid duplicates
                        if len(vulnerabilities) > 100:
                            break
                            
        except Exception as e:
            logger.error(f"Error with regex HTML parsing: {str(e)}")
            
        return vulnerabilities[:50]  # Limit to 50 vulnerabilities to avoid overwhelming
    
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
                    'source': 'BlackDuck JSON'
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
                    'fixed_version': None,
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
                    'source': 'OWASP Dependency Check XML'
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


    
    async def parse_with_enhancements(self, report_path: str) -> List[Dict]:
        """Enhanced version of your existing parse method"""
        from app.services.vulnerability_enhancer import VulnerabilityEnhancer
        
        # Use your existing parsing logic
        vulnerabilities = await self.parse_report(report_path)
        
        # Check if enhancement is enabled
        import os
        if os.getenv('ENABLE_FIXED_VERSION_RESOLUTION', 'true').lower() == 'true':
            enhancer = VulnerabilityEnhancer()
            vulnerabilities = await enhancer.enhance_vulnerabilities(vulnerabilities)
        
        return vulnerabilities
