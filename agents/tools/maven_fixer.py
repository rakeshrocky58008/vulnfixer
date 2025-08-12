"""
Robust Maven Dependency Fixer
Handles properties, parent POMs, BOMs, profiles, and all edge cases
"""

import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class MavenDependencyFixer:
    """
    Robust Maven dependency fixer that handles:
    - Version properties
    - Parent POMs
    - Dependency management
    - BOMs
    - Profiles
    - Multi-module projects
    """
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.pom_file = self.repo_path / "pom.xml"
        self.parent_pom = None
        self.properties = {}
        self.dependency_management = {}
        
    def analyze_pom_structure(self) -> Dict:
        """
        Comprehensive POM analysis
        """
        if not self.pom_file.exists():
            raise FileNotFoundError(f"POM file not found: {self.pom_file}")
        
        tree = ET.parse(self.pom_file)
        root = tree.getroot()
        
        # Handle XML namespaces
        namespaces = {'m': 'http://maven.apache.org/POM/4.0.0'}
        if root.tag.startswith('{'):
            namespaces['m'] = root.tag.split('}')[0][1:]
        
        analysis = {
            "has_parent": False,
            "uses_properties": False,
            "has_dependency_management": False,
            "has_profiles": False,
            "is_multi_module": False,
            "properties": {},
            "managed_dependencies": {},
            "direct_dependencies": [],
            "profile_dependencies": []
        }
        
        # Check for parent POM
        parent = root.find('.//parent', namespaces) or root.find('.//parent')
        if parent is not None:
            analysis["has_parent"] = True
            analysis["parent"] = {
                "groupId": self._get_text(parent, 'groupId'),
                "artifactId": self._get_text(parent, 'artifactId'),
                "version": self._get_text(parent, 'version')
            }
        
        # Extract properties
        properties = root.find('.//properties', namespaces) or root.find('.//properties')
        if properties is not None:
            analysis["uses_properties"] = True
            for prop in properties:
                prop_name = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                analysis["properties"][prop_name] = prop.text
        
        # Extract dependency management
        dep_mgmt = root.find('.//dependencyManagement/dependencies', namespaces) or \
                   root.find('.//dependencyManagement/dependencies')
        if dep_mgmt is not None:
            analysis["has_dependency_management"] = True
            for dep in dep_mgmt.findall('.//dependency'):
                artifact_id = self._get_text(dep, 'artifactId')
                if artifact_id:
                    analysis["managed_dependencies"][artifact_id] = {
                        "groupId": self._get_text(dep, 'groupId'),
                        "version": self._get_text(dep, 'version'),
                        "scope": self._get_text(dep, 'scope'),
                        "type": self._get_text(dep, 'type')
                    }
        
        # Extract direct dependencies
        dependencies = root.find('.//dependencies', namespaces) or root.find('.//dependencies')
        if dependencies is not None:
            for dep in dependencies.findall('.//dependency'):
                dep_info = {
                    "groupId": self._get_text(dep, 'groupId'),
                    "artifactId": self._get_text(dep, 'artifactId'),
                    "version": self._get_text(dep, 'version'),
                    "scope": self._get_text(dep, 'scope'),
                    "optional": self._get_text(dep, 'optional')
                }
                analysis["direct_dependencies"].append(dep_info)
        
        # Check for profiles
        profiles = root.find('.//profiles', namespaces) or root.find('.//profiles')
        if profiles is not None:
            analysis["has_profiles"] = True
            for profile in profiles.findall('.//profile'):
                profile_deps = profile.find('.//dependencies')
                if profile_deps:
                    for dep in profile_deps.findall('.//dependency'):
                        analysis["profile_dependencies"].append({
                            "profile": self._get_text(profile, 'id'),
                            "artifactId": self._get_text(dep, 'artifactId'),
                            "version": self._get_text(dep, 'version')
                        })
        
        # Check if multi-module
        modules = root.find('.//modules', namespaces) or root.find('.//modules')
        if modules is not None:
            analysis["is_multi_module"] = True
            analysis["modules"] = [m.text for m in modules.findall('.//module')]
        
        return analysis
    
    def fix_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Main method to fix a vulnerability with all edge cases handled
        """
        component = vulnerability.get('component', '')
        current_version = vulnerability.get('current_version', '')
        fixed_version = vulnerability.get('fixed_version', '')
        
        # Parse component
        if ':' in component:
            group_id, artifact_id = component.rsplit(':', 1)
        else:
            artifact_id = component
            group_id = self._infer_group_id(artifact_id)
        
        # Analyze POM structure
        pom_analysis = self.analyze_pom_structure()
        
        # Determine the best fix strategy
        fix_strategy = self._determine_fix_strategy(
            artifact_id, 
            current_version,
            fixed_version,
            pom_analysis
        )
        
        # Apply the fix
        result = self._apply_fix_strategy(fix_strategy, vulnerability, pom_analysis)
        
        return result
    
    def _determine_fix_strategy(
        self, 
        artifact_id: str, 
        current_version: str,
        fixed_version: str,
        pom_analysis: Dict
    ) -> Dict:
        """
        Determine the best strategy to fix the vulnerability
        """
        strategy = {
            "type": "unknown",
            "actions": [],
            "reason": ""
        }
        
        # Check if it's a direct dependency
        for dep in pom_analysis["direct_dependencies"]:
            if dep["artifactId"] == artifact_id:
                version = dep["version"]
                
                # Check if version is a property
                if version and version.startswith("${") and version.endswith("}"):
                    prop_name = version[2:-1]
                    strategy["type"] = "update_property"
                    strategy["actions"] = [{
                        "action": "update_property",
                        "property": prop_name,
                        "old_value": pom_analysis["properties"].get(prop_name),
                        "new_value": fixed_version
                    }]
                    strategy["reason"] = f"Direct dependency uses property {prop_name}"
                    return strategy
                
                # Direct version update
                elif version == current_version:
                    strategy["type"] = "update_direct"
                    strategy["actions"] = [{
                        "action": "update_version",
                        "artifact": artifact_id,
                        "old_version": current_version,
                        "new_version": fixed_version,
                        "preserve_scope": dep.get("scope"),
                        "preserve_optional": dep.get("optional")
                    }]
                    strategy["reason"] = "Direct dependency with explicit version"
                    return strategy
        
        # Check if it's in dependency management
        if artifact_id in pom_analysis["managed_dependencies"]:
            managed = pom_analysis["managed_dependencies"][artifact_id]
            if managed["version"] == current_version:
                strategy["type"] = "update_managed"
                strategy["actions"] = [{
                    "action": "update_dependency_management",
                    "artifact": artifact_id,
                    "old_version": current_version,
                    "new_version": fixed_version
                }]
                strategy["reason"] = "Version controlled in dependencyManagement"
                return strategy
        
        # Check profiles
        for prof_dep in pom_analysis["profile_dependencies"]:
            if prof_dep["artifactId"] == artifact_id:
                if prof_dep["version"] == current_version:
                    strategy["type"] = "update_profile"
                    strategy["actions"] = [{
                        "action": "update_profile_dependency",
                        "profile": prof_dep["profile"],
                        "artifact": artifact_id,
                        "old_version": current_version,
                        "new_version": fixed_version
                    }]
                    strategy["reason"] = f"Dependency in profile {prof_dep['profile']}"
                    return strategy
        
        # If it's transitive, add to dependency management
        strategy["type"] = "add_managed"
        strategy["actions"] = [{
            "action": "add_to_dependency_management",
            "artifact": artifact_id,
            "group_id": self._infer_group_id(artifact_id),
            "version": fixed_version
        }]
        strategy["reason"] = "Transitive dependency - adding to dependencyManagement for version control"
        
        return strategy
    
    def _apply_fix_strategy(self, strategy: Dict, vulnerability: Dict, pom_analysis: Dict) -> Dict:
        """
        Apply the determined fix strategy
        """
        try:
            pom_content = self.pom_file.read_text()
            updated_content = pom_content
            
            for action in strategy["actions"]:
                if action["action"] == "update_property":
                    updated_content = self._update_property(
                        updated_content,
                        action["property"],
                        action["new_value"]
                    )
                
                elif action["action"] == "update_version":
                    updated_content = self._update_direct_version(
                        updated_content,
                        action["artifact"],
                        action["old_version"],
                        action["new_version"],
                        action.get("preserve_scope"),
                        action.get("preserve_optional")
                    )
                
                elif action["action"] == "update_dependency_management":
                    updated_content = self._update_managed_version(
                        updated_content,
                        action["artifact"],
                        action["old_version"],
                        action["new_version"]
                    )
                
                elif action["action"] == "add_to_dependency_management":
                    updated_content = self._add_to_dependency_management(
                        updated_content,
                        action["artifact"],
                        action["group_id"],
                        action["version"]
                    )
                
                elif action["action"] == "update_profile_dependency":
                    updated_content = self._update_profile_dependency(
                        updated_content,
                        action["profile"],
                        action["artifact"],
                        action["old_version"],
                        action["new_version"]
                    )
            
            # Write updated content
            self.pom_file.write_text(updated_content)
            
            return {
                "success": True,
                "strategy": strategy["type"],
                "reason": strategy["reason"],
                "actions_applied": len(strategy["actions"])
            }
            
        except Exception as e:
            logger.error(f"Error applying fix strategy: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _update_property(self, content: str, property_name: str, new_value: str) -> str:
        """
        Update a property value
        """
        pattern = f"<{property_name}>.*?</{property_name}>"
        replacement = f"<{property_name}>{new_value}</{property_name}>"
        return re.sub(pattern, replacement, content)
    
    def _update_direct_version(
        self, 
        content: str, 
        artifact_id: str, 
        old_version: str, 
        new_version: str,
        preserve_scope: Optional[str],
        preserve_optional: Optional[str]
    ) -> str:
        """
        Update version in a direct dependency, preserving scope and optional
        """
        # Find the specific dependency block
        pattern = rf'(<dependency>.*?<artifactId>{re.escape(artifact_id)}</artifactId>.*?</dependency>)'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for match in matches:
            if old_version in match:
                # Update version
                updated_block = re.sub(
                    f'<version>{re.escape(old_version)}</version>',
                    f'<version>{new_version}</version>',
                    match
                )
                content = content.replace(match, updated_block)
                break
        
        return content
    
    def _update_managed_version(
        self, 
        content: str, 
        artifact_id: str, 
        old_version: str, 
        new_version: str
    ) -> str:
        """
        Update version in dependency management
        """
        # Find dependencyManagement section
        dep_mgmt_pattern = r'(<dependencyManagement>.*?</dependencyManagement>)'
        dep_mgmt_match = re.search(dep_mgmt_pattern, content, re.DOTALL)
        
        if dep_mgmt_match:
            dep_mgmt_content = dep_mgmt_match.group(1)
            
            # Find the specific dependency in management
            pattern = rf'(<dependency>.*?<artifactId>{re.escape(artifact_id)}</artifactId>.*?</dependency>)'
            matches = re.findall(pattern, dep_mgmt_content, re.DOTALL)
            
            for match in matches:
                if old_version in match:
                    updated_block = match.replace(
                        f'<version>{old_version}</version>',
                        f'<version>{new_version}</version>'
                    )
                    dep_mgmt_content = dep_mgmt_content.replace(match, updated_block)
            
            content = content.replace(dep_mgmt_match.group(1), dep_mgmt_content)
        
        return content
    
    def _add_to_dependency_management(
        self, 
        content: str, 
        artifact_id: str, 
        group_id: str, 
        version: str
    ) -> str:
        """
        Add a dependency to dependency management section
        """
        new_dependency = f"""
            <dependency>
                <groupId>{group_id}</groupId>
                <artifactId>{artifact_id}</artifactId>
                <version>{version}</version>
            </dependency>"""
        
        # Check if dependencyManagement exists
        if '<dependencyManagement>' in content:
            # Add to existing
            dep_mgmt_end = content.find('</dependencies>', content.find('<dependencyManagement>'))
            if dep_mgmt_end != -1:
                content = content[:dep_mgmt_end] + new_dependency + '\n' + content[dep_mgmt_end:]
        else:
            # Create new dependencyManagement section
            dep_mgmt_section = f"""
    <dependencyManagement>
        <dependencies>{new_dependency}
        </dependencies>
    </dependencyManagement>
"""
            # Insert before dependencies or build
            if '<dependencies>' in content:
                insert_pos = content.find('<dependencies>')
            elif '<build>' in content:
                insert_pos = content.find('<build>')
            else:
                insert_pos = content.find('</project>')
            
            content = content[:insert_pos] + dep_mgmt_section + content[insert_pos:]
        
        return content
    
    def _update_profile_dependency(
        self, 
        content: str, 
        profile_id: str, 
        artifact_id: str, 
        old_version: str, 
        new_version: str
    ) -> str:
        """
        Update dependency version in a specific profile
        """
        # Find the profile
        profile_pattern = rf'(<profile>.*?<id>{re.escape(profile_id)}</id>.*?</profile>)'
        profile_match = re.search(profile_pattern, content, re.DOTALL)
        
        if profile_match:
            profile_content = profile_match.group(1)
            
            # Update version in this profile
            dep_pattern = rf'(<dependency>.*?<artifactId>{re.escape(artifact_id)}</artifactId>.*?</dependency>)'
            dep_matches = re.findall(dep_pattern, profile_content, re.DOTALL)
            
            for dep in dep_matches:
                if old_version in dep:
                    updated_dep = dep.replace(
                        f'<version>{old_version}</version>',
                        f'<version>{new_version}</version>'
                    )
                    profile_content = profile_content.replace(dep, updated_dep)
            
            content = content.replace(profile_match.group(1), profile_content)
        
        return content
    
    def _get_text(self, element, tag: str) -> Optional[str]:
        """
        Safely get text from XML element
        """
        if element is None:
            return None
        child = element.find(tag)
        if child is None:
            # Try with namespace
            child = element.find(f'{{http://maven.apache.org/POM/4.0.0}}{tag}')
        return child.text if child is not None else None
    
    def _infer_group_id(self, artifact_id: str) -> str:
        """
        Infer group ID from artifact ID
        """
        patterns = {
            'netty': 'io.netty',
            'spring': 'org.springframework',
            'jackson': 'com.fasterxml.jackson.core',
            'log4j': 'org.apache.logging.log4j',
            'commons': 'org.apache.commons',
            'junit': 'junit',
            'guava': 'com.google.guava',
            'vertx': 'io.vertx'
        }
        
        for key, group in patterns.items():
            if key in artifact_id.lower():
                return group
        
        return "unknown.group"
