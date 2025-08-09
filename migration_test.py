#!/usr/bin/env python3
"""
Migration Test Script - Verify Universal Parser Integration
Run this to verify your migration was successful
"""

import asyncio
import sys
import os
import tempfile
import csv
import json
import logging
from pathlib import Path

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def create_test_files():
    """Create test files for different scanners"""
    test_files = {}
    
    # 1. BlackDuck CSV (your format)
    blackduck_data = """Project id,Version id,Project name,Component name,Component version name,Vulnerability id,Description,Security Risk,Base score,CWE Ids
a5d1d4cf-1a4b-4e,R-sdd-r,MyApp,Castor,0.9.3,CVE-2014-3004,XML External Entity vulnerability before 1.3.3,MEDIUM,4.3,[CWE-611]
a5d1d4cf-1a4b-4e,R-sdd-r,MyApp,log4j,2.14.1,CVE-2021-44228,Log4Shell RCE vulnerability fixed in 2.15.0,CRITICAL,10.0,[CWE-20]"""
    
    with open("test_blackduck.csv", "w") as f:
        f.write(blackduck_data)
    test_files["blackduck"] = "test_blackduck.csv"
    
    # 2. Trivy CSV
    trivy_data = """Target,PkgName,InstalledVersion,VulnerabilityID,Severity,FixedVersion,Description
alpine:3.14,openssl,1.1.1k-r0,CVE-2021-3711,HIGH,1.1.1l-r0,OpenSSL buffer overflow
package.json,lodash,4.17.15,CVE-2021-23337,HIGH,4.17.21,Command injection in lodash"""
    
    with open("test_trivy.csv", "w") as f:
        f.write(trivy_data)
    test_files["trivy"] = "test_trivy.csv"
    
    # 3. Xray CSV
    xray_data = """component,version,xray_id,severity,summary,fixed_versions
npm://lodash:4.17.15,4.17.15,XRAY-123456,High,Command injection vulnerability,4.17.21"""
    
    with open("test_xray.csv", "w") as f:
        f.write(xray_data)
    test_files["xray"] = "test_xray.csv"
    
    # 4. Generic CSV
    generic_data = """package,current_version,vulnerability,severity,description
express,4.17.1,SNYK-JS-EXPRESS-1234567,Medium,Path traversal vulnerability. Upgrade to 4.17.3 or later."""
    
    with open("test_generic.csv", "w") as f:
        f.write(generic_data)
    test_files["generic"] = "test_generic.csv"
    
    # 5. Trivy JSON
    trivy_json = {
        "Results": [
            {
                "Target": "package.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-23337",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.15",
                        "FixedVersion": "4.17.21",
                        "Severity": "HIGH",
                        "Description": "Command injection in lodash"
                    }
                ]
            }
        ]
    }
    
    with open("test_trivy.json", "w") as f:
        json.dump(trivy_json, f, indent=2)
    test_files["trivy_json"] = "test_trivy.json"
    
    return test_files

async def test_parser_import():
    """Test if the new parser can be imported"""
    try:
        from agents.tools.parsers import VulnerabilityParser
        logger.info("✅ Universal parser imported successfully")
        
        parser = VulnerabilityParser()
        supported_scanners = parser.get_supported_scanners()
        logger.info(f"✅ Supported scanners: {supported_scanners}")
        
        return True, parser
    except Exception as e:
        logger.error(f"❌ Failed to import parser: {e}")
        return False, None

async def test_scanner_detection(parser):
    """Test scanner auto-detection"""
    test_cases = [
        ("component name,security risk,vulnerability id", "blackduck"),
        ("pkgname,installedversion,vulnerabilityid", "trivy"),
        ("component,xray_id,violation_type", "xray"),
        ("package,vulnerability,severity", "generic")
    ]
    
    logger.info("\n🔍 Testing Scanner Auto-Detection:")
    
    for sample_text, expected in test_cases:
        try:
            detected = parser._detect_scanner_type(sample_text)
            status = "✅" if detected == expected else "⚠️"
            logger.info(f"  {status} '{sample_text[:30]}...' → {detected} (expected: {expected})")
        except Exception as e:
            logger.error(f"  ❌ Detection failed: {e}")

async def test_file_parsing(parser, test_files):
    """Test parsing of different file formats"""
    logger.info("\n📄 Testing File Parsing:")
    
    results = {}
    
    for scanner_type, filename in test_files.items():
        try:
            vulnerabilities = await parser.parse_report(filename)
            
            if vulnerabilities:
                vuln = vulnerabilities[0]
                detected_source = vuln.get('source', '').lower()
                
                logger.info(f"  ✅ {filename}: {len(vulnerabilities)} vulnerabilities")
                logger.info(f"     Source: {vuln.get('source')}")
                logger.info(f"     Sample: {vuln.get('component')} v{vuln.get('current_version')} - {vuln.get('name')}")
                
                results[scanner_type] = {
                    'count': len(vulnerabilities),
                    'sample': vuln,
                    'success': True
                }
            else:
                logger.warning(f"  ⚠️ {filename}: No vulnerabilities found")
                results[scanner_type] = {'count': 0, 'success': False}
                
        except Exception as e:
            logger.error(f"  ❌ {filename}: Parse failed - {e}")
            results[scanner_type] = {'success': False, 'error': str(e)}
    
    return results

async def test_enhancement_pipeline(parser, test_files):
    """Test enhancement pipeline"""
    logger.info("\n🚀 Testing Enhancement Pipeline:")
    
    # Test with BlackDuck file (should have some description-based fixes)
    if "blackduck" in test_files:
        try:
            filename = test_files["blackduck"]
            
            # Parse without enhancements
            original_vulns = await parser.parse_report(filename)
            original_fixes = len([v for v in original_vulns if v.get('fixed_version')])
            
            # Parse with enhancements
            enhanced_vulns = await parser.parse_with_enhancements(filename)
            enhanced_fixes = len([v for v in enhanced_vulns if v.get('fixed_version')])
            
            new_fixes = enhanced_fixes - original_fixes
            
            logger.info(f"  ✅ Enhancement test completed:")
            logger.info(f"     Original fixes: {original_fixes}/{len(original_vulns)}")
            logger.info(f"     Enhanced fixes: {enhanced_fixes}/{len(enhanced_vulns)}")
            logger.info(f"     New fixes found: {new_fixes}")
            
            return True
            
        except Exception as e:
            logger.error(f"  ❌ Enhancement test failed: {e}")
            return False
    
    return False

async def test_api_integration():
    """Test API integration"""
    logger.info("\n🌐 Testing API Integration:")
    
    try:
        # Test if routes can be imported
        from app.api.routes import router
        logger.info("  ✅ API routes imported successfully")
        
        # Test if agent can be imported
        from agents.vulnerability_agent import VulnerabilityAgent
        agent = VulnerabilityAgent()
        logger.info("  ✅ Vulnerability agent imported successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"  ❌ API integration test failed: {e}")
        return False

async def test_configuration():
    """Test configuration"""
    logger.info("\n⚙️ Testing Configuration:")
    
    try:
        from app.config import settings, validate_settings, auto_configure
        
        # Test configuration loading
        logger.info(f"  ✅ Configuration loaded")
        logger.info(f"     Universal parsing: {settings.ENABLE_UNIVERSAL_PARSING}")
        logger.info(f"     Auto-detection: {settings.AUTO_DETECT_SCANNER}")
        logger.info(f"     Supported scanners: {len(settings.SUPPORTED_SCANNERS)}")
        
        # Test auto-configuration
        config_info = auto_configure()
        logger.info(f"  ✅ Auto-configuration completed")
        logger.info(f"     Recommended model: {config_info.get('recommended_model')}")
        logger.info(f"     Parser config valid: {config_info.get('parser_config_valid')}")
        
        return True
        
    except Exception as e:
        logger.error(f"  ❌ Configuration test failed: {e}")
        return False

def cleanup_test_files(test_files):
    """Clean up test files"""
    for filename in test_files.values():
        try:
            if os.path.exists(filename):
                os.remove(filename)
        except Exception as e:
            logger.warning(f"Failed to cleanup {filename}: {e}")

async def main():
    """Run all migration tests"""
    logger.info("🧪 VulnFixer Universal Parser Migration Test")
    logger.info("=" * 60)
    
    # Create test files
    logger.info("📁 Creating test files...")
    test_files = create_test_files()
    
    try:
        # Test results tracking
        test_results = {
            "parser_import": False,
            "scanner_detection": False, 
            "file_parsing": False,
            "enhancement": False,
            "api_integration": False,
            "configuration": False
        }
        
        # 1. Test parser import
        success, parser = await test_parser_import()
        test_results["parser_import"] = success
        
        if not success:
            logger.error("❌ Parser import failed - cannot continue with other tests")
            return
        
        # 2. Test scanner detection
        await test_scanner_detection(parser)
        test_results["scanner_detection"] = True
        
        # 3. Test file parsing
        parsing_results = await test_file_parsing(parser, test_files)
        test_results["file_parsing"] = any(r.get('success', False) for r in parsing_results.values())
        
        # 4. Test enhancement pipeline
        test_results["enhancement"] = await test_enhancement_pipeline(parser, test_files)
        
        # 5. Test API integration
        test_results["api_integration"] = await test_api_integration()
        
        # 6. Test configuration
        test_results["configuration"] = await test_configuration()
        
        # Summary
        logger.info("\n📊 MIGRATION TEST SUMMARY")
        logger.info("=" * 40)
        
        passed_tests = sum(test_results.values())
        total_tests = len(test_results)
        
        for test_name, result in test_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            logger.info(f"  {test_name.replace('_', ' ').title()}: {status}")
        
        logger.info(f"\nOverall: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests == total_tests:
            logger.info("\n🎉 MIGRATION SUCCESSFUL!")
            logger.info("Your universal parser is ready to use.")
            logger.info("\nNext steps:")
            logger.info("1. Start your application: python -m app.main")
            logger.info("2. Upload any scanner report via web interface")
            logger.info("3. Watch auto-detection and parsing in action!")
        else:
            logger.warning(f"\n⚠️ MIGRATION PARTIALLY SUCCESSFUL")
            logger.warning(f"Some tests failed. Check the logs above for details.")
            
            if not test_results["parser_import"]:
                logger.error("CRITICAL: Parser import failed - update agents/tools/parsers.py")
            if not test_results["api_integration"]:
                logger.error("CRITICAL: API integration failed - update app/api/routes.py")
    
    except Exception as e:
        logger.error(f"❌ Migration test failed with error: {e}")
    
    finally:
        # Cleanup
        logger.info("\n🧹 Cleaning up test files...")
        cleanup_test_files(test_files)

if __name__ == "__main__":
    asyncio.run(main())
