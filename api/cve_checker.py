"""
Open Source CVE Checker for CERRT
Uses only free/open-source services:
- OSV (Open Source Vulnerabilities) API - FREE
- NVD (National Vulnerability Database) API - FREE
- Retire.js database - FREE/Open Source
"""

import requests
import re
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


# ============================================
# OSV API (Primary - Best for Libraries)
# ============================================

def check_library_vulnerabilities_osv(
    library_name: str, 
    version: str, 
    ecosystem: str = 'npm'
) -> List[Dict[str, Any]]:
    """
    Check vulnerabilities using OSV API (Free, no API key needed!)
    
    Supported ecosystems:
    - npm (JavaScript/Node.js)
    - PyPI (Python)
    - Maven (Java)
    - Go
    - RubyGems (Ruby)
    - crates.io (Rust)
    - Packagist (PHP)
    - NuGet (.NET)
    - Hex (Erlang/Elixir)
    
    Args:
        library_name: Name of the library (e.g., 'jquery', 'react')
        version: Version string (e.g., '3.6.0')
        ecosystem: Package ecosystem (default: 'npm')
    
    Returns:
        List of vulnerability dictionaries
    """
    api_url = "https://api.osv.dev/v1/query"
    
    # Normalize library name
    library_name = library_name.lower().strip()
    version = version.strip()
    
    payload = {
        "package": {
            "name": library_name,
            "ecosystem": ecosystem.upper()
        },
        "version": version
    }
    
    try:
        logger.info(f"Checking OSV for {library_name}@{version} in {ecosystem}")
        response = requests.post(api_url, json=payload, timeout=30)
        
        if response.status_code != 200:
            logger.warning(f"OSV API returned status {response.status_code}")
            return []
        
        data = response.json()
        
        vulnerabilities = []
        for vuln in data.get('vulns', []):
            # Extract CVE IDs from aliases
            cve_ids = [
                alias for alias in vuln.get('aliases', []) 
                if alias.startswith('CVE-')
            ]
            
            # Get severity and calculate CVSS score
            severity = vuln.get('database_specific', {}).get('severity', 'UNKNOWN')
            cvss_score = extract_cvss_from_osv(vuln)
            
            vulnerabilities.append({
                'id': vuln.get('id'),
                'cve_ids': cve_ids,
                'primary_cve': cve_ids[0] if cve_ids else None,
                'summary': vuln.get('summary', ''),
                'details': vuln.get('details', ''),
                'severity': severity,
                'cvss_score': cvss_score,
                'affected_versions': extract_affected_versions(vuln.get('affected', [])),
                'fixed_versions': extract_fixed_versions(vuln.get('affected', [])),
                'references': [ref.get('url') for ref in vuln.get('references', [])],
                'published': vuln.get('published'),
                'modified': vuln.get('modified'),
                'source': 'OSV'
            })
        
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {library_name}@{version}")
        return vulnerabilities
        
    except Exception as e:
        logger.error(f"OSV API failed for {library_name}@{version}: {e}")
        return []


def extract_cvss_from_osv(vuln: Dict) -> float:
    """
    Extract CVSS score from OSV vulnerability data
    Maps severity to approximate CVSS scores
    """
    severity_map = {
        'CRITICAL': 9.5,
        'HIGH': 7.5,
        'MEDIUM': 5.0,
        'MODERATE': 5.0,
        'LOW': 3.0,
        'UNKNOWN': 0.0
    }
    
    # Try to get from database_specific
    severity = vuln.get('database_specific', {}).get('severity', 'UNKNOWN')
    
    # Try to get actual CVSS if available
    cvss_v3 = vuln.get('database_specific', {}).get('cvss_v3')
    if cvss_v3:
        try:
            return float(cvss_v3.get('baseScore', 0.0))
        except:
            pass
    
    return severity_map.get(severity.upper(), 0.0)


def extract_affected_versions(affected_list: List[Dict]) -> List[str]:
    """Extract list of affected version ranges"""
    versions = []
    for affected in affected_list:
        ranges = affected.get('ranges', [])
        for r in ranges:
            events = r.get('events', [])
            for event in events:
                if 'introduced' in event:
                    versions.append(f">={event['introduced']}")
                elif 'fixed' in event:
                    versions.append(f"<{event['fixed']}")
    return versions


def extract_fixed_versions(affected_list: List[Dict]) -> List[str]:
    """Extract list of fixed versions"""
    fixed = []
    for affected in affected_list:
        ranges = affected.get('ranges', [])
        for r in ranges:
            events = r.get('events', [])
            for event in events:
                if 'fixed' in event:
                    fixed.append(event['fixed'])
    return list(set(fixed))  # Remove duplicates


# ============================================
# NVD API (Secondary - More comprehensive)
# ============================================

def check_library_vulnerabilities_nvd(library_name: str, version: str) -> List[Dict[str, Any]]:
    """
    Check vulnerabilities using NVD (National Vulnerability Database) API
    Free, no API key required (but rate limited)
    
    Note: NVD is slower and has rate limits (5 requests per 30 seconds without API key)
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Search for CVEs mentioning this library
    params = {
        'keywordSearch': f"{library_name} {version}",
        'resultsPerPage': 50
    }
    
    try:
        logger.info(f"Checking NVD for {library_name} {version}")
        response = requests.get(base_url, params=params, timeout=30)
        
        if response.status_code != 200:
            logger.warning(f"NVD API returned status {response.status_code}")
            return []
        
        data = response.json()
        
        cves = []
        for item in data.get('vulnerabilities', []):
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id')
            
            # Get CVSS score (prefer v3.1, fallback to v3.0, then v2)
            cvss_score = 0.0
            cvss_vector = ''
            
            metrics = cve_data.get('metrics', {})
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_v31 = metrics['cvssMetricV31'][0]
                cvss_score = cvss_v31.get('cvssData', {}).get('baseScore', 0.0)
                cvss_vector = cvss_v31.get('cvssData', {}).get('vectorString', '')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_v30 = metrics['cvssMetricV30'][0]
                cvss_score = cvss_v30.get('cvssData', {}).get('baseScore', 0.0)
                cvss_vector = cvss_v30.get('cvssData', {}).get('vectorString', '')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_v2 = metrics['cvssMetricV2'][0]
                cvss_score = cvss_v2.get('cvssData', {}).get('baseScore', 0.0)
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Get references
            references = [
                ref.get('url') for ref in cve_data.get('references', [])
            ]
            
            cves.append({
                'cve_id': cve_id,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'severity': calculate_severity_from_cvss(cvss_score),
                'description': description,
                'references': references,
                'published_date': cve_data.get('published'),
                'last_modified': cve_data.get('lastModified'),
                'source': 'NVD'
            })
        
        logger.info(f"Found {len(cves)} CVEs from NVD for {library_name}")
        return cves
        
    except Exception as e:
        logger.error(f"NVD API failed: {e}")
        return []


def calculate_severity_from_cvss(cvss_score: float) -> str:
    """Convert CVSS score to severity rating"""
    if cvss_score >= 9.0:
        return 'CRITICAL'
    elif cvss_score >= 7.0:
        return 'HIGH'
    elif cvss_score >= 4.0:
        return 'MEDIUM'
    elif cvss_score > 0.0:
        return 'LOW'
    else:
        return 'UNKNOWN'


# ============================================
# Ecosystem Detection
# ============================================

def get_ecosystem_for_library(library_name: str) -> str:
    """
    Automatically determine ecosystem based on library name
    """
    library_lower = library_name.lower()
    
    # JavaScript/Node.js libraries
    js_libraries = [
        'jquery', 'react', 'vue', 'angular', 'lodash', 'bootstrap', 
        'moment', 'axios', 'express', 'webpack', 'babel', 'typescript',
        'next', 'nuxt', 'svelte', 'ember', 'backbone', 'underscore',
        'd3', 'chart', 'three', 'socket.io', 'redux', 'mobx'
    ]
    
    # Python libraries
    python_libraries = [
        'django', 'flask', 'requests', 'numpy', 'pandas', 'scipy',
        'tensorflow', 'pytorch', 'keras', 'sqlalchemy', 'celery',
        'pillow', 'beautifulsoup', 'scrapy', 'pytest', 'fastapi'
    ]
    
    # PHP libraries
    php_libraries = [
        'symfony', 'laravel', 'wordpress', 'drupal', 'joomla',
        'phpunit', 'composer', 'guzzle', 'monolog', 'twig'
    ]
    
    # Ruby libraries
    ruby_libraries = [
        'rails', 'sinatra', 'devise', 'rspec', 'capybara',
        'activerecord', 'sidekiq', 'puma', 'nokogiri'
    ]
    
    # Java libraries
    java_libraries = [
        'spring', 'hibernate', 'junit', 'maven', 'gradle',
        'jackson', 'log4j', 'slf4j', 'apache', 'guava'
    ]
    
    if any(lib in library_lower for lib in js_libraries):
        return 'npm'
    elif any(lib in library_lower for lib in python_libraries):
        return 'PyPI'
    elif any(lib in library_lower for lib in php_libraries):
        return 'Packagist'
    elif any(lib in library_lower for lib in ruby_libraries):
        return 'RubyGems'
    elif any(lib in library_lower for lib in java_libraries):
        return 'Maven'
    else:
        return 'npm'  # Default to npm for frontend


# ============================================
# Combined Check (Best Results)
# ============================================

def check_library_vulnerabilities(
    library_name: str, 
    version: str, 
    ecosystem: Optional[str] = None
) -> Dict[str, Any]:
    """
    Check library vulnerabilities using multiple open-source services
    
    Returns comprehensive vulnerability report combining OSV and NVD data
    """
    # Auto-detect ecosystem if not provided
    if not ecosystem:
        ecosystem = get_ecosystem_for_library(library_name)
    
    logger.info(f"Checking vulnerabilities for {library_name}@{version} ({ecosystem})")
    
    # Check OSV (primary source - better for libraries)
    osv_vulns = check_library_vulnerabilities_osv(library_name, version, ecosystem)
    
    # Check NVD (secondary source - more comprehensive CVE database)
    # Note: Comment out if hitting rate limits
    nvd_vulns = check_library_vulnerabilities_nvd(library_name, version)
    
    # Combine and deduplicate
    all_vulnerabilities = osv_vulns + nvd_vulns
    
    # Deduplicate by CVE ID
    seen_cves = set()
    unique_vulns = []
    
    for vuln in all_vulnerabilities:
        # Get CVE identifier
        cve_id = vuln.get('cve_id') or vuln.get('primary_cve') or vuln.get('id')
        
        if cve_id and cve_id not in seen_cves:
            seen_cves.add(cve_id)
            unique_vulns.append(vuln)
        elif not cve_id:
            # Include non-CVE vulnerabilities from OSV
            unique_vulns.append(vuln)
    
    # Calculate overall risk
    max_cvss = max([v.get('cvss_score', 0.0) for v in unique_vulns], default=0.0)
    overall_severity = calculate_severity_from_cvss(max_cvss)
    
    return {
        'library': library_name,
        'version': version,
        'ecosystem': ecosystem,
        'vulnerability_count': len(unique_vulns),
        'vulnerabilities': unique_vulns,
        'max_cvss_score': max_cvss,
        'overall_severity': overall_severity,
        'is_vulnerable': len(unique_vulns) > 0,
        'checked_at': datetime.now().isoformat()
    }


# ============================================
# Bulk Library Checking
# ============================================

def check_multiple_libraries(libraries: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Check vulnerabilities for multiple libraries
    
    Args:
        libraries: List of dicts with 'name', 'version', and optional 'ecosystem'
        Example: [
            {'name': 'jquery', 'version': '3.6.0'},
            {'name': 'react', 'version': '17.0.2', 'ecosystem': 'npm'}
        ]
    
    Returns:
        List of vulnerability reports
    """
    results = []
    
    for lib in libraries:
        library_name = lib.get('name')
        version = lib.get('version')
        ecosystem = lib.get('ecosystem')
        
        if not library_name or not version:
            logger.warning(f"Skipping library with missing name or version: {lib}")
            continue
        
        try:
            result = check_library_vulnerabilities(library_name, version, ecosystem)
            results.append(result)
        except Exception as e:
            logger.error(f"Failed to check {library_name}@{version}: {e}")
            results.append({
                'library': library_name,
                'version': version,
                'error': str(e),
                'vulnerability_count': 0,
                'vulnerabilities': [],
                'is_vulnerable': False
            })
    
    return results


# ============================================
# Utility Functions
# ============================================

def version_compare(version1: str, version2: str) -> int:
    """
    Compare two version strings
    Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    try:
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        # Pad shorter version with zeros
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts += [0] * (max_len - len(v1_parts))
        v2_parts += [0] * (max_len - len(v2_parts))
        
        for i in range(max_len):
            if v1_parts[i] < v2_parts[i]:
                return -1
            elif v1_parts[i] > v2_parts[i]:
                return 1
        
        return 0
    except:
        # Fallback to string comparison
        if version1 < version2:
            return -1
        elif version1 > version2:
            return 1
        else:
            return 0


def is_version_affected(current_version: str, affected_ranges: List[str]) -> bool:
    """
    Check if current version is within affected ranges
    
    Args:
        current_version: Current library version
        affected_ranges: List of version ranges (e.g., ['>=1.0.0', '<2.0.0'])
    """
    is_affected = False
    
    for range_str in affected_ranges:
        if range_str.startswith('>='):
            min_version = range_str[2:]
            if version_compare(current_version, min_version) >= 0:
                is_affected = True
        elif range_str.startswith('>'):
            min_version = range_str[1:]
            if version_compare(current_version, min_version) > 0:
                is_affected = True
        elif range_str.startswith('<='):
            max_version = range_str[2:]
            if version_compare(current_version, max_version) <= 0:
                is_affected = True
        elif range_str.startswith('<'):
            max_version = range_str[1:]
            if version_compare(current_version, max_version) < 0:
                is_affected = True
        elif range_str.startswith('=='):
            exact_version = range_str[2:]
            if current_version == exact_version:
                is_affected = True
    
    return is_affected


# ============================================
# Example Usage
# ============================================

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*60)
    print("CVE CHECKER TEST")
    print("="*60 + "\n")
    
    # Test single library
    print("Testing: jQuery 3.6.0")
    result = check_library_vulnerabilities('jquery', '3.6.0', 'npm')
    
    print(f"\nLibrary: {result['library']} v{result['version']}")
    print(f"Ecosystem: {result['ecosystem']}")
    print(f"Vulnerabilities Found: {result['vulnerability_count']}")
    print(f"Max CVSS Score: {result['max_cvss_score']}")
    print(f"Overall Severity: {result['overall_severity']}")
    print(f"Is Vulnerable: {result['is_vulnerable']}")
    
    if result['vulnerabilities']:
        print("\nVulnerabilities:")
        for i, vuln in enumerate(result['vulnerabilities'][:3], 1):
            cve_id = vuln.get('cve_id') or vuln.get('primary_cve') or vuln.get('id')
            print(f"\n{i}. {cve_id}")
            print(f"   CVSS: {vuln.get('cvss_score', 0.0)}")
            print(f"   Severity: {vuln.get('severity', 'UNKNOWN')}")
            print(f"   Summary: {vuln.get('summary', vuln.get('description', ''))[:100]}...")
    
    # Test multiple libraries
    print("\n" + "="*60)
    print("BULK TEST")
    print("="*60 + "\n")
    
    libraries = [
        {'name': 'jquery', 'version': '3.5.0'},
        {'name': 'react', 'version': '16.8.0'},
        {'name': 'lodash', 'version': '4.17.19'}
    ]
    
    results = check_multiple_libraries(libraries)
    
    for result in results:
        print(f"\n{result['library']} v{result['version']}: ", end='')
        if result.get('error'):
            print(f"ERROR - {result['error']}")
        else:
            print(f"{result['vulnerability_count']} vulnerabilities (CVSS: {result['max_cvss_score']})")