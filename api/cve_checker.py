"""
Fixed Open Source CVE Checker for CERRT
Uses only free/open-source services with improved library matching
"""

import requests
import re
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from packaging.version import InvalidVersion, Version
from urllib.parse import quote

logger = logging.getLogger(__name__)


# ============================================
# Library Name Mapping (CRITICAL FIX)
# ============================================

# Map common frontend library names to their actual package names
LIBRARY_NAME_MAPPING = {
    # Frontend libraries that are in npm
    'jquery': 'jquery',
    'react': 'react',
    'react-dom': 'react-dom',
    'vue': 'vue',
    'vue.js': 'vue',
    'angular': '@angular/core',
    'angularjs': 'angular',  # Old Angular 1.x
    'lodash': 'lodash',
    'moment': 'moment',
    'moment.js': 'moment',
    'axios': 'axios',
    'bootstrap': 'bootstrap',
    'd3': 'd3',
    'd3.js': 'd3',
    'chart.js': 'chart.js',
    'three': 'three',
    'three.js': 'three',
    'socket.io': 'socket.io',
    'express': 'express',
    'webpack': 'webpack',
    'next': 'next',
    'nuxt': 'nuxt',
    
    # CSS frameworks
    'font-awesome': '@fortawesome/fontawesome-free',
    'font awesome': '@fortawesome/fontawesome-free',
    'fontawesome': '@fortawesome/fontawesome-free',
    'bulma': 'bulma',
    'tailwind': 'tailwindcss',
    'tailwind css': 'tailwindcss',
    
    # Python packages
    'django': 'Django',
    'flask': 'Flask',
    'requests': 'requests',
    'numpy': 'numpy',
    'pandas': 'pandas',
    
    # PHP packages
    'symfony': 'symfony/symfony',
    'laravel': 'laravel/framework',
    
    # WordPress
    'wordpress': 'wordpress',
    'joomla': 'joomla/joomla-cms',
    'drupal': 'drupal/core',
    'magento': 'magento/product-community-edition',
    'prestashop': 'prestashop/prestashop',
    'ghost': 'ghost',

    'aos': 'aos',
    'gsap': 'gsap',
    'swiper': 'swiper',
}


def normalize_library_name(library_name: str) -> str:
    """Normalize library name for package registry lookup"""
    library_lower = library_name.lower().strip()
    return LIBRARY_NAME_MAPPING.get(library_lower, library_lower)


def supports_latest_version_lookup(library_name: str) -> bool:
    """Return True when the package/CMS name can be resolved against a known source."""
    normalized_name = normalize_library_name(library_name)

    if library_name.lower().strip() in LIBRARY_NAME_MAPPING:
        return True

    if normalized_name == 'wordpress':
        return True

    if normalized_name.startswith('@'):
        return True

    if normalized_name in {
        'ghost',
        'jquery',
        'react',
        'react-dom',
        'vue',
        'bootstrap',
        'bulma',
        'tailwindcss',
        'django',
        'flask',
        'next',
        'nuxt',
        'express',
        'symfony/symfony',
        'laravel/framework',
        'joomla/joomla-cms',
        'drupal/core',
        'magento/product-community-edition',
        'prestashop/prestashop',
    }:
        return True

    return False


def fetch_latest_library_version(
    library_name: str,
    ecosystem: Optional[str] = None
) -> Optional[str]:
    """Fetch the latest available package version from the relevant registry."""
    normalized_name = normalize_library_name(library_name)
    ecosystem = ecosystem or get_ecosystem_for_library(normalized_name)
    ecosystem_lower = ecosystem.lower()

    try:
        if normalized_name == 'wordpress':
            response = requests.get(
                'https://api.wordpress.org/core/version-check/1.7/',
                timeout=15
            )
            if response.status_code == 200:
                offers = response.json().get('offers', [])
                for offer in offers:
                    current = offer.get('current')
                    if current:
                        return current

        if ecosystem_lower == 'npm':
            response = requests.get(
                f"https://registry.npmjs.org/{quote(normalized_name, safe='')}",
                timeout=15
            )
            if response.status_code == 200:
                return response.json().get('dist-tags', {}).get('latest')

        elif ecosystem_lower == 'pypi':
            response = requests.get(
                f"https://pypi.org/pypi/{quote(normalized_name, safe='')}/json",
                timeout=15
            )
            if response.status_code == 200:
                return response.json().get('info', {}).get('version')

        elif ecosystem_lower == 'packagist':
            response = requests.get(
                f"https://repo.packagist.org/p2/{quote(normalized_name, safe='')}.json",
                timeout=15
            )
            if response.status_code == 200:
                packages = response.json().get('packages', {}).get(normalized_name, [])
                versions = [pkg.get('version') for pkg in packages if pkg.get('version')]
                stable_versions = [version for version in versions if 'dev' not in version.lower()]
                candidates = stable_versions or versions
                if candidates:
                    return sorted(candidates, key=lambda version: _safe_version_key(version), reverse=True)[0]

    except requests.exceptions.RequestException as e:
        logger.warning(f"Latest version lookup failed for {normalized_name} ({ecosystem}): {e}")
    except Exception as e:
        logger.warning(f"Unexpected latest version lookup error for {normalized_name} ({ecosystem}): {e}")

    return None


def _safe_version_key(version: str):
    """Build a comparable key for version sorting with a string fallback."""
    cleaned_version = version.lstrip('v').strip()
    try:
        return (0, Version(cleaned_version))
    except InvalidVersion:
        return (1, cleaned_version)


# ============================================
# OSV API (Primary - Best for Libraries)
# ============================================

def check_library_vulnerabilities_osv(
    library_name: str, 
    version: str, 
    ecosystem: str = 'npm'
) -> List[Dict[str, Any]]:
    """
    Check vulnerabilities using OSV API
    
    FIXED: Proper ecosystem casing and better error handling
    """
    api_url = "https://api.osv.dev/v1/query"
    
    # Normalize library name
    library_name = normalize_library_name(library_name)
    version = version.strip()
    
    # Fix ecosystem casing - OSV is case-sensitive!
    ecosystem_map = {
        'npm': 'npm',
        'pypi': 'PyPI',
        'packagist': 'Packagist',
        'rubygems': 'RubyGems',
        'maven': 'Maven',
        'go': 'Go',
        'nuget': 'NuGet',
        'cargo': 'crates.io',
        'hex': 'Hex',
    }
    
    ecosystem_normalized = ecosystem_map.get(ecosystem.lower(), 'npm')
    
    payload = {
        "package": {
            "name": library_name,
            "ecosystem": ecosystem_normalized
        },
        "version": version
    }
    
    try:
        logger.info(f"Checking OSV for {library_name}@{version} in {ecosystem_normalized}")
        logger.debug(f"OSV Request payload: {json.dumps(payload, indent=2)}")
        
        response = requests.post(api_url, json=payload, timeout=30)
        
        logger.debug(f"OSV Response status: {response.status_code}")
        logger.debug(f"OSV Response body: {response.text[:500]}")
        
        if response.status_code != 200:
            logger.warning(f"OSV API returned status {response.status_code}: {response.text[:200]}")
            return []
        
        data = response.json()

        # logger.info("FULL OSV RESPONSE:")
        # logger.info(json.dumps(data, indent=2, default=str))
        
        # Check if response has vulnerabilities
        if not data.get('vulns'):
            logger.info(f"No vulnerabilities found in OSV for {library_name}@{version}")
            return []
        
        vulnerabilities = []
        for vuln in data.get('vulns', []):

            # logger.info("RAW VULNERABILITY:")
            # logger.info(json.dumps(vuln, indent=2, default=str))
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

           

            
            logger.info(
                f"Found vulnerability with CVSS {cvss_score}:\n{json.dumps(vuln, indent=2, default=str)}"
            )

        

        logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {library_name}@{version}")
        return vulnerabilities
        
    except requests.exceptions.RequestException as e:
        logger.error(f"OSV API request failed for {library_name}@{version}: {e}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"OSV API returned invalid JSON: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error in OSV API: {e}")
        return []


def extract_cvss_from_osv(vuln: Dict) -> float:
    """
    Extract CVSS score from OSV vulnerability data
    """
    severity_map = {
        'CRITICAL': 9.5,
        'HIGH': 7.5,
        'MEDIUM': 5.0,
        'MODERATE': 5.0,
        'LOW': 3.0,
        'UNKNOWN': 0.0
    }
    
    # Try to get from severity field first
    for sev in vuln.get('severity', []):
        if sev.get('type') == 'CVSS_V3':
            try:
                score_str = sev.get('score', '')
                # Parse CVSS vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                # For now, just look for baseScore in database_specific
                pass
            except:
                pass
    
    # Try to get from database_specific
    db_specific = vuln.get('database_specific', {})
    
    # Check for explicit CVSS score
    if 'cvss_score' in db_specific:
        try:
            return float(db_specific['cvss_score'])
        except:
            pass
    
    # Try cvss_v3
    if 'cvss_v3' in db_specific:
        try:
            cvss_v3 = db_specific['cvss_v3']
            if isinstance(cvss_v3, dict) and 'baseScore' in cvss_v3:
                return float(cvss_v3['baseScore'])
        except:
            pass
    
    # Fallback to severity mapping
    severity_str = db_specific.get('severity', 'UNKNOWN')
    return severity_map.get(severity_str.upper(), 0.0)


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
# Retire.js Database (Frontend Libraries)
# ============================================

def check_retirejs_vulnerabilities(library_name: str, version: str) -> List[Dict[str, Any]]:
    """
    Check vulnerabilities using Retire.js database
    This is specifically good for frontend JavaScript libraries
    """
    # Retire.js repository URL
    retirejs_url = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
    
    try:
        logger.info(f"Checking Retire.js database for {library_name}@{version}")
        response = requests.get(retirejs_url, timeout=60)
        
        if response.status_code != 200:
            logger.warning(f"Retire.js database fetch failed: {response.status_code}")
            return []
        
        retire_data = response.json()

        # logger.info("FULL RETIRE.JS RESPONSE:")
        # logger.info(json.dumps(retire_data, indent=2, default=str))
        
        # Normalize library name
        library_lower = library_name.lower()
        
        vulnerabilities = []
        
        # Search for the library in retire.js database
        for lib_key, lib_data in retire_data.items():
            if library_lower in lib_key.lower() or lib_key.lower() in library_lower:
                # Found the library, now check vulnerabilities
                for vuln in lib_data.get('vulnerabilities', []):


                    # Check if current version is affected
                    affected = False
                    
                    # Check "below" constraint
                    below_version = vuln.get('below')
                    if below_version:
                        if version_compare(version, below_version) < 0:
                            affected = True
                    
                    # Check "atOrAbove" constraint
                    at_or_above = vuln.get('atOrAbove')
                    if at_or_above:
                        if version_compare(version, at_or_above) < 0:
                            affected = False
                    
                    if affected:
                        # Extract CVE IDs from identifiers
                        cve_ids = []
                        for identifier_type, identifier_list in vuln.get('identifiers', {}).items():
                            if identifier_type == 'CVE':
                                cve_ids = identifier_list
                        
                        severity = vuln.get('severity', 'medium').upper()
                        
                        vulnerabilities.append({
                            'id': f"RETIRE-{lib_key}-{len(vulnerabilities)}",
                            'cve_ids': cve_ids,
                            'cve_id': cve_ids[0] if cve_ids else None,  # ← ADD THIS
                            'primary_cve': cve_ids[0] if cve_ids else None,
                            'summary': vuln.get('info', [''])[0] if vuln.get('info') else '',
                            'details': '\n'.join(vuln.get('info', [])),
                            'description': vuln.get('info', [''])[0] if vuln.get('info') else '',  # ← ADD THIS
                            'severity': severity,
                            'cvss_score': severity_to_cvss(severity),
                            'cvss_vector': '',  # ← ADD THIS (empty for Retire.js)
                            'affected_versions': [f"<{below_version}"] if below_version else [],
                            'fixed_versions': [below_version] if below_version else [],
                            'references': vuln.get('info', []),
                            'source': 'Retire.js'
                        })

        logger.info("All Vulnurabilities found:")
        logger.info(json.dumps(vulnerabilities, indent=2, default=str))
        
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities in Retire.js for {library_name}@{version}")
        return vulnerabilities
        
    except Exception as e:
        logger.error(f"Retire.js check failed: {e}")
        return []


def severity_to_cvss(severity: str) -> float:
    """Convert severity string to approximate CVSS score"""
    severity_map = {
        'CRITICAL': 9.5,
        'HIGH': 7.5,
        'MEDIUM': 5.0,
        'LOW': 3.0,
        'UNKNOWN': 0.0
    }
    return severity_map.get(severity.upper(), 5.0)


# ============================================
# NVD API with Better Querying
# ============================================

def check_library_vulnerabilities_nvd_cpe(library_name: str, version: str) -> List[Dict[str, Any]]:
    """
    Check NVD using CPE (Common Platform Enumeration) matching
    More accurate than keyword search
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Construct CPE match string
    # Format: cpe:2.3:a:vendor:product:version
    library_normalized = normalize_library_name(library_name)
    
    # Try keyword search with better filtering
    params = {
        'keywordSearch': library_normalized,
        'resultsPerPage': 20
    }
    
    try:
        logger.info(f"Checking NVD for {library_name}")
        response = requests.get(base_url, params=params, timeout=30)
        
        if response.status_code != 200:
            logger.warning(f"NVD API returned status {response.status_code}")
            return []
        
        data = response.json()
        
        cves = []
        for item in data.get('vulnerabilities', []):
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id')
            
            # Filter: Only include if library name appears in description
            descriptions = cve_data.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Check if this CVE actually relates to our library
            if library_normalized.lower() not in description.lower():
                continue
            
            # Get CVSS score
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
        
        logger.info(f"Found {len(cves)} relevant CVEs from NVD for {library_name}")
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
# Ecosystem Detection (FIXED)
# ============================================

def get_ecosystem_for_library(library_name: str) -> str:
    """Automatically determine ecosystem based on library name"""
    library_lower = library_name.lower()
    normalized_name = normalize_library_name(library_name).lower()

    if normalized_name == 'wordpress':
        return 'wordpress'

    if normalized_name.startswith('@'):
        return 'npm'

    if normalized_name in {
        'symfony/symfony',
        'laravel/framework',
        'joomla/joomla-cms',
        'drupal/core',
        'magento/product-community-edition',
        'prestashop/prestashop',
    }:
        return 'Packagist'
    
    # Frontend JavaScript libraries - these are in npm
    frontend_libs = [
        'jquery', 'react', 'vue', 'angular', 'lodash', 'bootstrap', 
        'moment', 'axios', 'express', 'webpack', 'babel', 'typescript',
        'next', 'nuxt', 'svelte', 'ember', 'backbone', 'underscore',
        'd3', 'chart', 'three', 'socket', 'redux', 'mobx', 'font-awesome',
        'bulma', 'tailwind', 'aos', 'gsap', 'swiper'
    ]
    
    # Python packages
    python_libs = [
        'django', 'flask', 'requests', 'numpy', 'pandas', 'scipy',
        'tensorflow', 'pytorch', 'keras', 'sqlalchemy', 'celery'
    ]
    
    # Check for matches
    if any(lib in library_lower for lib in frontend_libs):
        return 'npm'
    elif any(lib in library_lower for lib in python_libs):
        return 'PyPI'
    else:
        return 'npm'  # Default for frontend


# ============================================
# Combined Check with All Sources
# ============================================

def check_library_vulnerabilities(
    library_name: str, 
    version: str, 
    ecosystem: Optional[str] = None,
    use_all_sources: bool = True
) -> Dict[str, Any]:
    """
    Check library vulnerabilities using multiple sources
    
    Args:
        library_name: Library name (e.g., 'jquery')
        version: Version string (e.g., '3.6.0')
        ecosystem: Package ecosystem ('npm', 'PyPI', etc.)
        use_all_sources: If True, check all sources; if False, only OSV
    """
    # Auto-detect ecosystem if not provided
    if not ecosystem:
        ecosystem = get_ecosystem_for_library(library_name)
    
    logger.info(f"Checking vulnerabilities for {library_name}@{version} ({ecosystem})")
    
    all_vulnerabilities = []
    
    # Source 1: OSV (Primary)
    osv_vulns = check_library_vulnerabilities_osv(library_name, version, ecosystem)
    all_vulnerabilities.extend(osv_vulns)
    
    if use_all_sources:
        # Source 2: Retire.js (Good for frontend)
        if ecosystem.lower() == 'npm':
            retirejs_vulns = check_retirejs_vulnerabilities(library_name, version)
            all_vulnerabilities.extend(retirejs_vulns)
        
        # Source 3: NVD (Comprehensive but slower)
        # Uncomment if you need more comprehensive results
        # nvd_vulns = check_library_vulnerabilities_nvd_cpe(library_name, version)
        # all_vulnerabilities.extend(nvd_vulns)
    
    # Deduplicate by CVE ID
    seen_cves = set()
    unique_vulns = []
    
    for vuln in all_vulnerabilities:
        cve_id = vuln.get('cve_id') or vuln.get('primary_cve') or vuln.get('id')
        
        if cve_id and cve_id not in seen_cves:
            seen_cves.add(cve_id)
            unique_vulns.append(vuln)
        elif not cve_id:
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


def check_multiple_libraries(libraries: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Check vulnerabilities for multiple libraries"""
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
        v1 = Version(version1.lstrip('v').strip())
        v2 = Version(version2.lstrip('v').strip())

        if v1 < v2:
            return -1
        if v1 > v2:
            return 1
        return 0
    except (InvalidVersion, AttributeError, TypeError, ValueError):
        # Fallback to string comparison
        if version1 < version2:
            return -1
        elif version1 > version2:
            return 1
        else:
            return 0


# ============================================
# Example Usage
# ============================================

if __name__ == '__main__':
    # Configure logging with DEBUG level to see what's happening
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*60)
    print("FIXED CVE CHECKER TEST")
    print("="*60 + "\n")
    
    # Test with a library that has known vulnerabilities
    test_cases = [
        ('jquery', '3.4.0', 'npm'),      # Known vulnerable version
        ('lodash', '4.17.15', 'npm'),    # Known vulnerable version
        ('react', '16.13.0', 'npm'),     # Should have fewer/no vulns
        ('moment', '2.29.1', 'npm'),     # Deprecated library
    ]
    
    for lib_name, lib_version, lib_ecosystem in test_cases:
        print(f"\n{'='*60}")
        print(f"Testing: {lib_name} {lib_version}")
        print('='*60)
        
        result = check_library_vulnerabilities(lib_name, lib_version, lib_ecosystem)
        
        print(f"\nLibrary: {result['library']} v{result['version']}")
        print(f"Ecosystem: {result['ecosystem']}")
        print(f"Vulnerabilities Found: {result['vulnerability_count']}")
        print(f"Max CVSS Score: {result['max_cvss_score']}")
        print(f"Overall Severity: {result['overall_severity']}")
        print(f"Is Vulnerable: {result['is_vulnerable']}")
        
        if result['vulnerabilities']:
            print("\nTop Vulnerabilities:")
            for i, vuln in enumerate(result['vulnerabilities'][:3], 1):
                cve_id = vuln.get('cve_id') or vuln.get('primary_cve') or vuln.get('id')
                print(f"\n{i}. {cve_id}")
                print(f"   CVSS: {vuln.get('cvss_score', 0.0)}")
                print(f"   Severity: {vuln.get('severity', 'UNKNOWN')}")
                summary = vuln.get('summary') or vuln.get('details') or vuln.get('description', '')
                print(f"   Summary: {summary[:150]}...")
                print(f"   Source: {vuln.get('source')}")