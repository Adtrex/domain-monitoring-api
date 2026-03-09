"""
Nuclei Scanner Integration Module for CERRT

This module provides integration with the Nuclei security scanner.
It handles automatic download, execution, and result processing.
"""

import os
import platform
import subprocess
import json
import urllib.request
import zipfile
import stat
import logging
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Configuration
BIN_DIR = os.path.join(os.path.dirname(__file__), "../bin")
os.makedirs(BIN_DIR, exist_ok=True)

IS_WINDOWS = platform.system() == "Windows"
NUCLEI_VERSION = "v3.7.0"
NUCLEI_ZIP_NAME = f"nuclei_3.7.0_{'windows_amd64' if IS_WINDOWS else 'linux_amd64'}.zip"
NUCLEI_PATH = os.path.join(BIN_DIR, "nuclei.exe" if IS_WINDOWS else "nuclei")
NUCLEI_HOME = os.path.join(BIN_DIR, ".nuclei-home")


def _build_nuclei_env() -> Dict[str, str]:
    """Build environment vars so Nuclei always uses writable runtime paths."""
    os.makedirs(NUCLEI_HOME, exist_ok=True)

    env = os.environ.copy()
    env['HOME'] = NUCLEI_HOME
    env['XDG_CONFIG_HOME'] = NUCLEI_HOME
    env['XDG_CACHE_HOME'] = NUCLEI_HOME

    if IS_WINDOWS:
        env['USERPROFILE'] = NUCLEI_HOME

    return env


def _find_templates_dir(env: Dict[str, str]) -> Optional[str]:
    """Locate nuclei-templates directory across common runtime locations."""
    candidates = [
        os.path.join(env.get('HOME', ''), 'nuclei-templates'),
        os.path.join(BIN_DIR, 'nuclei-templates'),
        os.path.join(os.getcwd(), 'nuclei-templates'),
    ]

    for candidate in candidates:
        if candidate and os.path.isdir(candidate):
            return candidate
    return None


def _templates_dir_has_expected_content(templates_dir: str) -> bool:
    """Check if templates directory contains expected nuclei template structure."""
    expected_paths = [
        os.path.join(templates_dir, 'ssl'),
        os.path.join(templates_dir, 'dns'),
        os.path.join(templates_dir, 'http'),
    ]
    return any(os.path.exists(path) for path in expected_paths)


def ensure_nuclei_templates() -> Tuple[Dict[str, str], str]:
    """Ensure Nuclei templates are present and return (env, templates_dir)."""
    env = _build_nuclei_env()

    templates_dir = _find_templates_dir(env)
    if templates_dir and _templates_dir_has_expected_content(templates_dir):
        return env, templates_dir

    logger.info("Nuclei templates missing/incomplete. Attempting to download/update templates...")
    proc = subprocess.run(
        [NUCLEI_PATH, "-update-templates"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    if proc.returncode != 0:
        logger.warning(f"Nuclei template update returned code {proc.returncode}: {proc.stderr}")

    templates_dir = _find_templates_dir(env)
    if not templates_dir or not _templates_dir_has_expected_content(templates_dir):
        error_msg = (
            "Nuclei templates were not found or are incomplete after update. "
            "On Render, ensure runtime has writable storage and network egress to download templates."
        )
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    logger.info(f"Using Nuclei templates directory: {templates_dir}")
    return env, templates_dir


def resolve_template_path(template: str, templates_dir: str) -> str:
    """Resolve relative Nuclei template paths against detected templates dir."""
    if not template:
        return template

    if os.path.isabs(template) or os.path.exists(template):
        return template

    return os.path.join(templates_dir, template)


def download_nuclei():
    """
    Download and extract Nuclei binary if not already present
    """
    if os.path.exists(NUCLEI_PATH):
        return

    print(f"[INFO] Downloading Nuclei {NUCLEI_VERSION}...")
    logger.info(f"Downloading Nuclei {NUCLEI_VERSION}...")
    
    url = f"https://github.com/projectdiscovery/nuclei/releases/download/{NUCLEI_VERSION}/{NUCLEI_ZIP_NAME}"
    zip_path = os.path.join(BIN_DIR, NUCLEI_ZIP_NAME)

    try:
        urllib.request.urlretrieve(url, zip_path)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(BIN_DIR)
        os.remove(zip_path)

        if not IS_WINDOWS:
            st = os.stat(NUCLEI_PATH)
            os.chmod(NUCLEI_PATH, st.st_mode | stat.S_IEXEC)
        
        print("[INFO] Nuclei ready!")
        logger.info("Nuclei downloaded and ready")
    except Exception as e:
        logger.error(f"Failed to download Nuclei: {e}")
        raise Exception(f"Failed to download Nuclei: {e}")


def run_nuclei_scan(target: str, templates: List[str] = None) -> List[Dict[str, Any]]:
    """
    Execute Nuclei scan on a target URL
    
    Args:
        target (str): Target URL to scan
        templates (List[str]): List of template categories/paths to use
    
    Returns:
        List[Dict[str, Any]]: List of findings from Nuclei
    
    Example:
        >>> results = run_nuclei_scan('https://example.com', templates=['ssl', 'dns'])
        >>> print(len(results))
        5
    """
    download_nuclei()
    nuclei_env, templates_dir = ensure_nuclei_templates()
    templates = templates or ["ssl"]
    results = []

    if not os.path.exists(NUCLEI_PATH):
        error_msg = f"Nuclei binary not found at {NUCLEI_PATH}"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)

    logger.info(f"Running Nuclei scan on {target} with templates: {templates}")
    print(f"[INFO] Scanning {target} with templates: {templates}")

    for template in templates:
        resolved_template = resolve_template_path(template, templates_dir)
        command = [NUCLEI_PATH, "-u", target, "-t", resolved_template, "-jsonl"]
        
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                env=nuclei_env,
            )

            # Parse JSON lines output
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        results.append(data)
                    else:
                        logger.warning(f"Skipping non-dict JSON line: {line}")
                        print(f"[WARN] Skipping non-dict JSON line: {line}")
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON line: {line}")
                    print(f"[ERROR] Failed to parse JSON line: {line}")

            # Log stderr if present
            if proc.stderr:
                logger.warning(f"Nuclei stderr for template '{template}' ({resolved_template}): {proc.stderr}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Scan error for template '{template}': {e}")
            print(f"[ERROR] Scan error for template '{template}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            print(f"[ERROR] Unexpected error: {e}")

    logger.info(f"Scan completed. Found {len(results)} issues.")
    print(f"[INFO] Scan completed. Found {len(results)} issues.")
    
    return results


def parse_nuclei_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse and normalize a Nuclei finding result
    
    Args:
        result (Dict): Raw Nuclei JSON result
    
    Returns:
        Dict: Normalized finding data
    
    Example Nuclei output structure:
    {
        "template-id": "ssl-weak-cipher",
        "info": {
            "name": "Weak SSL Cipher Suites",
            "author": "pdteam",
            "severity": "medium",
            "description": "Weak cipher suites detected",
            "remediation": "Disable weak ciphers",
            "classification": {
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvss-score": 5.3,
                "cwe-id": "CWE-326"
            },
            "tags": ["ssl", "tls", "cipher"]
        },
        "type": "http",
        "host": "https://example.com",
        "matched-at": "https://example.com",
        "extracted-results": ["RC4", "3DES"],
        "timestamp": "2026-01-30T10:02:35Z"
    }
    """
    info = result.get('info', {})
    classification = info.get('classification', {})
    
    parsed_result = {
        'template_id': result.get('template-id', ''),
        'template_name': info.get('name', ''),
        'severity': info.get('severity', 'info'),
        'description': info.get('description', ''),
        'remediation': info.get('remediation', info.get('reference', '')),
        'cvss_score': classification.get('cvss-score'),
        'cvss_vector': classification.get('cvss-metrics'),
        'cwe_id': classification.get('cwe-id'),
        'matched_at': result.get('matched-at', ''),
        'host': result.get('host', ''),
        'evidence': ', '.join(result.get('extracted-results', [])) if result.get('extracted-results') else '',
        'tags': info.get('tags', []),
        'timestamp': result.get('timestamp', ''),
        'raw_result': result  # Keep raw result for reference
    }
    
    logger.debug(f"Parsed Nuclei result: {parsed_result}")
    
    return parsed_result


def categorize_template(template_id: str) -> str:
    """
    Categorize a Nuclei template ID into CERRT finding categories
    
    Args:
        template_id (str): Nuclei template ID
    
    Returns:
        str: Category (CVE, SSL, DNS, Email, Misconfiguration)
    """
    template_id = template_id.lower()
    
    if 'cve-' in template_id:
        return 'CVE'
    elif any(keyword in template_id for keyword in ['ssl', 'tls', 'certificate']):
        return 'SSL'
    elif any(keyword in template_id for keyword in ['dns', 'dnssec', 'zone-transfer']):
        return 'DNS'
    elif any(keyword in template_id for keyword in ['spf', 'dkim', 'dmarc', 'email', 'mx']):
        return 'Email'
    else:
        return 'Misconfiguration'


def map_severity_to_risk_rating(severity: str) -> str:
    """
    Map Nuclei severity to CERRT risk rating
    
    Args:
        severity (str): Nuclei severity (critical, high, medium, low, info)
    
    Returns:
        str: Risk rating (Critical, High, Medium, Low)
    """
    severity_map = {
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'info': 'Low'
    }
    return severity_map.get(severity.lower(), 'Low')


def get_check_type_from_template(template_id: str) -> str:
    """
    Determine specific check type from template ID
    
    Args:
        template_id (str): Nuclei template ID
    
    Returns:
        str: Specific check type
    """
    template_id = template_id.lower()
    
    # SSL/TLS checks
    if 'certificate' in template_id or 'cert-expiry' in template_id:
        return 'certificate'
    elif 'cipher' in template_id:
        return 'cipher'
    elif 'protocol' in template_id or 'tls-version' in template_id:
        return 'protocol'
    elif 'hsts' in template_id:
        return 'hsts'
    
    # DNS checks
    elif 'dnssec' in template_id:
        return 'dnssec'
    elif 'zone-transfer' in template_id or 'axfr' in template_id:
        return 'zone_transfer'
    elif 'hijack' in template_id:
        return 'hijacking'
    elif 'takeover' in template_id:
        return 'subdomain_takeover'
    
    # Email checks
    elif 'spf' in template_id:
        return 'SPF'
    elif 'dkim' in template_id:
        return 'DKIM'
    elif 'dmarc' in template_id:
        return 'DMARC'

    elif 'missing' in template_id and 'header' in template_id:
        return 'security_header'
    
    # Default
    else:
        return 'general'


def determine_email_status(result: Dict[str, Any]) -> str:
    """
    Determine email check status (PASS/FAIL) from Nuclei result
    
    Args:
        result (Dict): Nuclei result
    
    Returns:
        str: Status (PASS, FAIL, INVALID)
    """
    info = result.get('info', {})
    severity = info.get('severity', 'info').lower()
    template_id = result.get('template-id', '').lower()
    
    # If severity is high/critical/medium, it's a failure
    if severity in ['critical', 'high', 'medium']:
        return 'FAIL'
    
    # Check for specific failure keywords in template
    if any(keyword in template_id for keyword in ['missing', 'invalid', 'misconfigured']):
        return 'FAIL'
    
    # Otherwise, consider it a pass
    return 'PASS'


def get_recommendation_from_result(result: Dict[str, Any]) -> str:
    """
    Extract or generate recommendation from Nuclei result
    
    Args:
        result (Dict): Nuclei result
    
    Returns:
        str: Recommendation text
    """
    info = result.get('info', {})
    
    # Try to get explicit remediation
    remediation = info.get('remediation', '')
    if remediation:
        return remediation
    
    # Try reference URLs
    references = info.get('reference', [])
    if isinstance(references, list) and references:
        return f"See: {', '.join(references[:2])}"
    elif isinstance(references, str) and references:
        return f"See: {references}"
    
    # Generate generic recommendation based on severity
    severity = info.get('severity', 'info').lower()
    name = info.get('name', 'Issue')
    
    if severity in ['critical', 'high']:
        return f"Immediate remediation required for: {name}"
    elif severity == 'medium':
        return f"Address this issue: {name}"
    else:
        return f"Consider fixing: {name}"


def extract_certificate_info(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract certificate-specific information from SSL check results
    
    Args:
        result (Dict): Nuclei result
    
    Returns:
        Dict: Certificate information (expiry, days remaining, etc.)
    """
    extracted = result.get('extracted-results', [])
    
    cert_info = {
        'certificate_expiry': None,
        'certificate_days_remaining': None,
        'protocols_supported': [],
        'weak_ciphers': []
    }
    
    # Try to extract expiry info from extracted results
    # This is template-specific and may need adjustment
    for item in extracted:
        if isinstance(item, str):
            if 'days' in item.lower():
                # Try to extract number of days
                try:
                    days = int(''.join(filter(str.isdigit, item)))
                    cert_info['certificate_days_remaining'] = days
                except ValueError:
                    pass
            
            # Check for protocol mentions
            if any(proto in item.upper() for proto in ['TLS', 'SSL']):
                cert_info['protocols_supported'].append(item)
            
            # Check for weak ciphers
            if any(cipher in item.upper() for cipher in ['RC4', '3DES', 'DES', 'MD5']):
                cert_info['weak_ciphers'].append(item)
    
    return cert_info


def extract_missing_header(template_id):
    template_id = template_id.lower()

    header_map = {
        'content-security-policy': 'Content-Security-Policy',
        'x-frame-options': 'X-Frame-Options',
        'strict-transport-security': 'Strict-Transport-Security',
        'x-content-type-options': 'X-Content-Type-Options',
        'referrer-policy': 'Referrer-Policy',
        'permissions-policy': 'Permissions-Policy'
    }

    for key, header in header_map.items():
        if key in template_id:
            return header

    return None



# Template mapping for friendly names to Nuclei paths
TEMPLATE_MAP = {
    'ssl': 'ssl/',
    'tls': 'ssl/',
    'dns': 'dns/',
    'email': 'dns/txt-fingerprint.yaml,dns/spf-*.yaml,dns/dmarc-*.yaml',
    'headers': '',
    'security-headers': '',
    'cve': 'cves/',
    'misconfig': 'http/misconfiguration/',
    'misconfiguration': 'http/misconfiguration/',
    'javascript': 'javascript/',
    'js': 'javascript/',
    'library': 'javascript/',
}


def get_template_path(template_name: str) -> str:
    """
    Get Nuclei template path from friendly name
    
    Args:
        template_name (str): Friendly template name
    
    Returns:
        str: Nuclei template path
    """
    mapped = TEMPLATE_MAP.get(template_name.lower(), template_name)
    return mapped if mapped else ''


# Example usage and testing
if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s'
    )
    
    # Test scan
    try:
        print("\n" + "="*60)
        print("NUCLEI SCANNER TEST")
        print("="*60 + "\n")
        
        test_target = 'https://example.com'
        test_templates = ['ssl', 'dns']
        
        print(f"Target: {test_target}")
        print(f"Templates: {test_templates}\n")
        
        results = run_nuclei_scan(
            target=test_target,
            templates=test_templates
        )
        
        print(f"\n{'='*60}")
        print(f"Found {len(results)} issues")
        print(f"{'='*60}\n")
        
        # Show first 5 results
        for i, result in enumerate(results[:5], 1):
            parsed = parse_nuclei_result(result)
            print(f"{i}. {parsed['template_name']}")
            print(f"   Severity: {parsed['severity']}")
            print(f"   Category: {categorize_template(result.get('template-id', ''))}")
            print(f"   Risk Rating: {map_severity_to_risk_rating(parsed['severity'])}")
            print(f"   CVSS: {parsed['cvss_score']}")
            print(f"   Evidence: {parsed['evidence'][:80]}")
            print(f"   Recommendation: {get_recommendation_from_result(result)[:80]}")
            print()
    
    except Exception as e:
        print(f"Error: {e}")

