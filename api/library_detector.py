"""
Open Source Library and CMS Detection for CERRT
Uses only free/open-source methods:
- HTML/JavaScript parsing
- Header analysis
- Common file pattern detection
"""

import requests
import re
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


# ============================================
# Frontend Library Detection
# ============================================

def detect_frontend_libraries(url: str, timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Detect frontend libraries used on a webpage
    
    Returns list of detected libraries with versions
    """
    try:
        logger.info(f"Detecting libraries for {url}")
        
        # Fetch page content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        html = response.text
        
        libraries = []
        seen_libraries = set()  # Avoid duplicates
        
        # Parse HTML
        soup = BeautifulSoup(html, 'html.parser')
        
        # 1. Check inline JavaScript
        libraries.extend(_detect_from_inline_js(html))
        
        # 2. Check script src attributes
        libraries.extend(_detect_from_script_tags(soup, url))
        
        # 3. Check link href attributes (CSS libraries)
        libraries.extend(_detect_from_link_tags(soup, url))
        
        # 4. Check meta tags
        libraries.extend(_detect_from_meta_tags(soup))
        
        # 5. Check HTML comments
        libraries.extend(_detect_from_comments(html))
        
        # Deduplicate
        unique_libraries = []
        for lib in libraries:
            lib_key = f"{lib['name']}_{lib['version']}"
            if lib_key not in seen_libraries:
                seen_libraries.add(lib_key)
                unique_libraries.append(lib)
        
        logger.info(f"Detected {len(unique_libraries)} unique libraries")
        return unique_libraries
        
    except Exception as e:
        logger.error(f"Library detection failed for {url}: {e}")
        return []


def _detect_from_inline_js(html: str) -> List[Dict[str, Any]]:
    """Detect libraries from inline JavaScript code"""
    libraries = []
    
    # Common library patterns in inline JS
    patterns = [
        # jQuery
        (r'jQuery[.\s]+(v?[\d.]+)', 'jQuery'),
        (r'\$\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'jQuery'),
        
        # React
        (r'React[.\s]+(v?[\d.]+)', 'React'),
        (r'react@(\d+\.\d+\.\d+)', 'React'),
        
        # Vue
        (r'Vue[.\s]+(v?[\d.]+)', 'Vue.js'),
        (r'vue@(\d+\.\d+\.\d+)', 'Vue.js'),
        
        # Angular
        (r'Angular[.\s]+(v?[\d.]+)', 'Angular'),
        (r'angular@(\d+\.\d+\.\d+)', 'Angular'),
        
        # Bootstrap
        (r'Bootstrap[.\s]+(v?[\d.]+)', 'Bootstrap'),
        
        # Lodash
        (r'lodash[.\s]+(v?[\d.]+)', 'Lodash'),
        
        # Moment.js
        (r'moment[.\s]+(v?[\d.]+)', 'Moment.js'),
    ]
    
    for pattern, lib_name in patterns:
        matches = re.finditer(pattern, html, re.IGNORECASE)
        for match in matches:
            version = match.group(1).replace('v', '')
            libraries.append({
                'name': lib_name,
                'version': version,
                'source': 'inline_js',
                'confidence': 'medium'
            })
            break  # Only take first match per library
    
    return libraries


def _detect_from_script_tags(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    """Detect libraries from script src attributes"""
    libraries = []
    
    script_patterns = [
        # jQuery
        (r'jquery[.-]([\d.]+)(?:\.min)?\.js', 'jQuery'),
        (r'jquery\.js.*?([\d.]+)', 'jQuery'),
        
        # React
        (r'react[.-]([\d.]+)(?:\.min)?\.js', 'React'),
        (r'react-dom[.-]([\d.]+)', 'React DOM'),
        
        # Vue
        (r'vue[.-]([\d.]+)(?:\.min)?\.js', 'Vue.js'),
        
        # Angular
        (r'angular[.-]([\d.]+)(?:\.min)?\.js', 'Angular'),
        
        # Bootstrap
        (r'bootstrap[.-]([\d.]+)(?:\.min)?\.js', 'Bootstrap'),
        
        # Lodash
        (r'lodash[.-]([\d.]+)(?:\.min)?\.js', 'Lodash'),
        
        # Moment.js
        (r'moment[.-]([\d.]+)(?:\.min)?\.js', 'Moment.js'),
        
        # D3.js
        (r'd3[.-]([\d.]+)(?:\.min)?\.js', 'D3.js'),
        
        # Chart.js
        (r'chart[.-]([\d.]+)(?:\.min)?\.js', 'Chart.js'),
        
        # Three.js
        (r'three[.-]([\d.]+)(?:\.min)?\.js', 'Three.js'),
        
        # Axios
        (r'axios[.-]([\d.]+)(?:\.min)?\.js', 'Axios'),
        
        # Socket.io
        (r'socket\.io[.-]([\d.]+)(?:\.min)?\.js', 'Socket.io'),
    ]
    
    for script in soup.find_all('script', src=True):
        src = script['src']
        
        for pattern, lib_name in script_patterns:
            match = re.search(pattern, src, re.IGNORECASE)
            if match:
                version = match.group(1)
                libraries.append({
                    'name': lib_name,
                    'version': version,
                    'source_url': src if src.startswith('http') else f"{base_url}{src}",
                    'source': 'script_tag',
                    'confidence': 'high'
                })
    
    return libraries


def _detect_from_link_tags(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    """Detect CSS libraries from link tags"""
    libraries = []
    
    css_patterns = [
        # Bootstrap
        (r'bootstrap[.-]([\d.]+)(?:\.min)?\.css', 'Bootstrap'),
        
        # Font Awesome
        (r'font-awesome[.-]([\d.]+)(?:\.min)?\.css', 'Font Awesome'),
        
        # Bulma
        (r'bulma[.-]([\d.]+)(?:\.min)?\.css', 'Bulma'),
        
        # Tailwind
        (r'tailwind[.-]([\d.]+)(?:\.min)?\.css', 'Tailwind CSS'),
    ]
    
    for link in soup.find_all('link', href=True, rel='stylesheet'):
        href = link['href']
        
        for pattern, lib_name in css_patterns:
            match = re.search(pattern, href, re.IGNORECASE)
            if match:
                version = match.group(1)
                libraries.append({
                    'name': lib_name,
                    'version': version,
                    'source_url': href if href.startswith('http') else f"{base_url}{href}",
                    'source': 'link_tag',
                    'confidence': 'high'
                })
    
    return libraries


def _detect_from_meta_tags(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """Detect libraries/frameworks from meta tags"""
    libraries = []
    
    # Check generator meta tag
    generator = soup.find('meta', attrs={'name': 'generator'})
    if generator and generator.get('content'):
        content = generator['content']
        
        # WordPress
        match = re.search(r'WordPress\s+([\d.]+)', content, re.IGNORECASE)
        if match:
            libraries.append({
                'name': 'WordPress',
                'version': match.group(1),
                'source': 'meta_generator',
                'confidence': 'high',
                'type': 'CMS'
            })
        
        # Joomla
        match = re.search(r'Joomla!\s+-\s+([\d.]+)', content, re.IGNORECASE)
        if match:
            libraries.append({
                'name': 'Joomla',
                'version': match.group(1),
                'source': 'meta_generator',
                'confidence': 'high',
                'type': 'CMS'
            })
        
        # Drupal
        if 'drupal' in content.lower():
            libraries.append({
                'name': 'Drupal',
                'version': 'Unknown',
                'source': 'meta_generator',
                'confidence': 'medium',
                'type': 'CMS'
            })
    
    return libraries


def _detect_from_comments(html: str) -> List[Dict[str, Any]]:
    """Detect libraries from HTML comments"""
    libraries = []
    
    # Find all HTML comments
    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    
    for comment in comments:
        # jQuery
        match = re.search(r'jQuery\s+v([\d.]+)', comment, re.IGNORECASE)
        if match:
            libraries.append({
                'name': 'jQuery',
                'version': match.group(1),
                'source': 'html_comment',
                'confidence': 'medium'
            })
        
        # React
        match = re.search(r'React\s+v([\d.]+)', comment, re.IGNORECASE)
        if match:
            libraries.append({
                'name': 'React',
                'version': match.group(1),
                'source': 'html_comment',
                'confidence': 'medium'
            })
    
    return libraries


# ============================================
# CMS Detection
# ============================================

def detect_cms(url: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    Detect CMS (Content Management System)
    
    Detects:
    - WordPress
    - Joomla
    - Drupal
    - Magento
    - Shopify
    - Wix
    - Squarespace
    - And more...
    """
    try:
        logger.info(f"Detecting CMS for {url}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        html = response.text
        response_headers = response.headers
        
        # Check various CMS signatures
        cms_checks = [
            _detect_wordpress,
            _detect_joomla,
            _detect_drupal,
            _detect_magento,
            _detect_shopify,
            _detect_wix,
            _detect_squarespace,
            _detect_ghost,
            _detect_prestashop,
        ]
        
        for check_func in cms_checks:
            result = check_func(html, response_headers, url)
            if result:
                logger.info(f"Detected CMS: {result['name']}")
                return result
        
        logger.info("No CMS detected")
        return None
        
    except Exception as e:
        logger.error(f"CMS detection failed for {url}: {e}")
        return None


def _detect_wordpress(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect WordPress"""
    indicators = [
        'wp-content',
        'wp-includes',
        'wp-json',
        'wordpress',
        '/wp-admin/',
    ]
    
    if any(indicator in html for indicator in indicators):
        # Try to get version
        version = 'Unknown'
        
        # Check meta generator
        match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', html, re.IGNORECASE)
        if match:
            version = match.group(1)
        
        # Check readme.html
        try:
            readme_url = f"{url.rstrip('/')}/readme.html"
            readme_response = requests.get(readme_url, timeout=5)
            if readme_response.status_code == 200:
                version_match = re.search(r'Version ([\d.]+)', readme_response.text)
                if version_match:
                    version = version_match.group(1)
        except:
            pass
        
        return {
            'name': 'WordPress',
            'version': version,
            'confidence': 'high',
            'indicators': ['wp-content', 'wp-includes'],
            'type': 'CMS'
        }
    
    return None


def _detect_joomla(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect Joomla"""
    indicators = [
        '/media/jui/',
        '/templates/system/',
        'Joomla!',
        '/administrator/components/com_',
    ]
    
    if any(indicator in html for indicator in indicators):
        version = 'Unknown'
        
        # Check meta generator
        match = re.search(r'<meta name="generator" content="Joomla! - ([\d.]+)"', html, re.IGNORECASE)
        if match:
            version = match.group(1)
        
        return {
            'name': 'Joomla',
            'version': version,
            'confidence': 'high',
            'indicators': ['/media/jui/', 'Joomla!'],
            'type': 'CMS'
        }
    
    return None


def _detect_drupal(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect Drupal"""
    indicators = [
        '/sites/default/',
        '/sites/all/',
        'Drupal',
        '/misc/drupal.js',
        'sites/default/files',
    ]
    
    # Check X-Generator header
    if 'Drupal' in headers.get('X-Generator', ''):
        version_match = re.search(r'Drupal ([\d.]+)', headers['X-Generator'])
        version = version_match.group(1) if version_match else 'Unknown'
        
        return {
            'name': 'Drupal',
            'version': version,
            'confidence': 'high',
            'indicators': ['X-Generator header'],
            'type': 'CMS'
        }
    
    if any(indicator in html for indicator in indicators):
        # Try to get version from CHANGELOG.txt
        version = 'Unknown'
        try:
            changelog_url = f"{url.rstrip('/')}/CHANGELOG.txt"
            changelog_response = requests.get(changelog_url, timeout=5)
            if changelog_response.status_code == 200:
                version_match = re.search(r'Drupal ([\d.]+)', changelog_response.text)
                if version_match:
                    version = version_match.group(1)
        except:
            pass
        
        return {
            'name': 'Drupal',
            'version': version,
            'confidence': 'medium',
            'indicators': ['/sites/default/', '/sites/all/'],
            'type': 'CMS'
        }
    
    return None


def _detect_magento(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect Magento"""
    indicators = [
        '/skin/frontend/',
        '/js/mage/',
        'Mage.Cookies',
        '/magento_version',
    ]
    
    if any(indicator in html for indicator in indicators):
        return {
            'name': 'Magento',
            'version': 'Unknown',
            'confidence': 'high',
            'indicators': ['/skin/frontend/', '/js/mage/'],
            'type': 'CMS'
        }
    
    return None


def _detect_shopify(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect Shopify"""
    indicators = [
        'cdn.shopify.com',
        'Shopify.theme',
        'shopify-analytics',
    ]
    
    if any(indicator in html for indicator in indicators):
        return {
            'name': 'Shopify',
            'version': 'SaaS',
            'confidence': 'high',
            'indicators': ['cdn.shopify.com', 'Shopify.theme'],
            'type': 'CMS'
        }
    
    return None


def _detect_wix(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect Wix"""
    if 'wix.com' in html or 'X-Wix-' in str(headers):
        return {
            'name': 'Wix',
            'version': 'SaaS',
            'confidence': 'high',
            'indicators': ['wix.com'],
            'type': 'CMS'
        }
    
    return None


def _detect_squarespace(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect Squarespace"""
    if 'squarespace' in html.lower() or 'squarespace-cdn' in html:
        return {
            'name': 'Squarespace',
            'version': 'SaaS',
            'confidence': 'high',
            'indicators': ['squarespace'],
            'type': 'CMS'
        }
    
    return None


def _detect_ghost(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect Ghost"""
    if 'ghost' in html.lower() and '/ghost/api/' in html:
        return {
            'name': 'Ghost',
            'version': 'Unknown',
            'confidence': 'medium',
            'indicators': ['/ghost/api/'],
            'type': 'CMS'
        }
    
    return None


def _detect_prestashop(html: str, headers: Dict, url: str) -> Optional[Dict[str, Any]]:
    """Detect PrestaShop"""
    indicators = [
        'prestashop',
        '/modules/ps_',
        '/themes/classic/',
    ]
    
    if any(indicator in html.lower() for indicator in indicators):
        return {
            'name': 'PrestaShop',
            'version': 'Unknown',
            'confidence': 'medium',
            'indicators': ['prestashop', '/modules/ps_'],
            'type': 'CMS'
        }
    
    return None


# ============================================
# Combined Detection
# ============================================

def detect_technologies(url: str) -> Dict[str, Any]:
    """
    Detect all technologies (libraries + CMS) for a URL
    
    Returns comprehensive technology stack information
    """
    logger.info(f"Detecting technologies for {url}")
    
    result = {
        'url': url,
        'libraries': [],
        'cms': None,
        'total_libraries': 0,
        'has_cms': False
    }
    
    try:
        # Detect frontend libraries
        libraries = detect_frontend_libraries(url)
        result['libraries'] = libraries
        result['total_libraries'] = len(libraries)
        
        # Detect CMS
        cms = detect_cms(url)
        if cms:
            result['cms'] = cms
            result['has_cms'] = True
        
        logger.info(f"Detection complete: {len(libraries)} libraries, CMS: {cms['name'] if cms else 'None'}")
        
    except Exception as e:
        logger.error(f"Technology detection failed: {e}")
    
    return result


# ============================================
# Example Usage
# ============================================

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s'
    )
    
    # Disable SSL warnings for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("\n" + "="*60)
    print("TECHNOLOGY DETECTION TEST")
    print("="*60 + "\n")
    
    # Test URL
    test_url = 'https://example.com'
    
    print(f"Testing URL: {test_url}\n")
    
    result = detect_technologies(test_url)
    
    print(f"Total Libraries Detected: {result['total_libraries']}")
    print(f"CMS Detected: {result['cms']['name'] if result['cms'] else 'None'}")
    
    if result['libraries']:
        print("\nLibraries:")
        for lib in result['libraries']:
            print(f"  - {lib['name']} v{lib['version']} (confidence: {lib.get('confidence', 'unknown')})")
    
    if result['cms']:
        cms = result['cms']
        print(f"\nCMS Details:")
        print(f"  Name: {cms['name']}")
        print(f"  Version: {cms['version']}")
        print(f"  Confidence: {cms['confidence']}")
        print(f"  Indicators: {', '.join(cms['indicators'])}")