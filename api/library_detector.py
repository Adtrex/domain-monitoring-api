"""
Open Source Library and CMS Detection for CERRT
Enhanced version with improved detection capabilities
Uses only free/open-source methods:
- HTML/JavaScript parsing
- Header analysis
- Common file pattern detection
- Script content inspection
"""

import requests
import re
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
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
        
        # 2. Check script src attributes (ENHANCED)
        libraries.extend(_detect_from_script_tags(soup, url, headers, timeout))
        
        # 3. Check link href attributes (CSS libraries)
        libraries.extend(_detect_from_link_tags(soup, url))
        
        # 4. Check meta tags
        libraries.extend(_detect_from_meta_tags(soup))
        
        # 5. Check HTML comments
        libraries.extend(_detect_from_comments(html))
        
        # 6. Check for global JavaScript objects (NEW)
        libraries.extend(_detect_from_global_objects(html))
        
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


def _fetch_script_head(url: str, headers: Dict, timeout: int = 5, max_bytes: int = 3000) -> Optional[str]:
    """
    Fetch the first few KB of a script file to inspect for version info
    """
    try:
        response = requests.get(url, headers=headers, timeout=timeout, stream=True, verify=False)
        content = b''
        for chunk in response.iter_content(chunk_size=1024):
            content += chunk
            if len(content) >= max_bytes:
                break
        return content.decode('utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f"Failed to fetch script head from {url}: {e}")
        return None


def _extract_version_from_script_content(content: str, lib_name: str) -> Optional[str]:
    """
    Extract version from script file content using multiple patterns
    """
    if not content:
        return None
    
    # Pattern 1: Comment headers like /*! jQuery v3.6.0 */
    patterns = [
        rf'/\*[!\*]\s*{re.escape(lib_name)}\s+v?([\d.]+)',  # /*! jQuery v3.6.0 */
        rf'//\s*{re.escape(lib_name)}\s+v?([\d.]+)',        # // jQuery v3.6.0
        rf'{re.escape(lib_name)}\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']',  # jQuery.version = "3.6.0"
        rf'version:\s*["\'](\d+\.\d+\.\d+)["\']',           # version: "3.6.0"
        rf'VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']',        # VERSION = "3.6.0"
        r'@version\s+([\d.]+)',                              # @version 3.6.0
    ]
    
    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    # Generic version pattern in first 500 chars (common in minified files)
    first_part = content[:500]
    generic_match = re.search(r'v?([\d]+\.[\d]+\.[\d]+)', first_part)
    if generic_match:
        return generic_match.group(1)
    
    return None


def _detect_from_inline_js(html: str) -> List[Dict[str, Any]]:
    """Detect libraries from inline JavaScript code"""
    libraries = []
    
    # Common library patterns in inline JS
    patterns = [
        # jQuery
        (r'jQuery[.\s]+v?([\d.]+)', 'jQuery'),
        (r'\$\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']', 'jQuery'),
        
        # React
        (r'React[.\s]+v?([\d.]+)', 'React'),
        (r'react@(\d+\.\d+\.\d+)', 'React'),
        
        # Vue
        (r'Vue[.\s]+v?([\d.]+)', 'Vue.js'),
        (r'vue@(\d+\.\d+\.\d+)', 'Vue.js'),
        
        # Angular
        (r'Angular[.\s]+v?([\d.]+)', 'Angular'),
        (r'angular@(\d+\.\d+\.\d+)', 'Angular'),
        
        # Bootstrap
        (r'Bootstrap[.\s]+v?([\d.]+)', 'Bootstrap'),
        
        # Lodash
        (r'lodash[.\s]+v?([\d.]+)', 'Lodash'),
        
        # Moment.js
        (r'moment[.\s]+v?([\d.]+)', 'Moment.js'),
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


def _detect_from_global_objects(html: str) -> List[Dict[str, Any]]:
    """
    Detect libraries by checking for their global JavaScript objects/properties
    """
    libraries = []
    
    # Extract inline script content
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    combined_js = ' '.join(inline_scripts)
    
    # jQuery version check
    jquery_patterns = [
        r'\$\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
        r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
    ]
    for pattern in jquery_patterns:
        match = re.search(pattern, combined_js)
        if match:
            libraries.append({
                'name': 'jQuery',
                'version': match.group(1),
                'source': 'global_object',
                'confidence': 'high'
            })
            break
    
    # React version (often in React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED)
    if 'React' in html and 'react' in html.lower():
        react_match = re.search(r'React[.\w]*version[\'"]?\s*[:=]\s*[\'"](\d+\.\d+\.\d+)', combined_js, re.IGNORECASE)
        if react_match:
            libraries.append({
                'name': 'React',
                'version': react_match.group(1),
                'source': 'global_object',
                'confidence': 'high'
            })
    
    # Vue version
    vue_match = re.search(r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']', combined_js, re.IGNORECASE)
    if vue_match:
        libraries.append({
            'name': 'Vue.js',
            'version': vue_match.group(1),
            'source': 'global_object',
            'confidence': 'high'
        })
    
    return libraries


def _detect_from_script_tags(soup: BeautifulSoup, base_url: str, headers: Dict, timeout: int) -> List[Dict[str, Any]]:
    """Detect libraries from script src attributes - ENHANCED VERSION"""
    libraries = []
    
    # Library definitions with multiple detection patterns
    library_configs = {
        'jQuery': {
            'patterns': [
                r'jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'jquery(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/jquery/(\d+\.\d+\.\d+)/',
                r'@?jquery@(\d+\.\d+\.\d+)',
            ],
            'identifiers': ['jquery'],
            'cdn_patterns': ['code.jquery.com', 'ajax.googleapis.com/ajax/libs/jquery']
        },
        'React': {
            'patterns': [
                r'react[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'react(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/react/(\d+\.\d+\.\d+)/',
                r'@?react@(\d+\.\d+\.\d+)',
            ],
            'identifiers': ['react'],
            'cdn_patterns': ['unpkg.com/react', 'cdn.jsdelivr.net/npm/react']
        },
        'React DOM': {
            'patterns': [
                r'react-dom[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'react-dom(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/react-dom/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['react-dom'],
            'cdn_patterns': ['unpkg.com/react-dom']
        },
        'Vue.js': {
            'patterns': [
                r'vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'vue(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/vue/(\d+\.\d+\.\d+)/',
                r'@?vue@(\d+\.\d+\.\d+)',
            ],
            'identifiers': ['vue'],
            'cdn_patterns': ['unpkg.com/vue', 'cdn.jsdelivr.net/npm/vue']
        },
        'Angular': {
            'patterns': [
                r'angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'angular(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/angular/(\d+\.\d+\.\d+)/',
                r'@?angular@(\d+\.\d+\.\d+)',
            ],
            'identifiers': ['angular'],
            'cdn_patterns': ['ajax.googleapis.com/ajax/libs/angularjs']
        },
        'Bootstrap': {
            'patterns': [
                r'bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'bootstrap(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/bootstrap/(\d+\.\d+\.\d+)/',
                r'@?bootstrap@(\d+\.\d+\.\d+)',
            ],
            'identifiers': ['bootstrap'],
            'cdn_patterns': ['cdn.jsdelivr.net/npm/bootstrap', 'maxcdn.bootstrapcdn.com']
        },
        'Lodash': {
            'patterns': [
                r'lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'lodash(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/lodash/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['lodash'],
            'cdn_patterns': ['cdn.jsdelivr.net/npm/lodash']
        },
        'Moment.js': {
            'patterns': [
                r'moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'moment(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/moment/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['moment'],
            'cdn_patterns': ['cdnjs.cloudflare.com/ajax/libs/moment.js']
        },
        'D3.js': {
            'patterns': [
                r'd3[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'd3(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/d3/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['d3'],
            'cdn_patterns': ['d3js.org', 'cdn.jsdelivr.net/npm/d3']
        },
        'Chart.js': {
            'patterns': [
                r'chart[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'chart(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/chart\.js/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['chart'],
            'cdn_patterns': ['cdn.jsdelivr.net/npm/chart.js']
        },
        'Three.js': {
            'patterns': [
                r'three[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'three(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/three\.js/r(\d+)/',  # Three.js uses r128, r140 etc
            ],
            'identifiers': ['three'],
            'cdn_patterns': ['cdn.jsdelivr.net/npm/three', 'cdnjs.cloudflare.com/ajax/libs/three.js']
        },
        'Axios': {
            'patterns': [
                r'axios[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'axios(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/axios/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['axios'],
            'cdn_patterns': ['cdn.jsdelivr.net/npm/axios']
        },
        'Socket.io': {
            'patterns': [
                r'socket\.io[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'socket\.io(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/socket\.io/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['socket.io'],
            'cdn_patterns': ['cdn.socket.io']
        },
        'Swiper': {
            'patterns': [
                r'swiper[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'swiper(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/swiper/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['swiper'],
            'cdn_patterns': ['unpkg.com/swiper']
        },
        'AOS': {
            'patterns': [
                r'aos[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'aos(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'aos@(\d+\.\d+\.\d+)',  # ← FIX: CDN @version format  
                r'/aos/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['aos'],
            'cdn_patterns': ['unpkg.com/aos', 'cdn.jsdelivr.net/npm/aos']  # ← FIX: Add jsdelivr
        },
        'GSAP': {
            'patterns': [
                r'gsap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
                r'gsap(?:\.min)?\.js(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/gsap/(\d+\.\d+\.\d+)/',
            ],
            'identifiers': ['gsap'],
            'cdn_patterns': ['cdnjs.cloudflare.com/ajax/libs/gsap']
        }
    }
    
    detected_scripts = {}  # Track what we've already detected
    
    for script in soup.find_all('script', src=True):
        src = script['src'].strip()
        src_lower = src.lower()
        
        # Convert relative URLs to absolute
        if not src.startswith(('http://', 'https://', '//')):
            src_abs = urljoin(base_url, src)
        else:
            src_abs = src if src.startswith('http') else 'https:' + src
        
        # Try to detect library and version
        for lib_name, config in library_configs.items():
            # Skip if already detected this library
            if lib_name in detected_scripts:
                continue
            
            version = None
            detection_method = None
            
            # Method 1: Check URL patterns
            for pattern in config['patterns']:
                match = re.search(pattern, src_lower, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    detection_method = 'url_pattern'
                    break
            
            # Method 2: Check if URL contains library identifier
            if not version:
                for identifier in config['identifiers']:
                    if identifier in src_lower:
                        # Found the library, now try to fetch version from content
                        script_content = _fetch_script_head(src_abs, headers, timeout=5)
                        if script_content:
                            version = _extract_version_from_script_content(script_content, lib_name)
                            if version:
                                detection_method = 'script_content'
                        break
            
            # Method 3: Check CDN patterns (even without version in URL, fetch content)
            if not version:
                for cdn_pattern in config['cdn_patterns']:
                    if cdn_pattern in src_lower:
                        script_content = _fetch_script_head(src_abs, headers, timeout=5)
                        if script_content:
                            version = _extract_version_from_script_content(script_content, lib_name)
                            if version:
                                detection_method = 'cdn_content'
                        break
            
            # If we found a version, add it
            if version:
                detected_scripts[lib_name] = True
                libraries.append({
                    'name': lib_name,
                    'version': version,
                    'source_url': src_abs,
                    'source': 'script_tag',
                    'confidence': 'high' if detection_method in ['url_pattern', 'script_content'] else 'medium'
                })
    
    return libraries


def show_all_scripts(url):
    headers = {
        'User-Agent': 'Mozilla/5.0'
    }

    try:
        response = requests.get(url, headers=headers, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        print("\n========== ALL SCRIPTS FOUND ==========\n")

        scripts = soup.find_all("script")

        if not scripts:
            print("No scripts found.")
            return

        for i, script in enumerate(scripts, 1):

            # External scripts
            if script.get("src"):
                print(f"{i}. External Script → {script['src']}")

            # Inline scripts
            else:
                inline_preview = script.text.strip().replace("\n", " ")
                print(f"{i}. Inline Script → {inline_preview[:120]}...\n")

    except Exception as e:
        print("Error fetching scripts:", e)


def _detect_from_link_tags(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    """Detect CSS libraries from link tags - ENHANCED"""
    libraries = []
    
    css_configs = {
        'Bootstrap': {
            'patterns': [
                r'bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.css',
                r'bootstrap(?:\.min)?\.css(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/bootstrap/(\d+\.\d+\.\d+)/',
            ],
            'cdn_patterns': ['cdn.jsdelivr.net/npm/bootstrap', 'maxcdn.bootstrapcdn.com']
        },
        'Font Awesome': {
            'patterns': [
                r'font-awesome[.-](\d+\.\d+\.\d+)(?:\.min)?\.css',
                r'fontawesome[.-](\d+\.\d+\.\d+)(?:\.min)?\.css',
                r'font-awesome(?:\.min)?\.css(?:\?ver?=(\d+\.\d+\.\d+))?',
                r'/font-awesome/(\d+\.\d+\.\d+)/',
            ],
            'cdn_patterns': ['use.fontawesome.com', 'cdnjs.cloudflare.com/ajax/libs/font-awesome']
        },
        'Bulma': {
            'patterns': [
                r'bulma[.-](\d+\.\d+\.\d+)(?:\.min)?\.css',
                r'bulma(?:\.min)?\.css(?:\?ver?=(\d+\.\d+\.\d+))?',
            ],
            'cdn_patterns': ['cdn.jsdelivr.net/npm/bulma']
        },
        'Tailwind CSS': {
            'patterns': [
                r'tailwind[.-](\d+\.\d+\.\d+)(?:\.min)?\.css',
                r'tailwind(?:\.min)?\.css(?:\?ver?=(\d+\.\d+\.\d+))?',
            ],
            'cdn_patterns': ['cdn.tailwindcss.com']
        },
        'Animate.css': {
            'patterns': [
                r'animate[.-](\d+\.\d+\.\d+)(?:\.min)?\.css',
                r'animate(?:\.min)?\.css(?:\?ver?=(\d+\.\d+\.\d+))?',
            ],
            'cdn_patterns': ['cdnjs.cloudflare.com/ajax/libs/animate.css']
        }
    }
    
    for link in soup.find_all('link', href=True, rel='stylesheet'):
        href = link['href'].strip()
        href_lower = href.lower()
        
        for lib_name, config in css_configs.items():
            version = None
            
            # Try patterns
            for pattern in config['patterns']:
                match = re.search(pattern, href_lower, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else None
                    break
            
            if version:
                libraries.append({
                    'name': lib_name,
                    'version': version,
                    'source_url': href if href.startswith('http') else urljoin(base_url, href),
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
        match = re.search(r'jQuery\s+v?([\d.]+)', comment, re.IGNORECASE)
        if match:
            libraries.append({
                'name': 'jQuery',
                'version': match.group(1),
                'source': 'html_comment',
                'confidence': 'medium'
            })
        
        # React
        match = re.search(r'React\s+v?([\d.]+)', comment, re.IGNORECASE)
        if match:
            libraries.append({
                'name': 'React',
                'version': match.group(1),
                'source': 'html_comment',
                'confidence': 'medium'
            })
        
        # Bootstrap
        match = re.search(r'Bootstrap\s+v?([\d.]+)', comment, re.IGNORECASE)
        if match:
            libraries.append({
                'name': 'Bootstrap',
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
            readme_response = requests.get(readme_url, timeout=5, verify=False)
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
            changelog_response = requests.get(changelog_url, timeout=5, verify=False)
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
# WordPress Plugins & Themes Detection
# ============================================

def detect_wordpress_plugins(url: str, html: str, timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Detect WordPress plugins and their versions
    """
    plugins = []
    seen_plugins = set()
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    # Pattern to find wp-content/plugins references
    plugin_patterns = [
        r'/wp-content/plugins/([^/\'"]+)',
        r'wp-content/plugins/([^/\'"]+)',
    ]
    
    found_plugins = set()
    for pattern in plugin_patterns:
        matches = re.finditer(pattern, html, re.IGNORECASE)
        for match in matches:
            plugin_slug = match.group(1)
            if plugin_slug and plugin_slug not in found_plugins:
                found_plugins.add(plugin_slug)
    
    # For each plugin, try to get version
    for plugin_slug in found_plugins:
        if plugin_slug in seen_plugins:
            continue
        
        plugin_info = {
            'name': plugin_slug,
            'version': 'Unknown',
            'type': 'WordPress Plugin',
            'confidence': 'medium'
        }
        
        # Try common version detection methods
        version_found = False
        
        # Method 1: Check readme.txt
        try:
            readme_url = f"{url.rstrip('/')}/wp-content/plugins/{plugin_slug}/readme.txt"
            readme_response = requests.get(readme_url, headers=headers, timeout=5, verify=False)
            if readme_response.status_code == 200:
                # Look for "Stable tag:" or "Version:"
                version_match = re.search(r'(?:Stable tag|Version):\s*([\d.]+)', readme_response.text, re.IGNORECASE)
                if version_match:
                    plugin_info['version'] = version_match.group(1)
                    plugin_info['confidence'] = 'high'
                    version_found = True
                
                # Also try to get the proper plugin name
                name_match = re.search(r'Plugin Name:\s*(.+)', readme_response.text, re.IGNORECASE)
                if not name_match:
                    name_match = re.search(r'===\s*(.+?)\s*===', readme_response.text)
                if name_match:
                    plugin_info['name'] = name_match.group(1).strip()
        except:
            pass
        
        # Method 2: Check plugin's main PHP file for version
        if not version_found:
            try:
                # Common main file names
                main_files = [
                    f"{plugin_slug}.php",
                    "plugin.php",
                    "index.php"
                ]
                
                for main_file in main_files:
                    plugin_url = f"{url.rstrip('/')}/wp-content/plugins/{plugin_slug}/{main_file}"
                    plugin_response = requests.get(plugin_url, headers=headers, timeout=5, verify=False)
                    if plugin_response.status_code == 200:
                        # Look for version in PHP header comment
                        version_match = re.search(r'Version:\s*([\d.]+)', plugin_response.text, re.IGNORECASE)
                        if version_match:
                            plugin_info['version'] = version_match.group(1)
                            plugin_info['confidence'] = 'high'
                            version_found = True
                        
                        # Get plugin name from header
                        name_match = re.search(r'Plugin Name:\s*(.+)', plugin_response.text, re.IGNORECASE)
                        if name_match:
                            plugin_info['name'] = name_match.group(1).strip()
                        
                        if version_found:
                            break
            except:
                pass
        
        # Method 3: Check for version in script/style URLs
        if not version_found:
            version_in_url = re.search(rf'/wp-content/plugins/{re.escape(plugin_slug)}/[^?]*\?ver=([\d.]+)', html)
            if version_in_url:
                plugin_info['version'] = version_in_url.group(1)
                plugin_info['confidence'] = 'medium'
        
        seen_plugins.add(plugin_slug)
        plugins.append(plugin_info)
    
    return plugins


def detect_wordpress_theme(url: str, html: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    Detect WordPress theme and version
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    # Find theme slug from wp-content/themes
    theme_pattern = r'/wp-content/themes/([^/\'"]+)'
    theme_match = re.search(theme_pattern, html, re.IGNORECASE)
    
    if not theme_match:
        return None
    
    theme_slug = theme_match.group(1)
    
    theme_info = {
        'name': theme_slug,
        'version': 'Unknown',
        'type': 'WordPress Theme',
        'confidence': 'medium'
    }
    
    # Try to get theme details from style.css
    try:
        style_url = f"{url.rstrip('/')}/wp-content/themes/{theme_slug}/style.css"
        style_response = requests.get(style_url, headers=headers, timeout=5, verify=False)
        
        if style_response.status_code == 200:
            style_content = style_response.text[:2000]  # First 2KB should have header
            
            # Extract theme name
            name_match = re.search(r'Theme Name:\s*(.+)', style_content, re.IGNORECASE)
            if name_match:
                theme_info['name'] = name_match.group(1).strip()
            
            # Extract version
            version_match = re.search(r'Version:\s*([\d.]+)', style_content, re.IGNORECASE)
            if version_match:
                theme_info['version'] = version_match.group(1)
                theme_info['confidence'] = 'high'
            
            # Extract author
            author_match = re.search(r'Author:\s*(.+)', style_content, re.IGNORECASE)
            if author_match:
                theme_info['author'] = author_match.group(1).strip()
    except:
        pass
    
    # Fallback: Check for version in URL parameters
    if theme_info['version'] == 'Unknown':
        version_in_url = re.search(rf'/wp-content/themes/{re.escape(theme_slug)}/[^?]*\?ver=([\d.]+)', html)
        if version_in_url:
            theme_info['version'] = version_in_url.group(1)
    
    return theme_info


def detect_cms_extensions(url: str, html: str, cms_name: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Detect CMS-specific extensions (plugins, themes, modules)
    """
    result = {
        'plugins': [],
        'themes': None,
        'modules': [],
        'extensions': []
    }
    
    if cms_name == 'WordPress':
        # Detect WordPress plugins
        plugins = detect_wordpress_plugins(url, html, timeout)
        result['plugins'] = plugins
        
        # Detect WordPress theme
        theme = detect_wordpress_theme(url, html, timeout)
        result['themes'] = theme
    
    elif cms_name == 'Joomla':
        # Detect Joomla extensions
        result['extensions'] = _detect_joomla_extensions(html)
    
    elif cms_name == 'Drupal':
        # Detect Drupal modules
        result['modules'] = _detect_drupal_modules(html)
    
    return result


def _detect_joomla_extensions(html: str) -> List[Dict[str, Any]]:
    """
    Detect Joomla extensions
    """
    extensions = []
    seen_extensions = set()
    
    # Pattern for Joomla components
    component_pattern = r'/components/com_([^/\'"]+)'
    component_matches = re.finditer(component_pattern, html, re.IGNORECASE)
    
    for match in component_matches:
        component_name = match.group(1)
        if component_name not in seen_extensions:
            extensions.append({
                'name': f'com_{component_name}',
                'type': 'Joomla Component',
                'version': 'Unknown',
                'confidence': 'medium'
            })
            seen_extensions.add(component_name)
    
    # Pattern for Joomla modules
    module_pattern = r'/modules/mod_([^/\'"]+)'
    module_matches = re.finditer(module_pattern, html, re.IGNORECASE)
    
    for match in module_matches:
        module_name = match.group(1)
        if module_name not in seen_extensions:
            extensions.append({
                'name': f'mod_{module_name}',
                'type': 'Joomla Module',
                'version': 'Unknown',
                'confidence': 'medium'
            })
            seen_extensions.add(module_name)
    
    # Pattern for Joomla plugins
    plugin_pattern = r'/plugins/([^/]+)/([^/\'"]+)'
    plugin_matches = re.finditer(plugin_pattern, html, re.IGNORECASE)
    
    for match in plugin_matches:
        plugin_type = match.group(1)
        plugin_name = match.group(2)
        plugin_key = f"{plugin_type}_{plugin_name}"
        if plugin_key not in seen_extensions:
            extensions.append({
                'name': plugin_name,
                'type': f'Joomla Plugin ({plugin_type})',
                'version': 'Unknown',
                'confidence': 'medium'
            })
            seen_extensions.add(plugin_key)
    
    return extensions


def _detect_drupal_modules(html: str) -> List[Dict[str, Any]]:
    """
    Detect Drupal modules
    """
    modules = []
    seen_modules = set()
    
    # Pattern for Drupal modules
    module_patterns = [
        r'/sites/all/modules/([^/\'"]+)',
        r'/sites/default/modules/([^/\'"]+)',
        r'/modules/([^/\'"]+)',
    ]
    
    for pattern in module_patterns:
        matches = re.finditer(pattern, html, re.IGNORECASE)
        for match in matches:
            module_name = match.group(1)
            # Skip core modules
            if module_name not in ['system', 'user', 'node', 'block', 'comment']:
                if module_name not in seen_modules:
                    modules.append({
                        'name': module_name,
                        'type': 'Drupal Module',
                        'version': 'Unknown',
                        'confidence': 'medium'
                    })
                    seen_modules.add(module_name)
    
    return modules


# ============================================
# Web Server & Technology Detection
# ============================================

def detect_web_server(headers: Dict) -> Optional[Dict[str, Any]]:
    """
    Detect web server from response headers
    """
    server_header = headers.get('Server', headers.get('server', ''))
    
    if not server_header:
        return None
    
    # Common web servers
    servers = {
        'nginx': r'nginx/([\d.]+)',
        'Apache': r'Apache/([\d.]+)',
        'Microsoft-IIS': r'Microsoft-IIS/([\d.]+)',
        'LiteSpeed': r'LiteSpeed',
        'Cloudflare': r'cloudflare',
    }
    
    for server_name, pattern in servers.items():
        match = re.search(pattern, server_header, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else 'Unknown'
            return {
                'name': server_name,
                'version': version,
                'type': 'Web Server',
                'confidence': 'high'
            }
    
    return {
        'name': server_header.split('/')[0],
        'version': 'Unknown',
        'type': 'Web Server',
        'confidence': 'medium'
    }


def detect_programming_language(headers: Dict, html: str) -> List[Dict[str, Any]]:
    """
    Detect programming languages/frameworks
    """
    languages = []
    
    # Check headers
    x_powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
    
    if x_powered_by:
        # PHP
        php_match = re.search(r'PHP/([\d.]+)', x_powered_by, re.IGNORECASE)
        if php_match:
            languages.append({
                'name': 'PHP',
                'version': php_match.group(1),
                'type': 'Programming Language',
                'confidence': 'high'
            })
        
        # ASP.NET
        if 'ASP.NET' in x_powered_by:
            languages.append({
                'name': 'ASP.NET',
                'version': 'Unknown',
                'type': 'Framework',
                'confidence': 'high'
            })
    
    # Check for framework-specific patterns in HTML
    framework_patterns = {
        'Laravel': r'laravel_session',
        'Django': r'csrfmiddlewaretoken',
        'Rails': r'csrf-token.*Rails',
        'Next.js': r'__NEXT_DATA__|_next/static',
        'Nuxt.js': r'__NUXT__|_nuxt/',
        'Express': r'X-Powered-By.*Express',
    }
    
    for framework, pattern in framework_patterns.items():
        if re.search(pattern, html, re.IGNORECASE):
            languages.append({
                'name': framework,
                'version': 'Unknown',
                'type': 'Framework',
                'confidence': 'medium'
            })
    
    return languages


def detect_cdn(html: str, headers: Dict) -> List[Dict[str, Any]]:
    """
    Detect CDN usage
    """
    cdns = []
    seen_cdns = set()
    
    cdn_patterns = {
        'Cloudflare': ['cloudflare', 'cf-ray'],
        'Akamai': ['akamai'],
        'Fastly': ['fastly'],
        'Amazon CloudFront': ['cloudfront.net'],
        'MaxCDN': ['maxcdn', 'bootstrapcdn'],
        'jsDelivr': ['cdn.jsdelivr.net'],
        'unpkg': ['unpkg.com'],
        'Google CDN': ['ajax.googleapis.com'],
        'Microsoft Ajax CDN': ['ajax.aspnetcdn.com'],
        'cdnjs': ['cdnjs.cloudflare.com'],
    }
    
    # Check headers
    for cdn_name, patterns in cdn_patterns.items():
        for pattern in patterns:
            if pattern in str(headers).lower():
                if cdn_name not in seen_cdns:
                    cdns.append({
                        'name': cdn_name,
                        'type': 'CDN',
                        'confidence': 'high'
                    })
                    seen_cdns.add(cdn_name)
                    break
    
    # Check HTML content
    for cdn_name, patterns in cdn_patterns.items():
        for pattern in patterns:
            if pattern in html.lower():
                if cdn_name not in seen_cdns:
                    cdns.append({
                        'name': cdn_name,
                        'type': 'CDN',
                        'confidence': 'high'
                    })
                    seen_cdns.add(cdn_name)
                    break
    
    return cdns


def detect_analytics(html: str) -> List[Dict[str, Any]]:
    """
    Detect analytics and tracking tools
    """
    analytics = []
    
    analytics_patterns = {
        'Google Analytics': [r'google-analytics\.com/analytics\.js', r'googletagmanager\.com/gtag/js', r'UA-\d+-\d+', r'G-[A-Z0-9]+'],
        'Google Tag Manager': [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
        'Facebook Pixel': [r'connect\.facebook\.net/.*?/fbevents\.js', r'fbq\('],
        'Hotjar': [r'static\.hotjar\.com'],
        'Matomo': [r'matomo\.js', r'piwik\.js'],
        'Mixpanel': [r'mixpanel\.com/libs/mixpanel'],
        'Segment': [r'cdn\.segment\.com/analytics\.js'],
        'Heap Analytics': [r'heap\.com/heap'],
        'Plausible': [r'plausible\.io/js/plausible'],
        'Clicky': [r'static\.getclicky\.com'],
    }
    
    for tool_name, patterns in analytics_patterns.items():
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                analytics.append({
                    'name': tool_name,
                    'type': 'Analytics',
                    'confidence': 'high'
                })
                break
    
    return analytics


def detect_security_tools(headers: Dict, html: str) -> List[Dict[str, Any]]:
    """
    Detect security tools and services
    """
    security = []
    
    # Check security headers
    security_headers = {
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-XSS-Protection': 'XSS Protection',
        'Strict-Transport-Security': 'HSTS',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
    }
    
    for header, description in security_headers.items():
        if header in headers:
            security.append({
                'name': description,
                'type': 'Security Header',
                'confidence': 'high'
            })
    
    # Check for WAF/Security services
    waf_patterns = {
        'Cloudflare': ['cf-ray', 'cloudflare'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'Wordfence': ['wordfence'],
        'ModSecurity': ['mod_security', 'modsecurity'],
        'AWS WAF': ['x-amzn-requestid'],
    }
    
    for waf_name, patterns in waf_patterns.items():
        for pattern in patterns:
            if pattern in str(headers).lower() or pattern in html.lower():
                security.append({
                    'name': waf_name,
                    'type': 'WAF/Security',
                    'confidence': 'medium'
                })
                break
    
    return security


# ============================================
# Combined Detection
# ============================================

def detect_technologies(url: str) -> Dict[str, Any]:
    """
    Detect all technologies (libraries + CMS + plugins + more) for a URL
    
    Returns comprehensive technology stack information
    """
    logger.info(f"Detecting technologies for {url}")
    
    result = {
        'url': url,
        'libraries': [],
        'cms': None,
        'cms_extensions': {
            'plugins': [],
            'themes': None,
            'modules': [],
            'extensions': []
        },
        'web_server': None,
        'programming_languages': [],
        'cdn': [],
        'analytics': [],
        'security': [],
        'total_libraries': 0,
        'has_cms': False
    }
    
    try:
        # Fetch page with headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        html = response.text
        response_headers = response.headers
        
        # Detect frontend libraries
        libraries = detect_frontend_libraries(url)
        result['libraries'] = libraries
        result['total_libraries'] = len(libraries)
        
        # Detect CMS
        cms = detect_cms(url)
        if cms:
            result['cms'] = cms
            result['has_cms'] = True
            
            # Detect CMS extensions (plugins, themes, etc.)
            cms_extensions = detect_cms_extensions(url, html, cms['name'])
            result['cms_extensions'] = cms_extensions
        
        # Detect web server
        web_server = detect_web_server(response_headers)
        if web_server:
            result['web_server'] = web_server
        
        # Detect programming languages/frameworks
        programming_languages = detect_programming_language(response_headers, html)
        result['programming_languages'] = programming_languages
        
        # Detect CDN
        cdn = detect_cdn(html, response_headers)
        result['cdn'] = cdn
        
        # Detect analytics
        analytics = detect_analytics(html)
        result['analytics'] = analytics
        
        # Detect security tools
        security = detect_security_tools(response_headers, html)
        result['security'] = security
        
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
    print("ENHANCED TECHNOLOGY DETECTION TEST")
    print("="*60 + "\n")
    
    # Test URL
    test_url = 'https://zigaara.com'
    
    print(f"Testing URL: {test_url}\n")
    
    result = detect_technologies(test_url)

    show_all_scripts(test_url)
    
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}\n")
    
    # Libraries
    print(f"📚 Frontend Libraries: {result['total_libraries']}")
    if result['libraries']:
        for lib in result['libraries']:
            print(f"  ├─ {lib['name']} v{lib['version']} (confidence: {lib.get('confidence', 'unknown')})")
    
    # CMS
    if result['cms']:
        cms = result['cms']
        print(f"\n🔧 CMS: {cms['name']} v{cms['version']}")
        print(f"  └─ Confidence: {cms['confidence']}")
        
        # WordPress Plugins
        if result['cms_extensions']['plugins']:
            print(f"\n  🔌 WordPress Plugins ({len(result['cms_extensions']['plugins'])}):")
            for plugin in result['cms_extensions']['plugins'][:10]:  # Show first 10
                print(f"    ├─ {plugin['name']} v{plugin['version']}")
            if len(result['cms_extensions']['plugins']) > 10:
                print(f"    └─ ... and {len(result['cms_extensions']['plugins']) - 10} more")
        
        # WordPress Theme
        if result['cms_extensions']['themes']:
            theme = result['cms_extensions']['themes']
            print(f"\n  🎨 WordPress Theme:")
            print(f"    └─ {theme['name']} v{theme['version']}")
        
        # Joomla Extensions
        if result['cms_extensions']['extensions']:
            print(f"\n  🔌 Joomla Extensions ({len(result['cms_extensions']['extensions'])}):")
            for ext in result['cms_extensions']['extensions'][:5]:
                print(f"    ├─ {ext['name']} ({ext['type']})")
        
        # Drupal Modules
        if result['cms_extensions']['modules']:
            print(f"\n  🔌 Drupal Modules ({len(result['cms_extensions']['modules'])}):")
            for mod in result['cms_extensions']['modules'][:5]:
                print(f"    ├─ {mod['name']}")
    else:
        print(f"\n🔧 CMS: None detected")
    
    # Web Server
    if result['web_server']:
        server = result['web_server']
        print(f"\n🖥️  Web Server: {server['name']} v{server['version']}")
    
    # Programming Languages
    if result['programming_languages']:
        print(f"\n💻 Programming Languages/Frameworks:")
        for lang in result['programming_languages']:
            version_str = f" v{lang['version']}" if lang['version'] != 'Unknown' else ''
            print(f"  ├─ {lang['name']}{version_str}")
    
    # CDN
    if result['cdn']:
        print(f"\n🌐 CDN Services:")
        for cdn in result['cdn']:
            print(f"  ├─ {cdn['name']}")
    
    # Analytics
    if result['analytics']:
        print(f"\n📊 Analytics & Tracking:")
        for tool in result['analytics']:
            print(f"  ├─ {tool['name']}")
    
    # Security
    if result['security']:
        print(f"\n🔒 Security Features:")
        for sec in result['security']:
            print(f"  ├─ {sec['name']}")
    
    print(f"\n{'='*60}")