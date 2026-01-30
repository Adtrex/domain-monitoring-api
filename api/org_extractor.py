"""
Organization Name Extractor for CERRT

Extracts organization/company names from:
- Domain WHOIS data
- Website metadata
- SSL certificates
- About pages
- DNS records
"""

import requests
import re
from bs4 import BeautifulSoup
from typing import Optional
import logging
import socket

logger = logging.getLogger(__name__)


def extract_organization_name(url: str) -> Optional[str]:
    """
    Extract organization name from a URL using multiple methods
    
    Args:
        url: Target URL (e.g., 'https://example.com')
    
    Returns:
        Organization name or None
    """
    logger.info(f"Extracting organization name for {url}")
    
    # Try multiple extraction methods in order of reliability
    methods = [
        _extract_from_meta_tags,
        _extract_from_title,
        _extract_from_about_page,
        _extract_from_footer,
        _extract_from_domain_name,
    ]
    
    for method in methods:
        try:
            org_name = method(url)
            if org_name:
                logger.info(f"Organization found via {method.__name__}: {org_name}")
                return org_name
        except Exception as e:
            logger.debug(f"{method.__name__} failed: {e}")
            continue
    
    logger.warning(f"Could not extract organization name for {url}")
    return None


def _extract_from_meta_tags(url: str) -> Optional[str]:
    """
    Extract organization from meta tags (og:site_name, application-name, etc.)
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Try Open Graph site_name
        og_site_name = soup.find('meta', property='og:site_name')
        if og_site_name and og_site_name.get('content'):
            org_name = og_site_name['content'].strip()
            if _is_valid_org_name(org_name):
                return org_name
        
        # Try Twitter site
        twitter_site = soup.find('meta', attrs={'name': 'twitter:site'})
        if twitter_site and twitter_site.get('content'):
            org_name = twitter_site['content'].strip().lstrip('@')
            if _is_valid_org_name(org_name):
                return org_name
        
        # Try application-name
        app_name = soup.find('meta', attrs={'name': 'application-name'})
        if app_name and app_name.get('content'):
            org_name = app_name['content'].strip()
            if _is_valid_org_name(org_name):
                return org_name
        
        # Try author/publisher
        author = soup.find('meta', attrs={'name': 'author'})
        if author and author.get('content'):
            org_name = author['content'].strip()
            if _is_valid_org_name(org_name):
                return org_name
        
        publisher = soup.find('meta', property='article:publisher')
        if publisher and publisher.get('content'):
            org_name = publisher['content'].strip()
            if _is_valid_org_name(org_name):
                return org_name
        
        # Try schema.org organization
        org_schema = soup.find('script', type='application/ld+json')
        if org_schema:
            import json
            try:
                data = json.loads(org_schema.string)
                if isinstance(data, dict):
                    org_name = data.get('publisher', {}).get('name') or data.get('organization', {}).get('name')
                    if org_name and _is_valid_org_name(org_name):
                        return org_name
            except:
                pass
        
        return None
        
    except Exception as e:
        logger.debug(f"Meta tag extraction failed: {e}")
        return None


def _extract_from_title(url: str) -> Optional[str]:
    """
    Extract organization from page title
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        title = soup.find('title')
        if title and title.string:
            title_text = title.string.strip()
            
            # Common patterns: "Company Name - Tagline", "Welcome to Company Name"
            patterns = [
                r'^(.+?)\s*[-|–—]\s*',  # Before dash
                r'Welcome to (.+?)(?:\s*[-|]|$)',  # Welcome to...
                r'^(.+?)\s*\|\s*',  # Before pipe
            ]
            
            for pattern in patterns:
                match = re.search(pattern, title_text, re.IGNORECASE)
                if match:
                    org_name = match.group(1).strip()
                    if _is_valid_org_name(org_name):
                        return org_name
            
            # If no pattern matches, try the whole title if it's short enough
            if len(title_text) < 50 and _is_valid_org_name(title_text):
                return title_text
        
        return None
        
    except Exception as e:
        logger.debug(f"Title extraction failed: {e}")
        return None


def _extract_from_about_page(url: str) -> Optional[str]:
    """
    Try to find organization name from /about or /about-us page
    """
    try:
        from urllib.parse import urljoin
        
        about_paths = ['/about', '/about-us', '/about-us.html', '/company', '/who-we-are']
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for path in about_paths:
            try:
                about_url = urljoin(url, path)
                response = requests.get(about_url, headers=headers, timeout=10, verify=False)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Look for h1 or h2 with company name
                    for header in soup.find_all(['h1', 'h2'], limit=5):
                        text = header.get_text().strip()
                        
                        # Patterns like "About Company Name"
                        match = re.search(r'(?:About|Welcome to)\s+(.+)', text, re.IGNORECASE)
                        if match:
                            org_name = match.group(1).strip()
                            if _is_valid_org_name(org_name):
                                return org_name
                        
                        # Direct company name
                        if _is_valid_org_name(text) and len(text) < 50:
                            return text
                    
            except:
                continue
        
        return None
        
    except Exception as e:
        logger.debug(f"About page extraction failed: {e}")
        return None


def _extract_from_footer(url: str) -> Optional[str]:
    """
    Extract organization from footer copyright text
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find footer
        footer = soup.find('footer') or soup.find('div', class_=re.compile(r'footer', re.I))
        
        if footer:
            footer_text = footer.get_text()
            
            # Look for copyright patterns
            patterns = [
                r'©\s*(?:\d{4}\s*[-–—]\s*)?\d{4}\s+(.+?)(?:\.|All rights|$)',
                r'Copyright\s*©?\s*(?:\d{4}\s*[-–—]\s*)?\d{4}\s+(.+?)(?:\.|All rights|$)',
                r'©\s*(.+?)\s*(?:\d{4}|All rights)',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, footer_text, re.IGNORECASE)
                if match:
                    org_name = match.group(1).strip()
                    # Clean up common suffixes
                    org_name = re.sub(r'\s+(Inc|Ltd|LLC|Corp|Corporation|Limited)\.?$', r' \1', org_name, flags=re.IGNORECASE)
                    if _is_valid_org_name(org_name):
                        return org_name
        
        return None
        
    except Exception as e:
        logger.debug(f"Footer extraction failed: {e}")
        return None


def _extract_from_domain_name(url: str) -> Optional[str]:
    """
    Extract organization from domain name as last resort
    """
    try:
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Remove www. and TLD
        domain = re.sub(r'^www\.', '', domain)
        domain = re.sub(r'\.(com|org|net|gov|edu|co\.uk|gov\.ng|ng)$', '', domain)
        
        # Convert to title case
        org_name = domain.replace('-', ' ').replace('_', ' ').title()
        
        if _is_valid_org_name(org_name):
            return org_name
        
        return None
        
    except Exception as e:
        logger.debug(f"Domain name extraction failed: {e}")
        return None


def _is_valid_org_name(name: str) -> bool:
    """
    Validate if extracted string is a valid organization name
    """
    if not name or not isinstance(name, str):
        return False
    
    name = name.strip()
    
    # Length checks
    if len(name) < 2 or len(name) > 100:
        return False
    
    # Reject if it's just a URL
    if name.startswith('http') or '://' in name:
        return False
    
    # Reject common generic terms
    generic_terms = [
        'home', 'index', 'welcome', 'login', 'dashboard',
        'admin', 'portal', 'website', 'page', 'site',
        'loading', 'error', 'not found', '404', 'undefined'
    ]
    
    if name.lower() in generic_terms:
        return False
    
    # Reject if it's all numbers
    if name.isdigit():
        return False
    
    # Reject if it's a file extension
    if name.lower() in ['.html', '.php', '.asp', '.jsp']:
        return False
    
    return True


def extract_organization_from_whois(domain: str) -> Optional[str]:
    """
    Extract organization from WHOIS data (requires python-whois)
    Note: This is optional and requires additional setup
    """
    try:
        import whois
        
        w = whois.whois(domain)
        
        # Try organization field
        if hasattr(w, 'org') and w.org:
            org = w.org if isinstance(w.org, str) else w.org[0]
            if _is_valid_org_name(org):
                return org
        
        # Try registrant organization
        if hasattr(w, 'registrant_organization') and w.registrant_organization:
            org = w.registrant_organization
            if isinstance(org, list):
                org = org[0]
            if _is_valid_org_name(org):
                return org
        
        return None
        
    except ImportError:
        logger.debug("python-whois not installed, skipping WHOIS lookup")
        return None
    except Exception as e:
        logger.debug(f"WHOIS lookup failed: {e}")
        return None


def extract_organization_comprehensive(url: str) -> dict:
    """
    Comprehensive organization extraction with multiple data points
    
    Returns dict with:
    - name: Organization name
    - confidence: High/Medium/Low
    - source: Where the name was found
    """
    from urllib.parse import urlparse
    
    domain = urlparse(url).netloc or urlparse(url).path
    domain = re.sub(r'^www\.', '', domain)
    
    result = {
        'name': None,
        'confidence': 'Low',
        'source': None
    }
    
    # Method 1: Meta tags (High confidence)
    org = _extract_from_meta_tags(url)
    if org:
        result['name'] = org
        result['confidence'] = 'High'
        result['source'] = 'meta_tags'
        return result
    
    # Method 2: Title (Medium confidence)
    org = _extract_from_title(url)
    if org:
        result['name'] = org
        result['confidence'] = 'Medium'
        result['source'] = 'title'
        return result
    
    # Method 3: About page (High confidence)
    org = _extract_from_about_page(url)
    if org:
        result['name'] = org
        result['confidence'] = 'High'
        result['source'] = 'about_page'
        return result
    
    # Method 4: Footer (Medium confidence)
    org = _extract_from_footer(url)
    if org:
        result['name'] = org
        result['confidence'] = 'Medium'
        result['source'] = 'footer'
        return result
    
    # Method 5: WHOIS (Medium confidence)
    org = extract_organization_from_whois(domain)
    if org:
        result['name'] = org
        result['confidence'] = 'Medium'
        result['source'] = 'whois'
        return result
    
    # Method 6: Domain name (Low confidence)
    org = _extract_from_domain_name(url)
    if org:
        result['name'] = org
        result['confidence'] = 'Low'
        result['source'] = 'domain_name'
        return result
    
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
    print("ORGANIZATION NAME EXTRACTION TEST")
    print("="*60 + "\n")
    
    # Test URLs
    test_urls = [
        'https://nitda.gov.ng',
        'https://google.com',
        'https://microsoft.com',
        'https://github.com',
    ]
    
    for url in test_urls:
        print(f"\nTesting: {url}")
        print("-" * 40)
        
        # Simple extraction
        org_name = extract_organization_name(url)
        print(f"Organization: {org_name}")
        
        # Comprehensive extraction
        result = extract_organization_comprehensive(url)
        print(f"Detailed Result:")
        print(f"  Name: {result['name']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Source: {result['source']}")