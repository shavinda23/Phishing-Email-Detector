import re
from urllib.parse import urlparse
import requests
from typing import List, Dict

class URLAnalyzer:
    """Analyze URLs for phishing indicators"""
    
    # Common URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
        'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly', 'short.link'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
        '.work', '.click', '.link', '.download'
    ]
    
    # Legitimate domains (for typosquatting detection)
    LEGITIMATE_DOMAINS = [
        'paypal.com', 'amazon.com', 'facebook.com', 'google.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'instagram.com',
        'twitter.com', 'linkedin.com', 'ebay.com', 'chase.com',
        'wellsfargo.com', 'bankofamerica.com', 'citibank.com'
    ]
    
    def __init__(self, urls: List[str]):
        self.urls = urls
        self.findings = []
    
    def analyze(self) -> Dict:
        """Perform comprehensive URL analysis"""
        if not self.urls:
            return {
                'risk_score': 0,
                'findings': [],
                'suspicious_urls': []
            }
        
        suspicious_urls = []
        total_score = 0
        
        for url in self.urls:
            url_findings = self._analyze_single_url(url)
            if url_findings:
                suspicious_urls.append({
                    'url': url,
                    'issues': url_findings
                })
                total_score += len(url_findings) * 10
        
        self.findings = suspicious_urls
        
        return {
            'risk_score': min(total_score, 100),
            'findings': self.findings,
            'suspicious_urls': [item['url'] for item in suspicious_urls]
        }
    
    def _analyze_single_url(self, url: str) -> List[str]:
        """Analyze a single URL for suspicious patterns"""
        issues = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for IP address instead of domain
            if self._is_ip_address(domain):
                issues.append("Uses IP address instead of domain name")
            
            # Check for URL shorteners
            if any(shortener in domain for shortener in self.URL_SHORTENERS):
                issues.append("Uses URL shortener (hiding actual destination)")
            
            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                issues.append("Uses suspicious top-level domain")
            
            # Check for typosquatting
            typosquat = self._check_typosquatting(domain)
            if typosquat:
                issues.append(f"Possible typosquatting of {typosquat}")
            
            # Check for excessive subdomains
            if domain.count('.') > 3:
                issues.append("Excessive subdomains (possible obfuscation)")
            
            # Check for suspicious keywords in domain
            suspicious_keywords = ['secure', 'account', 'update', 'verify', 
                                  'login', 'banking', 'paypal', 'amazon']
            for keyword in suspicious_keywords:
                if keyword in domain and not any(legit in domain for legit in self.LEGITIMATE_DOMAINS):
                    issues.append(f"Suspicious keyword '{keyword}' in domain")
            
            # Check for @ symbol (username in URL)
            if '@' in url:
                issues.append("Contains @ symbol (URL obfuscation technique)")
            
            # Check for very long URLs
            if len(url) > 150:
                issues.append("Unusually long URL (possible obfuscation)")
            
            # Check for hexadecimal encoding
            if '%' in url and re.search(r'%[0-9A-Fa-f]{2}', url):
                hex_count = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
                if hex_count > 3:
                    issues.append("Heavy use of URL encoding (possible obfuscation)")
            
        except Exception as e:
            issues.append(f"Malformed URL structure")
        
        return issues
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        # Remove port if present
        domain = domain.split(':')[0]
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, domain):
            return True
        
        # IPv6 pattern (simplified)
        if ':' in domain and '[' in domain:
            return True
        
        return False
    
    def _check_typosquatting(self, domain: str) -> str:
        """Check for typosquatting of legitimate domains"""
        # Remove www. prefix
        domain = domain.replace('www.', '')
        
        for legit_domain in self.LEGITIMATE_DOMAINS:
            # Check for character substitution
            if self._similar_domain(domain, legit_domain):
                return legit_domain
        
        return None
    
    def _similar_domain(self, domain1: str, domain2: str) -> bool:
        """Check if domains are suspiciously similar"""
        # Remove TLD for comparison
        d1 = domain1.split('.')[0] if '.' in domain1 else domain1
        d2 = domain2.split('.')[0] if '.' in domain2 else domain2
        
        # Check if d1 contains d2 (e.g., paypa1.com contains paypal)
        if d2 in d1 and d1 != d2:
            return True
        
        # Check character substitution (l -> 1, o -> 0, etc.)
        substitutions = {'l': '1', 'i': '1', 'o': '0', 'a': '@'}
        for orig, sub in substitutions.items():
            if d1.replace(sub, orig) == d2:
                return True
        
        return False
    
    def get_url_details(self) -> List[Dict]:
        """Get detailed information about each URL"""
        details = []
        for url in self.urls:
            parsed = urlparse(url)
            details.append({
                'url': url,
                'domain': parsed.netloc,
                'scheme': parsed.scheme,
                'path': parsed.path
            })
        return details