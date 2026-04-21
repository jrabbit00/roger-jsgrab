#!/usr/bin/env python3
"""
Roger JSGrab - JavaScript file scraper for bug bounty hunting.
"""

import argparse
import concurrent.futures
import re
import requests
import sys
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Patterns to find
ENDPOINT_PATTERNS = [
    r'/api/[a-zA-Z0-9_/]+',
    r'/v\d+/[a-zA-Z0-9_/]+',
    r'/graphql',
    r'/rest/[a-zA-Z0-9_/]+',
    r'/wp-json/[a-zA-Z0-9_/]+',
    r'/ajax/[a-zA-Z0-9_/]+',
    r'/cgi-bin/[a-zA-Z0-9_/]+',
]

SECRET_PATTERNS = [
    (r'(?i)(api_key|apikey|API_KEY)\s*[=:]\s*["\']([^"\']{8,})["\']', 'API Key'),
    (r'(?i)(access_token|token|TOKEN)\s*[=:]\s*["\']([^"\']{16,})["\']', 'Token'),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', 'Password'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Key'),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private Key'),
    (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+', 'Bearer Token'),
    (r'(?i)basic\s+[a-zA-Z0-9+\/=]+', 'Basic Auth'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
    (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token'),
]

PARAM_PATTERNS = [
    r'\bid\s*[=:]\s*\d+',
    r'\buser_?id\s*[=:]\s*\d+',
    r'\badmin\s*[=:]',
    r'\bdebug\s*[=:]',
    r'\bredirect\s*[=:]\s*https?://',
    r'\burl\s*[=:]\s*https?://',
    r'\bfile\s*[=:]\s*[a-zA-Z0-9_\-\.]+',
    r'\bpath\s*[=:]\s*[/a-zA-Z0-9_\-\.]+',
    r'\btoken\s*[=:]\s*[a-zA-Z0-9_\-\.]+',
]

class RogerJSGrab:
    def __init__(self, target, output=None, threads=10, endpoints_only=False, 
                 secrets_only=False, quiet=False, depth=3, filter_domain=None):
        self.target = target.rstrip('/')
        self.output = output
        self.threads = threads
        self.endpoints_only = endpoints_only
        self.secrets_only = secrets_only
        self.quiet = quiet
        self.depth = depth
        self.filter_domain = filter_domain
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.js_files = []
        self.findings = []
        
    def extract_js_links(self, html, base_url):
        """Extract JS file links from HTML."""
        js_files = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Script tags
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                js_files.append(src)
        
        # Inline scripts with src attribute in data-src
        for script in soup.find_all('script', {'data-src': True}):
            js_files.append(script['data-src'])
        
        # Resolve relative URLs
        resolved = []
        for js in js_files:
            if js.startswith('//'):
                js = 'https:' + js
            elif js.startswith('/'):
                parsed = urlparse(base_url)
                js = f"{parsed.scheme}://{parsed.netloc}{js}"
            elif not js.startswith('http'):
                js = urljoin(base_url, js)
            
            # Filter domain if specified
            if self.filter_domain:
                if self.filter_domain in js:
                    resolved.append(js)
            else:
                resolved.append(js)
        
        return list(set(resolved))
    
    def extract_from_js(self, js_content):
        """Extract endpoints, secrets, params from JS content."""
        findings = []
        
        # API Endpoints
        if not self.secrets_only:
            for pattern in ENDPOINT_PATTERNS:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    findings.append(("Endpoint", match))
        
        # Secrets
        if not self.endpoints_only:
            for pattern, name in SECRET_PATTERNS:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    if isinstance(match, tuple):
                        findings.append((name, match[-1][:50] + "..." if len(match[-1]) > 50 else match[-1]))
                    else:
                        findings.append((name, match[:50] + "..." if len(match) > 50 else match))
        
        # Parameters
        if not self.endpoints_only and not self.secrets_only:
            for pattern in PARAM_PATTERNS:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    findings.append(("Parameter", match))
        
        return findings
    
    def analyze_js(self, url):
        """Download and analyze a JS file."""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                content = response.text
                findings = self.extract_from_js(content)
                
                result = {
                    "url": url,
                    "findings": findings
                }
                return result
        except Exception as e:
            if not self.quiet:
                print(f"[!] Error fetching {url}: {e}")
        
        return None
    
    def crawl(self, url, current_depth=0):
        """Recursively crawl pages to find JS files."""
        if current_depth >= self.depth:
            return
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                js_links = self.extract_js_links(response.text, url)
                self.js_files.extend(js_links)
                
                # Crawl found JS files for more links
                for js in js_links[:10]:  # Limit to avoid too many requests
                    try:
                        js_response = self.session.get(js, timeout=5, verify=False)
                        if js_response.status_code == 200:
                            more_links = self.extract_js_links(js_response.text, js)
                            self.js_files.extend(more_links)
                    except:
                        pass
                
                # Find links to crawl
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/') or href.startswith(self.target):
                        full_url = urljoin(url, href)
                        if self.filter_domain and self.filter_domain not in full_url:
                            continue
                        if full_url not in getattr(self, 'crawled', set()):
                            self.crawl(full_url, current_depth + 1)
        except Exception as e:
            if not self.quiet:
                print(f"[!] Error crawling {url}: {e}")
    
    def scan(self):
        """Run the JS scraper."""
        print(f"[*] Starting JS scraping on: {self.target}")
        print(f"[*] Max depth: {self.depth}")
        print("=" * 60)
        
        self.crawled = set()
        
        # Step 1: Find JS files
        print("[*] Crawling pages to find JS files...")
        self.crawl(self.target, 0)
        self.js_files = list(set(self.js_files))
        
        print(f"[*] Found {len(self.js_files)} JS files")
        
        if not self.js_files:
            print("[!] No JS files found!")
            return []
        
        # Step 2: Analyze each JS file
        print("[*] Analyzing JS files...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.analyze_js, js): js for js in self.js_files}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                result = future.result()
                if result and result['findings']:
                    for finding_type, finding_value in result['findings']:
                        if not self.quiet:
                            print(f"[{finding_type}] {finding_value}")
                        self.findings.append({
                            "file": result['url'],
                            "type": finding_type,
                            "value": finding_value
                        })
                
                if i % 20 == 0:
                    print(f"[*] Progress: {i}/{len(self.js_files)}")
        
        # Save results
        if self.output:
            with open(self.output, 'w') as f:
                f.write(f"# JS Grabber Results for {self.target}\n\n")
                for finding in self.findings:
                    f.write(f"[{finding['type']}] {finding['value']}\n")
                    f.write(f"  File: {finding['file']}\n\n")
        
        print()
        print("=" * 60)
        print(f"[*] Scan complete!")
        print(f"[*] JS files analyzed: {len(self.js_files)}")
        print(f"[*] Findings: {len(self.findings)}")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger JSGrab - JavaScript scraper for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL (e.g., https://target.com)")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-e", "--endpoints-only", action="store_true", help="Only extract API endpoints")
    parser.add_argument("-s", "--secrets-only", action="store_true", help="Only look for secrets/tokens")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--depth", type=int, default=3, help="Max crawl depth")
    parser.add_argument("--filter-domain", help="Only include JS from this domain")
    
    args = parser.parse_args()
    
    scanner = RogerJSGrab(
        target=args.target,
        output=args.output,
        threads=args.threads,
        endpoints_only=args.endpoints_only,
        secrets_only=args.secrets_only,
        quiet=args.quiet,
        depth=args.depth,
        filter_domain=args.filter_domain
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()