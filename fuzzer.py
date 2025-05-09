#!/usr/bin/env python3
"""
MassBypass Scanner - Mass Access Control Bypass Scanner

This tool performs mass scanning for access control bypasses by:
1. Discovering endpoints that return 401/403 responses
2. Applying RFC 3986 fuzzing techniques to bypass restrictions
3. Reporting successful access to otherwise restricted resources

Usage:
    python3 massbypass.py -d example.com -o results.json -t 20
    cat urls.txt | python3 massbypass.py -o results.json
    python3 massbypass.py --url-file targets.txt --screenshots --aggressive
"""

import argparse
import sys
import os
import json
import logging
import random
import time
import urllib.parse
import re
import concurrent.futures
import signal
import csv
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass, field, asdict
import subprocess
import shutil
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Import the access control bypass fuzzer
try:
    # Assuming the fuzzer module is in the same directory
    from acbypass_fuzzer import AccessControlBypassFuzzer, FuzzResult
except ImportError:
    sys.stderr.write("Error: Cannot import AccessControlBypassFuzzer. Make sure acbypass_fuzzer.py is in the same directory.\n")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('massbypass')

# Dataclasses for storing scan data
@dataclass
class TargetEndpoint:
    """Information about a target endpoint with restricted access"""
    url: str
    status_code: int
    content_type: str = ""
    content_length: int = 0
    redirect_url: str = ""
    response_time: float = 0.0
    server: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    auth_headers: List[str] = field(default_factory=list)
    notes: str = ""
    is_processed: bool = False
    bypass_attempts: int = 0
    
@dataclass
class BypassResult:
    """Result of a successful access control bypass"""
    original_url: str
    bypassed_url: str
    original_status: int
    bypassed_status: int
    mutation_type: str
    confidence: float
    content_diff_percent: float
    evidence: str = ""
    screenshot_path: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ScanStats:
    """Statistics about the scanning process"""
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    total_urls_scanned: int = 0
    restricted_endpoints_found: int = 0
    bypass_attempts: int = 0
    successful_bypasses: int = 0
    domains_scanned: Set[str] = field(default_factory=set)
    bypassed_domains: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization"""
        result = asdict(self)
        result['domains_scanned'] = list(self.domains_scanned)
        result['bypassed_domains'] = list(self.bypassed_domains)
        return result

class MassBypassScanner:
    """Scanner for mass discovery of access control bypasses"""
    
    def __init__(self, 
                concurrency: int = 10,
                timeout: int = 10,
                retry_attempts: int = 2,
                aggressive: bool = False,
                verify_ssl: bool = False,
                user_agent: str = None,
                proxy: str = None,
                cookies: Dict[str, str] = None,
                headers: Dict[str, str] = None,
                delay: float = 0,
                max_bypass_attempts: int = 50,
                take_screenshots: bool = False,
                chrome_path: str = None,
                output_dir: str = "results",
                save_responses: bool = False):
        """Initialize the scanner with configuration"""
        self.concurrency = concurrency
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.aggressive = aggressive
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.max_bypass_attempts = max_bypass_attempts
        self.take_screenshots = take_screenshots
        self.chrome_path = chrome_path or self._find_chrome()
        self.output_dir = output_dir
        self.save_responses = save_responses
        
        # Create output directory if needed
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        if self.take_screenshots and not os.path.exists(f"{output_dir}/screenshots"):
            os.makedirs(f"{output_dir}/screenshots")
        if self.save_responses and not os.path.exists(f"{output_dir}/responses"):
            os.makedirs(f"{output_dir}/responses")
        
        # Set default user agent if not provided
        if user_agent is None:
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        
        # Create a requests session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retry_attempts,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set session options
        self.session.verify = verify_ssl
        self.session.timeout = timeout
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache"
        })
        
        # Add custom headers if provided
        if headers:
            self.session.headers.update(headers)
        
        # Add cookies if provided
        if cookies:
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
        
        # Set proxy if provided
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
        
        # Initialize fuzzer
        self.fuzzer = AccessControlBypassFuzzer(
            threads=min(concurrency, 5),  # Limit fuzzer threads
            timeout=timeout,
            verify_ssl=verify_ssl,
            aggression_level=3 if aggressive else 2,
            verify_findings=True
        )
        self.fuzzer.session = self.session  # Share the session
        
        # Initialize tracking objects
        self.restricted_endpoints: Dict[str, TargetEndpoint] = {}
        self.successful_bypasses: List[BypassResult] = []
        self.scanned_urls: Set[str] = set()
        self.scan_stats = ScanStats()
        self.progress_update_interval = 50
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)
    
    def _find_chrome(self) -> Optional[str]:
        """Find Chrome/Chromium executable path"""
        chrome_paths = [
            # Linux
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            # macOS
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            # Windows
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]
        
        for path in chrome_paths:
            if os.path.exists(path):
                return path
        
        # Try to find using 'which' command on Unix
        try:
            chrome_path = subprocess.check_output(["which", "google-chrome"], 
                                                 stderr=subprocess.DEVNULL).decode().strip()
            if chrome_path:
                return chrome_path
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        try:
            chrome_path = subprocess.check_output(["which", "chromium-browser"], 
                                                stderr=subprocess.DEVNULL).decode().strip()
            if chrome_path:
                return chrome_path
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        logger.warning("Chrome/Chromium not found. Screenshots will be disabled.")
        self.take_screenshots = False
        return None
    
    def _handle_interrupt(self, sig, frame):
        """Handle interrupt signal gracefully"""
        logger.info("Received interrupt signal. Shutting down gracefully...")
        self._save_results("interrupted_results.json")
        sys.exit(0)
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to avoid duplicates"""
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Parse and normalize
        parsed = urllib.parse.urlparse(url)
        
        # Remove default ports
        netloc = parsed.netloc
        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
            if (parsed.scheme == 'http' and port == '80') or (parsed.scheme == 'https' and port == '443'):
                netloc = host
        
        # Remove trailing slash from path
        path = parsed.path
        if path == '':
            path = '/'
        elif path != '/' and path.endswith('/'):
            path = path[:-1]
        
        # Rebuild URL
        normalized = urllib.parse.urlunparse((
            parsed.scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            ''  # Remove fragment
        ))
        
        return normalized
    
    def _update_domain_stats(self, url: str):
        """Update domain statistics from URL"""
        try:
            domain = urllib.parse.urlparse(url).netloc.split(':')[0]
            self.scan_stats.domains_scanned.add(domain)
        except Exception:
            pass
    
    def _take_screenshot(self, url: str, identifier: str) -> str:
        """Take a screenshot of a URL using headless Chrome"""
        if not self.take_screenshots or not self.chrome_path:
            return ""
        
        # Create safe filename
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', identifier)
        filename = f"{self.output_dir}/screenshots/{safe_id}_{int(time.time())}.png"
        
        try:
            cmd = [
                self.chrome_path,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--screenshot=" + filename,
                "--window-size=1280,800",
                "--hide-scrollbars",
                url
            ]
            
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            
            if os.path.exists(filename):
                return filename
        except Exception as e:
            logger.debug(f"Screenshot error for {url}: {str(e)}")
        
        return ""
    
    def _save_response(self, url: str, response, identifier: str) -> str:
        """Save an HTTP response to disk"""
        if not self.save_responses:
            return ""
        
        # Create safe filename
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', identifier)
        filename = f"{self.output_dir}/responses/{safe_id}_{int(time.time())}.html"
        
        try:
            with open(filename, 'wb') as f:
                f.write(response.content)
            return filename
        except Exception as e:
            logger.debug(f"Save response error for {url}: {str(e)}")
        
        return ""
    
    def _calculate_content_diff(self, original_content: bytes, bypassed_content: bytes) -> float:
        """Calculate percentage difference between two response contents"""
        # Simple length comparison if either is empty
        if not original_content or not bypassed_content:
            if not original_content and not bypassed_content:
                return 0.0
            return 100.0
        
        # Calculate size difference percent
        size_diff = abs(len(original_content) - len(bypassed_content)) / max(len(original_content), len(bypassed_content))
        
        # If sizes are very different, no need for detailed comparison
        if size_diff > 0.5:  # More than 50% size difference
            return 100.0 * size_diff
        
        # Look for significant markers in bypassed content that weren't in original
        significant_markers = [
            b"<title>Admin", b"<h1>Admin", b"Dashboard", b"Configuration",
            b"user_id", b"email", b"password", b"token", b"secret", b"private",
            b"internal", b"confidential", b"restricted", b"access granted"
        ]
        
        # Check for markers in bypassed but not original
        original_text = original_content.lower()
        bypassed_text = bypassed_content.lower()
        
        marker_matches = sum(1 for marker in significant_markers 
                            if marker.lower() in bypassed_text and marker.lower() not in original_text)
        
        # Weight the marker matches in the result
        marker_factor = min(marker_matches * 0.2, 0.7)  # Up to 70% from markers
        
        # Combine factors
        return max((size_diff * 0.5 + marker_factor) * 100.0, 10.0)  # At least 10% if any difference
    
    def check_endpoint(self, url: str) -> Optional[TargetEndpoint]:
        """Check if an endpoint has response patterns indicating access restrictions"""
        normalized_url = self._normalize_url(url)
        
        # Skip URLs we've already processed
        if normalized_url in self.scanned_urls:
            return None
        
        self.scanned_urls.add(normalized_url)
        self.scan_stats.total_urls_scanned += 1
        self._update_domain_stats(normalized_url)
        
        # Add small delay if configured
        if self.delay > 0:
            time.sleep(self.delay)
        
        try:
            start_time = time.time()
            response = self.session.get(
                normalized_url,
                allow_redirects=False,  # Don't follow redirects to catch them
                timeout=self.timeout
            )
            response_time = time.time() - start_time
            
            # Check for various response patterns indicating access restrictions
            is_restricted = False
            restriction_type = ""
            
            # 1. Direct access denied responses
            if response.status_code in [401, 403]:
                is_restricted = True
                restriction_type = f"explicit_{response.status_code}"
            
            # 2. Redirects that might indicate authentication requirements
            elif response.status_code in [301, 302, 303, 307]:
                # Check if redirecting to login page or auth endpoint
                redirect_url = response.headers.get('Location', '')
                redirect_lower = redirect_url.lower()
                auth_indicators = ['login', 'signin', 'auth', 'sso', 'oauth', 'authenticate', 'account']
                
                if any(indicator in redirect_lower for indicator in auth_indicators):
                    is_restricted = True
                    restriction_type = f"auth_redirect_{response.status_code}"
            
            # 3. "Not Found" that might be masking Forbidden
            elif response.status_code == 404:
                # Check for endpoints that typically should exist if permissions were granted
                path_parts = urllib.parse.urlparse(normalized_url).path.strip('/').split('/')
                sensitive_endpoints = ['admin', 'config', 'settings', 'dashboard', 'console', 'internal', 
                                      'api', 'user', 'profile', 'account', 'manage', 'backend']
                
                if any(part.lower() in sensitive_endpoints for part in path_parts):
                    is_restricted = True
                    restriction_type = "masked_forbidden_404"
            
            # 4. Custom access denied pages that return 200 but contain denial indicators
            elif response.status_code == 200:
                # Only check text responses with appropriate size
                content_type = response.headers.get('Content-Type', '')
                is_text_response = 'text/html' in content_type or 'text/plain' in content_type
                is_small_response = len(response.content) < 5000  # Small responses may be error pages
                
                if is_text_response:
                    response_text = response.text.lower()
                    access_denied_indicators = [
                        'access denied', 'permission denied', 'not authorized', 'not authorised',
                        'unauthorized', 'forbidden', 'require login', 'login required',
                        'authentication required', 'please log in', 'please sign in',
                        'login to continue', 'sign in to continue', 'no permission',
                        'restricted area', 'restricted access', 'admin only'
                    ]
                    
                    if any(indicator in response_text for indicator in access_denied_indicators):
                        is_restricted = True
                        restriction_type = "custom_access_denied_page"
                
                # Check for login forms
                if 'text/html' in content_type and '<form' in response.text.lower():
                    if 'login' in response.text.lower() or 'password' in response.text.lower():
                        is_restricted = True
                        restriction_type = "login_form"
            
            # If this is a restricted endpoint, add it to our tracking
            if is_restricted:
                # Create target endpoint object
                endpoint = TargetEndpoint(
                    url=normalized_url,
                    status_code=response.status_code,
                    content_type=response.headers.get('Content-Type', ''),
                    content_length=len(response.content),
                    response_time=response_time,
                    server=response.headers.get('Server', ''),
                    headers={k: v for k, v in response.headers.items()},
                    notes=f"Restriction type: {restriction_type}"
                )
                
                # Check for authentication headers
                auth_headers = []
                if 'WWW-Authenticate' in response.headers:
                    auth_headers.append('WWW-Authenticate')
                if any(h for h in response.headers if h.lower().startswith('x-') and 'auth' in h.lower()):
                    auth_headers.extend([h for h in response.headers if h.lower().startswith('x-') and 'auth' in h.lower()])
                
                endpoint.auth_headers = auth_headers
                
                # Add redirect URL if this is a redirect
                if response.status_code in [301, 302, 303, 307]:
                    endpoint.redirect_url = response.headers.get('Location', '')
                
                # Save the original response if configured
                self._save_response(normalized_url, response, f"original_{response.status_code}")
                
                self.restricted_endpoints[normalized_url] = endpoint
                self.scan_stats.restricted_endpoints_found += 1
                
                logger.debug(f"Found restricted endpoint: {normalized_url} (Status: {response.status_code}, Type: {restriction_type})")
                return endpoint
                
        except requests.RequestException as e:
            logger.debug(f"Error checking {normalized_url}: {str(e)}")
        except Exception as e:
            logger.debug(f"Unexpected error checking {normalized_url}: {str(e)}")
        
        return None
    
    def attempt_bypass(self, endpoint: TargetEndpoint) -> List[BypassResult]:
        """Attempt to bypass access restrictions on an endpoint"""
        if endpoint.is_processed:
            return []
        
        successful_bypasses = []
        
        # Get the original response again to have fresh content for comparison
        try:
            original_response = self.session.get(
                endpoint.url,
                allow_redirects=False,
                timeout=self.timeout
            )
            
            # Run the fuzzer against this endpoint
            endpoint.bypass_attempts = 0
            fuzz_results = self.fuzzer.fuzz_url(endpoint.url)
            endpoint.bypass_attempts = len(fuzz_results)
            self.scan_stats.bypass_attempts += endpoint.bypass_attempts
            
            # Check each result for successful bypasses
            for result in fuzz_results:
                if result.confidence >= 0.6:  # Only process reasonably confident results
                    try:
                        # Get the bypassed response
                        bypassed_response = self.session.get(
                            result.fuzzed_url,
                            allow_redirects=False,
                            timeout=self.timeout
                        )
                        
                        # Check if we have a successful bypass (200 OK)
                        if bypassed_response.status_code == 200:
                            # Calculate content difference
                            content_diff = self._calculate_content_diff(
                                original_response.content, 
                                bypassed_response.content
                            )
                            
                            # If substantial difference or high confidence, consider it a bypass
                            if content_diff > 30 or result.confidence > 0.8:
                                # Take screenshot if configured
                                screenshot = ""
                                if self.take_screenshots:
                                    bypass_id = f"bypass_{endpoint.status_code}_to_200_{result.mutation_type}"
                                    screenshot = self._take_screenshot(result.fuzzed_url, bypass_id)
                                
                                # Save the bypassed response if configured
                                self._save_response(result.fuzzed_url, bypassed_response, 
                                                  f"bypass_{result.mutation_type}")
                                
                                # Create bypass result
                                bypass = BypassResult(
                                    original_url=endpoint.url,
                                    bypassed_url=result.fuzzed_url,
                                    original_status=endpoint.status_code,
                                    bypassed_status=bypassed_response.status_code,
                                    mutation_type=result.mutation_type,
                                    confidence=result.confidence,
                                    content_diff_percent=content_diff,
                                    evidence=result.evidence or "",
                                    screenshot_path=screenshot
                                )
                                
                                # Update stats
                                self.scan_stats.successful_bypasses += 1
                                try:
                                    domain = urllib.parse.urlparse(endpoint.url).netloc.split(':')[0]
                                    self.scan_stats.bypassed_domains.add(domain)
                                except Exception:
                                    pass
                                
                                successful_bypasses.append(bypass)
                                
                                logger.info(f"[BYPASS FOUND] {endpoint.url} -> {result.fuzzed_url} "
                                           f"(Status: {endpoint.status_code} -> 200, "
                                           f"Confidence: {result.confidence:.2f}, "
                                           f"Diff: {content_diff:.2f}%)")
                    
                    except requests.RequestException as e:
                        logger.debug(f"Error testing bypass URL {result.fuzzed_url}: {str(e)}")
                    except Exception as e:
                        logger.debug(f"Unexpected error testing bypass: {str(e)}")
            
            endpoint.is_processed = True
            
        except Exception as e:
            logger.debug(f"Error in bypass attempt for {endpoint.url}: {str(e)}")
        
        return successful_bypasses
    
    def _scan_worker(self, url: str) -> Tuple[Optional[TargetEndpoint], List[BypassResult]]:
        """Worker function for scanning a single URL"""
        endpoint = self.check_endpoint(url)
        
        if endpoint:
            # Only attempt bypass if we're below the max attempts limit
            if self.scan_stats.bypass_attempts < self.max_bypass_attempts:
                bypasses = self.attempt_bypass(endpoint)
                return endpoint, bypasses
            else:
                return endpoint, []
        
        return None, []
    
    def scan_urls(self, urls: List[str]) -> None:
        """Scan a list of URLs for access control bypasses"""
        logger.info(f"Starting scan with {len(urls)} URLs and {self.concurrency} threads")
        start_time = time.time()
        
        # Use a thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {executor.submit(self._scan_worker, url): url for url in urls}
            
            processed = 0
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    endpoint, bypasses = future.result()
                    if bypasses:
                        self.successful_bypasses.extend(bypasses)
                    
                    # Periodic progress update
                    processed += 1
                    if processed % self.progress_update_interval == 0:
                        elapsed = time.time() - start_time
                        percent_done = (processed / len(urls)) * 100
                        logger.info(f"Progress: {processed}/{len(urls)} URLs processed ({percent_done:.1f}%) " 
                                   f"in {elapsed:.1f}s - Found {len(self.successful_bypasses)} bypasses")
                
                except Exception as e:
                    logger.error(f"Error processing {url}: {str(e)}")
        
        # Scan completed
        self.scan_stats.end_time = datetime.now().isoformat()
        elapsed = time.time() - start_time
        
        logger.info(f"Scan completed in {elapsed:.1f} seconds")
        logger.info(f"Total URLs scanned: {self.scan_stats.total_urls_scanned}")
        logger.info(f"Restricted endpoints found: {self.scan_stats.restricted_endpoints_found}")
        logger.info(f"Bypass attempts: {self.scan_stats.bypass_attempts}")
        logger.info(f"Successful bypasses: {self.scan_stats.successful_bypasses}")
    
    def scan_from_file(self, filename: str) -> None:
        """Load URLs from a file and scan them"""
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Loaded {len(urls)} URLs from {filename}")
            self.scan_urls(urls)
        
        except Exception as e:
            logger.error(f"Error loading URLs from {filename}: {str(e)}")
            sys.exit(1)
    
    def scan_from_stdin(self) -> None:
        """Load URLs from stdin and scan them"""
        try:
            urls = [line.strip() for line in sys.stdin if line.strip()]
            
            logger.info(f"Loaded {len(urls)} URLs from stdin")
            self.scan_urls(urls)
        
        except Exception as e:
            logger.error(f"Error loading URLs from stdin: {str(e)}")
            sys.exit(1)
    
    def crawl_domain(self, domain: str, depth: int = 2, max_urls: int = 1000) -> None:
        """Crawl a domain using katana if available"""
        urls = []
        
        # Ensure domain has protocol
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain
        
        # Check if katana is installed
        katana_path = shutil.which('katana')
        if not katana_path:
            logger.error("Katana not found in PATH. Please install katana or provide URLs directly.")
            sys.exit(1)
        
        try:
            logger.info(f"Crawling {domain} with katana (depth={depth}, max={max_urls})...")
            
            cmd = [
                katana_path,
                '-u', domain,
                '-d', str(depth),
                '-c', str(max_urls),
                '-silent'
            ]
            
            output = subprocess.check_output(cmd).decode('utf-8', errors='ignore')
            urls = [line.strip() for line in output.splitlines() if line.strip()]
            
            logger.info(f"Discovered {len(urls)} URLs from {domain}")
            self.scan_urls(urls)
        
        except subprocess.SubprocessError as e:
            logger.error(f"Error running katana: {str(e)}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error during crawling: {str(e)}")
            sys.exit(1)
    
    def format_results(self, filename: str) -> None:
        """Save scan results to JSON and CSV formats with detailed categorization"""
        # Save full results to JSON
        try:
            # Convert results to serializable format
            results = {
                "scan_stats": self.scan_stats.to_dict(),
                "successful_bypasses": [asdict(bypass) for bypass in self.successful_bypasses],
                "restricted_endpoints": {url: asdict(endpoint) for url, endpoint in self.restricted_endpoints.items()}
            }
            
            # Add summary by restriction type and bypass type
            restriction_types = {}
            for url, endpoint in self.restricted_endpoints.items():
                rtype = "unknown"
                if "explicit_401" in endpoint.notes:
                    rtype = "explicit_401"
                elif "explicit_403" in endpoint.notes:
                    rtype = "explicit_403"
                elif "auth_redirect" in endpoint.notes:
                    rtype = "auth_redirect"
                elif "masked_forbidden_404" in endpoint.notes:
                    rtype = "masked_forbidden_404"
                elif "custom_access_denied" in endpoint.notes:
                    rtype = "custom_access_denied"
                elif "login_form" in endpoint.notes:
                    rtype = "login_form"
                
                if rtype not in restriction_types:
                    restriction_types[rtype] = 0
                restriction_types[rtype] += 1
            
            bypass_types = {}
            for bypass in self.successful_bypasses:
                bypass_type = bypass.mutation_type.split('_')[0]
                if bypass_type not in bypass_types:
                    bypass_types[bypass_type] = 0
                bypass_types[bypass_type] += 1
            
            results["summary"] = {
                "restriction_types": restriction_types,
                "bypass_types": bypass_types,
                "total_restricted_endpoints": len(self.restricted_endpoints),
                "total_successful_bypasses": len(self.successful_bypasses),
                "highest_confidence_bypass": max([bypass.confidence for bypass in self.successful_bypasses]) if self.successful_bypasses else 0,
                "average_content_diff": sum([bypass.content_diff_percent for bypass in self.successful_bypasses]) / len(self.successful_bypasses) if self.successful_bypasses else 0
            }
            
            # Save to JSON
            with open(os.path.join(self.output_dir, filename), 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Results saved to {os.path.join(self.output_dir, filename)}")
            
        except Exception as e:
            logger.error(f"Error saving JSON results: {str(e)}")
        
        # Also save successful bypasses to CSV for easy review
        csv_filename = os.path.splitext(filename)[0] + ".csv"
        try:
            with open(os.path.join(self.output_dir, csv_filename), 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Original URL", "Bypassed URL", "Original Status", 
                    "Mutation Type", "Confidence", "Content Diff %", 
                    "Evidence", "Restriction Type", "Screenshot Path"
                ])
                
                for bypass in self.successful_bypasses:
                    # Find the original endpoint to get its restriction type
                    restriction_type = "unknown"
                    if bypass.original_url in self.restricted_endpoints:
                        restriction_type = self.restricted_endpoints[bypass.original_url].notes
                    
                    writer.writerow([
                        bypass.original_url,
                        bypass.bypassed_url,
                        bypass.original_status,
                        bypass.mutation_type,
                        f"{bypass.confidence:.2f}",
                        f"{bypass.content_diff_percent:.2f}%",
                        bypass.evidence,
                        restriction_type,
                        bypass.screenshot_path
                    ])
            
            logger.info(f"CSV results saved to {os.path.join(self.output_dir, csv_filename)}")
        
        except Exception as e:
            logger.error(f"Error saving CSV results: {str(e)}")
            
        # Create a summary markdown report
        md_filename = os.path.splitext(filename)[0] + "_summary.md"
        try:
            with open(os.path.join(self.output_dir, md_filename), 'w') as f:
                f.write(f"# MassBypass Scanner Results Summary\n\n")
                f.write(f"Scan completed on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(f"## Overview\n\n")
                f.write(f"- Total URLs scanned: {self.scan_stats.total_urls_scanned}\n")
                f.write(f"- Restricted endpoints found: {self.scan_stats.restricted_endpoints_found}\n")
                f.write(f"- Successful bypasses: {self.scan_stats.successful_bypasses}\n")
                f.write(f"- Success rate: {(self.scan_stats.successful_bypasses / self.scan_stats.restricted_endpoints_found * 100) if self.scan_stats.restricted_endpoints_found else 0:.2f}%\n\n")
                
                # Add restriction types breakdown
                f.write(f"## Restriction Types\n\n")
                f.write(f"| Type | Count | Percentage |\n")
                f.write(f"|------|-------|------------|\n")
                for rtype, count in restriction_types.items():
                    percent = (count / self.scan_stats.restricted_endpoints_found * 100) if self.scan_stats.restricted_endpoints_found else 0
                    f.write(f"| {rtype} | {count} | {percent:.2f}% |\n")
                
                # Add bypass types breakdown
                f.write(f"\n## Successful Bypass Types\n\n")
                f.write(f"| Technique | Count | Success Rate |\n")
                f.write(f"|-----------|-------|-------------|\n")
                for btype, count in bypass_types.items():
                    # Calculate attempts of this type
                    attempts = 0
                    for endpoint in self.restricted_endpoints.values():
                        attempts += endpoint.bypass_attempts  # This is approximate
                    success_rate = (count / attempts * 100) if attempts else 0
                    f.write(f"| {btype} | {count} | {success_rate:.2f}% |\n")
                
                # Add domains with bypasses
                f.write(f"\n## Affected Domains\n\n")
                for domain in self.scan_stats.bypassed_domains:
                    f.write(f"- {domain}\n")
                
                # Add top bypasses
                f.write(f"\n## Top High-Confidence Bypasses\n\n")
                high_conf = sorted([b for b in self.successful_bypasses if b.confidence >= 0.8], 
                                  key=lambda x: x.confidence, reverse=True)
                for i, bypass in enumerate(high_conf[:10], 1):  # Top 10
                    f.write(f"### {i}. {bypass.original_url} (Confidence: {bypass.confidence:.2f})\n\n")
                    f.write(f"- Bypassed URL: `{bypass.bypassed_url}`\n")
                    f.write(f"- Technique: {bypass.mutation_type}\n")
                    f.write(f"- Evidence: {bypass.evidence}\n")
                    f.write(f"- Content difference: {bypass.content_diff_percent:.2f}%\n\n")
            
            logger.info(f"Markdown summary saved to {os.path.join(self.output_dir, md_filename)}")
            
        except Exception as e:
            logger.error(f"Error saving markdown summary: {str(e)}")
            
    def save_results(self, filename: str) -> None:
        """Save scan results to files"""
        self.format_results(filename)

def parse_args():
    parser = argparse.ArgumentParser(description='MassBypass - Mass Access Control Bypass Scanner')
    
    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-d', '--domain', help='Target domain to crawl and scan')
    input_group.add_argument('-u', '--url', help='Single URL to scan')
    input_group.add_argument('-f', '--url-file', help='File containing URLs to scan (one per line)')
    input_group.add_argument('-', '--stdin', action='store_true', help='Read URLs from stdin')
    
    # Output options
    parser.add_argument('-o', '--output', default='results.json', help='Output file for results')
    parser.add_argument('--output-dir', default='results', help='Directory to store results and screenshots')
    
    # Scanning options
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--retry', type=int, default=2, help='Number of retry attempts for failed requests')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds')
    parser.add_argument('--max-attempts', type=int, default=5000, 
                        help='Maximum number of bypass attempts before stopping')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth when using domain input')
    parser.add_argument('--max-urls', type=int, default=1000, 
                        help='Maximum number of URLs to crawl when using domain input')
    
    # Authentication and headers
    parser.add_argument('--cookies', help='Cookies to use (format: name1=value1;name2=value2)')
    parser.add_argument('--headers', help='Custom headers (format: name1:value1;name2:value2)')
    parser.add_argument('--user-agent', help='Custom user agent string')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    
    # Feature flags
    parser.add_argument('--aggressive', action='store_true', help='Use more aggressive fuzzing techniques')
    parser.add_argument('--ssl-verify', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--screenshots', action='store_true', help='Take screenshots of successful bypasses')
    parser.add_argument('--chrome-path', help='Path to Chrome/Chromium executable for screenshots')
    parser.add_argument('--save-responses', action='store_true', help='Save HTTP responses to disk')
    
    # Verbosity
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress informational output')
    
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)
    
    # Parse cookies if provided
    cookies = None
    if args.cookies:
        cookies = {}
        for cookie_pair in args.cookies.split(';'):
            if '=' in cookie_pair:
                name, value = cookie_pair.split('=', 1)
                cookies[name.strip()] = value.strip()
    
    # Parse headers if provided
    headers = None
    if args.headers:
        headers = {}
        for header_pair in args.headers.split(';'):
            if ':' in header_pair:
                name, value = header_pair.split(':', 1)
                headers[name.strip()] = value.strip()
    
    # Initialize scanner
    scanner = MassBypassScanner(
        concurrency=args.threads,
        timeout=args.timeout,
        retry_attempts=args.retry,
        aggressive=args.aggressive,
        verify_ssl=args.ssl_verify,
        user_agent=args.user_agent,
        proxy=args.proxy,
        cookies=cookies,
        headers=headers,
        delay=args.delay,
        max_bypass_attempts=args.max_attempts,
        take_screenshots=args.screenshots,
        chrome_path=args.chrome_path,
        output_dir=args.output_dir,
        save_responses=args.save_responses
    )
    
    # Start scanning based on input source
    try:
        if args.domain:
            scanner.crawl_domain(args.domain, depth=args.depth, max_urls=args.max_urls)
        elif args.url:
            scanner.scan_urls([args.url])
        elif args.url_file:
            scanner.scan_from_file(args.url_file)
        elif args.stdin:
            scanner.scan_from_stdin()
        
        # Save results
        scanner.save_results(args.output)
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted. Saving partial results...")
        scanner.save_results("interrupted_" + args.output)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        scanner.save_results("error_" + args.output)
        sys.exit(1)

if __name__ == "__main__":
    print("""
╭─────────────────────────────────────────────────────────╮
│                                                         │
│              MASSBYPASS SCANNER v1.0                    │
│      Mass Access Control Bypass Discovery Tool          │
│                                                         │
╰─────────────────────────────────────────────────────────╯
    """)
    main()
