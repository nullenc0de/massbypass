#!/usr/bin/env python3
"""
MassBypass Scanner - Mass Access Control Bypass Scanner

This tool identifies and bypasses access controls using RFC 3986 fuzzing techniques,
targeting vulnerabilities in URL processing implementations.

Usage:
    python3 fuzzer.py -d example.com -o results.json -t 20
    cat urls.txt | python3 fuzzer.py -o results.json
    python3 fuzzer.py --url-file targets.txt --screenshots --aggressive
"""

import argparse
import sys
import os
import logging
from massbypass import MassBypassScanner

# Import the support module
from acbypass_fuzzer import AccessControlBypassFuzzer, FuzzResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('fuzzer')

def load_urls_from_file(file_path: str) -> list:
    """Load URLs from a file, one URL per line"""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

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
    parser.add_argument('-a', '--aggressive', action='store_true', help='Use more aggressive fuzzing techniques')
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
            urls = load_urls_from_file(args.url_file)
            scanner.scan_urls(urls)
        elif args.stdin:
            urls = [line.strip() for line in sys.stdin if line.strip()]
            scanner.scan_urls(urls)
        
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
