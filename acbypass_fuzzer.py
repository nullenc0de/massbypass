#!/usr/bin/env python3
"""
Access Control Bypass Fuzzer

This module contains the AccessControlBypassFuzzer class which implements RFC 3986
fuzzing techniques to bypass access controls through URL manipulation.
"""

import re
import urllib.parse
import random
import logging
import time
import string
from typing import List, Dict, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('acbypass-fuzzer')

@dataclass
class FuzzResult:
    """Store information about a fuzz test result"""
    original_url: str
    fuzzed_url: str
    mutation_type: str
    original_response_code: int = 0
    fuzzed_response_code: int = 0
    original_response_size: int = 0
    fuzzed_response_size: int = 0
    confidence: float = 0.0
    verified: bool = False
    bypass_type: str = ""
    evidence: str = ""
    notes: str = ""

class AccessControlBypassFuzzer:
    """Fuzzer for testing URL manipulation techniques that can bypass access controls"""
    
    # RFC 3986 edge cases and parsing quirks
    RFC_EDGE_CASES = {
        # Path normalization quirks
        "DOT_SEGMENTS": [
            "./", "../", "/../", "/./", "/.//", "/./../", 
            "/a/../", "/./.././", "/a/./b/../", "//.//"
        ],
        
        # Slash variations 
        "SLASH_VARIANTS": [
            "//", "///", "////", "\\", "%2f", "%2F", "%5c", "%5C",
            "%252f", "%252F", "%255c", "%255C", "\\\\", "/\\"
        ],
        
        # URL encoding tricks
        "ENCODING_TRICKS": [
            # Double encoding
            {"orig": "/", "encoded": "%252f"},
            {"orig": ".", "encoded": "%252e"},
            {"orig": ":", "encoded": "%253a"},
            {"orig": "@", "encoded": "%2540"},
            # Non-standard hex encoding (uppercase/lowercase mixing)
            {"orig": "/", "encoded": "%2f"},
            {"orig": "/", "encoded": "%2F"},
            # UTF-8 overlong encoding
            {"orig": "/", "encoded": "%c0%af"},
            {"orig": ".", "encoded": "%c0%ae"},
            # Rare but valid hex chars
            {"orig": "/", "encoded": "%2f%20"},
            {"orig": "a", "encoded": "%61%20"},
        ],
        
        # Unicode normalization and homographs
        "UNICODE_TRICKS": [
            # Soft hyphen (used in CVE-2024-4577)
            {"orig": "-", "unicode": "\u00AD"},
            # Zero-width spaces
            {"orig": "", "unicode": "\u200B"},
            # Right-to-left mark
            {"orig": "", "unicode": "\u200F"},
            # Unicode normalization forms
            {"orig": "a", "unicode": "\u0061\u0301"},  # á (composed differently)
            {"orig": "i", "unicode": "\u0131"},        # dotless i
            # Homoglyphs
            {"orig": "a", "unicode": "\u0430"},        # Cyrillic 'а'
            {"orig": "e", "unicode": "\u0435"},        # Cyrillic 'е'
            {"orig": "o", "unicode": "\u043E"},        # Cyrillic 'о'
            {"orig": "p", "unicode": "\u0440"},        # Cyrillic 'р'
        ],
        
        # Authority confusion tricks
        "AUTHORITY_TRICKS": [
            # URL Authority tricks
            {"orig": "user:pass@", "trick": "user@"},
            {"orig": "@", "trick": "%40"},
            {"orig": "@", "trick": "%2540"},
            {"orig": ":", "trick": "%3A"},
        ],
        
        # Query string oddities
        "QUERY_TRICKS": [
            # Parameter repetition
            {"orig": "?param=value", "trick": "?param=value&param=value2"},
            # Empty parameter names
            {"orig": "?param=value", "trick": "?=value&param=value"},
            # Non-standard delimiters
            {"orig": "?param=value", "trick": "?param:value"},
            {"orig": "&", "trick": ";"},
            # Fragment confusion
            {"orig": "?", "trick": "#"},
            {"orig": "#", "trick": "?"},
        ],
        
        # IP Address representation tricks
        "IP_VARIATIONS": [
            # IPv4 address format variations
            {"orig": "127.0.0.1", "trick": "0177.0.0.1"},        # Octal
            {"orig": "127.0.0.1", "trick": "0x7f.0.0.1"},        # Hexadecimal
            {"orig": "127.0.0.1", "trick": "2130706433"},        # Decimal
            {"orig": "127.0.0.1", "trick": "127.1"},             # Compressed format
            {"orig": "localhost", "trick": "127.0.0.1"},         # Hostname to IP
            {"orig": "127.0.0.1", "trick": "[::ffff:127.0.0.1]"} # IPv6 mapped IPv4
        ],
        
        # Relative URL Resolution Exploits
        "RELATIVE_URL_TRICKS": [
            # Relative references may confuse resolvers
            {"orig": "/path/to/resource", "trick": "/path/to/./resource"},
            {"orig": "/path/resource", "trick": "/path/../path/resource"},
            {"orig": "/path/to/", "trick": "/path/./to/"},
            {"orig": "/one/two/three", "trick": "/one/two/../two/three"}
        ],
        
        # Scheme Confusion
        "SCHEME_TRICKS": [
            {"orig": "https://", "trick": "//"},                # Protocol-relative URL
            {"orig": "https://", "trick": "http://"},           # Scheme downgrade
            {"orig": "https://", "trick": "data:text/html,"},   # Scheme switch
            {"orig": "https://", "trick": "javascript:"},       # JavaScript scheme
            {"orig": "https://", "trick": "file://"}            # File scheme
        ],
        
        # Matrix URI Parameters
        "MATRIX_PARAMS": [
            {"orig": "/path/resource", "trick": "/path;p=v/resource"},
            {"orig": "/resource", "trick": "/;resource"},
            {"orig": "/user/profile", "trick": "/user;id=admin/profile"},
            {"orig": "/path/to", "trick": "/path;param=value;/to"}
        ],
        
        # Internationalized Resource Identifiers (IRI)
        "IRI_TRICKS": [
            # Test non-ASCII characters in various components
            {"orig": "example.com", "trick": "例.com"},
            {"orig": "/path", "trick": "/\u8def\u5f84"},         # Chinese "path"
            {"orig": "/admin", "trick": "/\u0430\u0434\u043c\u0438\u043d"},  # Cyrillic "admin"
            {"orig": "/settings", "trick": "/\u8a2d\u5b9a"}      # Japanese "settings"
        ],
        
        # URL Parser Disambiguation
        "PARSER_DISAMBIG": [
            {"orig": "?", "trick": "%3f"},              # Different parsers handle %3f differently
            {"orig": "#", "trick": "%23"},              # Some treat %23 as literal, not fragment
            {"orig": "/", "trick": "%2f%2f"},           # Double-slash encoded may parse differently
            {"orig": "@", "trick": "%40%40"},           # Double @ to confuse authority parsing
            {"orig": "user@host.com", "trick": "user%40host.com"}  # Encoded @ in hostname
        ],
        
        # Whitespace and Control Character Handling
        "WHITESPACE_TRICKS": [
            {"orig": " ", "trick": "%20"},              # Space
            {"orig": " ", "trick": "+"},                # Space alternative in some contexts
            {"orig": "", "trick": "%09"},               # Tab
            {"orig": "", "trick": "%00"},               # Null byte
            {"orig": "", "trick": "%0A"},               # Line feed
            {"orig": "", "trick": "%0D"},               # Carriage return
            {"orig": "", "trick": "%0D%0A"}             # CRLF
        ],
        
        # IDN (Internationalized Domain Names) Punycode Tricks
        "IDN_TRICKS": [
            {"orig": "admin.example.com", "trick": "xn--dmn-moa7i.example.com"},  # Using Punycode
            {"orig": "example.com", "trick": "example.com.%00"},     # Null byte after domain
            {"orig": "example.com", "trick": "xn--exmple-4nf.com"}   # Punycode variant
        ]
    }
    
    # RFC-specific vulnerability patterns based on historical CVEs
    CVE_PATTERNS = {
        # RFC 3986 (URI) vulnerability patterns
        "RFC3986": {
            "PATH_TRAVERSAL": [
                # Apache CVE-2021-41773/41772 style path traversal patterns
                {"orig": "/", "bypass": "/%2e%2e/"},
                {"orig": "/", "bypass": "/%2e%2e%2f"},
                {"orig": "/", "bypass": "/..;/"},
                {"orig": "/", "bypass": "/.%2e/"},
                {"orig": "/", "bypass": "/../"},
                {"orig": "/", "bypass": "/.../"},  # Variants that some parsers normalize incorrectly
                {"orig": "/", "bypass": "/;/"},    # Path parameter confusion
                {"orig": "/", "bypass": "//"},     # Double-slash normalization issues
            ],
            "PERCENT_ENCODING": [
                # URI encoding confusion issues
                {"orig": "/", "bypass": "/%5c"},   # Backslash encoded as forward slash
                {"orig": " ", "bypass": "%20"},    # Space encoding
                {"orig": " ", "bypass": "+"},      # Space alternative in some contexts
                {"orig": "/", "bypass": "%252f"},  # Double-encoded slash (historical bypass)
                {"orig": ".", "bypass": "%252e"},  # Double-encoded dot
            ],
            "UNICODE_NORMALIZATION": [
                # Unicode normalization bypasses (e.g., using full-width characters)
                {"orig": "/", "bypass": "／"},     # Full-width slash
                {"orig": ".", "bypass": "．"},     # Full-width dot
                {"orig": "-", "bypass": "－"},     # Full-width dash
            ]
        },
        
        # RFC 7230 (HTTP/1.1 Syntax) - HTTP Request Smuggling patterns
        "RFC7230": {
            "HEADER_INJECTION": [
                # Not directly used in URL fuzzing but noted for future HTTP header fuzzing
                {"name": "Content-Length", "bypass": "Content-Length: 0\r\nX-Ignored: X"},
                {"name": "Transfer-Encoding", "bypass": "Transfer-Encoding: chunked\r\nX-Ignored: X"},
                {"name": "Host", "bypass": "Host: example.com\r\nX-Forwarded-Host: evil.com"}
            ],
            "HEADER_FOLDING": [
                # Historical CRLFs in header values (not for URL fuzzing)
                {"name": "X-Header", "bypass": "X-Header: value\r\n other-value"}
            ]
        },
        
        # RFC 7235 (HTTP Authentication) - Auth bypass patterns
        "RFC7235": {
            "AUTH_BYPASS": [
                # Patterns that can be used in URL parameters to simulate auth
                {"orig": "", "bypass": "?access_token=FUZZ"},
                {"orig": "", "bypass": "?jwt=FUZZ"},
                {"orig": "", "bypass": "?auth=FUZZ"},
                {"orig": "", "bypass": "?token=FUZZ"}
            ]
        }
    }

    def __init__(self, 
                threads: int = 10, 
                timeout: int = 10, 
                verify_ssl: bool = False,
                aggression_level: int = 1,
                verify_findings: bool = True):
        """Initialize the fuzzer with configuration options"""
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.aggression_level = aggression_level  # 1-3, higher means more aggressive mutations
        self.verify_findings = verify_findings
        self.user_agent = 'AccessControlBypassFuzzer/1.0'
        
        # Create a requests session for efficiency
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Connection': 'close'
        })
        
        # Set up retry strategy
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = verify_ssl
    
    def _parse_url(self, url: str) -> urllib.parse.ParseResult:
        """Parse URL into its components according to RFC 3986"""
        try:
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urllib.parse.urlparse(url)
            return parsed
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return None
    
    def _reconstruct_url(self, scheme, netloc, path, params, query, fragment) -> str:
        """Reconstruct a URL from its components"""
        path = path or ''
        if params:
            path = f"{path};{params}"
        url = f"{scheme}://{netloc}{path}"
        if query:
            url = f"{url}?{query}"
        if fragment:
            url = f"{url}#{fragment}"
        return url
    
    def _double_encode(self, component: str) -> str:
        """Apply double URL encoding to a URL component"""
        # First encode
        first_encoded = urllib.parse.quote(component)
        # Then encode again
        double_encoded = ""
        for char in first_encoded:
            if char == '%':
                double_encoded += '%25'
            else:
                double_encoded += char
        return double_encoded
    
    def _mixed_encode(self, component: str) -> str:
        """Apply mixed URL encoding (some parts single, some double)"""
        encoded = ""
        for char in component:
            if char in "/?.&=":
                # Randomly decide whether to do single or double encoding
                if random.choice([True, False]):
                    encoded += urllib.parse.quote(char)
                else:
                    encoded += self._double_encode(char)
            else:
                encoded += char
        return encoded
        
    def _generate_rfc_edge_case_mutations(self, url: str) -> List[Tuple[str, str]]:
        """Generate URL mutations based on RFC 3986 edge cases and parsing quirks"""
        mutations = []
        parsed = self._parse_url(url)
        
        if not parsed:
            return mutations
        
        # Decompose the URL
        scheme = parsed.scheme
        netloc = parsed.netloc
        path = parsed.path
        params = parsed.params
        query = parsed.query
        fragment = parsed.fragment
        
        # Extract parts from netloc
        username = None
        password = None
        hostname = netloc
        port = None
        
        if '@' in netloc:
            userinfo, hostname = netloc.split('@', 1)
            if ':' in userinfo:
                username, password = userinfo.split(':', 1)
            else:
                username = userinfo
        
        if ':' in hostname:
            hostname, port_str = hostname.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                pass
        
        # 1. Path component mutations using extreme encoding variations
        if path:
            path_parts = path.split('/')
            for i in range(1, len(path_parts)):
                if path_parts[i]:
                    # Try all encoding tricks from our RFC edge cases
                    for encoding in self.RFC_EDGE_CASES["ENCODING_TRICKS"]:
                        path_parts_modified = path_parts.copy()
                        # Apply encoding to each character
                        encoded_part = path_parts[i]
                        for orig, encoded in [(encoding["orig"], encoding["encoded"])]:
                            encoded_part = encoded_part.replace(orig, encoded)
                        
                        if encoded_part != path_parts[i]:
                            path_parts_modified[i] = encoded_part
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"extreme_encoding_{encoding['encoded']}"))
                    
                    # Try unicode character substitutions
                    for unicode_trick in self.RFC_EDGE_CASES["UNICODE_TRICKS"]:
                        path_parts_modified = path_parts.copy()
                        unicode_part = path_parts[i].replace(
                            unicode_trick["orig"], unicode_trick["unicode"])
                        
                        if unicode_part != path_parts[i]:
                            path_parts_modified[i] = unicode_part
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"unicode_trick_{hex(ord(unicode_trick['unicode'][0]))}"))
                    
                    # Try Internationalized Resource Identifiers (IRI) tricks
                    for iri_trick in self.RFC_EDGE_CASES["IRI_TRICKS"]:
                        if "admin" in path_parts[i].lower() and iri_trick["orig"] == "/admin":
                            path_parts_modified = path_parts.copy()
                            path_parts_modified[i] = path_parts[i].lower().replace("admin", iri_trick["trick"].lstrip('/'))
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"iri_trick_{iri_trick['trick']}"))
                        elif "path" in path_parts[i].lower() and iri_trick["orig"] == "/path":
                            path_parts_modified = path_parts.copy()
                            path_parts_modified[i] = path_parts[i].lower().replace("path", iri_trick["trick"].lstrip('/'))
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"iri_trick_{iri_trick['trick']}"))
                    
                    # Try whitespace tricks within path segments
                    for ws_trick in self.RFC_EDGE_CASES["WHITESPACE_TRICKS"]:
                        if ws_trick["orig"] == " " and " " in path_parts[i]:
                            path_parts_modified = path_parts.copy()
                            path_parts_modified[i] = path_parts[i].replace(" ", ws_trick["trick"])
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"ws_trick_{ws_trick['trick']}"))
                        elif ws_trick["orig"] == "":
                            # Insert control characters at start/middle/end
                            path_parts_modified = path_parts.copy()
                            path_parts_modified[i] = ws_trick["trick"] + path_parts[i]
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"ws_trick_prefix_{ws_trick['trick']}"))
                            
                            path_parts_modified = path_parts.copy()
                            path_parts_modified[i] = path_parts[i] + ws_trick["trick"]
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"ws_trick_suffix_{ws_trick['trick']}"))
                    
                    # Try parser disambiguation tricks
                    for parser_trick in self.RFC_EDGE_CASES["PARSER_DISAMBIG"]:
                        if parser_trick["orig"] in path_parts[i]:
                            path_parts_modified = path_parts.copy()
                            path_parts_modified[i] = path_parts[i].replace(parser_trick["orig"], parser_trick["trick"])
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"parser_disambig_{parser_trick['trick']}"))
        
        # 2. Path traversal with all combinations of dot segment variations
        if path:
            for dot_segment in self.RFC_EDGE_CASES["DOT_SEGMENTS"]:
                # Try inserting at various positions
                path_parts = path.split('/')
                for i in range(len(path_parts)):
                    path_parts_modified = path_parts.copy()
                    path_parts_modified.insert(i, dot_segment.strip('/'))
                    new_path = '/'.join(path_parts_modified)
                    new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                    mutations.append((new_url, f"dot_segment_{dot_segment}"))
                
                # Try replacing existing segments
                if len(path_parts) > 2:
                    for i in range(1, len(path_parts)-1):
                        path_parts_modified = path_parts.copy()
                        path_parts_modified[i] = dot_segment.strip('/')
                        new_path = '/'.join(path_parts_modified)
                        new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                        mutations.append((new_url, f"dot_segment_replace_{dot_segment}"))
            
            # Relative URL Resolution Exploits
            for rel_trick in self.RFC_EDGE_CASES["RELATIVE_URL_TRICKS"]:
                # Only apply if the path structure matches
                if rel_trick["orig"] in path:
                    new_path = path.replace(rel_trick["orig"], rel_trick["trick"])
                    new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                    mutations.append((new_url, "relative_url_trick"))
            
            # Complex path normalization tricks
            # e.g., /admin/../public/ might normalize to /public/ but some parsers might not handle it correctly
            if '/' in path[1:]:
                main_segments = path.strip('/').split('/')
                for i in range(len(main_segments)):
                    for j in range(i+1, len(main_segments)):
                        # Create paths that should normalize away parts but might be parsed incorrectly
                        bypass_segment = main_segments[i] + '/' + '../' * (j-i) + main_segments[j]
                        new_path = '/' + bypass_segment
                        new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                        mutations.append((new_url, "normalization_bypass"))
        
        # 3. Slash variants - try different slash representations
        if path:
            for slash_variant in self.RFC_EDGE_CASES["SLASH_VARIANTS"]:
                # Replace a normal slash with variant
                if '/' in path[1:]:
                    variant_path = path.replace('/', slash_variant, 1)
                    new_url = self._reconstruct_url(scheme, netloc, variant_path, params, query, fragment)
                    mutations.append((new_url, f"slash_variant_{slash_variant}"))
                
                # Add an extra variant at the end of directory
                if not path.endswith('/'):
                    variant_path = path + slash_variant
                    new_url = self._reconstruct_url(scheme, netloc, variant_path, params, query, fragment)
                    mutations.append((new_url, f"slash_variant_append_{slash_variant}"))
                
                # Multiple consecutive variants
                if '/' in path:
                    variant_path = path.replace('/', slash_variant + slash_variant, 1)
                    new_url = self._reconstruct_url(scheme, netloc, variant_path, params, query, fragment)
                    mutations.append((new_url, f"double_slash_variant_{slash_variant}"))
        
        # 4. Host and Authority tricks
        # Authority/Host confusion tricks
        if '@' not in netloc:
            # Try adding fake credentials
            for auth_trick in self.RFC_EDGE_CASES["AUTHORITY_TRICKS"]:
                if auth_trick["orig"] == "@":
                    new_netloc = "admin" + auth_trick["trick"] + netloc
                    new_url = self._reconstruct_url(scheme, new_netloc, path, params, query, fragment)
                    mutations.append((new_url, f"authority_trick_{auth_trick['trick']}"))
        
        # IP Address representation tricks
        if netloc == "localhost" or re.match(r'^\d+\.\d+\.\d+\.\d+$', netloc):
            for ip_trick in self.RFC_EDGE_CASES["IP_VARIATIONS"]:
                if ip_trick["orig"] == netloc or ip_trick["orig"] == "localhost" and netloc == "localhost":
                    new_netloc = ip_trick["trick"]
                    new_url = self._reconstruct_url(scheme, new_netloc, path, params, query, fragment)
                    mutations.append((new_url, f"ip_variation_{ip_trick['trick']}"))
        
        # IDN Punycode tricks
        domain_parts = hostname.split('.')
        for idn_trick in self.RFC_EDGE_CASES["IDN_TRICKS"]:
            # Try replacing domain parts with Punycode variations
            if len(domain_parts) > 1:
                for i, part in enumerate(domain_parts):
                    if part.lower() in idn_trick["orig"].lower():
                        modified_domain_parts = domain_parts.copy()
                        # Extract the punycode part
                        punycode_part = idn_trick["trick"].split('.')[0]
                        modified_domain_parts[i] = punycode_part
                        new_hostname = '.'.join(modified_domain_parts)
                        
                        # Reconstruct netloc with port if present
                        new_netloc = new_hostname
                        if port:
                            new_netloc = f"{new_hostname}:{port}"
                        if username:
                            if password:
                                new_netloc = f"{username}:{password}@{new_netloc}"
                            else:
                                new_netloc = f"{username}@{new_netloc}"
                        
                        new_url = self._reconstruct_url(scheme, new_netloc, path, params, query, fragment)
                        mutations.append((new_url, f"idn_trick_{punycode_part}"))
        
        # 5. Query string manipulations  
        if query:
            # Parse query string
            query_params = urllib.parse.parse_qs(query, keep_blank_values=True)
            
            # Apply query tricks
            for query_trick in self.RFC_EDGE_CASES["QUERY_TRICKS"]:
                if "param" in query_trick["orig"]:
                    # This is a full parameter manipulation
                    if "param=value" in query_trick["orig"]:
                        new_query = query.replace("=", query_trick["trick"].split("=")[0], 1)
                        new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                        mutations.append((new_url, f"query_trick_delimiter"))
                else:
                    # This is a character replacement
                    if query_trick["orig"] in query:
                        new_query = query.replace(query_trick["orig"], query_trick["trick"])
                        new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                        mutations.append((new_url, f"query_trick_{query_trick['trick']}"))
            
            # Parser disambiguation tricks in query parameters
            for parser_trick in self.RFC_EDGE_CASES["PARSER_DISAMBIG"]:
                if parser_trick["orig"] in query:
                    new_query = query.replace(parser_trick["orig"], parser_trick["trick"])
                    new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                    mutations.append((new_url, f"query_parser_disambig_{parser_trick['trick']}"))
            
            # Apply whitespace tricks to query
            for ws_trick in self.RFC_EDGE_CASES["WHITESPACE_TRICKS"]:
                if ws_trick["orig"] == " " and " " in query:
                    new_query = query.replace(" ", ws_trick["trick"])
                    new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                    mutations.append((new_url, f"query_ws_trick_{ws_trick['trick']}"))
            
            # Try repeating parameters with different values (some parsers take first, some take last)
            for param, values in query_params.items():
                if values and param.lower() in ['id', 'user', 'user_id', 'userid', 'uid', 'file', 'path']:
                    new_query_params = query_params.copy()
                    # Add duplicate parameter with incremented value
                    if values[0].isdigit():
                        try:
                            new_value = str(int(values[0]) + 1)
                            new_query_params[param] = values + [new_value]
                            new_query = urllib.parse.urlencode(new_query_params, doseq=True)
                            new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                            mutations.append((new_url, "param_repetition_increment"))
                        except ValueError:
                            pass
                    
                    # Add duplicate parameter with "admin" value
                    new_query_params = query_params.copy()
                    new_query_params[param] = values + ["admin"]
                    new_query = urllib.parse.urlencode(new_query_params, doseq=True)
                    new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                    mutations.append((new_url, "param_repetition_admin"))
        
        # 6. Matrix URI parameters - new addition!
        if path:
            path_parts = path.split('/')
            for i in range(1, len(path_parts)):
                if path_parts[i]:
                    for matrix_trick in self.RFC_EDGE_CASES["MATRIX_PARAMS"]:
                        if "/resource" in matrix_trick["orig"] and len(path_parts[i]) > 3:
                            # Create a matrix parameter for this path segment
                            path_parts_modified = path_parts.copy()
                            matrix_param = matrix_trick["trick"].replace("resource", path_parts[i])
                            path_parts_modified[i] = matrix_param
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"matrix_params_{matrix_param}"))
                        elif matrix_trick["orig"] == "/path/resource" and i < len(path_parts) - 1:
                            # Create a matrix parameter between path segments
                            path_parts_modified = path_parts.copy()
                            matrix_param = "p=v"
                            path_parts_modified[i] = path_parts[i] + ";" + matrix_param
                            new_path = '/'.join(path_parts_modified)
                            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                            mutations.append((new_url, f"matrix_params_between_{matrix_param}"))
        
        # 7. Scheme Confusion (Protocol tricks)
        for scheme_trick in self.RFC_EDGE_CASES["SCHEME_TRICKS"]:
            if scheme_trick["orig"] == f"{scheme}://":
                new_scheme_part = scheme_trick["trick"]
                # Handle special case of protocol-relative URL
                if new_scheme_part == "//":
                    new_url = new_scheme_part + netloc + path
                    if params:
                        new_url += ";" + params
                    if query:
                        new_url += "?" + query
                    if fragment:
                        new_url += "#" + fragment
                else:
                    # Regular scheme replacement
                    new_url = url.replace(f"{scheme}://", new_scheme_part)
                
                mutations.append((new_url, f"scheme_trick_{new_scheme_part.rstrip('://')}"))
        
        # 8. Fragment/query confusion
        # Some servers process fragments incorrectly if they receive them first
        if query and not fragment:
            # Move query to fragment
            new_url = self._reconstruct_url(scheme, netloc, path, params, "", query)
            mutations.append((new_url, "query_to_fragment"))
        
        if fragment and not query:
            # Move fragment to query
            new_url = self._reconstruct_url(scheme, netloc, path, params, fragment, "")
            mutations.append((new_url, "fragment_to_query"))
        
        # 9. Extreme path traversal to access restricted paths
        for restricted_dir in ['admin', 'internal', 'private', 'console', 'dashboard', 'manage', 
                              'config', 'settings', 'user', 'account', 'api', 'backup']:
            # Prepend with path traversal
            for traversal in self.RFC_EDGE_CASES["DOT_SEGMENTS"][:3]:  # Use first 3 variants
                new_path = "/" + restricted_dir + traversal + path.lstrip('/')
                new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                mutations.append((new_url, f"restricted_path_traversal_{restricted_dir}"))
            
            # Try encoded versions of admin directories
            encoded_dir = ''.join('%{:02x}'.format(ord(c)) for c in restricted_dir)
            new_path = "/" + encoded_dir + path
            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
            mutations.append((new_url, f"encoded_restricted_dir_{restricted_dir}"))
            
            # Double-encoded restricted directory
            double_encoded_dir = ''.join('%25{:02x}'.format(ord(c)) for c in restricted_dir)
            new_path = "/" + double_encoded_dir + path
            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
            mutations.append((new_url, f"double_encoded_restricted_dir_{restricted_dir}"))
            
        # 10. Case manipulation tricks - some parsers are case-sensitive in places they shouldn't be
        if path:
            path_parts = path.split('/')
            for i in range(1, len(path_parts)):
                if path_parts[i]:
                    # Try case variations
                    path_parts_modified = path_parts.copy()
                    path_parts_modified[i] = path_parts[i].upper()
                    new_path = '/'.join(path_parts_modified)
                    new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                    mutations.append((new_url, "case_upper"))
                    
                    path_parts_modified = path_parts.copy()
                    path_parts_modified[i] = path_parts[i].lower()
                    new_path = '/'.join(path_parts_modified)
                    new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                    mutations.append((new_url, "case_lower"))
                    
                    path_parts_modified = path_parts.copy()
                    path_parts_modified[i] = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                                                 for i, c in enumerate(path_parts[i]))
                    new_path = '/'.join(path_parts_modified)
                    new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                    mutations.append((new_url, "case_mixed"))
        
        # 11. File extension tricks
        if '.' in path:
            base_path, ext = path.rsplit('.', 1)
            
            # Try adding a second extension
            for extra_ext in ['json', 'txt', 'html', 'xml', 'php', 'asp', 'jsp', 'bak', 'old']:
                new_path = f"{path}.{extra_ext}"
                new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                mutations.append((new_url, f"append_extension_{extra_ext}"))
            
            # Try inserting null byte before extension (null byte injection)
            new_path = f"{base_path}%00.{ext}"
            new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
            mutations.append((new_url, "nullbyte_extension"))
            
            # Try alternative extensions
            if ext.lower() in ['php', 'asp', 'jsp', 'html']:
                for alt_ext in ['php5', 'php4', 'php3', 'phtml', 'asp;jpg', 'asp%00', 'php%00', 'jsp%00']:
                    new_path = f"{base_path}.{alt_ext}"
                    new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                    mutations.append((new_url, f"alternative_extension_{alt_ext}"))
        
        # Return mutations based on aggression level but ensure variety
        all_mutations = mutations.copy()
        
        # Group mutations by type to ensure variety
        mutation_types = {}
        for url, mutation_type in all_mutations:
            base_type = mutation_type.split('_')[0]
            if base_type not in mutation_types:
                mutation_types[base_type] = []
            mutation_types[base_type].append((url, mutation_type))
        
        # Select mutations to ensure variety
        selected_mutations = []
        for base_type, type_mutations in mutation_types.items():
            # Take more or fewer based on aggression level
            count = min(len(type_mutations), self.aggression_level * 3)
            selected_mutations.extend(type_mutations[:count])
        
        # If we still have room, add more mutations
        if len(selected_mutations) < self.aggression_level * 20:
            remaining_count = self.aggression_level * 20 - len(selected_mutations)
            remaining = [m for m in all_mutations if m not in selected_mutations]
            selected_mutations.extend(remaining[:remaining_count])
        
        return selected_mutations
        
    def _generate_cve_specific_mutations(self, url: str) -> List[Tuple[str, str]]:
        """Generate mutations based on known CVE patterns from RFC implementations"""
        mutations = []
        parsed = self._parse_url(url)
        
        if not parsed:
            return mutations
        
        # Decompose the URL
        scheme = parsed.scheme
        netloc = parsed.netloc
        path = parsed.path
        params = parsed.params
        query = parsed.query
        fragment = parsed.fragment
        
        # 1. Apply RFC 3986 path traversal patterns (CVE-2021-41773 style)
        for pattern in self.CVE_PATTERNS["RFC3986"]["PATH_TRAVERSAL"]:
            # Apply to each path segment
            path_parts = path.split('/')
            for i in range(1, len(path_parts)):
                # Generate path with traversal inserted
                path_parts_modified = path_parts.copy()
                traversal = pattern["bypass"]
                
                # Insert before this segment
                new_path_parts = path_parts[:i] + [traversal.strip('/')] + path_parts[i:]
                new_path = '/' + '/'.join(part for part in new_path_parts if part)
                new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                mutations.append((new_url, f"cve_rfc3986_traversal_{traversal}"))
                
                # Try to access sensitive endpoints via traversal
                for sensitive in ["admin", "config", "sensitive", "internal", "private", "backup"]:
                    traverse_path = '/' + '/'.join(path_parts[:i]) + traversal + sensitive
                    new_url = self._reconstruct_url(scheme, netloc, traverse_path, params, query, fragment)
                    mutations.append((new_url, f"cve_rfc3986_sensitive_{sensitive}"))
        
        # 2. Apply RFC 3986 percent encoding patterns
        for pattern in self.CVE_PATTERNS["RFC3986"]["PERCENT_ENCODING"]:
            if pattern["orig"] in path:
                # Replace in path
                new_path = path.replace(pattern["orig"], pattern["bypass"])
                new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                mutations.append((new_url, f"cve_rfc3986_encoding_{pattern['bypass']}"))
        
        # 3. Apply Unicode normalization tricks
        for pattern in self.CVE_PATTERNS["RFC3986"]["UNICODE_NORMALIZATION"]:
            if pattern["orig"] in path:
                # Replace in path
                new_path = path.replace(pattern["orig"], pattern["bypass"])
                new_url = self._reconstruct_url(scheme, netloc, new_path, params, query, fragment)
                mutations.append((new_url, f"cve_rfc3986_unicode_{pattern['bypass']}"))
                
            # Also try for query parameters with these chars
            if query and pattern["orig"] in query:
                new_query = query.replace(pattern["orig"], pattern["bypass"])
                new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                mutations.append((new_url, f"cve_rfc3986_unicode_query_{pattern['bypass']}"))
        
        # 4. Apply RFC 7235 auth bypass tricks in URL parameters
        for pattern in self.CVE_PATTERNS["RFC7235"]["AUTH_BYPASS"]:
            # Skip if query already has auth parameters
            query_params = urllib.parse.parse_qs(query) if query else {}
            auth_params = ['token', 'auth', 'jwt', 'access_token', 'apikey', 'api_key']
            
            if not any(param in query_params for param in auth_params):
                # Add auth parameter
                new_query = query + ('&' if query else '') + pattern["bypass"].lstrip('?')
                new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                mutations.append((new_url, f"cve_rfc7235_auth_{pattern['bypass']}"))
                
                # Try with common auth token values
                for token_value in ["admin", "1", "true", "bypass", "ADMIN", "guest"]:
                    auth_param = pattern["bypass"].replace("FUZZ", token_value).lstrip('?')
                    new_query = query + ('&' if query else '') + auth_param
                    new_url = self._reconstruct_url(scheme, netloc, path, params, new_query, fragment)
                    mutations.append((new_url, f"cve_rfc7235_auth_{token_value}"))
        
        # Create the Apache CVE-2021-41773 specific pattern (documented real-world exploit)
        if path and len(path) > 1:
            # The exact pattern from the CVE
            for i in range(1, 4):  # Limit depth for efficiency
                traversal_path = '/' + '/'.join(['.'] * i) + path
                new_url = self._reconstruct_url(scheme, netloc, traversal_path, params, query, fragment)
                mutations.append((new_url, f"cve_2021_41773_traversal"))
                
                # The variant that worked in the CVE
                traversal_path = path + '//'
                new_url = self._reconstruct_url(scheme, netloc, traversal_path, params, query, fragment)
                mutations.append((new_url, f"cve_2021_41773_trailing"))
        
        return mutations
    
    def _test_url(self, url: str, mutation_type: str, original_url: str) -> FuzzResult:
        """Test a URL and analyze response for access control bypasses"""
        try:
            # First test the original URL to establish baseline
            original_response = self.session.get(
                original_url, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            # Now test the fuzzed URL
            fuzzed_response = self.session.get(
                url, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            # Create result object with both responses
            result = FuzzResult(
                original_url=original_url,
                fuzzed_url=url,
                mutation_type=mutation_type,
                original_response_code=original_response.status_code,
                fuzzed_response_code=fuzzed_response.status_code,
                original_response_size=len(original_response.content),
                fuzzed_response_size=len(fuzzed_response.content),
                confidence=0.0
            )
            
            # Analyze for access control bypass signs
            # Case 1: Original returns 401/403, but fuzzed returns 200
            if (original_response.status_code in [401, 403, 404] and 
                fuzzed_response.status_code == 200):
                result.confidence = 0.9
                result.bypass_type = "ACCESS_CONTROL_BYPASS"
                result.notes = f"Original URL returns {original_response.status_code}, but fuzzed URL returns 200 OK"
                
                # Look for evidence in response content
                if "admin" in fuzzed_response.text.lower() or "dashboard" in fuzzed_response.text.lower():
                    result.evidence = "Response contains admin/dashboard content"
                    result.confidence = 0.95
                elif "delete" in fuzzed_response.text.lower() or "edit" in fuzzed_response.text.lower():
                    result.evidence = "Response contains delete/edit functionality"
                    result.confidence = 0.9
                else:
                    result.evidence = "Different response from original URL"
            
            # Case 2: Both return 200, but content is significantly different
            elif (original_response.status_code == 200 and 
                  fuzzed_response.status_code == 200 and
                  abs(len(original_response.content) - len(fuzzed_response.content)) > 500):
                result.confidence = 0.7
                result.bypass_type = "INFORMATION_DISCLOSURE"
                result.notes = "Both URLs return 200, but response sizes differ significantly"
                
                # Look for evidence of information disclosure
                if "password" in fuzzed_response.text.lower() or "email" in fuzzed_response.text.lower():
                    result.evidence = "Response contains sensitive data (password/email references)"
                    result.confidence = 0.85
                elif "id" in fuzzed_response.text.lower() and "user" in fuzzed_response.text.lower():
                    result.evidence = "Response contains user identification data"
                    result.confidence = 0.8
                else:
                    result.evidence = "Substantially different response content"
            
            # Case 3: Original returns normal response, fuzzed returns error
            elif (original_response.status_code == 200 and 
                  fuzzed_response.status_code >= 500):
                result.confidence = 0.5
                result.bypass_type = "SERVER_ERROR"
                result.notes = f"Mutation caused server error {fuzzed_response.status_code}"
                result.evidence = "Server unable to handle modified URL correctly"
            
            # Adjust confidence based on mutation type
            if "auth_bypass_param" in mutation_type:
                result.confidence += 0.1
            elif "path_component_encoding" in mutation_type:
                result.confidence += 0.1
            elif "adjacent_resource_access" in mutation_type:
                result.confidence += 0.1
            # Give higher confidence to CVE-based mutations
            elif "cve_" in mutation_type:
                result.confidence += 0.2
            
            return result
        
        except requests.exceptions.Timeout:
            return FuzzResult(
                original_url=original_url,
                fuzzed_url=url,
                mutation_type=mutation_type,
                confidence=0.3,
                notes="Connection timeout",
                bypass_type="TIMEOUT"
            )
        except requests.exceptions.ConnectionError:
            return FuzzResult(
                original_url=original_url,
                fuzzed_url=url,
                mutation_type=mutation_type,
                confidence=0.2,
                notes="Connection error",
                bypass_type="CONNECTION_ERROR"
            )
        except Exception as e:
            return FuzzResult(
                original_url=original_url,
                fuzzed_url=url,
                mutation_type=mutation_type,
                confidence=0.1,
                notes=f"Error: {str(e)}",
                bypass_type="ERROR"
            )
    
    def _verify_finding(self, result: FuzzResult) -> FuzzResult:
        """
        Perform additional tests to verify an access control bypass
        and gather more evidence to reduce false positives
        """
        if not self.verify_findings:
            return result
        
        # Skip verification for low confidence results
        if result.confidence < 0.5:
            return result
        
        try:
            # For potential access control bypasses, verify we're seeing different content
            if result.bypass_type == "ACCESS_CONTROL_BYPASS":
                # Try with slight variation to confirm
                parsed = self._parse_url(result.fuzzed_url)
                variation_url = result.fuzzed_url
                
                # Add a small random parameter to avoid caching
                random_param = ''.join(random.choices(string.ascii_lowercase, k=8))
                if parsed.query:
                    variation_url += f"&_r={random_param}"
                else:
                    variation_url += f"?_r={random_param}"
                
                # Test the variation
                variation_response = self.session.get(
                    variation_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                # Check if we still get a success response
                if variation_response.status_code == 200:
                    result.verified = True
                    result.confidence += 0.1
                    result.notes += " | Verified: Mutation consistently bypasses restrictions"
                else:
                    result.verified = False
                    result.confidence -= 0.3
                    result.notes += " | Verification failed: Not consistently reproducible"
            
            # For information disclosure, check for specific patterns
            elif result.bypass_type == "INFORMATION_DISCLOSURE":
                # Look for sensitive data patterns
                fuzzed_response = self.session.get(
                    result.fuzzed_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                # Check for common sensitive data patterns in the response
                sensitive_patterns = [
                    r'password\s*[=:]\s*[\'"][^\'"]+[\'"]',
                    r'email\s*[=:]\s*[\'"][^@]+@[^@]+\.[^\'"]+"',
                    r'token\s*[=:]\s*[\'"][^\'"]+[\'"]',
                    r'api[_-]?key\s*[=:]\s*[\'"][^\'"]+[\'"]',
                    r'secret\s*[=:]\s*[\'"][^\'"]+[\'"]',
                    r'user_?id\s*[=:]\s*[\'"]?\d+[\'"]?',
                ]
                
                for pattern in sensitive_patterns:
                    if re.search(pattern, fuzzed_response.text, re.IGNORECASE):
                        result.verified = True
                        result.confidence += 0.2
                        result.evidence += f" | Found sensitive data matching pattern: {pattern}"
                        break
                else:
                    # If we get here, no sensitive patterns were found
                    result.confidence -= 0.1
                    result.notes += " | No definitive sensitive data patterns identified"
            
            return result
        except Exception as e:
            result.notes += f" | Verification error: {str(e)}"
            return result
    
    def fuzz_url(self, url: str) -> List[FuzzResult]:
        """Fuzz a single URL with multiple mutations"""
        results = []
        
        # Generate all types of mutations
        all_mutations = []
        
        # 1. Generate standard RFC 3986 edge case mutations
        rfc_mutations = self._generate_rfc_edge_case_mutations(url)
        all_mutations.extend(rfc_mutations)
        
        # 2. Generate CVE-specific mutations based on known vulnerabilities
        cve_mutations = self._generate_cve_specific_mutations(url)
        all_mutations.extend(cve_mutations)
        
        # Prioritize known CVE patterns (they're more likely to work based on history)
        cve_mutations_dict = {url: mutation_type for url, mutation_type in cve_mutations}
        rfc_mutations_dict = {url: mutation_type for url, mutation_type in rfc_mutations 
                             if url not in cve_mutations_dict}
        
        # Combine and limit based on aggression level
        priority_mutations = list(cve_mutations_dict.items())
        standard_mutations = list(rfc_mutations_dict.items())
        
        # Always include all CVE-specific mutations regardless of aggression level
        # They have historical success and are worth trying
        mutations_to_test = priority_mutations.copy()
        
        # Add standard mutations based on aggression level
        if self.aggression_level == 1:
            # Low aggression - add just a few standard mutations
            mutations_to_test.extend(standard_mutations[:20])
        elif self.aggression_level == 2:
            # Medium aggression - add more standard mutations
            mutations_to_test.extend(standard_mutations[:50])
        else:
            # High aggression - add all standard mutations
            mutations_to_test.extend(standard_mutations)
        
        # Test each mutation
        for i, (mutated_url, mutation_type) in enumerate(mutations_to_test):
            # Log progress periodically
            if i > 0 and i % 20 == 0:
                logger.debug(f"Tested {i}/{len(mutations_to_test)} mutations for {url}")
            
            result = self._test_url(mutated_url, mutation_type, url)
            
            # Verify promising findings
            if result.confidence >= 0.5:
                result = self._verify_finding(result)
            
            # Only include results with sufficient confidence
            if result.confidence >= 0.6:
                results.append(result)
                
                # Early success - if we find a confirmed high-confidence bypass with a CVE pattern
                # Log it immediately as these are valuable
                if result.confidence >= 0.8 and "cve_" in mutation_type:
                    logger.info(f"[HIGH-CONFIDENCE CVE BYPASS] {url} -> {mutated_url} "
                               f"(Type: {mutation_type}, Confidence: {result.confidence:.2f})")
        
        return results
