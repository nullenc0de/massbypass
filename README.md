# MassBypass Scanner

**MassBypass Scanner** is a powerful tool for automating the discovery of access control bypasses by exploiting RFC 3986 edge cases and implementation flaws. It targets endpoints that return 401, 403, 404, or authentication redirects, and attempts to bypass these restrictions using a comprehensive suite of URL manipulation techniques.

## Why MassBypass?

Many web applications enforce access controls but have flaws in their URL parsing implementation. These flaws can be exploited to bypass restrictions and access protected resources. MassBypass automates the discovery and exploitation of these vulnerabilities by:

- **Targeting Restricted Endpoints**: Automatically identifies 401/403/404 responses, login redirects, and custom access denied pages
- **RFC Edge Case Testing**: Applies hundreds of RFC 3986 parsing tricks and known CVE patterns
- **Mass Testing**: Processes thousands of URLs concurrently with intelligent throttling
- **Low False Positives**: Verifies findings with multiple confirmation techniques
- **Detailed Reporting**: Generates comprehensive reports with evidence and screenshots

## Installation

### Directory Structure

```
massbypass/
├── fuzzer.py                # Main entry point
├── massbypass.py            # Scanner implementation
├── acbypass_fuzzer.py       # RFC 3986 fuzzing engine
├── requirements.txt         # Dependencies
├── docs/                    # Documentation
└── README.md                # This file
```

### Requirements

- Python 3.8+
- Requests and urllib3 libraries
- Optional: katana (for domain crawling)
- Optional: Chrome/Chromium (for screenshots)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/massbypass.git
cd massbypass
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Optional: Install katana for domain crawling:
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Usage

### Basic Usage

```bash
# Scan a single URL
python fuzzer.py -u https://example.com/admin

# Scan URLs from a file
python fuzzer.py -f targets.txt -o results.json

# Pipe URLs from another tool
cat urls.txt | python fuzzer.py - -o results.json

# Crawl and scan a domain
python fuzzer.py -d example.com --depth 3 --max-urls 2000
```

### Advanced Options

```bash
# Aggressive scanning with more threads
python fuzzer.py -f urls.txt -a -t 20

# Authenticated scanning
python fuzzer.py -f urls.txt --cookies "session=abc123" --headers "Authorization:Bearer token"

# Take screenshots of successful bypasses
python fuzzer.py -u https://example.com/admin --screenshots

# Use with a proxy
python fuzzer.py -f targets.txt --proxy http://127.0.0.1:8080
```

### Full Command Options

```
usage: fuzzer.py [-h] (-d DOMAIN | -u URL | -f URL_FILE | -) [-o OUTPUT]
                [--output-dir OUTPUT_DIR] [-t THREADS] [--timeout TIMEOUT]
                [--retry RETRY] [--delay DELAY] [--max-attempts MAX_ATTEMPTS]
                [--depth DEPTH] [--max-urls MAX_URLS] [--cookies COOKIES]
                [--headers HEADERS] [--user-agent USER_AGENT] [--proxy PROXY]
                [-a] [--ssl-verify] [--screenshots] [--chrome-path CHROME_PATH]
                [--save-responses] [-v] [-q]
```

## How It Works

MassBypass Scanner uses a multi-stage process to find access control bypasses:

1. **Discovery Phase**: Identifies endpoints with access restrictions (401/403/404, login redirects, etc.)
2. **Fuzzing Phase**: Applies hundreds of RFC 3986 URL manipulations to each restricted endpoint
3. **Verification Phase**: Confirms successful bypasses by comparing responses and content differences
4. **Reporting Phase**: Generates detailed reports with evidence, screenshots, and statistics

### RFC 3986 Fuzzing Techniques

The scanner implements a comprehensive suite of techniques targeting common parser implementation flaws:

- **Path Traversal Exploits**: Using encoded path separators, dot segments, and normalization tricks
- **URL Encoding Manipulations**: Double encoding, mixed encoding, and Unicode normalization
- **Authority Confusion**: Credential injection and hostname manipulation
- **Matrix URI Parameters**: Semicolon-based parameter confusion
- **CVE-Specific Patterns**: Targeting known vulnerabilities like Apache's CVE-2021-41773

## Output Format

MassBypass generates three report formats:

1. **JSON Report** (`results.json`): Complete details of all findings
2. **CSV Report** (`results.csv`): Tabular format for easy review 
3. **Markdown Summary** (`results_summary.md`): Overview with statistics

Example of successful bypass in the JSON report:
```json
{
  "original_url": "https://example.com/admin",
  "bypassed_url": "https://example.com/%2e%2e/admin",
  "original_status": 403,
  "bypassed_status": 200,
  "mutation_type": "cve_rfc3986_traversal",
  "confidence": 0.95,
  "content_diff_percent": 78.5,
  "evidence": "Response contains admin dashboard content",
  "screenshot_path": "results/screenshots/bypass_403_to_200_traversal_1620742895.png"
}
```

## Example Workflow

1. Discover potential targets:
```bash
waybackurls example.com > urls.txt
```

2. Run initial scan with default settings:
```bash
python fuzzer.py -f urls.txt -o scan1.json
```

3. Review high-confidence results:
```bash
grep "HIGH-CONFIDENCE" scan1.log
```

4. Try aggressive scanning on promising endpoints:
```bash
python fuzzer.py -u https://example.com/admin -a --screenshots
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

* Inspired by research on RFC 3986 parsing vulnerabilities
* Uses techniques from real-world CVEs like Apache's CVE-2021-41773
* Special thanks to the security community for documenting URL parsing quirks

## Disclaimer

This tool is intended for legal security testing with proper authorization. Do not use against systems you don't have permission to test. The authors are not responsible for misuse or illegal use of this software.
