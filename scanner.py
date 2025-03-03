import socket
import sys
import asyncio
import aiohttp
import dns.resolver
import urllib3
import re
from datetime import datetime
import threading
from queue import Queue
import argparse
from typing import List, Dict, Optional, Union
import json
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import concurrent.futures
import warnings
import hashlib
import subprocess
import jwt
import xml.etree.ElementTree as ET
import base64
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import uuid
import yaml
import aiohttp.connector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("scanner.log"), logging.StreamHandler()]
)

class ProfessionalWebScanner:
    def __init__(self, url: str, options: Dict = None):
        """Initialize the professional web application scanner."""
        self.logger = logging.getLogger(__name__)
        self.target_url = url
        self.base_url = self._get_base_url(url)
        self.options = options or {}
        self.found_urls = set()
        self.visited_urls = set()
        self.forms_found = []
        self.apis_found = set()
        self.vulnerabilities = []
        self.scan_id = str(uuid.uuid4())
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'X-Scanner': f'ProWebScanner/{self.scan_id[:8]}'
        }
        self.target_cms = None
        self.semaphore = asyncio.Semaphore(self.options.get('threads', 10))  # Limit concurrent requests
        self.session = None  # Will be initialized in async context

    def _get_base_url(self, url: str) -> str:
        """Extract base URL from the target URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def _init_session(self):
        """Initialize aiohttp session with connection pooling."""
        connector = aiohttp.TCPConnector(limit=self.options.get('threads', 10), ssl=False)
        self.session = aiohttp.ClientSession(headers=self.headers, connector=connector)

    async def _close_session(self):
        """Close aiohttp session."""
        if self.session:
            await self.session.close()

    async def run_scan(self) -> Dict:
        """Main async scanning method."""
        try:
            await self._init_session()
            self.logger.info(f"Starting scan of {self.target_url} with {self.options.get('threads', 10)} threads")
            
            # Initial connection test
            async with self.semaphore:
                async with self.session.get(self.target_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    await response.text()
            self.logger.info(f"Connected to target: {self.target_url}")

            # Run scans concurrently
            await asyncio.gather(
                self.detect_cms(),
                self.scan_ssl(),
                self.check_security_misconfiguration(),
                self.check_subdomain_takeover()
            )

            if self.target_cms == "WordPress":
                await self.scan_wordpress()

            # Parameter-based scans
            parsed_url = urlparse(self.target_url)
            params = parse_qs(parsed_url.query)
            if params:
                await asyncio.gather(
                    self.check_ssrf_vulnerability(self.target_url, params),
                    self.check_open_redirect(self.target_url, params),
                    self.check_template_injection(self.target_url, params),
                    self.check_file_inclusion(self.target_url, params),
                    self.check_nosql_injection(self.target_url, params),
                    self.check_crlf_injection(self.target_url, params)
                )

            # Additional checks
            await asyncio.gather(
                self.check_api_security(self.target_url),
                self.check_graphql_vulnerabilities(f"{self.target_url}/graphql"),
                self.check_cors_misconfig(self.target_url),
                self.check_host_header_injection(self.target_url),
                self.test_csrf_vulnerability(self.target_url),
                self.check_rate_limiting(self.target_url),
                self.scan_for_vulnerabilities()
            )

            report = self.generate_report()
            self.export_report(report, self.options.get('output_format', 'json'))
            return report

        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            return {"status": "error", "message": str(e)}
        finally:
            await self._close_session()

    async def scan_ssl(self):
        """Async SSL/TLS vulnerability check."""
        try:
            hostname = urlparse(self.target_url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                    if cert_expiry < datetime.now():
                        self.vulnerabilities.append({
                            "type": "SSL/TLS", "severity": "Critical",
                            "details": "SSL certificate has expired", "url": self.target_url
                        })
                    cipher = ssock.cipher()
                    if any(weak in cipher[0] for weak in ['RC4', 'DES', '3DES', 'MD5']):
                        self.vulnerabilities.append({
                            "type": "SSL/TLS", "severity": "High",
                            "details": f"Weak cipher suite: {cipher[0]}", "url": self.target_url
                        })
                    version = ssock.version()
                    if version in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                        self.vulnerabilities.append({
                            "type": "SSL/TLS", "severity": "High",
                            "details": f"Outdated SSL/TLS version: {version}", "url": self.target_url
                        })
                    if 'subjectAltName' not in cert:
                        self.vulnerabilities.append({
                            "type": "SSL/TLS", "severity": "Medium",
                            "details": "Missing SAN in certificate", "url": self.target_url
                        })
        except Exception as e:
            self.vulnerabilities.append({
                "type": "SSL/TLS", "severity": "Critical",
                "details": f"SSL error: {str(e)}", "url": self.target_url
            })

    async def scan_wordpress(self):
        """Enhanced WordPress scanning."""
        self.logger.info(f"Scanning WordPress at {self.target_url}")
        tasks = [
            self._check_wp_endpoint("/wp-login.php", "Login page detected"),
            self._check_wp_endpoint("/wp-json/", "REST API exposed"),
            self._check_wp_version()
        ]
        await asyncio.gather(*tasks)

    async def _check_wp_endpoint(self, endpoint: str, desc: str):
        """Check WordPress endpoint exposure."""
        url = urljoin(self.target_url, endpoint)
        async with self.semaphore:
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        self.vulnerabilities.append({
                            "type": "WordPress", "severity": "Info",
                            "details": f"WordPress {desc}", "url": url
                        })
            except Exception as e:
                self.logger.debug(f"WP endpoint {url} check failed: {e}")

    async def _check_wp_version(self):
        """Detect WordPress version."""
        url = self.target_url
        async with self.semaphore:
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    text = await resp.text()
                    version_match = re.search(r'wp-embed.min.js\?ver=(\d+\.\d+\.\d+)', text)
                    if version_match:
                        version = version_match.group(1)
                        self.vulnerabilities.append({
                            "type": "WordPress", "severity": "Medium",
                            "details": f"WordPress version {version} detected", "url": url
                        })
            except Exception as e:
                self.logger.debug(f"WP version check failed: {e}")

    async def detect_cms(self):
        """Detect CMS asynchronously."""
        async with self.semaphore:
            try:
                async with self.session.get(self.target_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    text = await resp.text()
                    if 'wp-content' in text.lower():
                        self.target_cms = 'WordPress'
                        self.logger.info("Detected CMS: WordPress")
                    else:
                        self.target_cms = 'Unknown'
                        self.logger.info("CMS not detected")
            except Exception as e:
                self.logger.error(f"CMS detection failed: {e}")

    async def check_cors_misconfig(self, url: str):
        """Async CORS misconfiguration check."""
        test_origins = ['https://evil.com', 'null', self.base_url + '.evil.com']
        tasks = []
        for origin in test_origins:
            headers = self.headers.copy()
            headers['Origin'] = origin
            tasks.append(self._check_cors(url, headers, origin))
        await asyncio.gather(*tasks)

    async def _check_cors(self, url: str, headers: Dict, origin: str):
        async with self.semaphore:
            try:
                async with self.session.options(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    acao = resp.headers.get('Access-Control-Allow-Origin')
                    if acao == '*' or acao == origin:
                        self.vulnerabilities.append({
                            "type": "CORS Misconfiguration", "severity": "Medium",
                            "details": f"Permissive CORS policy for {origin}", "url": url
                        })
            except Exception as e:
                self.logger.debug(f"CORS check for {origin}: {e}")

    async def check_ssrf_vulnerability(self, url: str, params: Dict):
        """Async SSRF vulnerability test."""
        ssrf_payloads = [
            'http://localhost', 'http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/'
        ]
        tasks = []
        for param in params:
            for payload in ssrf_payloads:
                test_params = params.copy()
                test_params[param] = payload
                tasks.append(self._test_ssrf(url, test_params, param, payload))
        await asyncio.gather(*tasks)

    async def _test_ssrf(self, url: str, params: Dict, param: str, payload: str):
        async with self.semaphore:
            try:
                async with self.session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "instance" in text.lower() or "meta-data" in text.lower():
                            self.vulnerabilities.append({
                                "type": "SSRF", "severity": "High",
                                "details": f"SSRF in param '{param}'", "url": url, "payload": payload
                            })
            except Exception as e:
                self.logger.debug(f"SSRF test {payload}: {e}")

    async def check_open_redirect(self, url: str, params: Dict):
        """Async open redirect test."""
        redirect_payloads = ['https://evil.com', '//evil.com', 'javascript:alert(1)']
        tasks = []
        for param in params:
            for payload in redirect_payloads:
                test_params = params.copy()
                test_params[param] = payload
                tasks.append(self._test_redirect(url, test_params, param, payload))
        await asyncio.gather(*tasks)

    async def _test_redirect(self, url: str, params: Dict, param: str, payload: str):
        async with self.semaphore:
            try:
                async with self.session.get(url, params=params, allow_redirects=False,
                                          timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if any(p in location for p in ['evil.com', 'javascript:']):
                            self.vulnerabilities.append({
                                "type": "Open Redirect", "severity": "Medium",
                                "details": f"Redirect in param '{param}'", "url": url, "payload": payload
                            })
            except Exception as e:
                self.logger.debug(f"Redirect test {payload}: {e}")

    async def check_template_injection(self, url: str, params: Dict):
        """Async template injection test."""
        ssti_payloads = ['${7*7}', '{{7*7}}', '<%= 7 * 7 %>']
        tasks = []
        for param in params:
            for payload in ssti_payloads:
                test_params = params.copy()
                test_params[param] = payload
                tasks.append(self._test_ssti(url, test_params, param, payload))
        await asyncio.gather(*tasks)

    async def _test_ssti(self, url: str, params: Dict, param: str, payload: str):
        async with self.semaphore:
            try:
                async with self.session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    text = await resp.text()
                    if '49' in text:
                        self.vulnerabilities.append({
                            "type": "Template Injection", "severity": "High",
                            "details": f"SSTI in param '{param}'", "url": url, "payload": payload
                        })
            except Exception as e:
                self.logger.debug(f"SSTI test {payload}: {e}")

    async def check_security_misconfiguration(self):
        """Async security misconfiguration check."""
        common_paths = ['/.git', '/.env', '/wp-config.php', '/phpinfo.php', '/admin/']
        tasks = [self._check_path(path) for path in common_paths]
        await asyncio.gather(*tasks)

    async def _check_path(self, path: str):
        url = urljoin(self.base_url, path)
        async with self.semaphore:
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        self.vulnerabilities.append({
                            "type": "Security Misconfiguration", "severity": "Medium",
                            "details": f"Sensitive path {path} accessible", "url": url
                        })
            except Exception as e:
                self.logger.debug(f"Path check {url}: {e}")

    async def check_subdomain_takeover(self):
        """Enhanced subdomain takeover check."""
        hostname = urlparse(self.target_url).netloc
        try:
            answers = dns.resolver.resolve(hostname, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target)
                async with self.semaphore:
                    async with self.session.get(f"http://{cname}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 404 or "not found" in (await resp.text()).lower():
                            self.vulnerabilities.append({
                                "type": "Subdomain Takeover", "severity": "High",
                                "details": f"Potential takeover: {cname}", "url": self.target_url
                            })
        except Exception as e:
            self.logger.debug(f"Subdomain takeover check: {e}")

    async def test_csrf_vulnerability(self, url: str):
        """Basic CSRF test."""
        async with self.semaphore:
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        if not form.find('input', {'name': re.compile(r'csrf|token', re.I)}):
                            self.vulnerabilities.append({
                                "type": "CSRF", "severity": "Medium",
                                "details": "Form without CSRF token", "url": url
                            })
            except Exception as e:
                self.logger.debug(f"CSRF test: {e}")

    async def check_rate_limiting(self, url: str):
        """Basic rate limiting test."""
        async with self.semaphore:
            try:
                for _ in range(10):  # 10 rapid requests
                    async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=1)) as resp:
                        if resp.status == 429:
                            self.logger.info(f"Rate limiting detected at {url}")
                            return
                self.vulnerabilities.append({
                    "type": "Rate Limiting", "severity": "Low",
                    "details": "No rate limiting detected", "url": url
                })
            except Exception as e:
                self.logger.debug(f"Rate limit test: {e}")

    async def scan_for_vulnerabilities(self):
        """Placeholder for additional scans."""
        self.logger.info("Additional vulnerability scans (placeholder)")

    async def check_api_security(self, url: str):
        """Basic API security check."""
        api_endpoints = [f"{url}/api", f"{url}/v1", f"{url}/api/v1"]
        tasks = [self._check_api_endpoint(ep) for ep in api_endpoints]
        await asyncio.gather(*tasks)

    async def _check_api_endpoint(self, endpoint: str):
        async with self.semaphore:
            try:
                async with self.session.get(endpoint, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "json" in resp.headers.get("Content-Type", "").lower():
                            self.apis_found.add(endpoint)
                            if "authentication" not in text.lower():
                                self.vulnerabilities.append({
                                    "type": "API Security", "severity": "Medium",
                                    "details": "API endpoint without auth", "url": endpoint
                                })
            except Exception as e:
                self.logger.debug(f"API check {endpoint}: {e}")

    async def check_graphql_vulnerabilities(self, url: str):
        """Basic GraphQL check."""
        async with self.semaphore:
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200 and "graphql" in (await resp.text()).lower():
                        self.vulnerabilities.append({
                            "type": "GraphQL", "severity": "Info",
                            "details": "GraphQL endpoint detected", "url": url
                        })
            except Exception as e:
                self.logger.debug(f"GraphQL check: {e}")

    async def check_host_header_injection(self, url: str):
        """Host header injection test."""
        headers = self.headers.copy()
        headers['Host'] = 'evil.com'
        async with self.semaphore:
            try:
                async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    text = await resp.text()
                    if 'evil.com' in text:
                        self.vulnerabilities.append({
                            "type": "Host Header Injection", "severity": "High",
                            "details": "Host header reflected", "url": url
                        })
            except Exception as e:
                self.logger.debug(f"Host header test: {e}")

    async def check_nosql_injection(self, url: str, params: Dict):
        """Basic NoSQL injection test."""
        nosql_payload = {"$ne": None}
        for param in params:
            test_params = params.copy()
            test_params[param] = nosql_payload
            async with self.semaphore:
                try:
                    async with self.session.get(url, params=test_params, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200 and len(await resp.text()) > 1000:  # Arbitrary large response
                            self.vulnerabilities.append({
                                "type": "NoSQL Injection", "severity": "High",
                                "details": f"NoSQL injection in param '{param}'", "url": url
                            })
                except Exception as e:
                    self.logger.debug(f"NoSQL test: {e}")

    async def check_crlf_injection(self, url: str, params: Dict):
        """CRLF injection test."""
        crlf_payload = "test%0d%0aSet-Cookie:evil=1"
        for param in params:
            test_params = params.copy()
            test_params[param] = crlf_payload
            async with self.semaphore:
                try:
                    async with self.session.get(url, params=test_params, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if "Set-Cookie" in resp.headers:
                            self.vulnerabilities.append({
                                "type": "CRLF Injection", "severity": "High",
                                "details": f"CRLF injection in param '{param}'", "url": url
                            })
                except Exception as e:
                    self.logger.debug(f"CRLF test: {e}")

    async def check_file_inclusion(self, url: str, params: Dict):
        """Async file inclusion test."""
        lfi_payloads = ['../../../etc/passwd', '/etc/passwd%00']
        tasks = []
        for param in params:
            for payload in lfi_payloads:
                test_params = params.copy()
                test_params[param] = payload
                tasks.append(self._test_lfi(url, test_params, param, payload))
        await asyncio.gather(*tasks)

    async def _test_lfi(self, url: str, params: Dict, param: str, payload: str):
        async with self.semaphore:
            try:
                async with self.session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    text = await resp.text()
                    if 'root:' in text or 'nobody:' in text:
                        self.vulnerabilities.append({
                            "type": "LFI", "severity": "High",
                            "details": f"LFI in param '{param}'", "url": url, "payload": payload
                        })
            except Exception as e:
                self.logger.debug(f"LFI test {payload}: {e}")

    def generate_report(self) -> Dict:
        """Generate detailed security report."""
        report = {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "scan_time": str(datetime.now()),
            "summary": {
                "total_urls_discovered": len(self.found_urls),
                "total_urls_scanned": len(self.visited_urls),
                "total_vulnerabilities": len(self.vulnerabilities),
                "vulnerability_summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            },
            "vulnerabilities": self.vulnerabilities,
            "scanned_urls": list(self.visited_urls),
            "apis_found": list(self.apis_found),
            "scan_configuration": self.options
        }
        for vuln in self.vulnerabilities:
            report["summary"]["vulnerability_summary"][vuln["severity"]] += 1
        return report

    def export_report(self, report: Dict, format: str = 'json'):
        """Export report in multiple formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_scan_{timestamp}.{format.lower()}"
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
        elif format.lower() == 'html':
            self._generate_html_report(report, filename)
        elif format.lower() == 'yaml':
            with open(filename, 'w') as f:
                yaml.dump(report, f, default_flow_style=False)
        self.logger.info(f"Report exported to {filename}")

    def _generate_html_report(self, report: Dict, filename: str):
        """Generate HTML report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Security Scan Report {self.scan_id}</title>
        <style>
            body {{ font-family: Arial; margin: 20px; }}
            .vuln {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; }}
            .Critical {{ background: #ffebee; }} .High {{ background: #fff3e0; }}
            .Medium {{ background: #fff8e1; }} .Low {{ background: #f1f8e9; }}
        </style></head>
        <body>
        <h1>Security Scan Report</h1>
        <p>Target: {report['target_url']} | Scan Time: {report['scan_time']}</p>
        <h2>Summary</h2>
        <p>Total Vulnerabilities: {report['summary']['total_vulnerabilities']}</p>
        <h2>Vulnerabilities</h2>
        {"".join(f"<div class='vuln {v['severity']}'><h3>{v['type']} ({v['severity']})</h3><p>{v['details']}</p><p>URL: {v.get('url', 'N/A')}</p></div>" for v in report['vulnerabilities'])}
        </body></html>
        """
        with open(filename, 'w') as f:
            f.write(html)

async def run_scanner(url: str, options: Dict):
    """Async wrapper for scanner."""
    scanner = ProfessionalWebScanner(url, options)
    return await scanner.run_scan()

def main():
    """Main entry point for the scanner with command-line argument parsing."""
    # Initialize ArgumentParser with a detailed description for -h/--help output
    parser = argparse.ArgumentParser(
        description='Advanced Web Security Scanner: A powerful tool to identify vulnerabilities '
                   'in web applications, including SSL/TLS issues, injection attacks, and misconfigurations.',
        epilog='Example: python3 scanner.py https://example.com -t 20 -o html --full'
    )
    
    # Define command-line arguments with descriptive help messages
    parser.add_argument(
        'url', 
        help='Target URL to scan (e.g., https://example.com). Must be a valid URL.'
    )
    parser.add_argument(
        '-o', '--output', 
        choices=['json', 'html', 'yaml'], 
        default='json', 
        help='Output format for the scan report. Options: json (default), html, yaml.'
    )
    parser.add_argument(
        '-t', '--threads', 
        type=int, 
        default=10, 
        help='Number of concurrent threads for scanning (default: 10). Increase for faster scans, '
             'but beware of resource usage.'
    )
    parser.add_argument(
        '--full', 
        action='store_true', 
        help='Enable full scan mode for aggressive testing (currently a placeholder for future features).'
    )
    
    # Parse arguments; -h/--help is automatically handled by argparse to show the above info
    args = parser.parse_args()
    
    # Automatically prepend 'https://' if no scheme is provided in the URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    # Configure scanner options based on command-line input
    options = {
        'threads': args.threads,      # Number of concurrent requests
        'full_scan': args.full,       # Boolean flag for full scan mode
        'output_format': args.output  # Report format
    }
    
    # Run the scanner within an asyncio event loop
    try:
        report = asyncio.run(run_scanner(args.url, options))
        # Check if scan completed successfully (no error status in report)
        if report and report.get("status") != "error":
            print("\nScan Complete!")
            print("\nVulnerability Summary:")
            # Display a summary of vulnerabilities by severity
            for severity, count in report["summary"]["vulnerability_summary"].items():
                print(f"{severity}: {count}")
            print(f"\nReport saved as {args.output}")
        else:
            # Indicate failure if report contains an error status
            print("\nScan failed. Check logs for details.")
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        # Catch any unexpected errors and exit with failure
        print(f"\nError: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
