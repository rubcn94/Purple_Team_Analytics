#!/usr/bin/env python3
"""
Web Directory Scanner - Purple Team Security Suite
Discovers hidden paths and files on web servers using intelligent enumeration.

MITRE ATT&CK:
- T1083: File and Directory Discovery
- T1590: Gather Victim Network Information

This tool is for authorized penetration testing and security research only.
Unauthorized access to computer systems is illegal. Ensure you have explicit
written permission from the system owner before scanning.
"""

import sys
import json
import time
import argparse
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Set
import warnings

# Try to import requests, provide helpful feedback if missing
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] Warning: requests library not found. Install with: pip install requests")
    print("[!] Continuing with limited functionality...")


class DirectoryScanner:
    """Web directory enumeration with intelligent analysis and classification."""

    # Comprehensive wordlist of common paths (~350+ entries)
    DEFAULT_WORDLIST = [
        # Admin panels
        "/admin", "/administrator", "/admin.php", "/admin/login", "/admin/index.html",
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/cpanel", "/cPanel", "/whm", "/webdisk",
        "/phpmyadmin", "/phpMyAdmin", "/pma",
        "/manager", "/manager/html", "/host-manager",
        "/adminpanel", "/administratorpanel", "/controlpanel",
        "/user/admin", "/dashboard", "/panel",
        "/login", "/auth", "/signin", "/account",

        # Configuration files
        "/.env", "/.env.local", "/.env.backup", "/.env.example",
        "/config.php", "/configuration.php", "/config.xml",
        "/web.config", "/.htaccess", "/.htpasswd",
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
        "/config/database.yml", "/config/app.php",
        "/settings.php", "/config.ini", "/.editorconfig",

        # Version control
        "/.git", "/.git/", "/.git/HEAD", "/.git/config", "/.git/logs",
        "/.gitignore", "/.gitconfig", "/.github",
        "/.svn", "/.hg", "/.bzr",

        # Backup and temporary files
        "/backup", "/backups", "/backup.zip", "/backup.tar.gz",
        "/backup.sql", "/db.sql", "/database.sql", "/dump.sql",
        "/.bak", "/.backup", "/~backup",
        "/index.php.bak", "/index.html.bak", "/index.old",
        "/old", "/archive", "/previous",

        # API endpoints
        "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
        "/api/users", "/api/products", "/api/posts",
        "/graphql", "/graphql/", "/graphiql",
        "/rest", "/rest/api", "/rest/v1",
        "/swagger", "/swagger-ui", "/swagger.json",
        "/api-docs", "/apidocs", "/api/docs", "/documentation",
        "/openapi", "/openapi.json", "/openapi.yaml",

        # WordPress specific
        "/wp-content", "/wp-content/", "/wp-includes",
        "/wp-json", "/wp-json/", "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts", "/xmlrpc.php",
        "/wp-cron.php", "/wp-load.php", "/wp-mail.php",
        "/wp-settings.php", "/wp-activate.php",

        # Laravel/PHP frameworks
        "/vendor", "/vendor/", "/composer.json", "/composer.lock",
        "/artisan", "/.env", "/bootstrap/cache",
        "/storage/logs", "/storage/framework",
        "/config", "/resources", "/routes",

        # Django/Python frameworks
        "/manage.py", "/wsgi.py", "/asgi.py",
        "/settings.py", "/urls.py", "/views.py",
        "/migrations", "/static", "/media",

        # Ruby on Rails
        "/Gemfile", "/config.ru", "/Rakefile",
        "/app", "/lib", "/spec", "/test", "/tmp",

        # Server information
        "/server-status", "/server-info", "/status",
        "/info.php", "/phpinfo.php", "/php.php",
        "/version.php", "/test.php", "/test.html",
        "/README", "/LICENSE", "/CHANGELOG",

        # Error pages
        "/404", "/404.php", "/404.html",
        "/500", "/500.php", "/500.html",
        "/403", "/403.php", "/error",

        # Common directories
        "/uploads", "/uploads/", "/files", "/file",
        "/images", "/img", "/pics", "/pictures",
        "/downloads", "/download", "/downloads/",
        "/media", "/assets", "/static",
        "/temp", "/tmp", "/cache", "/logs",
        "/data", "/var", "/www", "/html",
        "/public", "/public_html", "/www-data",
        "/content", "/cms", "/site",

        # Security and metadata files
        "/robots.txt", "/sitemap.xml", "/sitemap.xml.gz",
        "/security.txt", "/.well-known", "/.well-known/security.txt",
        "/ads.txt", "/app-ads.txt", "/humans.txt",
        "/manifest.json", "/.htaccess", "/.htpasswd",
        "/.user.ini", "/.wgetrc", "/.listing",

        # Source code files (common extensions)
        "/index", "/index.html", "/index.php", "/index.jsp",
        "/index.aspx", "/index.cfm", "/index.xml",
        "/home", "/main", "/start", "/default",
        "/welcome", "/about", "/contact", "/help",
        "/search", "/error", "/redirect",

        # Node.js / npm
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/node_modules", "/node_modules/", "/npm-debug.log",
        "/.npmrc", "/.yarnrc", "/.nvm",

        # Docker/Container files
        "/Dockerfile", "/.dockerignore", "/docker-compose.yml",
        "/docker-compose.yaml", "/.docker",

        # CI/CD pipelines
        "/.gitlab-ci.yml", "/.travis.yml", "/Jenkinsfile",
        "/.circleci", "/.github/workflows", "/.github/actions",

        # Java / Spring Boot
        "/WEB-INF", "/META-INF", "/spring-boot.properties",
        "/application.properties", "/application.yml",
        "/pom.xml", "/build.gradle", "/target",

        # .NET / ASP.NET
        "/web.config", "/Global.asax", "/App_Data",
        "/App_Code", "/Bin", "/obj",

        # AWS / Cloud
        "/aws", "/.aws", "/cloudformation",
        "/.env.aws", "/env.json",

        # Development/Debug paths
        "/debug", "/debugbar", "/profiler",
        "/metrics", "/health", "/ready",
        "/actuator", "/actuator/health",

        # Testing endpoints
        "/test", "/tests", "/testing", "/qa",
        "/unit-tests", "/integration-tests",
        "/benchmark", "/perf",

        # Miscellaneous common paths
        "/search", "/query", "/find",
        "/submit", "/process", "/handler",
        "/callback", "/webhook", "/hook",
        "/upload", "/export", "/import",
        "/download", "/file", "/attachment",
        "/profile", "/user", "/users", "/account",
        "/settings", "/preferences", "/config",
        "/help", "/support", "/faq", "/docs",
        "/blog", "/news", "/feed", "/rss",
        "/category", "/tag", "/archive",
        "/privacy", "/terms", "/legal",
        "/sitemap", "/map", "/index",
    ]

    # Technology detection patterns
    TECH_SIGNATURES = {
        "WordPress": ["/wp-admin", "/wp-content", "/wp-json", "/xmlrpc.php"],
        "Laravel": ["/vendor", "/app", "/bootstrap", "/resources", "/routes"],
        "Django": ["/manage.py", "/admin", "/media", "/static", "/migrations"],
        "Ruby on Rails": ["/Gemfile", "/app", "/config", "/public", "/Rakefile"],
        "Spring Boot": ["/actuator", "/swagger-ui", "/api/v"],
        "Express.js": ["/package.json", "/node_modules", "/public"],
        "Flask": ["/static", "/templates", "/app.py"],
        "ASP.NET": ["/web.config", "/App_Data", "/bin"],
        "PHP": ["/phpmyadmin", "/info.php", "/config.php"],
        "Node.js": ["/package.json", "/node_modules"],
    }

    # Risk classification
    RISK_LEVELS = {
        "CRITICAL": {
            "patterns": [r"\.env", r"\.git/", r"\.git$", r"backup\.sql", r"backup\.zip",
                        r"config\.php\.bak", r"wp-config\.php\.bak", r"database\.sql"],
            "color": "\033[91m",  # Red
        },
        "HIGH": {
            "patterns": [r"/admin", r"/wp-admin", r"/phpmyadmin", r"/cpanel",
                        r"phpinfo\.php", r"\.htpasswd", r"/manager"],
            "color": "\033[93m",  # Yellow
        },
        "MEDIUM": {
            "patterns": [r"/backup", r"/old", r"/api", r"/uploads", r"/files",
                        r"/config", r"/temp", r"/logs"],
            "color": "\033[94m",  # Blue
        },
        "LOW": {
            "patterns": [r"/robots\.txt", r"/sitemap\.xml", r"/privacy", r"/terms",
                        r"/contact", r"/about"],
            "color": "\033[92m",  # Green
        },
    }

    def __init__(self, url: str, threads: int = 10, timeout: int = 5,
                 user_agent: Optional[str] = None, verify_ssl: bool = True,
                 rate_limit: float = 0.1, method: str = "HEAD",
                 follow_redirects: bool = True, custom_wordlist: Optional[List[str]] = None):
        """
        Initialize the directory scanner.

        Args:
            url: Target URL (e.g., https://example.com)
            threads: Number of concurrent threads (default 10)
            timeout: Request timeout in seconds
            user_agent: Custom User-Agent string
            verify_ssl: Verify SSL certificates
            rate_limit: Delay between requests in seconds (for Termux/rate limiting)
            method: HTTP method to use (HEAD or GET)
            follow_redirects: Follow redirects
            custom_wordlist: Custom list of paths to scan
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required. Install with: pip install requests")

        self.url = url.rstrip('/')
        self.threads = min(threads, 50)  # Cap at 50 to prevent resource exhaustion
        self.timeout = timeout
        self.rate_limit = max(rate_limit, 0.01)  # Minimum 10ms between requests
        self.method = method.upper()
        self.follow_redirects = follow_redirects

        # Parse URL
        parsed = urlparse(url)
        if not parsed.scheme:
            self.url = "https://" + url

        # Set up User-Agent
        if not user_agent:
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )
        self.headers = {"User-Agent": user_agent}

        # Set up requests session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.verify_ssl = verify_ssl
        if not verify_ssl:
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")

        # Wordlist
        self.wordlist = custom_wordlist or self.DEFAULT_WORDLIST

        # Results storage
        self.findings: List[Dict] = []
        self.tech_detected: Set[str] = set()
        self.response_cache: Dict[str, int] = {}
        self.redirect_chains: Dict[str, List[str]] = defaultdict(list)

        # 404 detection
        self.custom_404_signature = None
        self.custom_404_size_range = None

    def setup_404_detection(self) -> None:
        """Detect custom 404 responses to avoid false positives."""
        try:
            # Request a random non-existent path
            test_path = f"/nonexistent_{int(time.time())}_test"
            response = self._make_request(test_path)

            if response and response.status_code == 404:
                self.custom_404_signature = response.text[:100]
                self.custom_404_size_range = (
                    len(response.text) - 50,
                    len(response.text) + 50
                )
                print(f"[*] Custom 404 signature detected (size: {len(response.text)} bytes)")
        except Exception as e:
            print(f"[!] 404 detection failed: {e}")

    def _make_request(self, path: str) -> Optional[requests.Response]:
        """Make HTTP request with error handling."""
        try:
            time.sleep(self.rate_limit)

            full_url = urljoin(self.url, path)

            response = self.session.request(
                method=self.method,
                url=full_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=self.follow_redirects,
                stream=True
            )

            # Read content for analysis
            response.raw.read(amt=8192, decode_content=False)

            return response
        except (requests.RequestException, Exception) as e:
            return None

    def _is_custom_404(self, response: Optional[requests.Response]) -> bool:
        """Check if response is a custom 404."""
        if not response or not self.custom_404_signature:
            return False

        if response.status_code != 404:
            return False

        try:
            text_snippet = response.text[:100]
            size = len(response.text)

            # Check for signature match
            if text_snippet in self.custom_404_signature or \
               self.custom_404_signature in response.text:
                return True

            # Check size range
            if self.custom_404_size_range:
                min_size, max_size = self.custom_404_size_range
                if min_size <= size <= max_size:
                    return True
        except:
            pass

        return False

    def _classify_risk(self, path: str, status_code: int) -> str:
        """Classify finding by risk level."""
        # Skip 404s and errors
        if status_code >= 400 or status_code == 0:
            return "N/A"

        for level, config in self.RISK_LEVELS.items():
            for pattern in config["patterns"]:
                if re.search(pattern, path, re.IGNORECASE):
                    return level

        return "MEDIUM"  # Default for found paths

    def _detect_technologies(self, path: str) -> None:
        """Detect web technologies based on found paths."""
        for tech, signatures in self.TECH_SIGNATURES.items():
            if any(sig in path for sig in signatures):
                self.tech_detected.add(tech)

    def _handle_redirect(self, response: requests.Response, path: str) -> None:
        """Track redirect chains."""
        if hasattr(response, 'history') and response.history:
            chain = [r.url for r in response.history]
            chain.append(response.url)
            self.redirect_chains[path] = chain

    def scan_path(self, path: str) -> Optional[Dict]:
        """Scan a single path and return findings."""
        response = self._make_request(path)

        if not response:
            return None

        # Skip custom 404s
        if self._is_custom_404(response):
            return None

        # Valid status codes indicating found resources
        if response.status_code < 400:
            self._detect_technologies(path)
            risk_level = self._classify_risk(path, response.status_code)

            finding = {
                "path": path,
                "status_code": response.status_code,
                "size": len(response.text),
                "risk_level": risk_level,
                "content_type": response.headers.get("Content-Type", "unknown"),
                "title": self._extract_title(response),
                "timestamp": time.time(),
            }

            # Track redirects
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location")
                if location:
                    finding["redirect_to"] = location
                    self._handle_redirect(response, path)

            return finding

        return None

    def _extract_title(self, response: requests.Response) -> Optional[str]:
        """Extract title from HTML response."""
        try:
            match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        except:
            pass
        return None

    def scan(self, wordlist: Optional[List[str]] = None) -> None:
        """Execute the directory scanning."""
        wordlist = wordlist or self.wordlist

        print(f"\n{'='*70}")
        print(f"Web Directory Scanner - Purple Team Edition")
        print(f"{'='*70}")
        print(f"[*] Target URL: {self.url}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Method: {self.method}")
        print(f"[*] Rate limit: {self.rate_limit}s between requests")
        print(f"[*] Wordlist size: {len(wordlist)} paths")
        print(f"[*] SSL verification: {self.verify_ssl}")
        print(f"{'='*70}\n")

        # Setup 404 detection
        print("[*] Setting up custom 404 detection...")
        self.setup_404_detection()
        print()

        start_time = time.time()
        completed = 0

        # Thread pool scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_path, path): path
                for path in wordlist
            }

            for future in as_completed(futures):
                completed += 1
                path = futures[future]

                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                        self._print_finding(result)
                except Exception as e:
                    pass

                # Progress indicator
                if completed % 20 == 0:
                    elapsed = time.time() - start_time
                    rate = completed / elapsed if elapsed > 0 else 0
                    print(f"[*] Progress: {completed}/{len(wordlist)} "
                          f"({completed*100//len(wordlist)}%) "
                          f"- {rate:.1f} req/s", end='\r')

        elapsed = time.time() - start_time
        print(f"\n[+] Scan complete in {elapsed:.2f}s")
        self._print_summary(elapsed)

    def _print_finding(self, finding: Dict) -> None:
        """Print a single finding with color coding."""
        risk = finding["risk_level"]
        color_code = ""

        for level, config in self.RISK_LEVELS.items():
            if risk == level:
                color_code = config["color"]
                break

        reset = "\033[0m"

        status = finding["status_code"]
        size = finding["size"]
        content_type = finding["content_type"].split(';')[0] if finding["content_type"] else "?"

        output = f"{color_code}[{risk:8s}]{reset} {status:3d} "
        output += f"{size:8d}B {content_type:20s} {finding['path']}"

        if finding.get("redirect_to"):
            output += f" -> {finding['redirect_to']}"

        if finding.get("title"):
            output += f" ({finding['title'][:50]})"

        print(output)

    def _print_summary(self, elapsed: float) -> None:
        """Print scan summary and analysis."""
        print(f"\n{'='*70}")
        print("SCAN SUMMARY")
        print(f"{'='*70}")

        # Group by risk level
        risk_counts = defaultdict(int)
        for finding in self.findings:
            risk_counts[finding["risk_level"]] += 1

        print(f"\n[*] Total findings: {len(self.findings)}")
        print("[*] By risk level:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = risk_counts.get(level, 0)
            if count > 0:
                print(f"    - {level}: {count}")

        # Technologies detected
        if self.tech_detected:
            print(f"\n[*] Technologies detected ({len(self.tech_detected)}):")
            for tech in sorted(self.tech_detected):
                print(f"    - {tech}")

        # Top findings
        if self.findings:
            critical_findings = [f for f in self.findings
                               if f["risk_level"] == "CRITICAL"]
            if critical_findings:
                print(f"\n[!] CRITICAL findings:")
                for finding in critical_findings[:5]:
                    print(f"    - {finding['path']} ({finding['status_code']})")

            high_findings = [f for f in self.findings
                           if f["risk_level"] == "HIGH"]
            if high_findings:
                print(f"\n[!] HIGH risk findings:")
                for finding in high_findings[:5]:
                    print(f"    - {finding['path']} ({finding['status_code']})")

        print(f"\n[*] Scan duration: {elapsed:.2f}s")
        print(f"{'='*70}\n")

    def to_json(self) -> str:
        """Export findings as JSON."""
        export_data = {
            "metadata": {
                "target": self.url,
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_findings": len(self.findings),
                "technologies": list(self.tech_detected),
            },
            "findings": self.findings,
        }
        return json.dumps(export_data, indent=2, default=str)

    def save_json(self, filename: str = "scan_results.json") -> None:
        """Save results to JSON file."""
        with open(filename, 'w') as f:
            f.write(self.to_json())
        print(f"[+] Results saved to {filename}")


def interactive_mode() -> None:
    """Interactive mode for user input."""
    print("\n" + "="*70)
    print("Web Directory Scanner - Interactive Mode")
    print("="*70 + "\n")

    print("[!] DISCLAIMER: Only scan targets you own or have explicit permission to scan.")
    print("[!] Unauthorized access to computer systems is illegal.\n")

    url = input("[?] Target URL (e.g., https://example.com): ").strip()
    if not url:
        print("[!] URL is required")
        return

    threads = input("[?] Number of threads (default 10): ").strip()
    threads = int(threads) if threads else 10

    rate_limit = input("[?] Rate limit in seconds (default 0.1): ").strip()
    rate_limit = float(rate_limit) if rate_limit else 0.1

    verify_ssl = input("[?] Verify SSL certificates? (y/n, default y): ").strip().lower() != 'n'

    method = input("[?] HTTP method (HEAD/GET, default HEAD): ").strip().upper() or "HEAD"

    output_file = input("[?] Output JSON file (leave blank for no file): ").strip()

    try:
        scanner = DirectoryScanner(
            url=url,
            threads=threads,
            rate_limit=rate_limit,
            verify_ssl=verify_ssl,
            method=method
        )

        scanner.scan()

        if output_file:
            scanner.save_json(output_file)

        print("\n[+] Scan completed successfully")

    except Exception as e:
        print(f"[!] Error: {e}")


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description="Web Directory Scanner - Discover hidden paths and files on web servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python directory_scanner.py --url https://example.com
  python directory_scanner.py --url https://example.com --threads 20 --method GET
  python directory_scanner.py --url https://example.com --output results.json
  python directory_scanner.py  # Interactive mode
        """
    )

    parser.add_argument("--url", "-u", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--threads", "-t", type=int, default=10,
                       help="Number of concurrent threads (default 10, max 50)")
    parser.add_argument("--timeout", type=int, default=5,
                       help="Request timeout in seconds (default 5)")
    parser.add_argument("--rate-limit", type=float, default=0.1,
                       help="Delay between requests in seconds (default 0.1)")
    parser.add_argument("--method", "-m", choices=["HEAD", "GET"], default="HEAD",
                       help="HTTP method to use (default HEAD)")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--no-ssl-verify", action="store_true",
                       help="Disable SSL certificate verification")
    parser.add_argument("--output", "-o", help="Output JSON file for results")
    parser.add_argument("--wordlist", "-w", help="Custom wordlist file (one path per line)")
    parser.add_argument("--follow-redirects", action="store_true", default=True,
                       help="Follow HTTP redirects (default true)")

    args = parser.parse_args()

    # Interactive mode if no URL provided
    if not args.url:
        interactive_mode()
        return

    # Load custom wordlist if provided
    custom_wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(custom_wordlist)} paths from {args.wordlist}")
        except IOError as e:
            print(f"[!] Failed to load wordlist: {e}")
            return

    # Create scanner and run
    try:
        scanner = DirectoryScanner(
            url=args.url,
            threads=args.threads,
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            method=args.method,
            user_agent=args.user_agent,
            verify_ssl=not args.no_ssl_verify,
            follow_redirects=args.follow_redirects,
            custom_wordlist=custom_wordlist
        )

        scanner.scan()

        # Save results if requested
        if args.output:
            scanner.save_json(args.output)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
