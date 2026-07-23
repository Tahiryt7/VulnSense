from __future__ import annotations

# All checks are passive or use a single harmless detection payload. This tool must only be run against systems you own or are explicitly authorized to test.

import re
import socket
import ssl
import uuid
from difflib import SequenceMatcher
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from requests import Response, Session
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings


disable_warnings(InsecureRequestWarning)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    category: str
    owasp_category: str
    base_severity: int
    description: str
    recommendation: str


class Scanner:
    OWASP_A01 = "A01:2021 - Broken Access Control"
    OWASP_A02 = "A02:2021 - Cryptographic Failures"
    OWASP_A03 = "A03:2021 - Injection"
    OWASP_A04 = "A04:2021 - Insecure Design"
    OWASP_A05 = "A05:2021 - Security Misconfiguration"
    OWASP_A06 = "A06:2021 - Vulnerable and Outdated Components"
    OWASP_A07 = "A07:2021 - Identification and Authentication Failures"
    OWASP_A08 = "A08:2021 - Software and Data Integrity Failures"
    OWASP_A09 = "A09:2021 - Security Logging and Monitoring Failures"
    OWASP_A10 = "A10:2021 - Server-Side Request Forgery"

    SECURITY_HEADERS = {
        "Strict-Transport-Security": (
            3,
            "prevents downgrade attacks and enforces HTTPS usage",
            "Add an HSTS header such as Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ),
        "Content-Security-Policy": (
            3,
            "helps block cross-site scripting and content injection",
            "Define a restrictive Content-Security-Policy that only allows trusted sources",
        ),
        "X-Frame-Options": (
            2,
            "helps prevent clickjacking by controlling whether pages can be framed",
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use the frame-ancestors CSP directive",
        ),
        "X-Content-Type-Options": (
            2,
            "prevents MIME sniffing attacks by forcing browsers to respect content types",
            "Set X-Content-Type-Options: nosniff on all responses",
        ),
        "Referrer-Policy": (
            1,
            "controls how much browsing history and URL data is shared in referrer headers",
            "Set a Referrer-Policy such as strict-origin-when-cross-origin or no-referrer",
        ),
        "Permissions-Policy": (
            1,
            "restricts access to sensitive browser features like camera, geolocation, and microphone",
            "Add a Permissions-Policy header that disables unused browser features",
        ),
    }

    DIRECTORY_MARKERS = ["Index of /", "Parent Directory", "Directory listing", "directory listing"]
    DEBUG_MARKERS = [
        "Traceback",
        "Exception in",
        "Stack trace",
        "stack trace",
        "Fatal error",
        "Whitelabel Error Page",
        "debug",
        "at line",
    ]
    SQL_ERROR_MARKERS = [
        "sql syntax",
        "mysql_fetch",
        "ora-01756",
        "unclosed quotation mark",
        "you have an error in your sql syntax",
        "sqlstate",
    ]
    SENSITIVE_PATHS = (
        "/admin",
        "/admin/login",
        "/wp-admin",
        "/.env",
        "/config.php",
        "/server-status",
        "/phpinfo.php",
        "/actuator",
        "/debug",
    )
    SENSITIVE_PATH_HINTS = {
        "/.env": ("db_password", "app_key", "secret", "api_key", "=", "database_url"),
        "/config.php": ("<?php", "$", "define(", "db_", "password"),
        "/server-status": ("server uptime", "apache server status", "busy workers", "scoreboard"),
        "/phpinfo.php": ("php version", "php credits", "_server", "phpinfo()"),
        "/actuator": ("beans", "health", "env", "mappings", "_links"),
        "/debug": ("traceback", "debug", "stack", "exception"),
        "/.git/": ("refs", "objects", "head", "index"),
    }

    def __init__(self, target_url: str, timeout: float = 8.0):
        self.target_url = self._normalize_url(target_url)
        self.timeout = timeout
        self.session = Session()
        self.session.headers.update({"User-Agent": "VulnSense/1.0"})

    def run_full_scan(self, progress_cb: Optional[Callable[[str], None]] = None) -> List[Finding]:
        findings: List[Finding] = []
        try:
            response = self._fetch_target()
        except Exception as exc:
            return [self._check_failed_finding("fetch-target", f"Unable to fetch target: {exc}")]

        check_plan = [
            ("Checking security headers", "security-headers", lambda: self._check_security_headers(response)),
            ("Checking SSL/TLS and cryptographic controls", "tls", lambda: self._check_tls(response)),
            ("Checking cookie security", "cookies", lambda: self._check_cookies(response)),
            ("Checking server and technology banners", "banners", lambda: self._check_banners(response)),
            ("Checking common misconfigurations", "misconfigurations", self._check_misconfigurations),
            ("Checking broken access control heuristics", "access-control", lambda: self._check_broken_access_control(response)),
            ("Checking basic injection indicators", "injection", lambda: self._check_injection_basic(response)),
            ("Checking insecure design heuristics", "insecure-design", lambda: self._check_insecure_design_heuristics(response)),
            ("Checking component and integrity heuristics", "components", lambda: self._check_component_and_integrity_heuristics(response)),
            ("Checking logging heuristics", "logging", lambda: self._check_logging_heuristics(response)),
        ]

        for status_message, source_name, check_func in check_plan:
            if progress_cb:
                progress_cb(status_message)
            try:
                findings.extend(check_func())
            except Exception as exc:
                findings.append(self._check_failed_finding(source_name, f"Check failed safely: {exc}"))

        return findings

    def _normalize_url(self, target_url: str) -> str:
        value = target_url.strip()
        if not value:
            raise ValueError("Target URL cannot be empty")
        if "://" not in value:
            value = f"http://{value}"
        parsed = urlparse(value)
        if not parsed.netloc and parsed.path:
            parsed = urlparse(f"http://{parsed.path}")
        path = parsed.path or "/"
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))

    def _fetch_target(self) -> Response:
        return self.session.get(self.target_url, timeout=self.timeout, verify=False, allow_redirects=True)

    def _check_security_headers(self, response: Response) -> List[Finding]:
        findings: List[Finding] = []
        for header_name, (severity, protection, fix) in self.SECURITY_HEADERS.items():
            if header_name not in response.headers:
                findings.append(
                    Finding(
                        finding_id=self._finding_id("security-header", header_name),
                        title=f"Missing security header: {header_name}",
                        category="Security Headers",
                        owasp_category=self.OWASP_A05,
                        base_severity=severity,
                        description=f"The {header_name} header is missing. This header {protection}.",
                        recommendation=fix,
                    )
                )
        return findings

    def _check_tls(self, response: Response) -> List[Finding]:
        findings: List[Finding] = []
        page_html = response.text or ""

        findings.extend(self._check_insecure_form_submission(page_html))
        findings.extend(self._check_password_autocomplete(page_html))

        parsed = urlparse(self.target_url)
        if parsed.scheme.lower() == "http":
            findings.append(
                Finding(
                    finding_id=self._finding_id("tls", "plain-http"),
                    title="Target is served over plain HTTP",
                    category="TLS",
                    owasp_category=self.OWASP_A02,
                    base_severity=4,
                    description="The target is reachable over plain HTTP, so traffic is not encrypted in transit.",
                    recommendation="Serve the application over HTTPS and redirect all HTTP traffic to TLS.",
                )
            )
            return findings

        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return findings

        try:
            raw_socket = socket.create_connection((host, port), timeout=self.timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                protocol_version = tls_socket.version() or "unknown"
                if protocol_version in {"SSLv3", "TLSv1", "TLSv1.1"}:
                    findings.append(
                        Finding(
                            finding_id=self._finding_id("tls", "weak-protocol"),
                            title=f"Weak TLS protocol negotiated: {protocol_version}",
                            category="TLS",
                            owasp_category=self.OWASP_A02,
                            base_severity=4,
                            description=f"The server negotiated {protocol_version}, which is considered weak or obsolete.",
                            recommendation="Disable legacy SSL/TLS versions and allow only modern TLS 1.2 or TLS 1.3.",
                        )
                    )

                cert_bytes = tls_socket.getpeercert(binary_form=True)
                if cert_bytes:
                    findings.extend(self._check_certificate_expiry(cert_bytes))
        except Exception as exc:
            findings.append(self._check_failed_finding("tls-check", f"TLS check failed safely: {exc}"))
        return findings

    def _check_certificate_expiry(self, cert_bytes: bytes) -> List[Finding]:
        try:
            from OpenSSL import crypto
        except Exception:
            return []

        try:
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bytes)
            expiry_text = certificate.get_notAfter().decode("ascii")
            expiry_date = datetime.strptime(expiry_text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
            remaining_days = int((expiry_date - datetime.now(timezone.utc)).total_seconds() / 86400)
            if remaining_days <= 30:
                return [
                    Finding(
                        finding_id=self._finding_id("tls", "cert-expiry"),
                        title="TLS certificate is expiring soon" if remaining_days >= 0 else "TLS certificate is expired",
                        category="TLS",
                        owasp_category=self.OWASP_A02,
                        base_severity=2,
                        description=f"The TLS certificate expires in {remaining_days} day(s), which may disrupt trust if it lapses.",
                        recommendation="Renew and replace the certificate before it expires, and monitor certificate rotation.",
                    )
                ]
        except Exception:
            return []
        return []

    def _check_cookies(self, response: Response) -> List[Finding]:
        findings: List[Finding] = []
        cookie_headers = self._get_set_cookie_headers(response)
        for index, cookie_header in enumerate(cookie_headers, start=1):
            lower = cookie_header.lower()
            missing_secure = "secure" not in lower
            missing_httponly = "httponly" not in lower
            missing_samesite = "samesite" not in lower
            if missing_secure or missing_httponly or missing_samesite:
                severity = 3 if missing_secure or missing_httponly else 1
                missing_flags = []
                if missing_secure:
                    missing_flags.append("Secure")
                if missing_httponly:
                    missing_flags.append("HttpOnly")
                if missing_samesite:
                    missing_flags.append("SameSite")
                findings.append(
                    Finding(
                        finding_id=self._finding_id("cookie", str(index)),
                        title=f"Insecure cookie attributes missing: {', '.join(missing_flags)}",
                        category="Cookies",
                        owasp_category=self.OWASP_A02,
                        base_severity=severity,
                        description=f"Set-Cookie value '{cookie_header}' is missing the {', '.join(missing_flags)} attribute(s).",
                        recommendation="Set Secure and HttpOnly on sensitive cookies, and add a SameSite policy such as Lax or Strict.",
                    )
                )
        return findings

    def _check_banners(self, response: Response) -> List[Finding]:
        findings: List[Finding] = []
        for header_name in ("Server", "X-Powered-By", "X-AspNet-Version"):
            if header_name in response.headers:
                findings.append(
                    Finding(
                        finding_id=self._finding_id("banner", header_name),
                        title=f"Technology banner disclosed: {header_name}",
                        category="Banner Disclosure",
                        owasp_category=self.OWASP_A05,
                        base_severity=1,
                        description=f"The response exposes the {header_name} header, which can reveal implementation details to attackers.",
                        recommendation=f"Remove the {header_name} header where possible or configure the application and reverse proxy to suppress it.",
                    )
                )
        return findings

    def _check_misconfigurations(self) -> List[Finding]:
        findings: List[Finding] = []
        for path in ("/uploads/", "/images/", "/assets/", "/backup/", "/.git/"):
            try:
                response = self.session.get(self._build_path_url(path), timeout=self.timeout, verify=False)
                body = response.text[:50000]
                if self._contains_directory_listing(body):
                    severity = 4 if path == "/.git/" else 3
                    findings.append(
                        Finding(
                            finding_id=self._finding_id("misconfig", path),
                            title=f"Exposed directory listing at {path}",
                            category="Misconfiguration",
                            owasp_category=self.OWASP_A05,
                            base_severity=severity,
                            description=f"A GET request to {path} returned content consistent with a directory listing or exposed content browser.",
                            recommendation="Disable directory browsing and ensure sensitive content is not served from browsable web directories.",
                        )
                    )
                    continue
                if path == "/.git/" and response.status_code in {200, 301, 302}:
                    findings.append(
                        Finding(
                            finding_id=self._finding_id("misconfig", "git-exposed"),
                            title="Potentially exposed .git directory",
                            category="Misconfiguration",
                            owasp_category=self.OWASP_A05,
                            base_severity=4,
                            description="The /.git/ path responded positively enough to suggest source control metadata may be exposed.",
                            recommendation="Block access to .git directories at the web server or reverse proxy layer and remove them from the document root.",
                        )
                    )
            except Exception as exc:
                findings.append(self._check_failed_finding(f"misconfig-{path}", f"Misconfiguration check failed for {path}: {exc}"))

        try:
            random_path = f"/vulnsense-missing-{uuid.uuid4().hex}"
            response = self.session.get(self._build_path_url(random_path), timeout=self.timeout, verify=False)
            body = response.text[:50000]
            if self._contains_debug_markers(body):
                findings.append(
                    Finding(
                        finding_id=self._finding_id("misconfig", "debug-markers"),
                        title="Debug or stack-trace markers exposed on missing path",
                        category="Misconfiguration",
                        owasp_category=self.OWASP_A05,
                        base_severity=3,
                        description="A request to a nonexistent path returned content that appears to reveal stack traces or debug information.",
                        recommendation="Disable debug mode and replace verbose error pages with generic production-safe error handling.",
                    )
                )
        except Exception as exc:
            findings.append(self._check_failed_finding("misconfig-debug", f"Debug-marker check failed: {exc}"))

        return findings

    def _check_insecure_form_submission(self, html: str) -> List[Finding]:
        findings: List[Finding] = []
        if urlparse(self.target_url).scheme.lower() != "https":
            return findings

        form_actions = re.findall(r"<form\b[^>]*\baction\s*=\s*['\"]([^'\"]+)['\"][^>]*>", html, flags=re.IGNORECASE)
        for index, action in enumerate(form_actions, start=1):
            action_url = urljoin(self.target_url, action)
            if action_url.lower().startswith("http://"):
                findings.append(
                    Finding(
                        finding_id=self._finding_id("tls", f"insecure-form-action-{index}"),
                        title=f"HTTPS page submits form to insecure HTTP endpoint: {action}",
                        category="TLS",
                        owasp_category=self.OWASP_A02,
                        base_severity=3,
                        description="A form action points to an HTTP URL, which can expose submitted data to interception.",
                        recommendation="Submit forms only to HTTPS endpoints and enforce strict transport protections.",
                    )
                )
        return findings

    def _check_password_autocomplete(self, html: str) -> List[Finding]:
        findings: List[Finding] = []
        password_inputs = re.findall(r"<input\b[^>]*>", html, flags=re.IGNORECASE)
        counter = 0
        for input_tag in password_inputs:
            is_password = re.search(r"\btype\s*=\s*['\"]?password['\"]?", input_tag, flags=re.IGNORECASE)
            if not is_password:
                continue

            counter += 1
            autocomplete_match = re.search(r"\bautocomplete\s*=\s*['\"]([^'\"]+)['\"]", input_tag, flags=re.IGNORECASE)
            autocomplete_value = autocomplete_match.group(1).strip().lower() if autocomplete_match else ""
            if autocomplete_value not in {"off", "new-password"}:
                findings.append(
                    Finding(
                        finding_id=self._finding_id("tls", f"password-autocomplete-{counter}"),
                        title="Password input autocomplete policy is permissive",
                        category="TLS",
                        owasp_category=self.OWASP_A02,
                        base_severity=1,
                        description="A password input does not set autocomplete to off or new-password. This is an informational signal.",
                        recommendation="Set autocomplete='off' or autocomplete='new-password' on password fields where appropriate.",
                    )
                )
        return findings

    def _check_broken_access_control(self, baseline_response: Response) -> List[Finding]:
        """Heuristic reachable-without-auth check only; not full access-control testing.

        This check does not perform authenticated or role-based validation. It only flags
        sensitive paths that appear accessible without authentication.
        """
        findings: List[Finding] = []
        baseline_body = baseline_response.text or ""
        for path in self.SENSITIVE_PATHS:
            try:
                response = self.session.get(self._build_path_url(path), timeout=self.timeout, verify=False)
                if response.status_code != 200:
                    continue

                body = response.text or ""
                body_lower = body.lower()
                if self._is_generic_page(body, baseline_body):
                    continue

                # Common admin login pages are often intentional public entry points.
                if path in {"/admin", "/admin/login", "/wp-admin"} and self._looks_like_login_page(body_lower):
                    continue

                hints = self.SENSITIVE_PATH_HINTS.get(path, ())
                has_sensitive_indicator = any(hint in body_lower for hint in hints)
                if path in self.SENSITIVE_PATH_HINTS and not has_sensitive_indicator:
                    continue

                if path == "/.env" and "=" not in body:
                    continue

                if path == "/config.php" and "<?php" not in body_lower and "db_" not in body_lower:
                    continue

                if path == "/actuator" and "{" not in body and "_links" not in body_lower:
                    continue

                if path == "/server-status" and "server-status" not in body_lower and "scoreboard" not in body_lower:
                    continue

                if path == "/phpinfo.php" and "php" not in body_lower:
                    continue

                findings.append(
                    Finding(
                        finding_id=self._finding_id("access-control", path),
                        title=f"Sensitive path accessible without authentication: {path}",
                        category="Access Control",
                        owasp_category=self.OWASP_A01,
                        base_severity=3,
                        description=(
                            f"The sensitive path {path} returned HTTP 200 without credentials. "
                            "This may indicate weak access control enforcement."
                        ),
                        recommendation="Require authentication and authorization checks before serving sensitive endpoints.",
                    )
                )
            except Exception as exc:
                findings.append(self._check_failed_finding(f"access-control-{path}", f"Access-control heuristic failed for {path}: {exc}"))
        return findings

    def _check_injection_basic(self, response: Response) -> List[Finding]:
        # This check must only be run against systems you own or are explicitly authorized to test.
        findings: List[Finding] = []
        html = response.text or ""
        base_url = self._base_url_without_query()

        query_params = parse_qs(urlparse(self.target_url).query)
        form_params = self._discover_get_form_parameters(html)
        parameter_names = sorted(set(query_params.keys()) | set(form_params))

        if not parameter_names and "<form" not in html.lower() and not query_params:
            return findings
        if not parameter_names:
            parameter_names = ["vulnsense_test"]

        marker_payload = "<vulnsense_test>123</vulnsense_test>"
        sql_probe = "'"
        base_params: Dict[str, str] = {key: values[0] if values else "1" for key, values in query_params.items()}

        for param_name in parameter_names:
            marker_params = dict(base_params)
            marker_params[param_name] = marker_payload
            marker_response = self.session.get(base_url, params=marker_params, timeout=self.timeout, verify=False)
            marker_body = marker_response.text or ""
            if marker_payload in marker_body:
                findings.append(
                    Finding(
                        finding_id=self._finding_id("injection", f"reflected-{param_name}"),
                        title=f"Potential reflected input without escaping on parameter: {param_name}",
                        category="Injection",
                        owasp_category=self.OWASP_A03,
                        base_severity=3,
                        description=(
                            "A harmless marker payload appeared unescaped in the response body, "
                            "which can indicate reflected XSS risk."
                        ),
                        recommendation="Apply context-aware output encoding and input validation for reflected parameters.",
                    )
                )

            sql_params = dict(base_params)
            sql_params[param_name] = f"{sql_params.get(param_name, '1')}{sql_probe}"
            sql_response = self.session.get(base_url, params=sql_params, timeout=self.timeout, verify=False)
            sql_body = (sql_response.text or "").lower()
            if any(marker in sql_body for marker in self.SQL_ERROR_MARKERS):
                findings.append(
                    Finding(
                        finding_id=self._finding_id("injection", f"sql-error-{param_name}"),
                        title=f"Potential SQL error leakage from parameter probe: {param_name}",
                        category="Injection",
                        owasp_category=self.OWASP_A03,
                        base_severity=4,
                        description=(
                            "A single-quote probe triggered database-style error text in the response, "
                            "which can indicate injection handling weaknesses."
                        ),
                        recommendation="Use parameterized queries and return generic error responses without database internals.",
                    )
                )
        return findings

    def _check_insecure_design_heuristics(self, response: Response) -> List[Finding]:
        """Heuristic-only proxy checks for weak design signals, not definitive vulnerabilities."""
        findings: List[Finding] = []
        html = response.text or ""
        html_lower = html.lower()
        has_login_form = "password" in html_lower or "login" in html_lower
        has_captcha_or_rate_limit_signal = any(
            marker in html_lower for marker in ("captcha", "g-recaptcha", "hcaptcha", "turnstile", "rate limit", "too many attempts", "429")
        )
        if has_login_form and not has_captcha_or_rate_limit_signal and urlparse(self.target_url).scheme.lower() != "https":
            findings.append(
                Finding(
                    finding_id=self._finding_id("insecure-design", "login-without-controls"),
                    title="Login form over non-HTTPS with no visible anti-automation indicators",
                    category="Insecure Design",
                    owasp_category=self.OWASP_A04,
                    base_severity=2,
                    description=(
                        "A login-like surface appears present on HTTP with no visible CAPTCHA or rate-limit indicators. "
                        "This is a heuristic weak-design signal."
                    ),
                    recommendation="Use HTTPS everywhere and implement anti-automation controls such as rate limiting and account lockout strategies.",
                )
            )

        try:
            security_txt_response = self.session.get(self._build_path_url("/.well-known/security.txt"), timeout=self.timeout, verify=False)
            if security_txt_response.status_code != 200:
                findings.append(
                    Finding(
                        finding_id=self._finding_id("insecure-design", "missing-security-txt"),
                        title="security.txt not found at /.well-known/security.txt",
                        category="Insecure Design",
                        owasp_category=self.OWASP_A04,
                        base_severity=1,
                        description=(
                            "No security.txt was detected. Lack of a clear vulnerability disclosure process is an informational weak-design signal."
                        ),
                        recommendation="Publish a security.txt file with disclosure contacts and policy at /.well-known/security.txt.",
                    )
                )
        except Exception as exc:
            findings.append(self._check_failed_finding("insecure-design-security-txt", f"security.txt check failed: {exc}"))

        findings.extend(self._check_url_surface_heuristics(html))
        return findings

    def _check_component_and_integrity_heuristics(self, response: Response) -> List[Finding]:
        findings: List[Finding] = []
        html = response.text or ""
        findings.extend(self._check_outdated_component_signals(html))
        findings.extend(self._check_missing_csrf_signals(html))
        findings.extend(self._check_external_asset_integrity(html))
        return findings

    def _discover_get_form_parameters(self, html: str) -> List[str]:
        params: List[str] = []
        form_blocks = re.findall(r"<form\b[^>]*>.*?</form>", html, flags=re.IGNORECASE | re.DOTALL)
        for form_block in form_blocks:
            method_match = re.search(r"\bmethod\s*=\s*['\"]?([a-z]+)['\"]?", form_block, flags=re.IGNORECASE)
            method = method_match.group(1).lower() if method_match else "get"
            if method != "get":
                continue
            input_names = re.findall(r"<input\b[^>]*\bname\s*=\s*['\"]([^'\"]+)['\"]", form_block, flags=re.IGNORECASE)
            params.extend(input_names)
        return params

    def _base_url_without_query(self) -> str:
        parsed = urlparse(self.target_url)
        path = parsed.path or "/"
        return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

    def _check_outdated_component_signals(self, html: str) -> List[Finding]:
        findings: List[Finding] = []
        normalized_html = html.lower()
        component_patterns = [
            (r"jquery[-\.](1\.[0-9.]+|2\.[0-9.]+)", "jQuery 1.x/2.x"),
            (r"bootstrap[-\.](3\.[0-9.]+|4\.[0-3]\.[0-9]+)", "Bootstrap 3.x/4.0-4.3"),
            (r"angular(?:js)?[-\.](1\.[0-9.]+)", "AngularJS 1.x"),
        ]
        for pattern, label in component_patterns:
            match = re.search(pattern, normalized_html, flags=re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        finding_id=self._finding_id("component", label),
                        title=f"Possible outdated component disclosed: {label}",
                        category="Components",
                        owasp_category=self.OWASP_A06,
                        base_severity=2,
                        description=(
                            f"The page references {label} or a similarly versioned asset. "
                            "This is a passive indicator that the application may rely on an older component."
                        ),
                        recommendation="Review referenced third-party libraries and upgrade to supported, patched releases.",
                    )
                )
        return findings

    def _check_missing_csrf_signals(self, html: str) -> List[Finding]:
        findings: List[Finding] = []
        form_blocks = re.findall(r"<form\b[^>]*>.*?</form>", html, flags=re.IGNORECASE | re.DOTALL)
        for index, form_block in enumerate(form_blocks, start=1):
            has_post = bool(re.search(r"\bmethod\s*=\s*['\"]?post['\"]?", form_block, flags=re.IGNORECASE))
            has_auth_inputs = bool(re.search(r"\btype\s*=\s*['\"]?password['\"]?", form_block, flags=re.IGNORECASE)) or bool(
                re.search(r"\bname\s*=\s*['\"]?(username|email|user|login)['\"]?", form_block, flags=re.IGNORECASE)
            )
            has_csrf_token = bool(re.search(r"\b(name|id)\s*=\s*['\"]?(csrf|csrf_token|token|nonce|authenticity_token)['\"]?", form_block, flags=re.IGNORECASE))
            if has_post and has_auth_inputs and not has_csrf_token:
                findings.append(
                    Finding(
                        finding_id=self._finding_id("auth", f"missing-csrf-{index}"),
                        title="POST login-like form lacks an obvious CSRF token",
                        category="Authentication",
                        owasp_category=self.OWASP_A07,
                        base_severity=2,
                        description=(
                            "A login-like POST form was found without an obvious anti-CSRF token. "
                            "This is a heuristic signal only, not proof of a CSRF flaw."
                        ),
                        recommendation="Protect state-changing forms with per-request or session-bound CSRF tokens.",
                    )
                )
        return findings

    def _check_external_asset_integrity(self, html: str) -> List[Finding]:
        findings: List[Finding] = []
        parsed_target = urlparse(self.target_url)
        target_host = parsed_target.netloc.lower()
        missing_integrity_assets: List[str] = []

        for tag_match in re.finditer(r"<(script|link)\b[^>]*>", html, flags=re.IGNORECASE):
            tag = tag_match.group(0)
            tag_name = (tag_match.group(1) or "").lower()
            source_attr = self._extract_attribute(tag, "src") or self._extract_attribute(tag, "href")
            integrity_attr = self._extract_attribute(tag, "integrity")
            if not source_attr:
                continue

            resolved = urljoin(self.target_url, source_attr)
            resolved_parsed = urlparse(resolved)
            resolved_host = resolved_parsed.netloc.lower()

            is_external = bool(resolved_host and resolved_host != target_host)
            if not is_external:
                continue

            # Ignore non-asset links (language pages, navigation paths, etc.) to reduce noise.
            is_asset_like = bool(
                re.search(r"\.(js|mjs|css)(\?|$)", resolved_parsed.path.lower())
                or any(marker in resolved_parsed.path.lower() for marker in ("/assets/", "/static/", "/dist/", "/bundle"))
            )
            if tag_name == "link":
                rel_value = (self._extract_attribute(tag, "rel") or "").lower()
                is_asset_like = is_asset_like and any(keyword in rel_value for keyword in ("stylesheet", "preload", "modulepreload"))

            if not is_asset_like:
                continue

            if not integrity_attr:
                missing_integrity_assets.append(resolved)

        if missing_integrity_assets:
            sample_assets = sorted(set(missing_integrity_assets))[:5]
            findings.append(
                Finding(
                    finding_id=self._finding_id("integrity", "external-assets-missing-sri"),
                    title=f"External asset references missing integrity metadata ({len(set(missing_integrity_assets))})",
                    category="Integrity",
                    owasp_category=self.OWASP_A08,
                    base_severity=2,
                    description=(
                        "One or more external JS/CSS assets appear to be loaded without Subresource Integrity (SRI). "
                        f"Sample assets: {', '.join(sample_assets)}"
                    ),
                    recommendation="Add SRI for externally hosted static assets or host trusted immutable copies locally.",
                )
            )
        return findings

    def _check_logging_heuristics(self, response: Response) -> List[Finding]:
        findings: List[Finding] = []
        status = response.status_code
        body_lower = (response.text or "").lower()

        if status >= 500 and not any(marker in body_lower for marker in ("request id", "correlation id", "incident", "support reference", "trace id")):
            findings.append(
                Finding(
                    finding_id=self._finding_id("logging", "500-without-correlation"),
                    title="Server error response lacks obvious correlation or request-tracking cues",
                    category="Monitoring",
                    owasp_category=self.OWASP_A09,
                    base_severity=1,
                    description=(
                        "A server error response was observed without visible correlation or request-tracking cues. "
                        "This is a weak passive signal that operational monitoring may be limited."
                    ),
                    recommendation="Add structured logging, request IDs, and alerting for server-side failures.",
                )
            )

        if any(marker in body_lower for marker in ("traceback", "exception", "stack trace", "fatal error")) and not any(
            marker in body_lower for marker in ("request id", "correlation id", "trace id")
        ):
            findings.append(
                Finding(
                    finding_id=self._finding_id("logging", "verbose-error-without-id"),
                    title="Verbose error output lacks obvious correlation IDs",
                    category="Monitoring",
                    owasp_category=self.OWASP_A09,
                    base_severity=1,
                    description="Verbose error content is visible but no obvious correlation identifier is present for follow-up.",
                    recommendation="Replace verbose error pages with user-safe messages and log full details server-side with correlation IDs.",
                )
            )

        return findings

    def _check_url_surface_heuristics(self, html: str) -> List[Finding]:
        findings: List[Finding] = []
        url_like_names = re.findall(r"\bname\s*=\s*['\"]([^'\"]*(?:url|uri|redirect|return|next|dest|callback)[^'\"]*)['\"]", html, flags=re.IGNORECASE)
        if url_like_names:
            findings.append(
                Finding(
                    finding_id=self._finding_id("ssrf", url_like_names[0]),
                    title="Potential server-side URL handling surface discovered",
                    category="Server-Side Fetch Surface",
                    owasp_category=self.OWASP_A10,
                    base_severity=1,
                    description=(
                        "The page exposes inputs or parameter names that suggest URL, redirect, or callback handling. "
                        "This is only a passive heuristic and does not prove SSRF or open-redirect behavior."
                    ),
                    recommendation="Review URL-consuming parameters for allowlists, destination validation, and strict redirect handling.",
                )
            )
        return findings

    def _extract_attribute(self, tag: str, attribute_name: str) -> str:
        match = re.search(rf"\b{attribute_name}\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.IGNORECASE)
        return match.group(1) if match else ""

    def _looks_like_login_page(self, body_lower: str) -> bool:
        return any(marker in body_lower for marker in ("login", "sign in", "password", "username", "wp-login"))

    def _is_generic_page(self, candidate_body: str, baseline_body: str) -> bool:
        if not candidate_body or not baseline_body:
            return False
        candidate = self._normalize_text_for_similarity(candidate_body)
        baseline = self._normalize_text_for_similarity(baseline_body)
        if not candidate or not baseline:
            return False
        similarity = SequenceMatcher(None, candidate, baseline).ratio()
        if similarity >= 0.92:
            return True

        generic_markers = ("not found", "404", "page you requested", "go to homepage", "resource not found")
        return any(marker in candidate for marker in generic_markers) and similarity >= 0.75

    def _normalize_text_for_similarity(self, text: str) -> str:
        stripped = re.sub(r"<script\b[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL)
        stripped = re.sub(r"<style\b[^>]*>.*?</style>", "", stripped, flags=re.IGNORECASE | re.DOTALL)
        stripped = re.sub(r"\s+", " ", stripped)
        return stripped.strip().lower()[:2000]

    def _contains_directory_listing(self, body: str) -> bool:
        return any(marker.lower() in body.lower() for marker in self.DIRECTORY_MARKERS)

    def _contains_debug_markers(self, body: str) -> bool:
        return any(marker.lower() in body.lower() for marker in self.DEBUG_MARKERS)

    def _get_set_cookie_headers(self, response: Response) -> List[str]:
        raw_headers = getattr(response.raw, "headers", None)
        if raw_headers is not None:
            try:
                values = raw_headers.get_all("Set-Cookie")
                if values:
                    return list(values)
            except Exception:
                pass
            try:
                values = raw_headers.getlist("Set-Cookie")
                if values:
                    return list(values)
            except Exception:
                pass
        header_value = response.headers.get("Set-Cookie")
        return [header_value] if header_value else []

    def _finding_id(self, prefix: str, suffix: str) -> str:
        normalized_suffix = re.sub(r"[^a-z0-9]+", "-", suffix.lower()).strip("-") or "item"
        return f"{prefix}-{normalized_suffix}"

    def _build_path_url(self, path: str) -> str:
        parsed = urlparse(self.target_url)
        normalized_path = path if path.startswith("/") else f"/{path}"
        return urlunparse((parsed.scheme, parsed.netloc, normalized_path, "", "", ""))

    def _check_failed_finding(self, source: str, message: str) -> Finding:
        return Finding(
            finding_id=self._finding_id("check-failed", source),
            title=f"Check failed: {source}",
            category="Scan Reliability",
            owasp_category="N/A - Scan Reliability",
            base_severity=1,
            description=message,
            recommendation="Review the target URL, network access, and scanner permissions before running the assessment again.",
        )
