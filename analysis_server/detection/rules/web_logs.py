from __future__ import annotations
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _url(event: NormalizedEvent) -> str:
    """
        Returns the most complete URL available in the event, normalized to lowercase.
        Prefers the original URL if available, otherwise falls back to the path.
    """
    if event.url:
        original = event.url.original or ""
        path = event.url.path or ""
        result = original if (original and original != "-") else path
        return result.lower()
    return ""

def _status(event: NormalizedEvent) -> Optional[int]:
    """Returns the HTTP response status code if available, otherwise None."""
    if event.http:
        return event.http.response_status_code
    return None

def _ip(event: NormalizedEvent) -> Optional[str]:
    """Returns the source IP address of the event, or None if not available."""
    if event.source:
        return event.source.address
    return None

def _ts(event: NormalizedEvent) -> Optional[datetime]:
    """Returns the timestamp of the event, or None if not available."""
    return event.event.created if event.event else None

def _ua(event: NormalizedEvent) -> str:
    """Returns the user agent string, normalized to lowercase.""" 
    if event.http:
        return (event.http.user_agent or "").lower()
    return ""


# ─────────────────────────────────────────────
# PER-EVENT RULES
# ─────────────────────────────────────────────


_SQLI_PATTERNS = re.compile(
    r"(union\s+select|select\s+.+from|insert\s+into|drop\s+table"
    r"|or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'|--\s|;--"
    r"|xp_cmdshell|information_schema|sleep\s*\(|benchmark\s*\()",
    re.IGNORECASE,
)

class SqlInjectionRule(PerEventRule):
    """Detects common SQL injection patterns in URLs."""

    rule_id = "WEB_SQLI_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _SQLI_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="SQL Injection Attempt",
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["sqli", "web", "injection"],
            source="web_logs",
            description=f"SQL injection pattern detected in URL from {_ip(event)}",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            }
        )
    

_LFI_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|/etc/passwd"
    r"|/etc/shadow|/proc/self|boot\.ini|win\.ini"
    r"|file://|php://|zip://|data://)",
    re.IGNORECASE,
)


class PathTraversalRule(PerEventRule):
    """Detects path traversal and local file inclusion attempts."""

    rule_id = "WEB_LFI_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _LFI_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Path Traversal / LFI Attempt",
            severity=Severity.HIGH,
            confidence=0.90,
            technique_id="T1055",
            technique_name="Path Traversal",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["lfi", "traversal", "web"],
            source="web_logs",
            description=f"Path traversal detected in URL from {_ip(event)}",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            }
        )


_CMDI_PATTERNS = re.compile(
    r"(;|\||&&|\$\(|`)\s*(ls|cat|id|whoami|uname|wget|curl"
    r"|nc\s|ncat\s|bash|sh\s|python|perl|php)",
    re.IGNORECASE,
)


class CommandInjectionRule(PerEventRule):
    """Detects command injection patterns in URLs."""
    rule_id = "WEB_CMDI_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _CMDI_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Command Injection Attempt",
            severity=Severity.CRITICAL,
            confidence=0.88,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["cmdi", "web", "rce"],
            source="web_logs",
            description=f"Command injection pattern detected from {_ip(event)}",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            }
        )

_XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\("
    r"|document\.cookie|<iframe|<img[^>]+src\s*=)",
    re.IGNORECASE,
)

class XssAttemptRule(PerEventRule):
    """Detects common XSS patterns in URLs."""
    rule_id = "WEB_XSS_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _XSS_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="XSS Attempt",
            severity=Severity.MEDIUM,
            confidence=0.80,
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["xss", "web"],
            source="web_logs",
            description=f"XSS pattern detected in URL from {_ip(event)}",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            }
        )

_WEBSHELL_UPLOAD_PATTERNS = re.compile(
    r"(shell|backdoor|cmd|exec|payload|inject|exploit)",
    re.IGNORECASE
)

_WEBSHELL_EXTENSION_PATTERNS = re.compile(
    r"\.(php|php5|php7|phtml|phar|asp|aspx|jsp|jspx)(\?|&|$)",
    re.IGNORECASE
)

class WebshellUploadRule(PerEventRule):
    """Detects potential webshell uploads based on URL patterns and HTTP method."""
    rule_id = "WEB_WEBSHELL_UPLOAD_001"
    _UPLOAD_PATHS = re.compile(
        r"/(upload|uploads|files|media|images|img|static|assets|tmp|temp)/",
        re.IGNORECASE
    )

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        url = _url(event)
        method = (event.http.request_method or "").upper() if event.http else ""

        if method != "POST" or not url:
            return None

        has_dangerous_ext = bool(_WEBSHELL_EXTENSION_PATTERNS.search(url))
        has_suspicious_name = bool(_WEBSHELL_UPLOAD_PATTERNS.search(url))
        in_upload_dir = bool(self._UPLOAD_PATHS.search(url))

        if has_dangerous_ext and in_upload_dir:
            confidence = 0.95
        elif has_suspicious_name and has_dangerous_ext:
            confidence = 0.90
        elif has_suspicious_name and in_upload_dir:
            confidence = 0.80 
        else:
            return None  

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Webshell Upload Attempt",
            severity=Severity.CRITICAL,
            confidence=confidence,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["webshell", "upload", "web"],
            source="web_logs",
            description=f"Possible upload of webshell from {_ip(event)}: {url}",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
                "confidence_reason": (
                    "php_in_upload_dir" if has_dangerous_ext and in_upload_dir
                    else "suspicious_name_with_ext" if has_suspicious_name and has_dangerous_ext
                    else "suspicious_name_in_upload_dir"
                )
            }
        )



_WEBSHELL_EXEC_PATTERNS = re.compile(
    r"(cmd|exec|command|shell|run|system|passthru|eval)\s*=\s*"
    r".*(whoami|net[\+%20]+user|ipconfig|systeminfo|dir[\+%20]|ls[\+%20]"
    r"|cat[\+%20]|id|uname|hostname|tasklist|netstat|wget|curl|powershell)",
    re.IGNORECASE
)

class WebshellExecutionRule(PerEventRule):
    """Detects potential webshell command execution based on URL patterns."""
    rule_id = "WEB_WEBSHELL_EXEC_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _WEBSHELL_EXEC_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Webshell Command Execution",
            severity=Severity.CRITICAL,
            confidence=0.95,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["webshell", "rce", "execution", "web"],
            source="web_logs",
            description=f"Execution of command via webshell from {_ip(event)}: {url}",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            }
        )



_MALICIOUS_UPLOAD_PATTERNS = re.compile(
    r"\.(exe|dll|bat|ps1|vbs|vbe|msi|bin|elf|sh|py|rb|pl)(\?|&|$|%)",
    re.IGNORECASE
)

class MaliciousFileUploadRule(PerEventRule):
    """Detects uploads of potentially malicious files based on URL patterns and HTTP method."""
    rule_id = "WEB_MALICIOUS_UPLOAD_001"

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        url = _url(event)
        method = (event.http.request_method or "").upper() if event.http else ""

        if method != "POST" or not url:
            return None
        if not _MALICIOUS_UPLOAD_PATTERNS.search(url):
            return None

        high_risk_ext = re.search(r"\.(exe|dll|bat|ps1|vbs|msi)(\?|&|$|%)", url, re.IGNORECASE)
        severity = Severity.CRITICAL if high_risk_ext else Severity.HIGH
        confidence = 0.92 if high_risk_ext else 0.80

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Malicious Executable Upload",
            severity=severity,
            confidence=confidence,
            technique_id="T1608.001",
            technique_name="Upload Malware",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.DELIVERY,
            tags=["upload", "malware", "executable", "web"],
            source="web_logs",
            description=f"Upload of malicious executable from {_ip(event)}: {url}",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
                "high_risk": bool(high_risk_ext),
            }
        )

class UploadedFileAccessRule(PerEventRule):
    """Detects access to uploaded files with potential execution parameters."""
    rule_id = "WEB_UPLOAD_ACCESS_001"
    
    _UPLOAD_ACCESS = re.compile(
        r"/(upload|uploads|files|media|hackable)/.+\.(jpg|jpeg|png|gif|pdf)",
        re.IGNORECASE
    )

    def match(self, event: NormalizedEvent, index: int) -> Optional[DetectionFinding]:
        url = _url(event)
        method = (event.http.request_method or "").upper() if event.http else ""
        
        if method != "GET" or not url:
            return None
        if not self._UPLOAD_ACCESS.search(url):
            return None
        
        if not re.search(r"\?(cmd|exec|system|page)=", url, re.IGNORECASE):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Uploaded File Execution Attempt",
            severity=Severity.CRITICAL,
            confidence=0.92,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["webshell", "upload", "execution"],
            source="web_logs",
            description=f"Access to uploaded file with execution parameters from {_ip(event)}: {url}",
            timestamp=_ts(event) or datetime.now(timezone.utc),
            triggered_by=[index],
            extra={"source_ip": _ip(event), "url": url}
        )

# ────────────────────────────────────────────
# AGGREGATE RULES
# ───────────────────────────────────────────


MAX_INDICES = 20 # Limit the number of the triggering events we store in the finding to avoid huge payloads

class BruteForceRule(AggregateRule):
    """Detects potential brute force attacks based on multiple failed auth attempts from the same IP to the same URL."""
    rule_id = "WEB_BRUTE_FORCE_001"
    THRESHOLD = 10

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
        by_ip_url: dict[tuple, list[tuple[int, NormalizedEvent]]] = defaultdict(list)

        for i, e in enumerate(events):
            if not _ip(e):
                continue

            method = (e.http.request_method or "").upper() if e.http else ""
            status = _status(e)

            if status in (401, 403) or (method == "POST" and status == 302):
                key = (_ip(e), _url(e))
                by_ip_url[key].append((i, e))

        for (ip, url), hits in by_ip_url.items():
            if len(hits) < self.THRESHOLD:
                continue

            auth_keywords = ("login", "signin", "auth", "password", "brute")
            confidence = 0.95 if any(k in url for k in auth_keywords) else 0.80

            indices = [i for i, _ in hits]
            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Web Brute Force",
                severity=Severity.HIGH,
                confidence=confidence,
                technique_id="T1110",
                technique_name="Brute Force",
                tactic=MitreTactic.CREDENTIAL_ACCESS,
                kill_chain_phase=KillChainPhase.EXPLOITATION,
                tags=["bruteforce", "web", "auth"],
                source="web_logs",
                description=f"{len(hits)} repeated requests to '{url}' from {ip}",
                timestamp=_ts(hits[0][1]) or datetime.now(timezone.utc),
                triggered_by=indices[:MAX_INDICES],
                event_count=len(hits),
                extra={"source_ip": ip, "target_url": url}
            ))

        return findings

class ReconScannerRule(AggregateRule):
    """IP which generates many 404 requests = directory scanning."""
    rule_id = "WEB_RECON_SCAN_001"
    THRESHOLD = 20

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
        by_ip: dict[str, list[tuple[int, NormalizedEvent]]] = defaultdict(list)

        for i, e in enumerate(events):
            if _status(e) == 404 and _ip(e):
                by_ip[_ip(e)].append((i, e))

        for ip, hits in by_ip.items():
            if len(hits) < self.THRESHOLD:
                continue

            indices = [i for i, _ in hits]
            first_ts = _ts(hits[0][1])
            urls = [_url(e) for _, e in hits[:5]] 

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Web Directory Scanning",
                severity=Severity.MEDIUM,
                confidence=0.85,
                technique_id="T1595.003",
                technique_name="Wordlist Scanning",
                tactic=MitreTactic.INITIAL_ACCESS,
                kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                tags=["recon", "scanning", "web"],
                source="web_logs",
                description=f"{len(hits)} 404 requests from {ip} — possible directory scan",
                timestamp=first_ts or datetime.now(timezone.utc),
                triggered_by=indices[:MAX_INDICES],
                event_count=len(hits),
                extra={
                    "source_ip": ip,
                    "sample_urls": urls,
                }
            ))

        return findings


_SCANNER_UA_PATTERNS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz"
    r"|burpsuite|hydra|medusa|nessus|openvas|nuclei|zgrab"
    r"|python-requests|python-urllib|curl|wget|go-http-client)",
    re.IGNORECASE,
)

class ScannerUserAgentRule(AggregateRule):
    """Detects potential reconnaissance tools based on user agent strings."""
    rule_id = "WEB_SCANNER_UA_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        
        findings = []
        by_tool: dict[str, list[tuple[int, NormalizedEvent]]] = defaultdict(list)

        for i, e in enumerate(events):
            ua = _ua(e)
            if not ua:
                continue

            match = _SCANNER_UA_PATTERNS.search(ua)
            if match:
                tool = match.group(1).lower()  # "gobuster", "nikto" etc.
                by_tool[tool].append((i, e))

        for tool, hits in by_tool.items():
            indices = [i for i, _ in hits]
            first_ts = _ts(hits[0][1])
            source_ips = list({_ip(e) for _, e in hits if _ip(e)})

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Known Scanner Detected",
                severity=Severity.MEDIUM,
                confidence=0.95,
                technique_id="T1595",
                technique_name="Active Scanning",
                tactic=MitreTactic.INITIAL_ACCESS,
                kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                tags=["scanner", "recon", "web"],
                source="web_logs",
                description=f"Scanning tool '{tool}' detected — {len(hits)} requests from {len(source_ips)} IPs",
                timestamp=first_ts or datetime.now(timezone.utc),
                triggered_by=indices[:MAX_INDICES],
                event_count=len(hits),
                extra={
                    "tool": tool,
                    "source_ips": source_ips,
                }
            ))

        return findings
# ────────────────────────────────────────────
# Factory 
# ───────────────────────────────────────────
def get_web_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        SqlInjectionRule(),
        PathTraversalRule(),
        CommandInjectionRule(),
        XssAttemptRule(),
        WebshellUploadRule(),
        WebshellExecutionRule(),
        MaliciousFileUploadRule(),
        UploadedFileAccessRule()
    ]
    aggregate = [
        BruteForceRule(),
        ReconScannerRule(),
        ScannerUserAgentRule(),
    ]
    return per_event, aggregate