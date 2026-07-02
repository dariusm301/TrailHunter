from __future__ import annotations
from importlib.resources import path
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional

from models.events import NormalizedEvent
from detection.engine import PerEventRule, AggregateRule
from detection.models import (
    Capability, DetectionFinding, Severity,
    MitreTactic, KillChainPhase,
)
from urllib.parse import parse_qs
from ..helpers import _url, _status, _ip, _ts, _ua, _file_name, _cmd_from_url, _method, _body



_SQLI_PATTERNS = re.compile(
    r"(union\s+select|select\s+.+from|insert\s+into|drop\s+table"
    r"|or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'|--\s|;--"
    r"|xp_cmdshell|information_schema|sleep\s*\(|benchmark\s*\()",
    re.IGNORECASE,
)



_CMDI_PATTERNS = re.compile(
    r"(;|\||&&|\$\(|`)\s*(ls|cat|id|whoami|uname|wget|curl"
    r"|nc\s|ncat\s|bash|sh\s|python|perl|php)",
    re.IGNORECASE,
)

_LFI_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|/etc/passwd"
    r"|/etc/shadow|/proc/self|boot\.ini|win\.ini"
    r"|file://|php://|zip://|data://)",
    re.IGNORECASE,
)

_XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\("
    r"|document\.cookie|<iframe|<img[^>]+src\s*=)",
    re.IGNORECASE,
)


_WEBSHELL_UPLOAD_PATTERNS = re.compile(
    r"(shell|backdoor|cmd|exec|payload|inject|exploit)",
    re.IGNORECASE
)

_WEBSHELL_EXTENSION_PATTERNS = re.compile(
    r"\.(php|php5|php7|phtml|phar|asp|aspx|jsp|jspx)(\?|&|$)",
    re.IGNORECASE
)

_WEBSHELL_EXEC_PATTERNS = re.compile(
    r"(cmd|exec|command|shell|run|system|passthru|eval)\s*=\s*"
    r".*(whoami|net[\+%20]+(user|localgroup)|ipconfig|systeminfo"
    r"|dir[\+%20]|ls[\+%20]|cat[\+%20]|id|uname|hostname"
    r"|tasklist|netstat|wget|curl|powershell)",
    re.IGNORECASE
)


_MALICIOUS_UPLOAD_PATTERNS = re.compile(
    r"\.(exe|dll|bat|ps1|vbs|vbe|msi|bin|elf|sh|py|rb|pl)(\?|&|$|%)",
    re.IGNORECASE
)

_SCANNER_UA_PATTERNS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz"
    r"|burpsuite|hydra|medusa|nessus|openvas|nuclei|zgrab"
    r"|python-requests|python-urllib|curl|wget|go-http-client)",
    re.IGNORECASE,
)


_UPLOAD_ACCESS = re.compile(
    r"/(upload|uploads|files|media|hackable)/.+\.(jpg|jpeg|png|gif|pdf)",
    re.IGNORECASE
)


_UPLOAD_PATHS = re.compile(
    r"/(upload|uploads|files|media|images|img|static|assets|tmp|temp)/",
    re.IGNORECASE
)



class SqlInjectionRule(PerEventRule):

    rule_id = "WEB_SQLI_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _SQLI_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="SQL Injection Attempt",
            rule_type="per_event",
            requires=[],
            provides=[],
            severity=Severity.HIGH,
            confidence=0.85,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["sqli", "web", "injection"],
            source="web_logs",
            description=f"SQL injection pattern detected in URL from {_ip(event)}",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            }
        )
    

class PathTraversalRule(PerEventRule):

    rule_id = "WEB_LFI_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _LFI_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Path Traversal / LFI Attempt",
            rule_type="per_event",
            requires=[],
            provides=[],
            severity=Severity.HIGH,
            confidence=0.90,
            technique_id="T1055",
            technique_name="Path Traversal",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.DELIVERY,
            tags=["lfi", "traversal", "web"],
            source="web_logs",
            description=f"Path traversal detected in URL from {_ip(event)}",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            },
            entities={
                "source_ip": _ip(event),
                "file_name": _file_name(event),
            }
        )


class CommandInjectionRule(PerEventRule):
    rule_id = "WEB_CMDI_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _CMDI_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Command Injection Attempt",
            rule_type="per_event",
            requires=[],
            provides=[],
            severity=Severity.CRITICAL,
            confidence=0.88,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["cmdi", "web", "rce"],
            source="web_logs",
            description=f"Command injection pattern detected from {_ip(event)}",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            },
            entities={
                "source_ip": _ip(event),
                "file_name": _file_name(event),
            }
        )


class XssAttemptRule(PerEventRule):
    rule_id = "WEB_XSS_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _XSS_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="XSS Attempt",
            rule_type="per_event",
            requires=[],
            provides=[],
            severity=Severity.MEDIUM,
            confidence=0.80,
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["xss", "web"],
            source="web_logs",
            description=f"XSS pattern detected in URL from {_ip(event)}",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            },
            entities={
                "source_ip": _ip(event),
                "file_name": _file_name(event)
            }
        )


class WebshellUploadRule(PerEventRule):
    rule_id = "WEB_WEBSHELL_UPLOAD_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        url = _url(event)
        method = (event.http.request_method or "").upper() if event.http else ""

        if method != "POST" or not url:
            return None

        has_dangerous_ext = bool(_WEBSHELL_EXTENSION_PATTERNS.search(url))
        has_suspicious_name = bool(_WEBSHELL_UPLOAD_PATTERNS.search(url))
        in_upload_dir = bool(_UPLOAD_PATHS.search(url))

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
            rule_type="per_event",
            requires=[],
            provides=[Capability("webshell_dropped", bind=("source_ip", "file_name"), values=(_ip(event), _file_name(event)))],
            severity=Severity.CRITICAL,
            confidence=confidence,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.PERSISTENCE,
            kill_chain_phase=KillChainPhase.INSTALLATION,
            tags=["webshell", "upload", "web"],
            source="web_logs",
            description=f"Possible upload of webshell from {_ip(event)}: {url}",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
                "confidence_reason": (
                    "php_in_upload_dir" if has_dangerous_ext and in_upload_dir
                    else "suspicious_name_with_ext" if has_suspicious_name and has_dangerous_ext
                    else "suspicious_name_in_upload_dir"
                )
            },
            entities={
                "source_ip": _ip(event),
                "file_name": _file_name(event)
            }
        )


class WebshellExecutionRule(PerEventRule):
    rule_id = "WEB_WEBSHELL_EXEC_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        url = _url(event)
        if not url or not _WEBSHELL_EXEC_PATTERNS.search(url):
            return None

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Webshell Command Execution",
            rule_type="per_event",
            requires=[Capability("webshell_dropped", bind=("file_name",), values=(_file_name(event),))],
            provides=[Capability("web_command", bind=("command_line",), values=(_cmd_from_url(url),)) if _cmd_from_url(url) else []],
            fusion_key=[("webshell_command", _cmd_from_url(url))] if _cmd_from_url(url) else [],
            severity=Severity.CRITICAL,
            confidence=0.95,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["webshell", "rce", "execution", "web"],
            source="web_logs",
            description=f"Execution of command via webshell from {_ip(event)}: {url}",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
            },
            entities={
                "source_ip": _ip(event),
                "file_name": _file_name(event),
                "command": _cmd_from_url(url),
            }
        )

class MaliciousFileUploadRule(PerEventRule):
    rule_id = "WEB_MALICIOUS_UPLOAD_001"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
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
            rule_type="per_event",
            requires=[],
            provides=[],
            severity=severity,
            confidence=confidence,
            technique_id="T1608.001",
            technique_name="Upload Malware",
            tactic=MitreTactic.INITIAL_ACCESS,
            kill_chain_phase=KillChainPhase.DELIVERY,
            tags=["upload", "malware", "executable", "web"],
            source="web_logs",
            description=f"Upload of malicious executable from {_ip(event)}: {url}",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
                "high_risk": bool(high_risk_ext),
            },
            entities={
                "source_ip": _ip(event),
                "file_name": _file_name(event),
            }
        )
_SHELL_METACHARS = re.compile(r'[|;&`$]|\$\(|%0a|\n')

_SUSPICIOUS_CMD_TOKENS = re.compile(
    r'\b('
    r'net\s+(user|localgroup|group)|'
    r'whoami|systeminfo|ipconfig|ifconfig|hostname|'
    r'powershell(\.exe)?|cmd(\.exe)?(\s+/c)?|'
    r'wget|curl|certutil|bitsadmin|'
    r'nc(\.exe)?\s|netcat|ncat|'
    r'cat\s+/etc/passwd|/bin/(ba)?sh|/bin/dash|'
    r'ping\s+-[nc]\s|'
    r'reg\s+(add|query|delete)|schtasks|'
    r'wmic|rundll32|mshta|'
    r'tasklist|taskkill|'
    r'echo\s.*>\s|type\s+nul|'
    r'base64\s+-d|certutil\s+-decode'
    r')\b',
    re.IGNORECASE
)


def _suspicious_cmd_from_body(event: NormalizedEvent) -> Optional[str]:
    """Scanează toate valorile din body-ul POST, indiferent de numele
    parametrului, după pattern-uri de command injection / LotL."""
    raw = _body(event)
    if not raw:
        return None
    try:
        parsed = parse_qs(raw, keep_blank_values=False)
    except Exception:
        return None

    for values in parsed.values():
        for v in values:
            v = v.strip()
            if not v:
                continue
            if _SUSPICIOUS_CMD_TOKENS.search(v) and _SHELL_METACHARS.search(v):
                return v
    return None


class WebshellPostBodyExecutionRule(PerEventRule):
    rule_id = "WEB_WEBSHELL_EXEC_002"

    def match(self, event: NormalizedEvent) -> Optional[DetectionFinding]:
        if _method(event) != "POST":
            return None
        url = _url(event)
        if not url:
            return None

        cmd = _suspicious_cmd_from_body(event)
        if not cmd:
            return None

        file_name = _file_name(event)

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name="Suspicious Command in POST Body",
            rule_type="per_event",
            requires=[],
            provides=[Capability("web_command", bind=("command_line",), values=(cmd,))],
            fusion_key=[("webshell_command", cmd)],
            severity=Severity.CRITICAL,
            confidence=0.85,
            technique_id="T1505.003",
            technique_name="Web Shell",
            tactic=MitreTactic.EXECUTION,
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            tags=["webshell", "rce", "execution", "web", "post_body"],
            source="web_logs",
            description=f"Suspicious command detected in POST body from {_ip(event)} to {url}: {cmd}",
            timestamp=_ts(event) or None,
            triggered_by=[event.id],
            extra={
                "source_ip": _ip(event),
                "url": url,
                "status_code": _status(event),
                "raw_body": _body(event),
            },
            entities={
                "source_ip": _ip(event),
                "file_name": file_name,
                "command": cmd,
            }
        )

# ────────────────────────────────────────────
# AGGREGATE RULES
# ───────────────────────────────────────────

class BruteForceRule(AggregateRule):
    rule_id = "WEB_BRUTE_FORCE_001"
    THRESHOLD = 10

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
        by_ip_url: dict[tuple, list[tuple[int, NormalizedEvent]]] = defaultdict(list)
        for i, e in enumerate(events):
            if not _ip(e):
                continue

            method = (e.http.request_method or "") if e.http else ""
            status = _status(e)
            if status in (401, 403) or (method == "post" and status == 302):
                key = (_ip(e), _url(e))
                by_ip_url[key].append((i, e))

        for (ip, url), hits in by_ip_url.items():
            if len(hits) < self.THRESHOLD:
                continue

            auth_keywords = ("login", "signin", "auth", "password", "brute")
            confidence = 0.95 if any(k in url for k in auth_keywords) else 0.80

            ids = [e.id for _, e in hits]
            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Web Brute Force",
                rule_type="aggregate",
                requires=[],
                provides=[Capability("credential_candidate", bind=("source_ip",), values=(_ip(hits[0][1]),))],
                severity=Severity.MEDIUM,
                confidence=confidence,
                technique_id="T1110",
                technique_name="Brute Force",
                tactic=MitreTactic.CREDENTIAL_ACCESS,
                kill_chain_phase=KillChainPhase.DELIVERY,
                tags=["bruteforce", "web", "auth"],
                source="web_logs",
                description=f"{len(hits)} repeated requests to '{url}' from {ip}",
                timestamp=_ts(hits[0][1]) or None,
                triggered_by=ids,
                event_count=len(hits),
                extra={"source_ip": ip, "target_url": url},
                entities={
                    "source_ip": ip,
                }
            ))

        return findings

class ReconScannerRule(AggregateRule):
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

            ids = [e.id for _, e in hits]
            first_ts = _ts(hits[0][1])
            urls = [_url(e) for _, e in hits[:5]] 

            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Web Directory Scanning",
                rule_type="aggregate",
                requires=[],
                provides=[],
                severity=Severity.MEDIUM,
                confidence=0.85,
                technique_id="T1595.003",
                technique_name="Wordlist Scanning",
                tactic=MitreTactic.INITIAL_ACCESS,
                kill_chain_phase= KillChainPhase.RECONNAISSANCE,
                tags=["recon", "scanning", "web"],
                source="web_logs",
                description=f"{len(hits)} 404 requests from {ip} — possible directory scan",
                timestamp= first_ts or None ,
                triggered_by=ids,
                event_count=len(hits),
                extra={
                    "source_ip": ip,
                    "sample_urls": urls,
                },
                entities={
                    "source_ip": ip,
                }
            ))

        return findings



class ScannerUserAgentRule(AggregateRule):
    rule_id = "WEB_SCANNER_UA_001"

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        findings = []
        by_tool_ip: dict[tuple[str, str], list[tuple[int, NormalizedEvent]]] = defaultdict(list)
        
        for i, e in enumerate(events):
            ua = _ua(e)
            if not ua:
                continue
            match = _SCANNER_UA_PATTERNS.search(ua)
            if match:
                tool = match.group(1).lower()
                ip = _ip(e) or "unknown"
                by_tool_ip[(tool, ip)].append((i, e))
        
        for (tool, ip), hits in by_tool_ip.items():
            ids = [e.id for _, e in hits]
            first_ts = _ts(hits[0][1])
            findings.append(DetectionFinding(
                rule_id=self.rule_id,
                rule_name="Known Scanner Detected",
                rule_type="aggregate",
                requires=[],
                provides=[],
                severity=Severity.MEDIUM,
                confidence=0.95,
                technique_id="T1595",
                technique_name="Active Scanning",
                tactic=MitreTactic.INITIAL_ACCESS,
                kill_chain_phase=KillChainPhase.RECONNAISSANCE,
                tags=["scanner", "recon", "web"],
                source="web_logs",
                description=f"Scanning tool '{tool}' detected — {len(hits)} requests from {ip}",
                timestamp=first_ts or None,
                triggered_by=ids,
                event_count=len(hits),
                extra={
                    "tool": tool,
                    "source_ip": [ip],
                },
            ))
        return findings
        

class SuccessfulLoginAfterBruteForce(AggregateRule):
    rule_id = "WEB_LOGIN_SUCCESS_AFTER_BF_001"
    FAILED_THRESHOLD = 3

    def match(self, events: list[NormalizedEvent]) -> list[DetectionFinding]:
        sorted_events = sorted(
            [e for e in events if e.url and e.http],
            key=lambda e: _ts(e)
        )

        failed:  dict[str, list[tuple[str, datetime]]] = defaultdict(list)
        already_detected: set[str] = set()
        findings = []

        for idx, e in enumerate(sorted_events):
            ip     = e.source.ip if e.source else None
            path   = e.url.path if e.url else ""
            method = e.http.request_method if e.http else ""
            status = e.http.response_status_code if e.http else None

            if not ip or "/login.php" not in path:
                continue
            if method == "post" and status == 302:
                next_req = next(
                    (n for n in sorted_events[idx + 1:]
                     if n.source and n.source.ip == ip and n.http),
                    None
                )
                if not next_req:
                    failed[ip].append((e.id, e.timestamp))
                    continue

                next_path   = next_req.url.path if next_req.url else ""

                if "/login.php" not in next_path:
                    if ip in already_detected:
                        continue
                    prior = failed.get(ip, [])
                    if len(prior) >= self.FAILED_THRESHOLD:
                        triggered = [eid for eid, _ in prior[-10:]] + [e.id]
                        findings.append(DetectionFinding(
                            rule_id=self.rule_id,
                            rule_name="Successful Login After Brute Force",
                            rule_type="aggregate",
                            requires=[Capability("credential_candidate", bind=("source_ip",), values=(ip,))],
                            provides=[Capability("valid_credential", bind=("source_ip",), values=(ip,))],
                            severity=Severity.HIGH,
                            confidence=0.92,
                            technique_id="T1110",
                            technique_name="Brute Force",
                            tactic=MitreTactic.CREDENTIAL_ACCESS,
                            kill_chain_phase=KillChainPhase.DELIVERY,
                            tags=["bruteforce", "login", "success", "web"],
                            source="web_logs",
                            description=f"Login success on /login.php from {ip} after {len(prior)} failed attempts",
                            timestamp=_ts(e),
                            triggered_by=triggered,
                            event_count=len(triggered),
                            extra={"source_ip": ip, "failed_count": len(prior)},
                            entities={
                                "source_ip": ip,
                            }
                        ))
                        already_detected.add(ip)
                else:
                    failed[ip].append((e.id, e.timestamp))

        return findings
  
def get_web_rules() -> tuple[list[PerEventRule], list[AggregateRule]]:
    per_event = [
        SqlInjectionRule(),
        PathTraversalRule(),
        CommandInjectionRule(),
        XssAttemptRule(),
        WebshellUploadRule(),
        WebshellExecutionRule(),
        MaliciousFileUploadRule(),
        WebshellPostBodyExecutionRule()
    ]
    aggregate = [
        BruteForceRule(),
        ReconScannerRule(),
        ScannerUserAgentRule(),
        SuccessfulLoginAfterBruteForce(),
    ]
    return per_event, aggregate