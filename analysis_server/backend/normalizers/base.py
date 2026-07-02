from abc import ABC, abstractmethod
from typing import Optional
from models.events import DNSAnswerFields, NormalizedEvent
from datetime import datetime, timezone
import re

class BaseNormalizer(ABC):

    @staticmethod
    def _parse_time(ts : str | None) -> datetime:
        if not ts:
            return datetime.now()
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    
    @staticmethod
    def parse_kv(message: str, delimiter: str = ";") -> dict:
        fields = {}
        for part in message.split(delimiter):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                fields[key.strip()] = value.strip()
        return fields
    
    @staticmethod
    def _parse_user(raw: str) -> tuple[str | None, str | None]:
        """"DOMAIN\\user -> (domain, username)"""
        if not raw:
            return None, None
        if "\\" in raw:
            domain, name = raw.split("\\", 1)
            return domain.strip(), name.strip()
        return None, raw.strip()
    
    @staticmethod
    def _hex_to_int(value: str) -> int | None:
        try:
            return int(value, 16) if value else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_ms_date(value: str | None) -> datetime | None:
        if not value or not isinstance(value, str):
            return None
        
        # Format 1: /Date(1234567890000)/ — WMI/scheduled tasks
        match = re.search(r'/Date\((\d+)\)/', value)
        if match:
            ms = int(match.group(1))
            if ms <= 946684800000:  # before 2000-01-01, invalid
                return None
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        
        # Format 2: d1234567890000 — legacy WMI
        match = re.search(r'd(\d+)', value)
        if match:
            ms = int(match.group(1))
            if ms <= 946684800000:
                return None
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        
        return None
    
    @abstractmethod
    def normalize(self, data: dict) -> NormalizedEvent | None:
        raise NotImplementedError("Subclasses must implement this method")

    @staticmethod
    def _normalize_executable(executable: str | None) -> str | None:
        if not executable:
            return None
        return executable.strip().lower().split("\\")[-1].split("/")[-1] or None

    @staticmethod
    def _normalize_command_line(raw: str | None) -> str | None:
        """Strip cmd.exe /s /c wrapper and unquote."""
        if not raw:
            return None
        raw = raw.strip().lower()
        m = re.match(
            r'^cmd(?:\.exe)?\s+/[sS]\s+/[cC]\s+"(.+)"$',
            raw,
            re.IGNORECASE
        )
        if m:
            return m.group(1)
        m = re.match(
            r'^cmd(?:\.exe)?\s+/[cC]\s+"(.+)"$',
            raw,
            re.IGNORECASE
        )
        if m:
            return m.group(1)
        
        return raw

    @staticmethod
    def _normalize_args(args: list[str] | None) -> list[str] | None:
        if not args:
            return None
        return [arg.strip().lower() for arg in args]
    
    @staticmethod
    def _normalize_domain(domain: str | None) -> str | None:
        if not domain:
            return None
        return domain.strip().lower().replace("\\", "").replace("/", "") or None

    @staticmethod
    def _normalize_username(username: str | None) -> str | None:
        if not username:
            return None
        return username.strip().lower().split("\\")[-1].split("/")[-1] or None

    @staticmethod
    def _normalize_ip(ip: str | None) -> str | None:
        if not ip:
            return None
        return ip.strip().lower() or None


    @staticmethod
    def _normalize_logon_id(value: str | None) -> str | None:
        if not value:
            return None
        cleaned = value.strip().strip("'\"").lower()
        try:
            return f"0x{int(cleaned, 16):x}"
        except (ValueError, TypeError):
            return None
    
    @staticmethod
    def _normalize_pid(pid: str | None) -> int | None:
        if not pid:
            return None
        try:
            return int(pid)
        except ValueError:
            return None
        
    @staticmethod
    def _normalize_process_name(name: str | None) -> str | None:
        if not name:
            return None
        return name.strip().strip("'\"").lower().split("\\")[-1].split("/")[-1] or None
    
    @staticmethod
    def _parse_dns_answers(query_results: str | None) -> list[DNSAnswerFields] | None:
        if not query_results:
            return None
        answers = []
        for result in query_results.split(";"):
            result = result.strip()
            if not result:
                continue
            answers.append(
                DNSAnswerFields(
                    data=result,
                    type="A"
                )
            )
        return answers
    
    @staticmethod
    def _normalize_response_code(response_code : str | None) -> str | None:
        if not response_code:
            return None
        return response_code.strip().lower()
        
    @staticmethod
    def _clean(value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower()
        return value or None

    @staticmethod
    def _normalize_hostname(hostname: str | None) -> str | None:
        if not hostname:
            return None
        return hostname.strip().lower() or None

    @staticmethod
    def _normalize_filename(path: str | None) -> str | None:
        if not path:
            return None
        return path.strip().lower().split("\\")[-1].split("/")[-1] or None

    @staticmethod
    def _extract_hostname(raw: dict) -> str | None:
        if not raw:
            return None
        for key in ("computer", "Computer", "hostname", "host"):
            if raw.get(key):
                return BaseNormalizer._normalize_hostname(raw[key])
        ed = raw.get("event_data") or {}
        for key in ("Computer", "Hostname"):
            if ed.get(key):
                return BaseNormalizer._normalize_hostname(ed[key])
        return None

    @staticmethod
    def _extract_username_and_domain(raw: str | None) -> tuple[str | None, str | None]:
        """'DOMAIN\\user' -> (username, domain)."""
        if not raw:
            return None, None
        raw = raw.strip()
        if "\\" in raw:
            domain, _, username = raw.partition("\\")
            return (username.strip() or None, domain.strip() or None)
        return (raw or None, None)

    @staticmethod
    def _normalize_port(value) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
        
    @staticmethod
    def _normalize_mac(mac: str | None) -> str | None:
        if not mac:
            return None
        return mac.strip().lower() or None
    
    _EXE_EXTENSIONS = ("exe", "bat", "cmd", "ps1", "vbs", "js", "msc", "com", "scr", "dll")

    _BARE_BINARIES = {
        "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
        "certutil", "bitsadmin", "rundll32", "regsvr32", "wmic", "net",
        "reg", "sc", "schtasks", "msiexec", "forfiles", "whoami", "ping",
    }

    @staticmethod
    def _split_command(action: str | None) -> tuple[str | None, list[str] | None]:
        """'C:\\x.exe -a -b' -> ('C:\\x.exe', ['-a', '-b'])"""
        if not action or not action.strip():
            return None, None
        action = action.strip()

        ext_pattern = re.compile(
            r"\.(?:" + "|".join(BaseNormalizer._EXE_EXTENSIONS) + r")$",
            re.IGNORECASE
        )

        # 1. Quoted executable
        if action[0] in ('"', "'"):
            q = action[0]
            end = action.find(q, 1)
            if end != -1:
                exe = action[1:end]
                rest = action[end + 1:].strip()
                return exe, (rest.split() if rest else None)

        # 2. First token are known binary or has known extension
        parts = action.split(None, 1)
        first = parts[0]
        rest = parts[1] if len(parts) > 1 else None
        base = first.split("\\")[-1].split("/")[-1].lower().split(".")[0]

        if ext_pattern.search(first) or base in BaseNormalizer._BARE_BINARIES:
            return first, (rest.split() if rest else None)

        # Fallback - search for first token with known extension anywhere in string
        m = re.match(
            r"^(.*?\.(?:" + "|".join(BaseNormalizer._EXE_EXTENSIONS) + r"))(?:\s+(.*))?$",
            action, re.IGNORECASE
        )
        if m:
            return m.group(1), (m.group(2).split() if m.group(2) else None)

        return first, (rest.split() if rest else None)
        
    @staticmethod
    def _parse_command_line_args(command_line: str | None) -> list[str] | None:
        """Parse command_line into args array, preserving payload after /c intact."""
        if not command_line:
            return None
        
        import shlex
        try:
            parts = shlex.split(command_line, posix=False)
            return [p.strip('"') for p in parts if p.strip('"')]
        except ValueError:
            return command_line.split()

    @staticmethod
    def _normalize_task_name(task_name: str | None) -> str | None:
        if not task_name:
            return None
        task_name = task_name.replace("'", "").replace("\\", "")
        return task_name.strip().lower() or None
    
    @staticmethod
    def _is_probe(event: NormalizedEvent, probe_ips: set[str]) -> bool:
        if probe_ips is None or probe_ips == []:
            return False
        if event.source and event.destination:
            return event.source.ip in probe_ips or event.destination.ip in probe_ips
        return False