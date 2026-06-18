

from typing import Optional

import re


def _normalize_executable(executable: str) -> str:
    return executable.lower().strip().split("\\")[-1].split("/")[-1]

def normalize_command_line(raw: str) -> str:
    """Strip cmd.exe /s /c wrapper and unquote."""
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

def _normalize_args(args: list[str]) -> list[str]:
    return [arg.strip().lower() for arg in args]

def _normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().replace("\\", "").replace("/", "")

def _normalize_username(username: str) -> str:
    return username.strip().lower().split("\\")[-1].split("/")[-1]

def _normalize_ip(ip: str) -> str:
    return ip.strip().lower()

def _normalize_logon_id(self, value: str | None) -> str | None:
    cleaned = self._clean(value)
    if not cleaned:
        return None
    try:
        return f"0x{int(cleaned, 16):x}"  
    except (ValueError, TypeError):
        return None
    
def _extract_hostname(self, raw: dict) -> Optional[str]:
    """Extract hostname from user fields like 'winmachine\\admin'."""
    ed = raw.get("event_data", {})
    for field in ("SourceUser", "TargetUser", "User"):
        value = ed.get(field, "")
        if "\\" in value:
            domain = value.split("\\")[0]
            if domain.upper() not in ("NT AUTHORITY", "BUILTIN", "NT SERVICE", ""):
                return domain
    return None
