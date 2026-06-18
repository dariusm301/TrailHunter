

import re
from typing import Optional
from urllib.parse import parse_qs, urlparse
from models.events import NormalizedEvent
from datetime import datetime


def _ts(event: NormalizedEvent) -> datetime:
    return event.timestamp or None

def _action(event: NormalizedEvent) -> str:
    return (event.event.action or "") if event.event else ""

def _src_ip(event: NormalizedEvent) -> Optional[str]:
    return event.source.address if event.source else None

def _process_name(event: NormalizedEvent) -> str:
    if event.process and event.process.name:
        return event.process.name
    return ""

def _dst_port(event: NormalizedEvent) -> Optional[int]:
    if event.destination and event.destination.port:
        return event.destination.port
    return None

def _dst_ip(event: NormalizedEvent) -> Optional[str]:
    if event.destination and event.destination.ip:
        return event.destination.ip
    return None

def _src_port(event: NormalizedEvent) -> Optional[int]:
    if event.source and event.source.port:
        return event.source.port
    return None


def _username(event: NormalizedEvent) -> str:
    return (event.user.name or "").lower() if event.user else ""

def _pid(event: NormalizedEvent) -> Optional[int]:
    return event.process.pid if event.process else None

def _parent_name(event: NormalizedEvent) -> str:
    if event.process and event.process.parent:
        return (event.process.parent.name or "").lower()
    return ""

def _parent_pid(event: NormalizedEvent) -> Optional[int]:
    if event.process and event.process.parent:
        return event.process.parent.pid
    return None

def _path(event: NormalizedEvent) -> str:
    return (event.registry.path or "").lower() if event.registry else ""

def _value(event: NormalizedEvent) -> str:
    v = event.registry.value if event.registry else None
    if isinstance(v, list):
        v = v[0] if v else None
    return (v or "")

def _data(event: NormalizedEvent) -> str:
    return (event.registry.data or "") if event.registry else ""

def _executable(event: NormalizedEvent) -> str:
    return (event.process.executable or "")if event.process else ""

def _task_name(event: NormalizedEvent) -> str:
    return (event.event.code or "") if event.event else ""

def _state(event: NormalizedEvent) -> str:
    return (event.event.action or "") if event.event else ""

def _get_original(event: NormalizedEvent) -> str:
    if not event.event:
        return ""
    original = event.event.original or ""
    if isinstance(original, bytes):
        original = original.decode("utf-8", errors="ignore")
    return original

def _event_id(event: NormalizedEvent) -> Optional[int]:
    return event.winlog.event_id if event.winlog else None

def _target_executable(event: NormalizedEvent) -> str:
    if event.target and event.target.process:
        return (event.target.process.executable or "").lower()
    return ""

def _host(event: NormalizedEvent) -> Optional[str]:
    if event.host and event.host.name:
        return event.host.name
    if event.winlog and event.winlog.computer_name:
        return event.winlog.computer_name
    return None

def _winlog_extra(event: NormalizedEvent, key: str, default=None):
    if event.winlog and event.winlog.extra:
        return event.winlog.extra.get(key, default)
    return default


def _url(event: NormalizedEvent) -> Optional[str]:
    url = event.url
    if not url:
        return None
   
    raw = url.original
    if raw and raw != "-":
        return raw
    return url.path  

def _status(event: NormalizedEvent) -> Optional[int]:
    if not event.http:
        return None
    raw = event.http.response_status_code
    return int(raw) if raw is not None else None

def _ip(event: NormalizedEvent) -> Optional[str]:
    src = event.source
    if not src:
        return None
    return src.ip or src.address


def _ua(event: NormalizedEvent) -> str:
    return (event.http.user_agent or "").lower() if event.http else ""

def _method(event: NormalizedEvent) -> Optional[str]:
    if not event.http:
        return None
    m = event.http.request_method
    return m.upper() if m else None

def _group_name(event: NormalizedEvent) -> str:
    if event.group and event.group.name:
        return event.group.name.lower()
    return ""

def _script_block_id(event: NormalizedEvent) -> Optional[str]:
    return event.powershell.script_block_id if event.powershell else None

def _runspace_id(event: NormalizedEvent) -> Optional[str]:
    return event.powershell.runspace_id if event.powershell else None

def _script_text(event: NormalizedEvent) -> str:
    return (event.powershell.script_block_text or "") if event.powershell else ""

def _hostname(event: NormalizedEvent) -> str:
    return (event.host.hostname or "") if event.host else ""


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
        return event.source.ip
    return None

def _ts(event: NormalizedEvent) -> Optional[datetime]:
    """Returns the timestamp of the event, or None if not available."""
    return event.event.created if event.event else None


def _file_name(event: NormalizedEvent) -> Optional[str]:
    url = _url(event)
    if not url:
        return None

    parsed = urlparse(url)

    qs = parse_qs(parsed.query)
    for param in ("page", "file", "path", "include", "load"):
        values = qs.get(param, [])
        if values:
            candidate = values[0].rstrip("/").split("/")[-1]
            if "." in candidate: 
                return candidate

    name = parsed.path.rstrip("/").split("/")[-1]
    return name if (name and "." in name) else None

def _cmd_from_url(url: str) -> Optional[str]:
    """Extracts a potential command from the URL query parameters."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in ("cmd", "exec", "command", "shell", "run", "system", "passthru", "eval"):
        values = qs.get(param, [])
        if values:
            return values[0]
    return None

def _get_args(event: NormalizedEvent) -> str:
    if event.process.args:
        return " ".join(event.process.args)
    return None

def _logon_id(event: NormalizedEvent) -> Optional[str]:
    """Returns the logon ID of the event, or None if not available."""
    if event.logon:
        return event.logon.id
    return None

def _extract_command(event: NormalizedEvent) -> Optional[str]:
    if event.process and event.process.command_line:
        return event.process.command_line
    return None

