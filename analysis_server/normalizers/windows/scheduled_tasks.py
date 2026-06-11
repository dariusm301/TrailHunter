from normalizers.base import BaseNormalizer
from models.events import *
import re
from datetime import datetime, timezone
import shlex

_EXE_EXT = ("exe", "bat", "cmd", "ps1", "vbs", "js", "msc", "com", "scr", "dll")
_EXT_RE  = re.compile(r"\.(?:" + "|".join(_EXE_EXT) + r")$", re.IGNORECASE)
 
_BARE_BINARIES = {
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
    "certutil", "bitsadmin", "rundll32", "regsvr32", "wmic", "net",
    "reg", "sc", "schtasks", "msiexec", "forfiles", "whoami", "ping",
}


def _split_action(action: str) -> tuple[str | None, list[str] | None]:
    """
    """
    if not action or not action.strip():
        return None, None
    action = action.strip()
 
    # 1. Quoted executable.
    if action[0] in ('"', "'"):
        q = action[0]
        end = action.find(q, 1)
        if end != -1:
            exe = action[1:end]
            rest = action[end + 1:].strip()
            return exe, (rest.split() if rest else None)
 
    parts = action.split(None, 1)
    first = parts[0]
    rest  = parts[1] if len(parts) > 1 else None
 
    base = first.split("\\")[-1].split("/")[-1].lower()
    if _EXT_RE.search(first) or base in _BARE_BINARIES:
        return first, (rest.split() if rest else None)
 
    m = re.match(r"^(.*?\.(?:" + "|".join(_EXE_EXT) + r"))(?:\s+(.*))?$",
                 action, re.IGNORECASE)
    if m:
        return m.group(1), (m.group(2).split() if m.group(2) else None)
 
    return first, (rest.split() if rest else None)



class ScheduledTasksNormalizer(BaseNormalizer):
    def _parse_ms_date(self, value: str | None) -> datetime | None:
        if not value:
            return None
        match = re.search(r'/Date\((\d+)\)/', value)
        if not match:
            return None
        ms = int(match.group(1))
        if ms <= 946684800000:  # Timestamp is before 2000-01-01, likely invalid
            return None
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    
    def _parse_scheduled_tasks(self, raw: dict) -> list[NormalizedEvent]:
      
        events = []    
        actions = raw.get("actions")
        actions_list = [actions] if isinstance(actions, str) else actions or []
        for action in actions_list:
            executable, args = _split_action(action)
            events.append(NormalizedEvent(
                    timestamp = self._parse_ms_date(raw.get("last_run")),
                    event=EventFields(
                        type="scheduled_tasks",
                        category="windows",
                        dataset="windows_scheduled_tasks",
                        module="scheduled_tasks",
                        action=raw.get("state").lower() if raw.get("state") else None,
                        original=str(raw).encode('utf-8'),
                        provider="windows_scheduled_tasks",
                        code=str(raw.get("last_result")) if raw.get("last_result") is not None else None,
                        risk_score=1
                    ),

                    process=ProcessFields(
                        name=raw.get("task_name"),
                        command_line=action,
                        executable=executable,
                        args=args if args else None,
                        args_count=len(args) if args else None,
                        start=self._parse_ms_date(raw.get("last_run")),
                        exit_code=int(raw.get("last_result")) if raw.get("last_result") is not None else None
                    )

                ))
        return events
    
    def normalize(self, raw: dict) -> NormalizedEvent:
        return self._parse_scheduled_tasks(raw)