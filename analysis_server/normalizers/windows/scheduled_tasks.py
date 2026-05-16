from normalizers.base import BaseNormalizer
from models.events import *
import re

class ScheduledTasksNormalizer(BaseNormalizer):
    def _parse_scheduled_tasks(self, raw: dict) -> list[NormalizedEvent]:
        executable = None
        args = None
        events = []
        extensions = "exe|bat|cmd|ps1|vbs|js|msc"
        pattern = rf"^(.*?\.(?:{extensions}))\s*(.*)$"      
        actions = raw.get("actions")
        actions_list = [actions] if isinstance(actions, str) else actions or []
        for action in actions_list:
            match = re.search(pattern, action, re.IGNORECASE)
            if match:
                executable = match.group(1)
                args = match.group(2).split()
            events.append(NormalizedEvent(
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