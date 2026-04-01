from normalizers.base import BaseNormalizer
from models.events import *
import re

class ScheduledTasksNormalizer(BaseNormalizer):
    def _parse_scheduled_tasks(self, raw: dict) -> NormalizedEvent:
        executable = None
        args = None
        extensions = "exe|bat|cmd|ps1|vbs|js|msc"
        pattern = rf"^(.*?\.(?:{extensions}))\s*(.*)$"        
        match = re.search(pattern, raw.get("actions", ""), re.IGNORECASE)
        if match:
            executable = match.group(1)
            args = match.group(2)
        return NormalizedEvent(
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
                command_line=raw.get("actions"),
                executable=executable,
                args=args.split() if args else None,
                args_count=len(args.split()) if args else None,
                start=self._parse_ms_date(raw.get("last_run")),
                exit_code=int(raw.get("last_result")) if raw.get("last_result") is not None else None
            )

        )
    
    def normalize(self, raw: dict) -> NormalizedEvent:
        return self._parse_scheduled_tasks(raw)