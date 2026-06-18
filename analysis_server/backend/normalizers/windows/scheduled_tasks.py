from normalizers.base import BaseNormalizer
from models.events import *
import re
from datetime import datetime, timezone


class ScheduledTasksNormalizer(BaseNormalizer):

    def _parse_ms_date(self, value: str | None) -> datetime | None:
        if not value:
            return None
        match = re.search(r'/Date\((\d+)\)/', value)
        if not match:
            return None
        ms = int(match.group(1))
        if ms <= 946684800000:
            return None
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)

    def _parse_scheduled_tasks(self, raw: dict) -> list[NormalizedEvent]:
        events = []
        last_run_dt = self._parse_ms_date(raw.get("last_run"))

        actions = raw.get("actions")
        actions_list = [actions] if isinstance(actions, str) else actions or []

        for action in actions_list:
            executable, args = self._split_command(action)
            events.append(NormalizedEvent(
                timestamp=last_run_dt,
                event=EventFields(
                    category="process",
                    dataset="windows.scheduled_tasks",
                    code=self._normalize_task_name(raw.get("task_name")),
                    module="scheduled_tasks",
                    action="Scheduled Task Saved",
                    original=str(raw).encode("utf-8"),
                    provider="windows_scheduled_tasks",
                    risk_score=1,
                ),
                process=ProcessFields(
                    name=self._normalize_executable(executable),
                    command_line=self._normalize_command_line(action),
                    executable=self._normalize_executable(executable),
                    args=self._normalize_args(args),
                    args_count=len(args) if args else None,
                    start=last_run_dt,
                    exit_code=int(raw.get("last_result")) if raw.get("last_result") is not None else None,
                ),
            ))
        return events

    def normalize(self, raw: dict) -> list[NormalizedEvent]:
        return self._parse_scheduled_tasks(raw)