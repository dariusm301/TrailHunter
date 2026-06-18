from ..base import BaseNormalizer
from models.events import *


class PowerShellNormalizer(BaseNormalizer):
    def normalize(self, raw: dict) -> NormalizedEvent | None:
        event_id = raw.get("event_id")
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        return parser(raw)

    # ─────────────────────────────────────────────
    # Event 4104 — Execute a Remote Command (Script Block Logging)
    # ─────────────────────────────────────────────
    def _parse_4104(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        script_content = self._clean(ed.get("ScriptBlockText", "")) or ""

        return NormalizedEvent(
            event=EventFields(
                action="scriptblock-logged",
                category="process",
                code="4104",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_powershell",
                module="powershell",
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-PowerShell",
            ),
            user=UserFields(
                name=self._normalize_username(ed.get("UserId")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-PowerShell/Operational",
                event_id=4104,
                provider_name="Microsoft-Windows-PowerShell",
                extra={
                    "script_block_text": script_content,
                    "script_block_id": self._clean(ed.get("ScriptBlockId")),
                    "path": self._clean(ed.get("Path")),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4103 — Logging module (Pipeline Execution)
    # ─────────────────────────────────────────────
    def _parse_4103(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="powershell_pipeline_execution",
                category="process",
                code="4103",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_powershell",
                module="powershell",
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-PowerShell",
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-PowerShell/Operational",
                event_id=4103,
                provider_name="Microsoft-Windows-PowerShell",
                extra={
                    "command_invocation": self._clean(ed.get("ContextInfo")),
                    "payload": self._clean(ed.get("Payload")),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4105 — ScriptBlock invocation started
    # ─────────────────────────────────────────────
    def _parse_4105(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="scriptblock-started",
                category="process",
                code="4105",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_powershell",
                module="powershell",
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-PowerShell",
            ),
            host=HostFields(
                hostname=self._normalize_hostname(raw.get("hostname")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-PowerShell/Operational",
                event_id=4105,
                provider_name="Microsoft-Windows-PowerShell",
            ),
            powershell=PowerShellFields(
                script_block_id=self._clean(ed.get("ScriptBlockId")),
                runspace_id=self._clean(ed.get("RunspaceId")),
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4106 — ScriptBlock invocation completed
    # ─────────────────────────────────────────────
    def _parse_4106(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="scriptblock-completed",
                category="process",
                code="4106",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_powershell",
                module="powershell",
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-PowerShell",
            ),
            host=HostFields(
                hostname=self._normalize_hostname(raw.get("hostname")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-PowerShell/Operational",
                event_id=4106,
                provider_name="Microsoft-Windows-PowerShell",
            ),
            powershell=PowerShellFields(
                script_block_id=self._clean(ed.get("ScriptBlockId")),
                runspace_id=self._clean(ed.get("RunspaceId")),
            ),
        )