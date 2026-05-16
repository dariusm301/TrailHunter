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
        script_content = ed.get("ScriptBlockText", "")
        
        # Analiză de severitate bazată pe cuvinte cheie suspecte (Simple Heuristics)
        suspicious_keywords = ["-enc", "base64", "iex", "invoke-expression", "bypass", "hidden"]
        is_suspicious = any(k in script_content.lower() for k in suspicious_keywords)
        severity = 4 if is_suspicious else 2

        return NormalizedEvent(
            event=EventFields(
                action="powershell_script_block",
                category="process",
                type="info",
                code="4104",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_powershell",
                module="powershell",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-PowerShell",
            ),
            # PowerShell logs includ adesea contextul utilizatorului în metadata
            user=UserFields(
                name=self._clean(ed.get("UserId", "").split("\\")[-1]),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-PowerShell/Operational",
                event_id=4104,
                provider_name="Microsoft-Windows-PowerShell",
                extra={
                    "script_block_text": script_content,
                    "script_block_id": ed.get("ScriptBlockId"),
                    "path": ed.get("Path"), # Calea scriptului dacă este salvat pe disc
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4103 — Module Logging (Pipeline Execution)
    # ─────────────────────────────────────────────
    def _parse_4103(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        
        return NormalizedEvent(
            event=EventFields(
                action="powershell_pipeline_execution",
                category="process",
                type="info",
                code="4103",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_powershell",
                module="powershell",
                severity=2,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-PowerShell",
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-PowerShell/Operational",
                event_id=4103,
                provider_name="Microsoft-Windows-PowerShell",
                extra={
                    "command_invocation": ed.get("ContextInfo"),
                    "payload": ed.get("Payload"),
                },
            ),
        )