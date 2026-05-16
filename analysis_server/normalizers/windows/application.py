from ..base import BaseNormalizer
from models.events import *


class ApplicationNormalizer(BaseNormalizer):
    def normalize(self, raw: dict) -> NormalizedEvent | None:
        event_id = raw.get("event_id")
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        return parser(raw)

    # ─────────────────────────────────────────────
    # Event 23 — App Repair Triggered
    # ─────────────────────────────────────────────
    def _parse_23(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        
        error_code = ed.get("OperationError")
        severity = 3 if error_code and error_code != "0" else 2

        return NormalizedEvent(
            event=EventFields(
                action="app_repair_triggered",
                category="application",
                type="info",
                code="23",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_application",
                module="application",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-AppModel-Runtime",
            ),
            winlog=WinLogsFields(
                channel="Application",
                event_id=23,
                provider_name="Microsoft-Windows-AppModel-Runtime",
                extra={
                    "operation": ed.get("Operation"),
                    "package_family": ed.get("PackageFamily"),
                    "operation_error": error_code,
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 24 — App Repair Finished
    # ─────────────────────────────────────────────
    def _parse_24(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        
        repair_error = ed.get("RepairTriggerError")
        op_error = ed.get("OperationError")
        severity = 2 if repair_error == "0" else 3

        return NormalizedEvent(
            event=EventFields(
                action="app_repair_finished",
                category="application",
                type="info",
                code="24",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_application",
                module="application",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-AppModel-Runtime",
            ),
            winlog=WinLogsFields(
                channel="Application",
                event_id=24,
                provider_name="Microsoft-Windows-AppModel-Runtime",
                extra={
                    "operation": ed.get("Operation"),
                    "package_family": ed.get("PackageFamily"),
                    "repair_trigger_error": repair_error,
                    "operation_error": op_error,
                },
            ),
        )
    
    # ─────────────────────────────────────────────
    # Event 8198 — License Activation Scheduler (Security-SPP)
    # ─────────────────────────────────────────────
    def _parse_8198(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})      
        error_code = ed.get("Hr") or ed.get("ErrorCode")
        severity = 4 if error_code and error_code != "0" else 2
        return NormalizedEvent(
            event=EventFields(
                action="software_protection_service_error",
                category="iam",
                type="info",
                code="8198",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_application",
                module="application",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Security-SPP",
            ),
            winlog=WinLogsFields(
                channel="Application",
                event_id=8198,
                provider_name="Microsoft-Windows-Security-SPP",
                extra={
                    "error_code": error_code,
                    "hr": ed.get("Hr"),
                    "event_context": ed 
                },
            ),
        )