from ..base import BaseNormalizer
from models.events import *


class SystemNormalizer(BaseNormalizer):
    def normalize(self, raw: dict) -> NormalizedEvent | None:
        event_id = raw.get("event_id")
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        return parser(raw)

    # ─────────────────────────────────────────────
    # Event 7045 — Service Installed
    # ─────────────────────────────────────────────
    def _parse_7045(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        
        service_name = ed.get("ServiceName", "").lower()
        service_type = ed.get("ServiceType", "")
        
        severity = 4 if "kernel" in service_type.lower() else 3

        return NormalizedEvent(
            event=EventFields(
                action="service_installed",
                category="host",
                type="creation",
                code="7045",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Service Control Manager",
            ),
            user=UserFields(
                name=self._clean(ed.get("AccountName", "").split("\\")[-1]) if ed.get("AccountName") else None,
                domain=self._clean(ed.get("AccountName", "").split("\\")[0] if ed.get("AccountName") and "\\" in ed.get("AccountName", "") else None),
            ),
            winlog=WinLogsFields(
                channel="System",
                event_id=7045,
                provider_name="Service Control Manager",
                extra={
                    "service_name": ed.get("ServiceName"),
                    "service_file_path": ed.get("ImagePath"),
                    "service_type": service_type,
                    "start_type": ed.get("StartType"),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 104 — Log File Cleared (Anti-Forensics)
    # ─────────────────────────────────────────────
    def _parse_104(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        
        return NormalizedEvent(
            event=EventFields(
                action="log_cleared",
                category="host",
                type="deletion",
                code="104",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                severity=5, # Critic - cineva șterge urmele
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Eventlog",
            ),
            user=UserFields(
                name=self._clean(ed.get("SubjectUserName")),
                domain=self._clean(ed.get("SubjectDomainName")),
            ),
            winlog=WinLogsFields(
                channel="System",
                event_id=104,
                provider_name="Microsoft-Windows-Eventlog",
                extra={
                    "channel_cleared": ed.get("Channel"),
                    "backup_path": ed.get("BackupPath"),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 4720 — User Account Created (IAM)
    # ─────────────────────────────────────────────
    def _parse_4720(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="user_account_created",
                category="iam",
                type="creation",
                code="4720",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                severity=3,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                name=self._clean(ed.get("TargetUserName")),
                domain=self._clean(ed.get("TargetDomainName")),
            ),
            winlog=WinLogsFields(
                channel="Security", 
                event_id=4720,
                provider_name="Microsoft-Windows-Security-Auditing",
                extra={
                    "privileges": ed.get("PrivilegeList"),
                    "created_by": ed.get("SubjectUserName")
                },
            ),
        )
    
    # ─────────────────────────────────────────────
    # Event 20 — Windows Update Failure
    # ─────────────────────────────────────────────
    def _parse_20(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        error_code = ed.get("errorCode")
        
        return NormalizedEvent(
            event=EventFields(
                action="installation_failed",
                category="configuration",
                type="error",
                code="20",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                severity=3,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-WindowsUpdateClient",
            ),
            winlog=WinLogsFields(
                channel="System",
                event_id=20,
                provider_name="Microsoft-Windows-WindowsUpdateClient",
                extra={
                    "update_title": ed.get("updateTitle"),
                    "error_code": error_code,
                    "update_guid": ed.get("updateGuid"),
                    "revision_number": ed.get("updateRevisionNumber")
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 10016 — DistributedCOM Permissions (DCOM)
    # ─────────────────────────────────────────────
    def _parse_10016(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        
        target_component = ed.get("param4", "")
        is_security_related = "SecurityCenter" in target_component
        severity = 3 if is_security_related else 2

        return NormalizedEvent(
            event=EventFields(
                action="dcom_permission_error",
                category="iam",
                type="access",
                code="10016",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-DistributedCOM",
            ),
            user=UserFields(
                name=self._clean(ed.get("param7")),
                domain=self._clean(ed.get("param6")),
                id=self._clean(ed.get("param8")), # SID-ul
            ),
            winlog=WinLogsFields( 
                channel="System",
                event_id=10016,
                provider_name="Microsoft-Windows-DistributedCOM",
                extra={
                    "component": target_component,
                    "permission_type": ed.get("param3"), # ex: Launch
                    "access_type": ed.get("param2"),     # ex: Local
                    "address": ed.get("param9"),         # ex: LocalHost (LRPC)
                    "clsid": ed.get("param4")
                },
            ),
        )