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
        service_type = ed.get("ServiceType", "")
        severity = 4 if "kernel" in service_type.lower() else 3
        username, domain = self._extract_username_and_domain(ed.get("AccountName", ""))

        return NormalizedEvent(
            event=EventFields(
                action="service_installed",
                category="host",
                code="7045",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                severity=severity,
                original=raw.get("message", "").encode("utf-8"),
                provider="Service Control Manager",
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),
            ),
            winlog=WinLogsFields(
                channel="System",
                event_id=7045,
                provider_name="Service Control Manager",
                extra={
                    "service_name": self._clean(ed.get("ServiceName")),
                    "service_file_path": self._clean(ed.get("ImagePath")),
                    "service_type": self._clean(service_type),
                    "start_type": self._clean(ed.get("StartType")),
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
                code="104",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                severity=5,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Eventlog",
            ),
            user=UserFields(
                name=self._normalize_username(ed.get("SubjectUserName")),
                domain=self._normalize_domain(ed.get("SubjectDomainName")),
            ),
            winlog=WinLogsFields(
                channel="System",
                event_id=104,
                provider_name="Microsoft-Windows-Eventlog",
                extra={
                    "channel_cleared": self._clean(ed.get("Channel")),
                    "backup_path": self._clean(ed.get("BackupPath")),
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
                code="4720",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                severity=3,
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Security-Auditing",
            ),
            user=UserFields(
                name=self._normalize_username(ed.get("TargetUserName")),
                domain=self._normalize_domain(ed.get("TargetDomainName")),
            ),
            winlog=WinLogsFields(
                channel="Security",
                event_id=4720,
                provider_name="Microsoft-Windows-Security-Auditing",
                extra={
                    "privileges": self._clean(ed.get("PrivilegeList")),
                    "created_by": self._normalize_username(ed.get("SubjectUserName")),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 20 — Windows Update Failure
    # ─────────────────────────────────────────────
    def _parse_20(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})

        return NormalizedEvent(
            event=EventFields(
                action="installation_failed",
                category="configuration",
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
                    "update_title": self._clean(ed.get("updateTitle")),
                    "error_code": self._clean(ed.get("errorCode")),
                    "update_guid": self._clean(ed.get("updateGuid")),
                    "revision_number": self._clean(ed.get("updateRevisionNumber")),
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 10016 — DistributedCOM Permissions (DCOM)
    # ─────────────────────────────────────────────
    def _parse_10016(self, raw: dict) -> NormalizedEvent:
        ed = raw.get("event_data", {})
        target_component = ed.get("param4", "")

        return NormalizedEvent(
            event=EventFields(
                action="dcom_permission_error",
                category="iam",
                code="10016",
                created=self._parse_time(raw.get("time_created")),
                dataset="windows_system",
                module="system",
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-Distributed",
            ),
            user=UserFields(
                name=self._normalize_username(ed.get("param7")),
                domain=self._normalize_domain(ed.get("param6")),
                id=self._clean(ed.get("param8")),
            ),
            winlog=WinLogsFields(
                channel="System",
                event_id=10016,
                provider_name="Microsoft-Windows-DistributedCOM",
                extra={
                    "component": self._clean(target_component),
                    "permission_type": self._clean(ed.get("param3")),
                    "access_type": self._clean(ed.get("param2")),
                    "address": self._clean(ed.get("param9")),
                    "clsid": self._clean(ed.get("param4")),
                },
            ),
        )