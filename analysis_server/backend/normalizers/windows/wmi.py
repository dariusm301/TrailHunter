from ..base import BaseNormalizer
from models.events import *
import re
from .services.convert_sid import convert_raw_sid_to_string


class WMINormalizer(BaseNormalizer):

    def normalize(self, raw: dict) -> NormalizedEvent | None:
        event_id = raw.get('event_id')
        parser = getattr(self, f"_parse_{event_id}", None)
        if not parser:
            return None
        return parser(raw)

    # ─────────────────────────────────────────────
    # Event 5858 — WMI Query Error
    # ─────────────────────────────────────────────
    def _parse_5858(self, raw: dict) -> NormalizedEvent:
        kv = self.parse_kv(raw.get('message', ''))
        domain, user = self._parse_user(kv.get("User", ""))
        hostname = self._normalize_hostname(kv.get("ClientMachine"))

        return NormalizedEvent(
            event=EventFields(
                action="wmi_query_error",
                category="configuration",
                code=str(raw.get("event_id")),
                created=self._parse_time(raw.get("time_created")),
                dataset="windows.wmi",
                original=raw.get("message", "").encode("utf-8"),
                provider="Microsoft-Windows-WMI-Activity",
                severity=1,
                module="windows",
            ),
            host=HostFields(
                hostname=hostname,
            ),
            user=UserFields(
                name=self._normalize_username(user),
                domain=self._normalize_domain(domain),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(kv.get("ClientProcessId")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
                computer_name=hostname,
            ),
        )

    # ─────────────────────────────────────────────
    # Event 5857 — WMI Provider Start
    # ─────────────────────────────────────────────
    def _parse_5857(self, raw: dict) -> NormalizedEvent:
        message = raw.get('message', '')
        sentence, _, kv_part = message.partition(".")
        kv = self.parse_kv(kv_part)

        provider_match = re.match(r"^(.+?) provider started with result code (0x[0-9a-fA-F]+)", sentence)
        provider_name = provider_match.group(1) if provider_match else None
        result_code = self._clean(provider_match.group(2)) if provider_match else None

        return NormalizedEvent(
            event=EventFields(
                action="wmi_provider_start",
                category="configuration",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows.wmi",
                module="windows",
                severity=1,
                original=message.encode("utf-8"),
                provider=self._clean(provider_name),
            ),
            process=ProcessFields(
                name=self._normalize_process_name(kv.get("HostProcess")),
                pid=self._normalize_pid(kv.get("ProcessID")),
                executable=self._clean(kv.get("ProviderPath")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
                extra={
                    "result_code": result_code,
                },
            ),
        )

    # ─────────────────────────────────────────────
    # Event 5859 — WMI Notification Query
    # ─────────────────────────────────────────────
    def _parse_5859(self, raw: dict) -> NormalizedEvent:
        kv = self.parse_kv(raw.get('message', ''))
        provider_raw = kv.get("Provider", "")
        provider_name = provider_raw.split(",")[0].strip() if provider_raw else None

        return NormalizedEvent(
            event=EventFields(
                provider=self._clean(provider_name),
                action="wmi_notification_query",
                category="configuration",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows.wmi",
                module="windows",
                severity=1,
                original=raw.get("message", "").encode("utf-8"),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(kv.get("HostProcessID")),
            ),
            user=UserFields(
                id=self._clean(kv.get("OwnerName")),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
            ),
        )

    # ─────────────────────────────────────────────
    # Event 5860 — WMI Subscription Query
    # ─────────────────────────────────────────────
    def _parse_5860(self, raw: dict) -> NormalizedEvent:
        kv = self.parse_kv(raw.get('message', ''))
        domain, user = self._parse_user(kv.get("UserName", ""))

        # kv doesn't parse fields with commas in values correctly,
        # so regex remains only for ClientProcessID and ClientMachine
        pid_match = re.search(r'ClientProcessID\s*=\s*(\d+)', raw.get('message', ''))
        host_match = re.search(r'ClientMachine\s*=\s*([^;]+)', raw.get('message', ''))
        pid = self._normalize_pid(pid_match.group(1)) if pid_match else None
        hostname = self._normalize_hostname(host_match.group(1)) if host_match else None

        return NormalizedEvent(
            event=EventFields(
                provider="WMI Subscription",
                action="wmi_subscription_query",
                category="configuration",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows.wmi",
                module="windows",
                severity=1,
                original=raw.get("message", "").encode("utf-8"),
            ),
            host=HostFields(
                hostname=hostname,
            ),
            process=ProcessFields(
                pid=pid,
            ),
            user=UserFields(
                name=self._normalize_username(user),
                domain=self._normalize_domain(domain),
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
                computer_name=hostname,
            ),
        )

    # ─────────────────────────────────────────────
    # Event 5861 — WMI Event Subscription Created
    # ─────────────────────────────────────────────
    def _parse_5861(self, raw: dict) -> NormalizedEvent:
        kv = self.parse_kv(raw.get('message', ''))

        consumer_raw = kv.get('Consumer', '')
        consumer_type_match = re.match(r'^([^=]+)', consumer_raw)
        consumer_type = self._clean(consumer_type_match.group(1)) if consumer_type_match else None
        consumer_name_match = re.search(r'="?([^"]+)"?', consumer_raw)
        consumer_name = self._clean(consumer_name_match.group(1)) if consumer_name_match else None

        sid_search = re.search(r'CreatorSID\s*=\s*{([^}]+)}', kv.get('PossibleCause', ''))
        sid_raw = sid_search.group(1).strip() if sid_search else None
        sid = convert_raw_sid_to_string(
            [int(x.strip()) for x in sid_raw.split(",")]
        ) if sid_raw else None

        return NormalizedEvent(
            event=EventFields(
                provider="WMI Event Log Binding",
                action="wmi_event_subscription_created",
                category="persistence",
                code=str(raw.get('event_id')),
                created=self._parse_time(raw.get('time_created')),
                dataset="windows.wmi",
                module="windows",
                severity=1,
                original=raw.get('message', '').encode('utf-8'),
            ),
            user=UserFields(
                id=sid,
            ),
            process=ProcessFields(
                name=self._normalize_process_name(consumer_type),
                entity_id=consumer_name,
            ),
            winlog=WinLogsFields(
                channel="Microsoft-Windows-WMI-Activity/Operational",
                event_id=raw.get("event_id"),
                provider_name="Microsoft-Windows-WMI-Activity",
            ),
        )