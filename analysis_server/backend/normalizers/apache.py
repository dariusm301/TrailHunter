from normalizers.base import BaseNormalizer
from models.events import *
from datetime import datetime, timezone


class ApacheNormalizer(BaseNormalizer):

    # ─────────────────────────────────────────────
    # Access Log
    # ─────────────────────────────────────────────
    def _normalize_access_log(self, raw: dict) -> NormalizedEvent:
        ts = datetime.strptime(
            raw.get("timestamp"), "%d/%b/%Y:%H:%M:%S %z"
        ).astimezone(timezone.utc)

        return NormalizedEvent(
            timestamp=ts,
            event=EventFields(
                action="apache_access_log",
                category="web",
                dataset="apache.access",
                module="apache",
                original=str(raw).encode("utf-8"),
                created=ts,
            ),
            network=NetworkFields(
                protocol="http",
                transport="tcp",
                direction="inbound",
            ),
            source=SourceFields(
                ip=self._normalize_ip(raw.get("client_ip")),
            ),
            http=HTTPFields(
                request_method=self._clean(raw.get("method")),
                response_status_code=raw.get("status_code"),
                user_agent=self._clean(raw.get("user_agent")),
            ),
            url=UrlFields(
                original=self._clean(raw.get("referer")),
                path=self._clean(raw.get("path")),
            ),
        )

    # ─────────────────────────────────────────────
    # Error Log
    # ─────────────────────────────────────────────
    def _normalize_error_log(self, raw: dict) -> NormalizedEvent:
        address, port = self._parse_host_port(raw.get("client"))
        ts = datetime.strptime(
            raw.get("timestamp"), "%a %b %d %H:%M:%S.%f %Y"
        ).replace(tzinfo=timezone.utc)

        return NormalizedEvent(
            timestamp=ts,
            event=EventFields(
                action="apache_error_log",
                category="web",
                dataset="apache.error",
                module="apache",
                original=str(raw).encode("utf-8"),
                created=ts,
                severity_label=self._clean(raw.get("level")),
                reason=self._clean(raw.get("message")),
            ),
            source=SourceFields(
                ip=self._normalize_ip(address),
                port=self._normalize_port(port),
            ),
        )

    def normalize(self, raw: dict, log_type: str) -> NormalizedEvent:
        if "access" in log_type:
            return self._normalize_access_log(raw)
        elif "error" in log_type:
            return self._normalize_error_log(raw)
        else:
            raise ValueError(f"Unsupported log type: {log_type}")

    @staticmethod
    def _parse_host_port(value: str | None) -> tuple[str | None, int | None]:
        if not value or ":" not in value:
            return value, None
        host, _, port_str = value.rpartition(":")
        return (host or None), BaseNormalizer._normalize_port(port_str)