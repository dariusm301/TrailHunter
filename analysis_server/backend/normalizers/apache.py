from normalizers.base import BaseNormalizer
from models.events import *
from datetime import datetime, timezone

from normalizers.helpers.dumpio_parser import DumpIOParser, DumpioRequest


class ApacheNormalizer(BaseNormalizer):
    def __init__(self):
        self._dumpio_parser = DumpIOParser()

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

    def _normalize_dumpio(self, raw: DumpioRequest) -> NormalizedEvent:
        
        body = raw.body.strip() if raw.body else None
        return NormalizedEvent(
            timestamp=raw.timestamp_start,
            event=EventFields(
                action="apache_dumpio_request",
                category="web",
                dataset="apache.dumpio",
                module="apache",
                original="".join(raw.raw_chunks).encode("utf-8"),
                created=raw.timestamp_end,
            ),
            network=NetworkFields(
                protocol="http",
                transport="tcp",
                direction="inbound",
            ),
            source=SourceFields(
                ip=self._normalize_ip(raw.client_ip),
                port=self._normalize_port(raw.client_port),
            ),
            http=HTTPFields(
                request_method=self._clean(raw.method),
                request_body=body or None,
            ),
            url=UrlFields(
                path=self._clean(raw.path),
            ),
        )

    def normalize(self, raw: dict, log_type: str) -> NormalizedEvent | None:
        
        if "access" in log_type:
            return self._normalize_access_log(raw)
        elif "error" in log_type:
            if self._dumpio_parser.is_dumpio_line(raw):
                request = self._dumpio_parser.feed(raw)
                if request is None:
                    return None
                return self._normalize_dumpio(request)
            return self._normalize_error_log(raw)
        else:
            raise ValueError(f"Unsupported log type: {log_type}")

    @staticmethod
    def _parse_host_port(value: str | None) -> tuple[str | None, int | None]:
        if not value or ":" not in value:
            return value, None
        host, _, port_str = value.rpartition(":")
        return (host or None), BaseNormalizer._normalize_port(port_str)