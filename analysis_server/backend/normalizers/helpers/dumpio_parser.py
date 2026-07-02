import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class DumpioRequest:
    client_ip: Optional[str]
    client_port: Optional[int]
    timestamp_start: Optional[datetime]
    timestamp_end: Optional[datetime]
    method: Optional[str] = None
    path: Optional[str] = None
    http_version: Optional[str] = None
    headers: dict = field(default_factory=dict)
    body: str = ""
    raw_chunks: list = field(default_factory=list)


def _split_client(value: Optional[str]) -> tuple[Optional[str], Optional[int]]:
    if not value or ":" not in value:
        return value, None
    host, _, port_str = value.rpartition(":")
    try:
        port = int(port_str)
    except (TypeError, ValueError):
        port = None
    return (host or None), port


class _Connection:
    _REQUEST_LINE_RE = re.compile(
        r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s"
    )

    def __init__(self, client: str):
        self.client = client
        self._init_state()

    def _init_state(self) -> None:
        self.ts_start: Optional[datetime] = None
        self.ts_end: Optional[datetime] = None
        self.buffer = ""
        self.headers_parsed = False
        self.content_length: Optional[int] = None
        self.request_line: Optional[str] = None
        self.headers: dict = {}
        self.body = ""
        self.raw_chunks: list = []
        self.orphan_chunks: list = []

    def feed(self, chunk: str, ts: datetime) -> None:
        if not self.headers_parsed and not self.buffer:
            if not self._REQUEST_LINE_RE.match(chunk):
                self.orphan_chunks.append(chunk)
                return

        if self.ts_start is None:
            self.ts_start = ts
        self.ts_end = ts
        self.raw_chunks.append(chunk)

        if not self.headers_parsed:
            self.buffer += chunk
            if "\r\n\r\n" in self.buffer:
                head, _, rest = self.buffer.partition("\r\n\r\n")
                lines = head.split("\r\n")
                self.request_line = lines[0] if lines else None
                for h in lines[1:]:
                    if ":" in h:
                        k, _, v = h.partition(":")
                        self.headers[k.strip().lower()] = v.strip()
                self.headers_parsed = True
                self.content_length = int(self.headers.get("content-length", 0) or 0)
                self.body = rest
        else:
            self.body += chunk

    def is_complete(self) -> bool:
        if not self.headers_parsed:
            return False
        if not self.content_length:
            return True
        return len(self.body.encode("utf-8", errors="ignore")) >= self.content_length

    def to_request(self) -> DumpioRequest:
        method = path = http_version = None
        if self.request_line:
            parts = self.request_line.split(" ")
            if len(parts) == 3:
                method, path, http_version = parts

        body = self.body[: self.content_length] if self.content_length else self.body
        client_ip, client_port = _split_client(self.client)

        return DumpioRequest(
            client_ip=client_ip,
            client_port=client_port,
            timestamp_start=self.ts_start,
            timestamp_end=self.ts_end,
            method=method,
            path=path,
            http_version=http_version,
            headers=dict(self.headers),
            body=body,
            raw_chunks=list(self.raw_chunks),
        )

    def reset(self) -> None:
        self._init_state()


class DumpIOParser:
    DATA_RE = re.compile(r"\(data-HEAP\):\s*(?P<payload>.*)$")
    SIZE_ONLY_RE = re.compile(r"^\d+\s+bytes\s*$")
    CLIENT_RE = re.compile(r"\[client\s+([\d.]+):(\d+)\]")
    TS_FORMAT = "%a %b %d %H:%M:%S.%f %Y"

    _ESCAPE_MAP = {
        "\\\\": "\\",
        "\\r": "\r",
        "\\n": "\n",
        "\\t": "\t",
        '\\"': '"',
    }

    def __init__(self):
        self._connections: dict[str, _Connection] = {}

    def is_dumpio_line(self, raw: dict) -> bool:
        message = raw.get("message") or ""
        level = raw.get("level") or ""
        return "mod_dumpio:" in message or "dumpio" in level

    def _extract_client(self, raw: dict) -> Optional[str]:
        client = raw.get("client")
        if client:
            return client

        message = raw.get("message") or ""
        match = self.CLIENT_RE.search(message)
        if match:
            return f"{match.group(1)}:{match.group(2)}"

        return None

    def feed(self, raw: dict) -> Optional[DumpioRequest]:
        message = raw.get("message") or ""
        match = self.DATA_RE.search(message)
        if not match:
            return None

        payload = match.group("payload")
        if self.SIZE_ONLY_RE.match(payload):
            return None

        chunk = self._unescape(payload)

        client = self._extract_client(raw)
        if client is None:
            return None

        ts = self._parse_ts(raw.get("timestamp"))

        conn = self._connections.get(client)
        if conn is None:
            conn = _Connection(client=client)
            self._connections[client] = conn

        conn.feed(chunk, ts)

        if conn.is_complete():
            request = conn.to_request()
            conn.reset()
            return request

        return None

    @classmethod
    def _unescape(cls, text: str) -> str:
        for esc, real in cls._ESCAPE_MAP.items():
            text = text.replace(esc, real)
        return text

    @classmethod
    def _parse_ts(cls, ts_str: Optional[str]) -> Optional[datetime]:
        if not ts_str:
            return None
        return datetime.strptime(ts_str, cls.TS_FORMAT).replace(tzinfo=timezone.utc)