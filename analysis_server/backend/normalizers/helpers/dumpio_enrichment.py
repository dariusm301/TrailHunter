# normalizers/helpers/cross_source_enrichment.py
import re
from collections import defaultdict
from datetime import timedelta
from typing import Optional, List
from models.events import NormalizedEvent, SourceFields


_SESSION_COOKIE_PATTERNS = (
    r'PHPSESSID=([a-zA-Z0-9]+)',
    r'ASP\.NET_SessionId=([a-zA-Z0-9]+)',
    r'JSESSIONID=([a-zA-Z0-9.\-]+)',
    r'connect\.sid=([^;]+)',
)


def _get_original_text(event: NormalizedEvent) -> str:
    raw = event.event.original if event.event else None
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="ignore")
    return str(raw)


def _extract_session_id(event: NormalizedEvent) -> Optional[str]:
    raw = _get_original_text(event)
    if not raw:
        return None
    for pattern in _SESSION_COOKIE_PATTERNS:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _correlation_key(event: NormalizedEvent) -> tuple:
    method = (event.http.request_method.upper() if event.http and event.http.request_method else "")
    path = (event.url.path if event.url and event.url.path else "")
    return (method, path)


def enrich_dumpio_with_ip(
    dumpio_events: List[NormalizedEvent],
    access_log_events: List[NormalizedEvent],
    window_seconds: int = 10,
) -> List[NormalizedEvent]:
    window = timedelta(seconds=window_seconds)

    by_session: dict[str, list] = defaultdict(list)
    by_path: dict[tuple, list] = defaultdict(list)

    for ev in access_log_events:
        ip = ev.source.ip if ev.source else None
        ts = ev.timestamp
        if not ip or not ts:
            continue

        sid = _extract_session_id(ev)
        if sid:
            by_session[sid].append((ts, ip))

        by_path[_correlation_key(ev)].append((ts, ip))

    def _best_match(candidates: list, ref_ts) -> Optional[str]:
        best_ip, best_delta = None, window + timedelta(seconds=1)
        for ts, ip in candidates:
            if ts is None or ref_ts is None:
                continue
            delta = abs(ref_ts - ts)
            if delta <= window and delta < best_delta:
                best_ip, best_delta = ip, delta
        return best_ip

    matched, fallback_matched, unmatched = 0, 0, 0

    for ev in dumpio_events:
        if ev.source and ev.source.ip:
            continue

        ref_ts = ev.timestamp
        resolved_ip = None
        match_method = None

        sid = _extract_session_id(ev)
        if sid and sid in by_session:
            resolved_ip = _best_match(by_session[sid], ref_ts)
            if resolved_ip:
                match_method = "session"

        if not resolved_ip:
            key = _correlation_key(ev)
            if key in by_path:
                resolved_ip = _best_match(by_path[key], ref_ts)
                if resolved_ip:
                    match_method = "path_fallback"

        if resolved_ip:
            if not ev.source:
                ev.source = SourceFields()
            ev.source.ip = resolved_ip
            matched += 1 if match_method == "session" else 0
            fallback_matched += 1 if match_method == "path_fallback" else 0
        else:
            unmatched += 1

    print(f"dumpio IP enrichment: {matched} session-matched, "
          f"{fallback_matched} path-fallback, {unmatched} unmatched")

    return dumpio_events