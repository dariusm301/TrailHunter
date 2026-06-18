from normalizers.base import BaseNormalizer
from models.events import *


class ProcessesNormalizer(BaseNormalizer):

    def _parse_processes(self, raw: dict) -> NormalizedEvent:
        domain, username = self._parse_user(raw.get("owner"))

        return NormalizedEvent(
            event=EventFields(
                action="process_snapshot",
                category="process",
                dataset="windows.processes",
                module="windows",
                original=str(raw).encode("utf-8"),
            ),
            user=UserFields(
                name=self._normalize_username(username),
                domain=self._normalize_domain(domain),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(raw.get("pid")),
                name=self._normalize_process_name(raw.get("name")),
                command_line=self._normalize_command_line(raw.get("command_line")),
                executable=self._normalize_executable(raw.get("executable_path")),
                hash_sha256=self._clean(raw.get("hash_sha256")) if raw.get("hash_sha256") != "no_path" else None,
                start=self._parse_time(raw.get("start_time")),
                parent=ProcessFields(
                    pid=self._normalize_pid(raw.get("parent_pid")),
                ),
            ),
        )

    def normalize(self, raw: dict) -> NormalizedEvent:
        return self._parse_processes(raw)