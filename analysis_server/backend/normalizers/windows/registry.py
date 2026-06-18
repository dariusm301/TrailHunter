import re
from normalizers.base import BaseNormalizer
from models.events import *


class RegistryNormalizer(BaseNormalizer):

    def _parse_registry(self, raw: dict, key_path: str) -> NormalizedEvent | None:
        try:
            result = NormalizedEvent(
                event=EventFields(
                    category="registry",
                    action="registry_change",
                    dataset="windows.registry",
                    module="registry",
                    original=str(raw).encode("utf-8") if raw else None,
                ),
                registry=RegistryFields(
                    path=self._clean(key_path),
                    value=self._clean(raw.get("name")),
                    data=self._clean(raw.get("value")),
                ),
            )
        except Exception as e:
            print(f"Error parsing registry event {raw} with key path {key_path}: {e}")
            return None
        return result

    def _parse_servicies(self, raw: dict, key_path: str) -> NormalizedEvent | None:
        try:
            executable, args = self._split_command(raw.get("imagepath"))

            result = NormalizedEvent(
                event=EventFields(
                    category="registry",
                    action="registry_change",
                    dataset="windows.registry",
                    module="registry",
                    original=str(raw).encode("utf-8") if raw else None,
                ),
                registry=RegistryFields(
                    path=self._clean(key_path),
                    value=self._clean(raw.get("name")),
                    data=self._clean(raw.get("imagepath")),
                ),
                process=ProcessFields(
                    name=self._normalize_process_name(raw.get("name")),
                    command_line=self._normalize_command_line(raw.get("imagepath")),
                    executable=self._normalize_executable(executable),
                    args=self._normalize_args(args),
                    args_count=len(args) if args else 0,
                ),
            )
        except Exception as e:
            print(f"Error parsing service registry event {raw} with key path {key_path}: {e}")
            return None
        return result

    def normalize(self, data: dict, key_path: str) -> NormalizedEvent | None:
        if not data:
            return None
        if "services" in key_path.lower():
            return self._parse_servicies(data, key_path)
        return self._parse_registry(data, key_path)