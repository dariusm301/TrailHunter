import re

from normalizers.base import BaseNormalizer
from models.events import *
class RegistryNormalizer(BaseNormalizer):
    def _parse_registry(self, raw: dict, key_path: str) -> NormalizedEvent:
        
        return NormalizedEvent(
            event=EventFields(
                category="registry",
                action="registry_change",
                dataset="windows.registry",
                module="registry",
                original=str(raw).encode('utf-8') if raw else None
            ),

            registry=RegistryFields(
                path=self._clean(key_path),
                value=self._clean(raw.get("name")),
                data=self._clean(raw.get("value"))
            )
        )
    def _parse_servicies(self, raw: dict, key_path: str) -> NormalizedEvent:
        
        executable = None
        args = None
        extensions = "exe|bat|cmd|ps1|vbs|js|msc"
        pattern = rf"^(.*?\.(?:{extensions}))\s*(.*)$"     
        match = re.search(pattern, raw.get("imagepath", ""), re.IGNORECASE)
        if match:
            executable = match.group(1)
            args = match.group(2)
        return NormalizedEvent( 
            event=EventFields(
                category="registry",
                action="registry_change",
                dataset="windows.registry",
                module="registry",
                original=str(raw).encode('utf-8') if raw else None
            ),
            registry=RegistryFields(
                path= key_path,
                value=self._clean(raw.get("name")),
                data=self._clean(raw.get("imagepath"))
            ),
            process=ProcessFields(
                name=raw.get("name"),
                command_line=raw.get("imagepath"),
                executable=executable if executable else None,
                args=args.split() if args else None,
                args_count=len(args.split()) if args else 0
            )
        )
    
    def normalize(self, data: dict, key_path: str) -> NormalizedEvent | None:
        if not data:
            return None
        if "services" in key_path.lower():
            return self._parse_servicies(data, key_path)
        return self._parse_registry(data, key_path)