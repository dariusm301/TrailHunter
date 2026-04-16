from abc import ABC, abstractmethod
from models.events import NormalizedEvent
from datetime import datetime
import re

class BaseNormalizer(ABC):

    @staticmethod
    def _parse_time(ts : str | None) -> datetime:
        if not ts:
            return datetime.now()
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    
    @staticmethod
    def parse_kv(message: str, delimiter: str = ";") -> dict:
        fields = {}
        for part in message.split(delimiter):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                fields[key.strip()] = value.strip()
        return fields
    
    @staticmethod
    def _parse_user(raw: str) -> tuple[str | None, str | None]:
        """"DOMAIN\\user -> (domain, username)"""
        if not raw:
            return None, None
        if "\\" in raw:
            domain, name = raw.split("\\", 1)
            return domain.strip(), name.strip()
        return None, raw.strip()
    
    @staticmethod
    def _clean(value: str | None) -> str | None:
        if value in ('', None, '-'):
            return None
        return value.strip()
    
    @staticmethod
    def _hex_to_int(value: str) -> int | None:
        try:
            return int(value, 16) if value else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_ms_date(value: str) -> datetime | None:
        if not value or not isinstance(value, str):
            return None
        match = re.search(r'd(\d+)', value)
        if match:
            timestamp = int(match.group(1)) / 1000
            return BaseNormalizer._parse_time(timestamp)
        return None
    
    @abstractmethod
    def normalize(self, data: dict) -> NormalizedEvent | None:
        raise NotImplementedError("Subclasses must implement this method")