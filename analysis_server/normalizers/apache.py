from normalizers.base import BaseNormalizer
from models.events import *

class ApacheNormalizer(BaseNormalizer):
    
    def _normalize_access_log(self, raw : dict) -> NormalizedEvent:
        """ Example Apache access log format:
         {
              "client_ip": "127.0.0.1",
              "timestamp": "28/Mar/2026:02:42:44 +0200",
              "method": "GET",
              "path": "/security.php",
              "status_code": 200,
              "bytes": 5188,
              "referer": "http://127.0.0.1/index.php",
              "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
            }
        """
        return NormalizedEvent(
            event=EventFields(
                action="apache_access_log",
                category="web",
                dataset="apache.access",
                module="apache",
                original=str(raw).encode("utf-8"),
                created=raw.get("timestamp")
            ),
            network=NetworkFields(
                protocol="http",
                transport="tcp",
                direction="inbound"
            ),
            source=SourceFields(
                address=raw.get("client_ip")
            ),
            http=HTTPFields(
                request_method=raw.get("method"),
                response_status_code=raw.get("status_code"),
                agent=raw.get("user_agent")
            ),
            url=UrlFields(
                original=raw.get("referer"),
                path=raw.get("path")
            )
        )

    def _normalize_error_log(self, raw: dict) -> NormalizedEvent:
        """ Example Apache error log format:
        {
              "timestamp": "Sat Mar 28 02:39:18.085906 2026",
              "level": "ssl:warn",
              "module": "pid 10972:tid 460",
              "client": null,
              "message": "AH01909: www.example.com:443:0 server certificate does NOT include an ID which matches the server name"
        }
        """
        return NormalizedEvent(
            event=EventFields(
                action="apache_error_log",
                category="web",
                dataset="apache.error",
                module="apache",
                original=str(raw).encode("utf-8"),
                created=raw.get("timestamp"),
                severity_label=raw.get("level"),
                reason=raw.get("message")
            ),
            source=SourceFields(
                address=raw.get("client", "").split(":")[0] if raw.get("client") else None,
                port=int(raw.get("client", "").split(":")[1]) if raw.get("client") and ":" in raw.get("client") else None
            )
        )
    
    def normalize(self, raw: dict, log_type : str) -> NormalizedEvent:
        if "access" in log_type:
            return self._normalize_access_log(raw)
        elif "error" in log_type:
            return self._normalize_error_log(raw)
        else:
            raise ValueError(f"Unsupported log type: {log_type}")
