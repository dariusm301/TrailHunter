from normalizers.base import BaseNormalizer
from models.events import *


class NetworkNormalizer(BaseNormalizer):

    def _parse_interfaces(self, raw: dict) -> NormalizedEvent:
        try:
            result = NormalizedEvent(
                event=EventFields(
                    action="network_interface_snapshot",
                    category="configuration",
                    dataset="windows.network",
                    module="windows",
                    original=str(raw).encode("utf-8"),
                ),
                host=HostFields(
                    ip=self._normalize_ip(raw.get("ip_address")),
                ),
                network=NetworkFields(
                    name=self._clean(raw.get("interface")),
                    gateway=self._normalize_ip(raw.get("gateway")),
                    dns_servers=self._clean(raw.get("dns_servers")),
                ),
            )
        except Exception as e:
            print(f"Error parsing network interface {raw}: {e}")
            return None
        return result

    def _parse_tcp_connections(self, raw: dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action=f"tcp_{self._clean(raw.get('state', 'connection').lower())}",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8"),
            ),
            network=NetworkFields(
                protocol="tcp",
            ),
            source=SourceFields(
                ip=self._normalize_ip(raw.get("local_address")),
                port=self._normalize_port(raw.get("local_port")),
            ),
            destination=DestinationFields(
                ip=self._normalize_ip(raw.get("remote_address")),
                port=self._normalize_port(raw.get("remote_port")),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(raw.get("pid")),
                name=self._normalize_process_name(raw.get("process_name")),
            ),
        )

    def _parse_udp_endpoints(self, raw: dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="udp_endpoint",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8"),
            ),
            network=NetworkFields(
                protocol="udp",
            ),
            source=SourceFields(
                ip=self._normalize_ip(raw.get("local_address")),
                port=self._normalize_port(raw.get("local_port")),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(raw.get("pid")),
                name=self._normalize_process_name(raw.get("process_name")),
            ),
        )

    def _parse_listening_ports(self, raw: dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="listening_port",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8"),
            ),
            source=SourceFields(
                ip=self._normalize_ip(raw.get("local_address")),
                port=self._normalize_port(raw.get("local_port")),
            ),
            process=ProcessFields(
                pid=self._normalize_pid(raw.get("pid")),
                name=self._normalize_process_name(raw.get("process_name")),
            ),
        )

    def _parse_arp_cache(self, raw: dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="arp_cache_entry",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8"),
            ),
            host=HostFields(
                ip=self._normalize_ip(raw.get("ip_address")),
                mac=self._normalize_mac(raw.get("mac_address")),
            ),
            network=NetworkFields(
                name=self._clean(raw.get("interface")),
            ),
        )

    def _parse_dns_cache(self, raw: dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="dns_cache_entry",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8"),
            ),
            destination=DestinationFields(
                ip=self._normalize_ip(raw.get("data")),
            ),
            url=UrlFields(
                original=self._clean(raw.get("entry")),
            ),
        )

    def normalize(self, data: dict, data_type: str) -> NormalizedEvent | None:
        parser = getattr(self, f"_parse_{data_type}", None)
        if not parser:
            return None
        return parser(data)