from normalizers.base import BaseNormalizer
from models.events import *
class NetworkNormalizer(BaseNormalizer):

    def _parse_interfaces(self, raw : dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="network_interface_snapshot",
                category="configuration",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8")
            ),
            host=HostFields(
                ip=raw.get("ip_address")   
            ),
            network=NetworkFields(
                name=raw.get("interface"),
                gateway=raw.get("gateway"),
                dns_servers=raw.get("dns_servers")
            )
        )
    
    def _parse_tcp_connections(self, raw : dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action=f"tcp_{raw.get('state', 'connection').lower()}",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8")
            ),
            network=NetworkFields(
                protocol="tcp",
            ),
            source=SourceFields(
                address=raw.get("local_address"),
                port=raw.get("local_port")
            ),
            destination=DestinationFields(
                address=raw.get("remote_address"),
                port=raw.get("remote_port")
            ),
            process=ProcessFields(
                pid=raw.get("pid"),
                name=raw.get("process_name")
            )
        )
    
    def _parse_udp_endpoints(self, raw : dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="udp_endpoint",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8")
            ),
            network=NetworkFields(
                protocol="udp",
            ),
            source=SourceFields(
                address=raw.get("local_address"),
                port=raw.get("local_port")
            ),
            process=ProcessFields(
                pid=raw.get("pid"),
                name=raw.get("process_name")
            )
        )
    
    def _parse_listening_ports(self, raw : dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="listening_port",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8")
            ),
            source=SourceFields(
                address=raw.get("local_address"),
                port=raw.get("local_port")
            ),
            process=ProcessFields(
                pid=raw.get("pid"),
                name=raw.get("process_name")
            )
        )
    
    def _parse_arp_cache(self, raw : dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="arp_cache_entry",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8")
            ),
            host=HostFields(
                ip=raw.get("ip_address"),
                mac=raw.get("mac_address")
            ),
            network=NetworkFields(
                name=raw.get("interface"),

            ),
        )
    
    def _parse_dns_cache(self, raw : dict) -> NormalizedEvent:
        return NormalizedEvent(
            event=EventFields(
                action="dns_cache_entry",
                category="network",
                dataset="windows.network",
                module="windows",
                original=str(raw).encode("utf-8")
            ),
            destination=DestinationFields(
                address=raw.get("data")
            ),
            url=UrlFields(
                original=raw.get("entry")
            )
        )


    def normalize(self, data : dict, data_type : str) -> NormalizedEvent | None:
        parser = getattr(self, f"_parse_{data_type}", None)
        if not parser:
            return None
        return parser(data)