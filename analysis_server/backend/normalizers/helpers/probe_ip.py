import ipaddress

def _is_meaningful_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not addr.is_link_local  
    except ValueError:
        return False

def _resolve_probe_ips(summary: dict) -> set[str]:
   
    collector_ip = summary.get("collector_ip", {})
    all_ips = {ip for ips in collector_ip.values() for ip in ips}
    return {ip for ip in all_ips if _is_meaningful_ip(ip)}