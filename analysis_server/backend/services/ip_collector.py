import socket
import psutil

def get_collector_ips() -> dict[str, list[str]]:
    """Returns a map of interface_name -> [ipv4, ...]"""
    result = {}
    for iface, addrs in psutil.net_if_addrs().items():
        ipv4s = [
            a.address
            for a in addrs
            if a.family == socket.AF_INET and not a.address.startswith("127.")
        ]
        if ipv4s:
            result[iface] = ipv4s
    return result