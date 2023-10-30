import ipaddress

"""
host
host_formated == host for hostname and ipv4
              == bracket wrapped IPv6 address
"""
class Peer:
    def __init__(self, host_str, port:int):
        self.port = port
        try:
            ip = ipaddress.ip_address(host_str)
            self.host_str = ip.compressed
        except:
            # not an ip, but a DNS name
            self.host_str = host_str

    def __str__(self) -> str:
        return f"{self.host_str}:{self.port}"

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Peer) and self.host_str == o.host_str \
            and self.port == o.port

    def __hash__(self) -> int:
        return (self.port, self.host_str).__hash__()

    def __repr__(self) -> str:
        return f"Peer: {self}"
