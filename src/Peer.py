import ipaddress
import socket

"""
host
host_formated == host for hostname and ipv4
              == bracket wrapped IPv6 address
"""
class Peer:
    def __init__(self, host_str, port:int):
        self.host_ip = None
        self.port = port
        try:
            self.host_ip = ipaddress.ip_address(host_str)
            self.host_str = self.host_ip.compressed
        except:
            # not an ip, but a DNS name
            try:
                self.host_str = host_str
                ip_str = socket.gethostbyname(host_str)
                self.host_ip = ipaddress.ip_address(ip_str)
            except:
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

    # CR think of this function as some "Object.ToString()" in Java, that's why it's placed here
    def to_csv(self):
        return f"{self.host},{self.port}"
