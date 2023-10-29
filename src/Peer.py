import ipaddress

"""
host
host_formated == host for hostname and ipv4
              == bracket wrapped IPv6 address
"""
class Peer:
    def __init__(self, host_str, port:int):
        self.port = port
        self.isBoostrap = False # peers which are created were not hardcoded, thus isBootstrap is False
        try:
            ip = None
            ip = ipaddress.ip_address(host_str)

            self.host = ip.compressed

            self.host_formatted = self.host
        except:
            # not an ip, but a DNS name
            self.host = host_str
            self.host_formatted = host_str
        # CR hostname is still to be validated
        # the to-do tag in the solution is still there.
        # I think we validated it in main.py?

    def tagBootstrap(self):
        self.isBoostrap = True

    def __str__(self) -> str:
        return f"{self.host_formatted}:{self.port}"

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Peer) and self.host == o.host \
            and self.port == o.port

    def __hash__(self) -> int:
        return (self.port, self.host).__hash__()

    def __repr__(self) -> str:
        return f"Peer: {self}"
