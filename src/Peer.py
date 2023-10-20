import ipaddress

"""
host
host_formated == host for hostname and ipv4
"""
class Peer:
    def __init__(self, host_str, port:int):
        self.port = port
        self.host_formated = ''
        self.host = ''
        # TODO: validate host_str and populate properties
        self.host = host_str

    def __str__(self) -> str:
        return f"{self.host_formated}:{self.port}"

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Peer) and self.host == o.host \
            and self.port == o.port

    def __hash__(self) -> int:
        return (self.port, self.host).__hash__()

    def __repr__(self) -> str:
        return f"Peer: {self}"
