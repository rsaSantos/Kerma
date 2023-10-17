from Peer import Peer
from typing import Iterable, Set

PEER_DB_FILE = "peers.csv"


def store_peer(peer: Peer, existing_peers: Iterable[Peer] = None):
    # append to file
    pass


def load_peers() -> Set[Peer]:
    # read from file
    pass
