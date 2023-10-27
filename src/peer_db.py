from Peer import Peer
from typing import Iterable, Optional, Set
import csv

PEER_DB_FILE = "peers.csv"

# TODO: TASK 2: Logic on how to store/load peers. Introduce metadata: connected, last seen, etc.

##################
# Writing to DB:

def get_peer_db_str(peer: Peer) -> str:
    return f"{peer.host},{peer.port}"

def store_peers(peers: Iterable[Peer]):
    # Update the DB: get all peers and add the new ones
    all_peers = load_peers()

    # TODO: Get only the first 500 peers (for now) -> FIX W/ TIMESTAMP?
    all_peers = list(all_peers)[:500]

    all_peers = set([get_peer_db_str(peer) for peer in all_peers])
    new_rcvd_peers = set([get_peer_db_str(peer) for peer in peers])

    all_peers.update(new_rcvd_peers)
    with open(PEER_DB_FILE, "w") as f:
        f.write("host,port\n") # Write the header
        f.writelines([peer + "\n" for peer in all_peers])

##################
# Reading from DB:

def get_peer_from_str(s: str) -> Peer:
    host, port = s.split(",")
    return Peer(host, int(port))

def load_peers() -> Set[Peer]:
    with open(PEER_DB_FILE, "r") as f:
        f.readline() # Skip the first line
        return set([get_peer_from_str(line) for line in f.readlines()])

def get_shareable_peers() -> Set[str]:
    all_peers = load_peers()

    # TODO: For now, there is no strategy for choosing which peers to share.
    all_peers_str = [str(peer) for peer in all_peers]
    return set(list(all_peers_str)[:29])
