from Peer import Peer
from typing import Iterable, Optional, Set
import csv

PEER_DB_FILE = "peers.csv"


def store_peer(peer: Peer, existing_peers: Optional[Iterable[Peer]] = None):
    with open(PEER_DB_FILE, 'a',newline='') as fd:
        row = [peer.host_formated, peer.port] #or host? what's the difference?
        writer = csv.writer(fd)
        writer.writerow(row)
    # append to file


def load_peers() -> Set[Peer]:
    file = open(PEER_DB_FILE)
    reader = csv.reader(file)
    peers = set()
    for row in reader:
        if row[1].isdigit():        # this should skip the header, ok
            peer = Peer (row[0], int(row[1])) #TODO test cases: what if row1 is negative? etc
            print(peer)
            peers.add(peer)
        else:
            pass
    print(peers)
    return peers


    # read from file

