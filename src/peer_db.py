from Peer import Peer
from typing import Iterable, Optional, Set
import time

PEER_DB_FILE = "peers.csv"

def get_peer_db_str(peer: Peer, timestamp: int) -> str:
    return f"{peer.host_str},{peer.port},{timestamp}"

def update_timestamp(peer: Peer, timestamp: int = 0):
    all_peers_dict = load_peers()
    if peer in all_peers_dict:
        all_peers_dict[peer] = int(timestamp)
        write_to_csv(all_peers_dict)

def remove_peer(peer: Peer):
    all_peers_dict = load_peers()
    if peer in all_peers_dict:
        del all_peers_dict[peer]
        write_to_csv(all_peers_dict)

def store_peers(peers: Iterable[Peer]):
    all_peers_dict = load_peers()

    for peer in peers:
        # CR: remove if statement "if p peer not in peers", now it always updates the value of peer to current timestamp
        all_peers_dict[peer] = int(time.time())

    write_to_csv(all_peers_dict)

def write_to_csv(peers_dict: dict):
    all_peers_str = [get_peer_db_str(peer, timestamp) for peer, timestamp in peers_dict.items()]
    with open(PEER_DB_FILE, "w") as f:
        f.write("host,port,timestamp\n")
        f.writelines([peer + "\n" for peer in all_peers_str])

def get_peer_from_str(s: str) -> (Peer, int):
    host, port, timestamp = s.split(",")
    return Peer(host, int(port)), int(timestamp)
    
def load_peers() -> dict[Peer, int]:
    with open(PEER_DB_FILE, "r") as f:
        f.readline() # Skip the first line
        peers_dic = dict()
        for line in f.readlines():
            peer, timestamp = get_peer_from_str(line)
            if peer not in peers_dic:
                peers_dic[peer] = timestamp

        return peers_dic

def get_shareable_peers() -> Set[str]:
    all_peers_dict = load_peers()

    all_peers_list = [(peer, timestamp) for peer, timestamp in all_peers_dict.items()]
    all_peers_list.sort(key = lambda x : x[1], reverse=True) # Sort peers by timestamp (newest first)
    all_peers_list = [str(peer) for peer, _ in all_peers_list]

    return set(all_peers_list[:29])          # Return the first 29 peers.
