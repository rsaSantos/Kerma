from Peer import Peer
from typing import Iterable, Set, Dict
import csv
import datetime
import constants as const

PEER_DB_FILE = "peers.csv"

# TODO: TASK 2: Logic on how to store/load peers. Introduce metadata: connected, last seen, etc.
##################
# Writing to DB:

#takes an object of type Peer, returns its string representation
def get_peer_db_str(peer: Peer) -> str:
   return f"{peer.host},{peer.port}"


# adds a set of peer to the csv
# I think this is for sure something that needs to change.
# Currently, the timestamp of "last_seen" is updated upon STORING the peer in the csv, not upon CONNECTING.
# I need to understand where exactly the connection is completed, so that I can adjust this logic flaw.
# It will probably make things trickier, but that's where my problem-solving skills will be honed, hopefully.
def store_peers(peers: Iterable[Peer]):
    all_peers = load_peers()

    for peer in peers:
        all_peers[peer] = datetime.datetime.now().date() #updates timestamp to today

    # all_peers = list(all_peers)[:500]

    all_peers = [peer.to_csv()+ ',' + str(ts) for peer,ts in all_peers.items()] #CR changed function to Peer.to_csv
    # new_rcvd_peers = set([peer.to_csv()+',' for peer in peers])
    # all_peers.update(new_rcvd_peers)

    write_to_csv(all_peers)

def write_to_csv(lines):
    with open(PEER_DB_FILE, "w") as f:
        f.write("host,port,last_seen\n") # Write the header
        f.writelines([line + "\n" for line in lines])


##################
# Reading from DB:
# datetime.strptime(datetime_str, '%m/%d/%y')
# builds a peer from a string
def get_peer_from_str(s: str) -> (Peer, datetime.datetime.date):
    host, port, timestamp = s.split(",")
    return Peer(host, int(port)), datetime.datetime.strptime(timestamp.rstrip(), '%Y-%m-%d').date()

# reads all peers from csv
def load_peers() -> Dict[Peer, datetime.datetime.date]:
    with open(PEER_DB_FILE, "r") as f:
        f.readline() # Skip the first line
        peers_dict = {}
        for line in f.readlines():
            peer, timestamp = get_peer_from_str(line)
            peers_dict[peer] = timestamp
        return peers_dict


#picks 29 peers from all peers recent enough (our own is appended first, see main)
def get_shareable_peers() -> Set[str]:

    def is_recent(timestamp): #return True if the timestamp is less or equal than 7 days ago
        return timestamp >= datetime.datetime.now().date() - datetime.timedelta(days=7)

    all_peers = load_peers()
    filtered_peers = filter( lambda x : is_recent (all_peers[x]), all_peers)

    all_peers_str = [str(peer) for peer in filtered_peers]
    return set(all_peers_str[:29]) #TODO add randomizer, I think it's the very core aspect of gossiping

# CR: to be precise, my idea would be: pick all the peers that are recent enough (e.g.: 245 peers),
# and select 29 of them randomly for sharing. Should the word "shareable" mean anything to me?
# Maybe I should have paid more attention to this "shareable" thing. That could be an important criterion I missed.