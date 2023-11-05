from unittest import TestCase

from Peer import Peer
from peer_db import write_to_csv, get_shareable_peers, load_peers, store_peers, PEER_DB_FILE
import datetime
import time


class TestPeerDB(TestCase):
    def setUp(self):
        self.hosts = ['35.207.97.80', '35.207.97.80', '100.100.101.102', '128.130.122.101', '102.100.101.105', '0.0.0.0', '101.100.101.102']
        self.ports = ['18018', '18019','18018','18018','18018','18019','18018']
        self.dates = ['2023-10-27', '2023-01-19', '2023-09-25', '2023-10-28', '2022-10-29', '2023-10-22', '2022-08-25']
        self.stamps = [int(time.mktime(datetime.datetime.strptime(s, "%Y-%m-%d").timetuple())) for s in self.dates]
        self.test_db = {Peer(h, p): s for h, p, s in zip(self.hosts, self.ports, self.stamps)}
        write_to_csv(self.test_db)

    def tearDown(self): #what to do after tests are performed (e.g.: delete files created in the process)
        pass

    def test_get_shareable_peers(self):
        shareable_peers = get_shareable_peers() #expect peers list sorted by timestamp (int descending)
        expected_shareable_peers = {str(h)+":"+str(p) for h, p in zip(self.hosts, self.ports)} # set of peers strings
        self.assertEqual(shareable_peers, expected_shareable_peers) # should verify with more than 29 peers

    def test_load_peers(self):
        peers = load_peers()
        true_peers = {Peer(h,int(p)): s
                      for h, p, s in zip(self.hosts, self.ports, self.stamps)}
        self.assertEqual(true_peers, peers)

    def test_store_peers(self):
        peers_to_write = [Peer('111.222.111.222',18018), Peer('222.100.222.100',18018), Peer('35.207.97.80',18018)]
        store_peers(peers_to_write)
        now_timestamp = int(time.time())
        with open(PEER_DB_FILE, "r") as f:
            file = f.readlines()
        expected_line_list = (['host,port,timestamp\n',] +
                              [h + ',' + p + ',' + str(s) + '\n' for h, p, s in zip(self.hosts, self.ports, self.stamps)] +
                              ['111.222.111.222,18018,'+ str(now_timestamp) +'\n', '222.100.222.100,18018,'+
                               str(now_timestamp) +'\n'])
        expected_line_list[1] = '35.207.97.80,18018,'+ str(now_timestamp)+'\n'
        self.assertEqual(expected_line_list, file)
        # expected_peers = load_peers()