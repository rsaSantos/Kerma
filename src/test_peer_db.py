from unittest import TestCase

from Peer import Peer
from peer_db import write_to_csv, get_shareable_peers, load_peers, store_peers, PEER_DB_FILE
import datetime


class TestPeerDB(TestCase):
    def setUp(self):
        self.hosts = ['35.207.97.80', '35.207.97.80', '100.100.101.102', '128.130.122.101', '102.100.101.105', '0.0.0.0', '101.100.101.102']
        self.ports = ['18018', '18019','18018','18018','18018','18019','18018']
        self.stamps = ['2023-10-27', '2023-01-19', '2023-09-25', '2023-10-28', '2022-10-29', '2023-10-22', '2022-08-25']
        self.test_db = [h + ',' + p + ',' + s  for h, p, s in zip(self.hosts, self.ports, self.stamps)]
        write_to_csv(self.test_db)

    def tearDown(self): #what to do after tests are performed (e.g.: delete files created in the process)
        pass

    def test_get_shareable_peers(self):
        shareable_peers = get_shareable_peers()
        self.assertEqual({str(Peer('128.130.122.101',18018)),
                           str(Peer('35.207.97.80',18018)),
                           str(Peer('0.0.0.0', 18019))},
                          shareable_peers)

    def test_load_peers(self):
        peers = load_peers()
        true_peers = {Peer(h,int(p)): datetime.datetime.strptime(s.rstrip(),'%Y-%m-%d').date()
                      for h, p, s in zip(self.hosts, self.ports, self.stamps)}
        self.assertEqual(true_peers, peers)

    def test_store_peers(self):
        peers_to_write = [Peer('111.222.111.222',18018), Peer('222.100.222.100',18018), Peer('35.207.97.80',18018)]
        store_peers(peers_to_write)
        date_today = str(datetime.datetime.now().date())
        with open(PEER_DB_FILE, "r") as f:
            file = f.readlines()
        expected_line_list = (['host,port,last_seen\n',] +
                              [h + ',' + p + ',' + s + '\n'  for h, p, s in zip(self.hosts, self.ports, self.stamps)] +
                              ['111.222.111.222,18018,'+date_today+'\n', '222.100.222.100,18018,'+date_today+'\n'])
        expected_line_list[1] = '35.207.97.80,18018,'+date_today+'\n'
        self.assertEqual(expected_line_list, file)
        # expected_peers = load_peers()