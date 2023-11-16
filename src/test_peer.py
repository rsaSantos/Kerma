import unittest
from Peer import Peer


class TestPeer(unittest.TestCase):

    def test_init(self):
        list_peers = [("192.101.100.151", 8080), ("testi.p", 8080), ("mypeeer.net", 18018)]
        for h, p in list_peers:
            with self.subTest(host=h, port=p):
                peer = Peer(h, p)
                self.assertIsInstance(peer, Peer)
                # assert isinstance(peer, Peer)


    def test_str(self):
        list_peers = [Peer("192.101.100.151", 8080), Peer("testi.p", 8080), Peer("mypeer.net", 18018)]
        expected_str = ["192.101.100.151:8080", "testi.p:8080", "mypeer.net:18018"]
        for p, s in zip(list_peers, expected_str):
            with self.subTest(p=p, s=s):  # creates subtest for each p and s in p[] and s[]
                self.assertEqual(s, str(p))


if __name__ == '__main__':
    unittest.main()
