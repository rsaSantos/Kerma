import unittest
import json
from jcs import canonicalize

from objects import *
from message.msgexceptions import *

# support snippettino
def canon(obj):
    obj = canonicalize(obj)
    obj = json.loads(obj.decode())
    return obj

# tx_object = canonicalize(tx_object)
# tx_object = json.loads(tx_object.decode())

class TestTask3(unittest.IsolatedAsyncioTestCase):

    #############################################
    # TESTING BLOCK VALIDATION

    def test_valid_block(self):
        # objectid is 0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6
        print("Testing block validation 1: Valid Block")
        valid_object = {
            "T": "00000000abc00000000000000000000000000000000000000000000000000000",
            "created" : 1671148800,
            "miner" : "grader",
            "nonce" : "1000000000000000000000000000000000000000000000000000000001aaf999",
            "note" : "This block has a coinbase transaction ",
            "previd" : "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
            " txids" : [
                "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
            ],
            "type": "block"  # space in "type " won't do, "type" is fine. help.
        }
        valid_object = canon(valid_object)
        self.assertTrue(validate_object(valid_object))

    def test_block_bad_timestamp(self):
        # timestamps ("created" key) can be invalid?
        return True

    def test_block_missing_keys(self):
        print("Testing block validation 3: Missing Key")
        invalid_object = {  # missing "prev_id"
            "T": "00000000abc00000000000000000000000000000000000000000000000000000",
            "created ": 1671148800,
            "miner": "grader",
            "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
            "note ": "This block has a coinbase transaction ",
            " txids ": [
                "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
            ],
            "type": "block"  # space in "type " won't do, "type" is fine. help.
        }
        invalid_object = canon(invalid_object)
        self.assertRaises(InvalidFormatException, validate_object, invalid_object)
        # validateObject should contain all necessary keys
        # unittest > subtest, otherwise use pytest
        # create a list of json blocks, for json in jsonlist assertRaise or smth. if it works, try subtest.
        # TODO try removing other keys, more keys, all keys.
    def test_block_target(self):
        # has to be 00000000abc00000000000000000000000000000000000000000000000000000
        #
        # TODO
        return True

    def test_verify_pow(self):  # good + bad ending? does it exist? where?
        # TODO
        return True

    def test_block_txs(self):
        # function to test: (if we have block txs in our db. if not, check if we send "getobject" msg.)
        # TODO how?
        return True

    def test_block_indexing_with_coinbase(self):
        # we have a bunch of txs, but the coinbase one is not at index 0.
        # TODO
        return True


    ############################################
    # TESTING COINBASE TXs

    def test_coinbase_evaluation_valid(self):
        print("Testing coinbase value (valid)")
        tx_object = {
            "height": 0,
            "outputs": [
                {
                    "pubkey": "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b",
                    "value": 50000000000000
                }
            ],
            "type": "transaction"
        }
        tx_object = canon(tx_object)
        self.assertTrue(validate_object(tx_object))  # TODO change method

    def test_coinbase_index(self):
        tx_object = {
            "height": 1,  # has to be 0, if it's not we expect an error
            "outputs": [
                {
                    "pubkey": "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969",
                    "value": 50000000000000
                }
            ],
            "type": "transaction"
        }
        self.assertRaises(Exception, validate_transaction, tx_object)  # TODO refine

    def test_coinbase_evaluation_invalid(self):
        print("Testing coinbase value (not valid)")
        tx_object = {
            "height": 0,
            "outputs": [
                {
                    "pubkey": "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969",
                    "value": 20000000000000  # too little! should throw an exception
                }
            ],
            "type": "transaction"
        }

        tx_object = canon(tx_object)
        self.assertRaises(InvalidFormatException, validate_transaction, tx_object)  # TODO


if __name__ == '__main__':
    unittest.main()

'''
objectid is 0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6
{
    "T": "00000000abc00000000000000000000000000000000000000000000000000000" ,
    "created ": 1671148800,
    "miner": "grader" ,
    "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999" ,
    "note ": "This block has a coinbase transaction " ,
    "previd ": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2" ,
    " txids ": [
        "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
    ] ,
    "type ": "block"
}
'''
