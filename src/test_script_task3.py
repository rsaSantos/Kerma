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


class TestTask3(unittest.IsolatedAsyncioTestCase):

    #############################################
    # TESTING BLOCK VALIDATION

    # Testing support functions for evaluation
    # These are super trivial, I will perform these tests for
    # Both practicing and because u can never be too sure.
    def test_validate_objectid(self):
        valid_oid = "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6"
        invalid_oids = ["",
                        "0000000093a2820d67495ac01ad38f74",
                        "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2000000000000",
                        "invalidcharacters01234567890123456789012345678901234567890123456",
                        "invalidsymbols!?£$4567890123456789012345678901234567890123456789",
                        "invalidcharsandsymbols,!?&34567890123456789012345678901234567890",
                        "invalidprettymucheverything!(£$1234567890123456789012345678901234567890"
                        ]
        self.assertIsNone(validate_objectid(valid_oid))  # a la verga SOY GENIUS
        for o in invalid_oids:
            with self.subTest(o=o):
                oid = o
                self.assertRaises(InvalidFormatException, validate_objectid, oid)

    def test_validate_pubkey(self):
        # TODO
        return True

    def test_validate_signature(self):
        # TODO
        return True

    def test_validate_nonce(self):
        # TODO
        return True

    def test_validate_target(self):
        # TODO
        return True


    def test_validate_block(self):
        # objectid is 0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6
        print("Testing block validation:")
        valid_object = {
            "T": "00000000abc00000000000000000000000000000000000000000000000000000",
            "created": 1671148800,
            "miner": "grader",
            "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
            "note": "This block has a coinbase transaction ",
            "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
            " txids": [
                "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
            ],
            "type": "block"
        }

        # TODO : define invalid blocks, each with some invalid parameter (e.g.: Target, nonce, type, missing keys...
        # TODO : append those to a list, and run the test using SubTest. Piece a cake, go go go!!!
        valid_object = canon(valid_object)
        self.assertTrue(validate_object(valid_object))

    def test_get_objid(self):
        # TODO : try incorrect hash, empty value, invalid value ("_$!", idk)
        return True

    def test_block_missing_keys(self):  # TODO refactor in test_validate_block!!
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

    ############################################
    # TESTING COINBASE TXs

    def test_coinbase_evaluation(self):
        print("Testing coinbase value")
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
        self.assertTrue(validate_object(tx_object))  # TODO change method and add invalid cases. sT may be required.

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
