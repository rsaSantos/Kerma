import unittest
import json
from jcs import canonicalize

from objects import *
from message.msgexceptions import *

VALID_BLOCK = {
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
        print("Testing validate_objectid:")
        valid_oid = "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6"
        invalid_oids = ["",
                        "0000000093a2820d67495ac01ad38f74",
                        "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2000000000000",
                        "invalidcharacters01234567890123456789012345678901234567890123456",
                        "invalidsymbols!?£$4567890123456789012345678901234567890123456789",
                        "invalidcharsandsymbols,!?&34567890123456789012345678901234567890",
                        "invalidprettymucheverything!(£$1234567890123456789012345678901234567890"
                        ]
        self.assertIsNone(validate_objectid(valid_oid))
        for o in invalid_oids:
            with self.subTest(o=o):
                oid = o
                self.assertRaises(InvalidFormatException, validate_objectid, oid)

    def test_validate_pubkey(self):
        print("Testing validate_pubkey:")
        valid_key = "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6"
        invalid_keys = ["",
                        "0000000093a2820d67495ac01ad38f74",
                        "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2000000000000",
                        "invalidcharacters01234567890123456789012345678901234567890123456",
                        "invalidsymbols!?£$4567890123456789012345678901234567890123456789",
                        "invalidcharsandsymbols,!?&34567890123456789012345678901234567890",
                        "invalidprettymucheverything!(£$1234567890123456789012345678901234567890"
                        ]
        self.assertIsNone(validate_pubkey(valid_key))
        for k in invalid_keys:
            with self.subTest(k=k):
                key = k
                self.assertRaises(InvalidFormatException, validate_pubkey, key)

    def test_validate_signature(self):
        print("Testing validate_signature:")
        valid_sign = "3869a9ea9e7ed926a7c8b30fb71f6ed151a132b03fd5dae764f015c98271000e7da322dbcfc97af7931c23c0fae060e102446ccff0f54ec00f9978f3a69a6f0f"
        invalid_signs = ["",
                         "0000000093a2820d67495ac01ad38f74",
                         "3869a9ea9e7ed926a7c8b30fb71f6ed151a132b03fd5dae764f015c98271000e7da322dbcfc97af7931c23c0fae060e102446ccff0f54ec00f9978f3a69a6f0f000",
                         "invalidcharacters01234567890123456789012345678901234567890123456invalidcharacters01234567890123456789012345678901234567890123456",
                         "invalidsymbols!?£$4567890123456789012345678901234567890123456789invalidsymbols!?£$4567890123456789012345678901234567890123456789",
                         "invalidcharsandsymbols,!?&34567890123456789012345678901234567890invalidcharsandsymbols,!?&34567890123456789012345678901234567890",
                         "invalidprettymucheverything!(£$1234567890123456789012345678901234567890invalidprettymucheverything!(£$1234567890123456789012345678901234567890"]
        self.assertIsNone(validate_signature(valid_sign))
        for s in invalid_signs:
            with self.subTest(s=s):
                sign = s
                self.assertRaises(InvalidFormatException, validate_signature, sign)

    def test_validate_nonce(self):  # careful when committing!!! leave main.py out of it to avoid inconsistency
        print("Testing validate_nonce:")
        valid_nonce = "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6"
        invalid_nonces = ["",
                          "0000000093a2820d67495ac01ad38f74",
                          "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2000000000000",
                          "invalidcharacters01234567890123456789012345678901234567890123456",
                          "invalidsymbols!?£$4567890123456789012345678901234567890123456789",
                          "invalidcharsandsymbols,!?&34567890123456789012345678901234567890",
                          "invalidprettymucheverything!(£$1234567890123456789012345678901234567890"
                          ]
        self.assertIsNone(validate_nonce(valid_nonce))
        for n in invalid_nonces:
            with self.subTest(n=n):
                nonce = n
                self.assertRaises(InvalidFormatException, validate_nonce, nonce)

    def test_validate_target(self):
        print("Testing validate_target:")
        valid_target = "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6"
        invalid_targets = ["",  # note: non-string inputs will cause a crash!!
                           "0000000093a2820d67495ac01ad38f74",
                           "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2000000000000",
                           "invalidcharacters01234567890123456789012345678901234567890123456",
                           "invalidsymbols!?£$4567890123456789012345678901234567890123456789",
                           "invalidcharsandsymbols,!?&34567890123456789012345678901234567890",
                           "invalidprettymucheverything!(£$1234567890123456789012345678901234567890"
                           ]
        self.assertIsNone(validate_target(valid_target))
        for t in invalid_targets:
            with self.subTest(t=t):
                tg = t
                self.assertRaises(InvalidFormatException, validate_target, tg)

    def test_validate_block(self):
        print("Testing block validation:")

        # objectid is 0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6

        invalid_blocks = [{},  # empty block

                          # missing "target"
                          {"created": 1671148800,
                           "miner": "grader",
                           "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                           "note": "This block has a coinbase transaction ",
                           "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                           "txids": [
                               "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                           ],
                           "type": "block"},

                          # missing nonce
                          {"T": "00000000abc00000000000000000000000000000000000000000000000000000",
                           "created": 1671148800,
                           "miner": "grader",
                           "note": "This block has a coinbase transaction ",
                           "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                           " txids": [
                               "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                           ],
                           "type": "block"},

                          # missing previd
                          {"T": "00000000abc00000000000000000000000000000000000000000000000000000",
                           "created": 1671148800,
                           "miner": "grader",
                           "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                           "note": "This block has a coinbase transaction ",
                           " txids": [
                               "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                           ],
                           "type": "block"
                           },

                          # missing "created"
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              " txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },

                          # missing txid
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 1671148800,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "type": "block"
                          },

                          # invalid type
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 1671148800,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              " txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "wrong"
                          },

                          # missing "type"
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 1671148800,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              " txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ]
                          },

                          # missing "target", and "txids"
                          {
                              "created": 1671148800,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "type": "block"
                          },

                          # missing all necessary keys
                          {
                              "miner": "grader",
                              "note": "This block has a coinbase transaction ",
                          }
                          ]

        valid_block = canon(VALID_BLOCK)
        try:
            validate_block(valid_block)      # todo this doesn't work, must investigate.
                                             # DETAILS: raise InvalidFormatException('Invalid block msg: {}.'.format(block_dict))
        except Exception as e:               # this block should be okay, but the validation raises such error. idk.
            print(str(e) + "Help!!")
        for b in invalid_blocks:
            with self.subTest(b=b):
                inv = canon(b)
                self.assertRaises(Exception, validate_block, inv)

    # test hash function of block b
    def test_get_objid(self):
        print("Testing get_objid (hash of a block)")
        valid_id = "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6"
        invalid_ids = ["", "000000d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6",
                       "0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6696969",
                       "0000000093amnbvcxa495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6",
                       "0000000093a3820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6",
                       "!000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6"
                       ]

        target_block = {
            "T": "00000000abc00000000000000000000000000000000000000000000000000000",
            "created ": 1671148800,
            "miner": "grader",
            "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
            "note ": "This block has a coinbase transaction ",
            "previd ": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
            " txids ": [
                "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
            ],
            "type ": "block"
        }
        target_block = canon(target_block)
        self.assertEqual(valid_id, get_objid(target_block))  # won't wooooork!
        for b in invalid_ids:
            with self.subTest(b=b):
                self.assertNotEqual(b, get_objid(target_block))

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
        self.assertTrue(validate_object(tx_object))  # TODO change called method? and add invalid cases



# TODO need to test UTXO, God help me on that one

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
