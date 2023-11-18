import unittest
import json
from jcs import canonicalize

from objects import *
from message.msgexceptions import *

VALID_BLOCK = {
    "T": "00000000abc00000000000000000000000000000000000000000000000000000",
    "created": 1671148800,
    "miner": "grader",
    "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
    "note": "This block has a coinbase transaction ",
    "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
    "txids": [
        "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
    ],
    "type": "block"
}

COINBASE_TX = {
    "height": 0,
    "outputs": [
        {
            "pubkey": "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b",
            "value": 50000000000000
        }
    ],
    "type": "transaction"
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
        invalid_targets = ["",
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

    def test_valid_block_valid(self):
        try:
            valid_block = canon(VALID_BLOCK)
            # self.assertEqual({'missing_tx_ids': ['6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a']}, validate_block(valid_block))
            genesis = canon(const.GENESIS_BLOCK)  # todo investigate, doesn't work. PoW is wrong for genesis ID?? should we even validate GENESIS?
            validate_block(valid_block)
            validate_block(genesis)
        except Exception:
            self.fail("Exception was thrown")  # there was an exception
        # self.assertEqual({'missing_tx_ids': []}, validate_block(genesis))

    # what I want to do here is: I have a list of invalid blocks, and a list that corresponds to the exceptions
    # that each invalid block is supposed to raise. These are paired in a zip function.
    def test_validate_block_invalid(self):

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
                          },
                          # invalid T value
                          {
                              "T": "10000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 1671148800,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },

                          # invalid nonce: not hex
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 1671148800,
                              "miner": "grader",
                              "nonce": "10000000zy000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },
                          # invalid nonce: too long
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 1671148800,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf9990",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },
                          # "created" has value None
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": None,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              " txids ": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },
                          # "created" value is too old (with respect to prev_data)
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 15,  # IS THIS OLD ENOUGH?
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },
                          # "note" value is invalid (too long)
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 1671148800,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "Nobody expects the Spanish Inquisition! Our chief weapon is surprise...surprise and fear...fear and surprise.... our two weapons are fear and surprise...and ruthless efficiency.",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },
                          # "miner" value is invalid (too long)
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": 1671148800,
                              "miner": "Nobody expects the Spanish Inquisition! Amongst our weaponry are such diverse elements as fear, surprise, ruthless efficiency, and an almost fanatical devotion to the Pope, and nice red uniforms - oh damn!",
                              # TODO QUI
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },
                          # "created" value is not valid (negative number)
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": -1,
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              "txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          },
                          # "created" value is not valid (type mismatch)
                          {
                              "T": "00000000abc00000000000000000000000000000000000000000000000000000",
                              "created": "and now for something completely different",
                              "miner": "grader",
                              "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
                              "note": "This block has a coinbase transaction ",
                              "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                              " txids": [
                                  "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
                              ],
                              "type": "block"
                          }

                          ]
        expected_exceptions = [KeyError,  # 0 empty block fails when fetching key `previd`
                               InvalidFormatException,  # 1 missing key "target"
                               InvalidFormatException,  # 2 missing key "nonce"
                               KeyError,  # 3 missing key "previd" when fetching key `previd`
                               InvalidFormatException,  # 4 missing key "created"
                               InvalidFormatException,  # 5 missing key "txid"
                               InvalidFormatException,  # 6 invalid key "type"
                               InvalidFormatException,  # 7 missing key "type"
                               InvalidFormatException,  # 8 two missing keys
                               KeyError,  # 9 all keys missing when fetching key `previd`
                               InvalidFormatException,  # 10 invalid target
                               InvalidFormatException,  # 11 invalid nonce, not hex
                               InvalidFormatException,  # 12 invalid nonce, too long
                               InvalidFormatException,  # 13 "created" is none
                               InvalidBlockTimestampException,  # 14 "created" is invalid
                               InvalidBlockTimestampException,  # 15 "note" is too long
                               InvalidBlockTimestampException,  # 16 "miner" too long
                               InvalidBlockTimestampException,  # 17 "created" is invalid (e.g.: -1)
                               InvalidFormatException]  # 18 "created" is invalid (e.g.: string)
        for b, e in zip(invalid_blocks, expected_exceptions):
            with self.subTest(b=b, e=e):
                inv = canon(b)
                self.assertRaises(e, validate_block, inv)  # self.assertraises "e" from zip :D

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
            "created": 1671148800,
            "miner": "grader",
            "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999",
            "note": "This block has a coinbase transaction",
            "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
            "txids": [
                "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
            ],
            "type": "block"
        }
        target_block = canon(target_block)
        self.assertEqual(valid_id, get_objid(target_block))  # won't wooooork!
        for b in invalid_ids:
            with self.subTest(b=b):
                self.assertNotEqual(b, get_objid(target_block))

    def test_verify_block(self):
        # call None, None, prev_utxo, prev_height, txs

        """ if coinbase_tx is not None and coinbase_tx['height'] != height:
            raise InvalidBlockCoinbaseException("Coinbase transaction does not have the correct height.
            Block height is {}, coinbase height is {}.".format(height, coinbase_tx['height']))
        """

        """ Iterate over all transactions in the block...skip coinbase if needed
            total_fees = 0
            for tx in txs[1:] if is_first_transaction_coinbase else txs:
                If the transaction is coinbase, throw an error because it should be the first transaction
                if 'inputs' not in tx:
                raise InvalidBlockCoinbaseException("A coinbase transaction was referenced but is not at the first position.")"""

        """        if i['outpoint']['txid'] not in input_txs_dicts:
            raise UnknownObjectException('Object not present in DB: {}.'.format(i['outpoint']['txid']))"""

        """tx_data = input_txs_dicts[i['outpoint']['txid']]
        if(tx_data is None):
            raise UnknownObjectException('Object not present in DB: {}.'.format(i['outpoint']['txid']))"""
        pass

    def test_validate_transaction(self):
        invalid_transactions = [
            # missing "type" key
            {"inputs": [
                {
                    "outpoint": {
                        "txid": "f71408bf847d7dd15824574a7cd4afdfaaa2866286910675cd3fc371507aa196",
                        "index": 0
                    },
                    "sig": "3869a9ea9e7ed926a7c8b30fb71f6ed151a132b03fd5dae764f015c98271000e7da322dbcfc97af7931c23c0fae060e102446ccff0f54ec00f9978f3a69a6f0f"
                }
            ],
                "outputs": [
                    {
                        "pubkey": "077a2683d776a71139fd4db4d00c16703ba0753fc8bdc4bd6fc56614e659cde3",
                        "value": 5100000000
                    }
                ]
            },

            # missing "outputs" key
            {"type": "transaction",
             "inputs": [
                 {
                     "outpoint": {
                         "txid": "f71408bf847d7dd15824574a7cd4afdfaaa2866286910675cd3fc371507aa196",
                         "index": 0
                     },
                     "sig": "3869a9ea9e7ed926a7c8b30fb71f6ed151a132b03fd5dae764f015c98271000e7da322dbcfc97af7931c23c0fae060e102446ccff0f54ec00f9978f3a69a6f0f"
                 }
             ]
             },
            # missing "inputs" key
            {"type": "transaction",
             "outputs": [
                 {
                     "pubkey": "077a2683d776a71139fd4db4d00c16703ba0753fc8bdc4bd6fc56614e659cde3",
                     "value": 5100000000
                 }
             ]
             },
            # missing "height" key (coinbase transaction)
            {
                "outputs": [
                    {
                        "pubkey": "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b",
                        "value": 50000000000000
                    }
                ],
                "type": "transaction"
            }
        ]

        for it in invalid_transactions:
            it = canon(it)
            with self.subTest(it=it):
                self.assertRaises(InvalidFormatException, validate_transaction, it)
        # TODO add more tests, yes yes I am actively avoiding database interaction ç.ç

    def test_handle_object_message(self):
        # TODO
        pass


"""
@@@ VALID BLOCK @@@
objectid is 0000000093a2820d67495ac01ad38f74eabd8966517ab15c1cb3f2df1c71eea6
{
    "T": "00000000abc00000000000000000000000000000000000000000000000000000" ,
    "created ": 1671148800,
    "miner": "grader" ,
    "nonce": "1000000000000000000000000000000000000000000000000000000001aaf999" ,
    "note": "This block has a coinbase transaction " ,
    "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2" ,
    " txids": [
        "6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"
    ] ,
    "type": "block"
}
"""


"""
@@@ VALID TRANSACTION (syntactically, that is) @@@
{
"type":" transaction " ,
"inputs":[
{
"outpoint":{
"txid":"f71408bf847d7dd15824574a7cd4afdfaaa2866286910675cd3fc371507aa196" ,
"index":0
},
"sig":"3869a9ea9e7ed926a7c8b30fb71f6ed151a132b03fd5dae764f015c98271000e7
da322dbcfc97af7931c23c0fae060e102446ccff0f54ec00f9978f3a69a6f0f"
}
] ,
"outputs":[
{
"pubkey":"077a2683d776a71139fd4db4d00c16703ba0753fc8bdc4bd6fc56614e659cde3" ,
"value":5100000000
}
]
}
"""