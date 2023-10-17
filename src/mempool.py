import copy
import sqlite3

import constants as const
import objects

# get expanded object for 
def fetch_object(oid, cur):
    pass # TODO

# get utxo for block
def fetch_utxo(bid, cur):
    pass # TODO

# returns (blockid, intermediate_blocks)
def find_lca_and_intermediate_blocks(tip, blockids):
    pass # TODO

# return a list of transactions by index
def find_all_txs(txids):
    pass # TODO

# return a list of transactions in blocks
def get_all_txids_in_blocks(blocks):
    pass # TODO

# get (id of lca, list of old blocks from lca, list of new blocks from lca) 
def get_lca_and_intermediate_blocks(old_tip: str, new_tip: str):
    pass # TODO

def rebase_mempool(old_tip, new_tip, mptxids):
    pass # TODO

class Mempool:
    def __init__(self, bbid: str, butxo: dict):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = []

    def try_add_tx(self, tx: dict) -> bool:
        pass # TODO

    def rebase_to_block(self, bid: str):
        pass # TODO