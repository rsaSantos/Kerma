import copy
import sqlite3

import constants as const
import kermastorage
import copy
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

def rebase_mempool(old_tip_block, new_tip_block, mptxids):
    block_pointer = new_tip_block
    while(kermastorage.get_block_height(block_pointer) != kermastorage.get_block_height(old_tip_block)):
        block_pointer = kermastorage.get_block_data(block_pointer)['previd']
    old_tip_divergent_blocks = []
    old_tip_pointer = old_tip_block
    while(kermastorage.get_block_data(old_tip_pointer)['previd'] != kermastorage.get_block_data(block_pointer)['previd']):
        old_tip_divergent_blocks.append(old_tip_pointer)
        old_tip_pointer = kermastorage.get_block_data(old_tip_pointer)['previd']
        block_pointer = kermastorage.get_block_data(block_pointer)['previd']
    old_tip_divergent_blocks.reverse()
    missing_txs = []
    for block_id in old_tip_divergent_blocks:
        missing_txs += kermastorage.get_block_data(block_id)['txids']
    missing_txs += mptxids
    return missing_txs
        
class Mempool:
    def __init__(self, bbid: str, butxo: dict):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = []
        self.utxo_spent_values = dict()

    def try_add_tx(self, tx: dict) -> bool:
        num_of_occurences = 0
        sum_of_inputs = 0
        for input_tx in tx['inputs']:
            for i in range(len(self.utxo)):
                if(input_tx['outpoint']['txid'] == self.utxo[i]['txid'] and input_tx['outpoint']['index'] == self.utxo[i]['index']):
                    num_of_occurences += 1
                    sum_of_inputs += self.utxo[i]['value']
                    self.utxo_spent_values[(self.utxo[i]['txid'], self.utxo[i]['index'])] -= self.utxo[i]['value']
                    if(self.utxo_spent_values[(self.utxo[i]['txid'], self.utxo[i]['index'])] < 0):
                        return False
                    break
        if(len(tx['inputs']) != num_of_occurences):
            return False
        
        sum_of_outputs = sum([o['value'] for o in tx['outputs']])
        if(sum_of_outputs > sum_of_inputs):
            return False
        
        append_utxo = []
        for i in range(len(tx['outputs'])):
            append_utxo.append({"txid": objects.get_objid(tx), "index": i, "value": tx['outputs'][i]['value']})
            self.utxo_spent_values[(objects.get_objid(tx), i)] = tx['outputs'][i]['value']
            
        self.txs.append(objects.get_objid(tx))
        self.utxo += append_utxo
        
        return True

    def rebase_to_block(self, bid: str):
        self.base_block_id = bid
        self.utxo = kermastorage.get_utxo_set(bid)
        
        new_spent_values_utxo = []
        for i in range(self.utxo):
            new_spent_values_utxo[(self.utxo[i]['txid'], self.utxo[i]['index'])] = self.utxo[i]['value']
            
        txs = copy.deepcopy(self.txs)
        for tx in txs:
            self.try_add_tx(kermastorage.get_object(tx))