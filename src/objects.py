from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re
import copy
import time

import constants as const
import kermastorage
from message.msgexceptions import *

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    if(not re.match(OBJECTID_REGEX, objid_str)):
        raise InvalidFormatException("Object's 'objectid' is of incorrect format.")

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    if(not re.match(PUBKEY_REGEX, pubkey_str)):
        raise InvalidFormatException("Object's 'pubkey' is of incorrect format.")


SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    if(not re.match(SIGNATURE_REGEX, sig_str)):
        raise InvalidFormatException("Object's 'sig' is of incorrect format.")

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    if(not re.match(NONCE_REGEX, nonce_str)):
        raise InvalidFormatException("Object's 'nonce' is of incorrect format.")


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    if(not re.match(TARGET_REGEX, target_str)):
        raise InvalidFormatException("Object's 'target' is of incorrect format.")


def validate_transaction_input(in_dict):
    if sorted(list(in_dict.keys())) != sorted(['sig', 'outpoint']):
        raise InvalidFormatException('Invalid transaction field inputs: {}.'.format(in_dict))
    validate_signature(in_dict['sig'])
    if sorted(list(in_dict['outpoint'].keys())) != sorted(['txid', 'index']):
        raise InvalidFormatException('Invalid transaction field outpoint: {}.'.format(in_dict['outpoint']))
    validate_objectid(in_dict['outpoint']['txid'])
    if(not isinstance(in_dict['outpoint']['index'], int) or in_dict['outpoint']['index'] < 0):
        raise InvalidFormatException('Invalid transaction field index: {}.'.format(in_dict['outpoint']['index']))
    
    obj_dict = kermastorage.get_transaction(in_dict['outpoint']['txid'])
    if(obj_dict is None):
        raise UnknownObjectException('Object not present in DB: {}.'.format(in_dict['outpoint']['txid']))
    
    if(obj_dict['type'] != "transaction"):
        raise InvalidFormatException('Wrong object referenced in the DB: {}.'.format(in_dict['outpoint']['txid']))
    if(in_dict['outpoint']['index'] >= len(obj_dict['outputs'])):
        raise InvalidTxOutpointException('Transaction index is out of scope: {}.'.format(in_dict['outpoint']['index']))
    return True

def validate_transaction_output(out_dict):
    if sorted(list(out_dict.keys())) != sorted(['pubkey', 'value']):
        raise InvalidFormatException('Invalid transaction field outputs: {}.'.format(out_dict))
    validate_pubkey(out_dict['pubkey'])
    if(not isinstance(out_dict['value'], int) or out_dict['value'] < 0):
        raise InvalidFormatException('Transaction key value is invalid: {}.'.format(out_dict['value']))
    return True

def validate_transaction(trans_dict):
    if sorted(list(trans_dict.keys())) != sorted(['type', 'inputs', 'outputs']) and sorted(list(trans_dict.keys())) != sorted(['type', 'height', 'outputs']):
        raise InvalidFormatException('Invalid transaction msg: {}.'.format(trans_dict))
    for d in trans_dict['outputs']:
        validate_transaction_output(d)
    if('height' in trans_dict):
        if(not isinstance(trans_dict['height'], int) or trans_dict['height'] < 0):
            raise InvalidFormatException('Transaction key height is invalid: {}.'.format(trans_dict['height']))
    else:
        if(len(trans_dict['inputs']) == 0):
            raise InvalidFormatException('Transaction inputs must be non-zero: {}.'.format(trans_dict['inputs']))
        for d in trans_dict['inputs']:
            validate_transaction_input(d)
        weak_law_of_conservation(trans_dict)
        no_double_spend(trans_dict['inputs'])
        verify_transaction(trans_dict, trans_dict['inputs'])

    return True

def validate_block(block_dict, all_txs_in_db=False):
    is_not_genesis_block = block_dict['previd'] is not None
    if(all_txs_in_db):
        prev_utxo = []
        if(is_not_genesis_block):
            prev_utxo = kermastorage.get_object(block_dict['previd'], "block", True)['utxo'] # This is assuming we will keep the UTXO as {"utxo": [{"txid": 0x...1, "index": 0}, {...}]}
        txs = []
        for tx in block_dict['txids']:
            txs.append(kermastorage.get_transaction(tx))
        prev_height = 0
        if(is_not_genesis_block):
            prev_height = kermastorage.get_block(block_dict['previd'])['txids'][0]['height']  # We get the previous object from the DB (since its DB it respects the protocol), thus coinbase is index 0
        return verify_block(block_dict, kermastorage.get_block(block_dict['previd']), prev_utxo, prev_height, txs)  # Return the new UTXO
        
    valid_block = False
    if sorted(list(block_dict.keys())) == sorted(['type', 'txids', 'nonce', 'previd', 'created', 'T']):
        valid_block = True
    if not valid_block and sorted(list(block_dict.keys())) == sorted(['type', 'txids', 'nonce', 'previd', 'created', 'T', 'miner']):
        valid_block = True
    if not valid_block and sorted(list(block_dict.keys())) == sorted(['type', 'txids', 'nonce', 'previd', 'created', 'T', 'note']):
        valid_block = True
    if not valid_block and sorted(list(block_dict.keys())) == sorted(['type', 'txids', 'nonce', 'previd', 'created', 'T', 'miner', 'note']):
        valid_block = True
    if not valid_block:
        raise InvalidFormatException('Invalid block msg: {}.'.format(block_dict))
    validate_nonce(block_dict['nonce'])
    validate_target(block_dict['T'])
    if(block_dict['T'] != "00000000abc00000000000000000000000000000000000000000000000000000"):
        raise InvalidFormatException('Invalid block msg "T" attribute: {}.'.format(block_dict))
    prev_time = 0
    if block_dict['T'] != None:
        prev_time = kermastorage.get_block(block_dict['prev'])['created']
    if(not isinstance(block_dict['created'], int) or block_dict['created'] < prev_time or block_dict['created'] > int(time.time())):
        if(isinstance(block_dict['created'], int)):
            raise InvalidBlockTimestampException('Invalid block msg "created" attribute: {}.'.format(block_dict))
        else:
            raise InvalidFormatException('Invalid block msg "created" attribute: {}.'.format(block_dict))
    if(block_dict['miner'] is not None and ((not block_dict['miner'].isprintable()) or (len(block_dict['miner']) > 128))):
        raise InvalidBlockTimestampException('Invalid block msg "miner" attribute: {}.'.format(block_dict))
    if(block_dict['note'] is not None and ((not block_dict['note'].isprintable()) or (len(block_dict['note']) > 128))):
        raise InvalidBlockTimestampException('Invalid block msg "note" attribute: {}.'.format(block_dict))
    if(is_not_genesis_block):
        validate_objectid(block_dict['previd'])
    tx_missing = {}
    for tx in block_dict['txids']:
        validate_objectid(tx)
        if(kermastorage.get_transaction(tx) is None):
            tx_missing[tx] = True
        else:
            tx_missing[tx] = False
    if(get_objid(block_dict) >= block_dict['T']):
        raise InvalidBlockPoWException('PoW is wrong: {}.'.format(block_dict))
    
    missing_tx = []
    for tx in tx_missing.keys():
        if(tx_missing[tx]):
            missing_tx.append(tx)

    if(len(missing_tx) == 0):
        validate_block(block_dict, True)
    
    return {"utxo": None, "txs": missing_tx}

def validate_object(obj_dict):
    if 'type' not in obj_dict:
        raise InvalidFormatException("Object does not contain key 'type'.")
    obj_type = obj_dict['type']
    if(obj_type == "transaction" and validate_transaction(obj_dict)):
        return None
    elif(obj_type == "block"):
        return validate_block(obj_dict)
    else:
        raise InvalidFormatException("Object has invalid key 'type'.")

def get_objid(obj_dict):
    h = hashlib.blake2s()
    h.update(canonicalize(obj_dict))
    return h.hexdigest()

# perform semantic checks

# weak law of conservation
def weak_law_of_conservation(trans_dict):
    sum_of_inputs = 0
    for i in trans_dict['inputs']:
        sum_of_inputs += kermastorage.get_transaction(i['outpoint']['txid'])['outputs'][i['outpoint']['index']]['value']
    sum_of_outputs = 0
    for o in trans_dict['outputs']:
        sum_of_outputs += o['value']
    if(sum_of_inputs < sum_of_outputs):
        raise InvalidTxConservationException('Sum of outputs is larger than sum of inputs: {}.'.format(trans_dict['inputs']))

# double-spend check
def no_double_spend(inputs_list):
    for i in inputs_list:
        if(inputs_list.count(i) >= 2):
            raise InvalidTxConservationException('Double spending: {}.'.format(inputs_list))

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
    try:
        public_key.verify(bytes.fromhex(sig), json.dumps(tx_dict, separators=(',', ':')).encode())
        print("Signature is valid.")
    except InvalidSignature:
        print("Signature is invalid.")
        raise InvalidTxSignatureException('Invalid signature: {}.'.format(sig))


def verify_transaction(tx_dict, input_txs):
    modified_tx = copy.deepcopy(tx_dict)
    for i in range(len(modified_tx['inputs'])):
        modified_tx['inputs'][i]['sig'] = None
    for i in input_txs:
        verify_tx_signature(modified_tx, i['sig'], kermastorage.get_transaction(i['outpoint']['txid'])['outputs'][i['outpoint']['index']]['pubkey'])

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    new_utxo = copy.deepcopy(prev_utxo)
    for tx in txs:
        if(tx.has_key('inputs')):
            num_of_occurences = 0
            indices_to_remove = []
            for input_tx in tx['inputs']:
                for i in range(len(new_utxo)):
                    if(input_tx['outpoint']['txid'] == new_utxo[i]['txid'] and input_tx['outpoint']['index'] == new_utxo[i]['index']):
                        num_of_occurences += 1
                        indices_to_remove.append(i)
                        break
            if(len(tx['inputs']) > num_of_occurences):
                raise InvalidTxOutpointException('Transaction in block does not respect UTXO: {}.'.format(txs))
            filtered_utxo = [(index, value) for index, value in enumerate(new_utxo) if index not in indices_to_remove]
            append_utxo = []
            for i in range(len(tx['outputs'])):
                append_utxo.append({"txid": get_objid(tx), "index": i})
            new_utxo = filtered_utxo + append_utxo
            
    ## VERIFY COINBASE
            
    return 0
