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
    
    obj_dict = kermastorage.get_transaction_data(in_dict['outpoint']['txid'])
    if(obj_dict is None):
        raise UnknownObjectException('Object not present in DB: {}.'.format(in_dict['outpoint']['txid']))
    
    if(obj_dict['type'] != "transaction"):
        raise InvalidFormatException('Wrong object referenced in the DB: {}.'.format(in_dict['outpoint']['txid']))
    if(in_dict['outpoint']['index'] >= len(obj_dict['outputs'])):
        raise InvalidTxOutpointException('Transaction index is out of scope: {}.'.format(in_dict['outpoint']['index']))
    
    return (in_dict['outpoint']['txid'], obj_dict)

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
        if len(trans_dict['outputs']) != 1:
            raise InvalidFormatException('Coibase transaction can only have one output. It has {}.'.format(len(trans_dict['outputs'])))
    else:
        if(len(trans_dict['inputs']) == 0):
            raise InvalidFormatException('Transaction inputs must be non-zero: {}.'.format(trans_dict['inputs']))
        #
        # To optimize DB queries, we should get all the transactions of inputs from the database.
        # This way we can avoid querying the DB for each input for the following checks.
        #
        input_txs_dicts = {}
        for d in trans_dict['inputs']:
            tx_id, tx_dict = validate_transaction_input(d)
            input_txs_dicts[tx_id] = tx_dict

        weak_law_of_conservation(trans_dict, input_txs_dicts)
        no_double_spend(trans_dict['inputs'])
        verify_transaction(trans_dict, input_txs_dicts)

    return True

def validate_block(block_dict, all_txs_in_db=False):
    is_not_genesis_block = block_dict['previd'] is not None
    block_id = get_objid(block_dict)
    if not is_not_genesis_block and block_id != const.GENESIS_BLOCK_ID:
        raise InvalidGenesisException('Invalid genesis block: {}.'.format(block_dict))

    prev_block_data = None
    prev_utxo = []
    prev_height = 0
    if is_not_genesis_block: # Get full prev block from DB!
        validate_objectid(block_dict['previd'])
    
        prev_full_block = kermastorage.get_block_full(block_dict['previd'])
        if prev_full_block is None:
            raise UnknownObjectException('Object not present in DB: {}.'.format(block_dict['previd']))
        
        prev_block_data = prev_full_block[0]
        prev_utxo = prev_full_block[1]
        prev_height = prev_full_block[2]

    if(all_txs_in_db):
        txs = []
        for tx in block_dict['txids']:
            txs.append(kermastorage.get_transaction_data(tx))
        return verify_block(prev_utxo, prev_height, txs)  # Return the new UTXO
        
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
    
    if(block_id >= block_dict['T']):
        raise InvalidBlockPoWException('PoW is wrong: {}.'.format(block_dict))
    
    if block_dict['created'] is None:
        raise InvalidFormatException('Invalid block msg "created" attribute: {}.'.format(block_dict))
    
    prev_time = 0 if prev_block_data is None else prev_block_data['created']
    if(not isinstance(block_dict['created'], int) or block_dict['created'] < prev_time or block_dict['created'] > int(time.time())):
        if(isinstance(block_dict['created'], int)):
            raise InvalidBlockTimestampException('Invalid block msg "created" attribute: {}.'.format(block_dict))
        else:
            raise InvalidFormatException('Invalid block msg "created" attribute: {}.'.format(block_dict))
    
    if(block_dict['miner'] is not None and ((not block_dict['miner'].isprintable()) or (len(block_dict['miner']) > 128))):
        raise InvalidBlockTimestampException('Invalid block msg "miner" attribute: {}.'.format(block_dict))
    
    if(block_dict['note'] is not None and ((not block_dict['note'].isprintable()) or (len(block_dict['note']) > 128))):
        raise InvalidBlockTimestampException('Invalid block msg "note" attribute: {}.'.format(block_dict))
    
    tx_missing = []
    for tx_id in block_dict['txids']:
        validate_objectid(tx_id)
        if not kermastorage.check_objectid_exists(tx_id):
            tx_missing.append(tx_id)

    if(len(tx_missing) == 0):
        validate_block(block_dict, True)
    
    return {"missing_tx_ids": tx_missing }

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

def weak_law_of_conservation(trans_dict, input_txs_dicts):
    sum_of_inputs = 0
    for i in trans_dict['inputs']:
        # Check if the input transaction is in the input_txs_dicts dictionary
        if i['outpoint']['txid'] not in input_txs_dicts:
            raise UnknownObjectException('Object not present in DB: {}.'.format(i['outpoint']['txid']))
        
        tx_data = input_txs_dicts[i['outpoint']['txid']]
        if(tx_data is None):
            raise UnknownObjectException('Object not present in DB: {}.'.format(i['outpoint']['txid']))
        
        sum_of_inputs += tx_data['outputs'][i['outpoint']['index']]['value']

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
    except InvalidSignature:
        raise InvalidTxSignatureException('Invalid signature: {}.'.format(sig))

def verify_transaction(tx_dict, input_txs_dicts):
    modified_tx = copy.deepcopy(tx_dict)
    input_txs = copy.deepcopy(tx_dict['inputs'])

    for i in range(len(input_txs)):
        modified_tx['inputs'][i]['sig'] = None
    
    for i in input_txs:
        if i['outpoint']['txid'] not in input_txs_dicts:
            raise UnknownObjectException('Object not present in DB: {}.'.format(i['outpoint']['txid']))
        
        tx_data = input_txs_dicts[i['outpoint']['txid']]
        if(tx_data is None):
            raise UnknownObjectException('Object not present in DB: {}.'.format(i['outpoint']['txid']))
        
        verify_tx_signature(modified_tx, i['sig'], tx_data['outputs'][i['outpoint']['index']]['pubkey'])

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(prev_utxo, prev_height, txs):
    #
    # Format of the UTXO set: [ { "txid": <txid>, "index": <index>, "value": <int> }, ... ]
    #
    new_utxo = [] if prev_utxo is None else copy.deepcopy(prev_utxo)
    
    # Check if the first transaction is coinbase
    is_first_transaction_coinbase = len(txs) > 0 and 'inputs' not in txs[0]
    coinbase_tx = txs[0] if is_first_transaction_coinbase else None
    coinbase_txid = get_objid(coinbase_tx) if is_first_transaction_coinbase else None

    height = prev_height + 1
    if coinbase_tx is not None and coinbase_tx['height'] != height:
        raise InvalidBlockCoinbaseException("Coinbase transaction does not have the correct height. Block height is {}, coinbase height is {}.".format(height, coinbase_tx['height']))

    if coinbase_tx is not None:
        new_utxo.append({"txid": coinbase_txid, "index": 0, "value": coinbase_tx['outputs'][0]['value']})

    # Iterate over all transactions in the block...skip coinbase if needed
    total_fees = 0
    for tx in txs[1:] if is_first_transaction_coinbase else txs:
        # If the transaction is coinbase, throw an error because it should be the first transaction
        if 'inputs' not in tx:
            raise InvalidBlockCoinbaseException("A coinbase transaction was referenced but is not at the first position.")
        
        # Iterate all the inputs of the transaction...
        sum_of_inputs = 0
        num_of_occurences = 0
        indices_to_remove = []
        for input_tx in tx['inputs']:
            # Check if it spends from the coinbase transaction
            if(input_tx['outpoint']['txid'] == coinbase_txid):
                raise InvalidTxOutpointException("Transaction {} spends from the coinbase transaction of the same block.".format(tx))

            # For each input, check if it is in the UTXO set
            for i in range(len(new_utxo)):
                # If it is, schedule to remove it from the UTXO set
                if(input_tx['outpoint']['txid'] == new_utxo[i]['txid'] and input_tx['outpoint']['index'] == new_utxo[i]['index']):
                    num_of_occurences += 1
                    indices_to_remove.append(i)
                    sum_of_inputs += new_utxo[i]['value']
                    break

        if(len(tx['inputs']) != num_of_occurences):
            raise InvalidTxOutpointException('Transaction in block does not respect UTXO: {}.'.format(txs))

        # Filter the new UTXO set by not including the removed indices
        filtered_utxo = []
        for index, value in enumerate(new_utxo):
            if index not in indices_to_remove:
                filtered_utxo.append({"txid": value["txid"], "index": value["index"], "value": value["value"]})

        # Get the txid of the transaction
        txid = get_objid(tx)

        # Add the new UTXO set to the filtered UTXO set
        append_utxo = []
        for i in range(len(tx['outputs'])):
            append_utxo.append({"txid": txid, "index": i, "value": tx['outputs'][i]['value']})

        # The new UTXO set is the filtered UTXO set + the new UTXO set
        new_utxo = filtered_utxo + append_utxo

        # Calculate the mining fee and add it to the total fees
        sum_of_outputs = sum([o['value'] for o in tx['outputs']])
        fee = sum_of_inputs - sum_of_outputs

        # Verify that the difference between the sum of inputs and the sum of outputs is not negative
        if fee < 0:
            raise InvalidTxConservationException('Sum of outputs ({}) is larger than sum of inputs ({}).'.format(sum_of_outputs, sum_of_inputs))
        
        # Add the fee to the total fees
        total_fees += fee
            
    # Verify coinbase transaction value.
    # The value should be less than or equal to the sum of the fees and the block reward.
    coinbase_tx_value = coinbase_tx['outputs'][0]['value'] if coinbase_tx is not None else 0
    if coinbase_tx_value > total_fees + const.BLOCK_REWARD:
        raise InvalidBlockCoinbaseException("Coinbase transaction value is larger than the sum of the fees and the block reward. Coinbase value is {}, sum of fees is {}, block reward is {}.".format(coinbase_tx_value, total_fees, const.BLOCK_REWARD))

    return { "utxo": new_utxo, "height": height }
