from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re
import copy

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
    pass # todo


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    pass # todo


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

def validate_block(block_dict):
    # todo
    return True

def validate_object(obj_dict):
    if 'type' not in obj_dict:
        raise InvalidFormatException("Object does not contain key 'type'.")
    obj_type = obj_dict['type']
    if(obj_type == "transaction"):
        validate_transaction(obj_dict)
    elif(obj_type == "block"):
        validate_block(obj_dict)
    else:
        raise InvalidFormatException("Object has invalid key 'type'.")
    return True

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

class BlockVerifyException(Exception):
    pass # TODO: TASK 2 -> move to error messages?

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    # todo
    return 0
