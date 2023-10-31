from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re

import constants as const

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
    if sorted(in_dict['outpoint']) != sorted(['txid', 'index']):
        raise InvalidFormatException('Invalid transaction field outpoint: {}.'.format(in_dict))
    validate_objectid(in_dict['outpoint']['txid'])
    if(not isinstance(in_dict['outpoint']['index'], int)):
        raise InvalidFormatException('Invalid transaction field index: {}.'.format(in_dict))
    return True

def validate_transaction_output(out_dict):
    if sorted(list(out_dict.keys())) != sorted(['pubkey', 'value']):
        raise InvalidFormatException('Invalid transaction field outputs: {}.'.format(out_dict))
    validate_pubkey(out_dict['pubkey'])
    if(not isinstance(out_dict['value'], int) or out_dict['value'] < 0):
        raise InvalidFormatException('Transaction key value is invalid: {}.'.format(out_dict['value']))
    return True

def validate_transaction(trans_dict):
    if sorted(list(trans_dict.keys())) != sorted(['type', 'inputs', 'outputs']) or sorted(list(trans_dict.keys())) != sorted(['type', 'height', 'outputs']):
        raise InvalidFormatException('Invalid transaction msg: {}.'.format(trans_dict))
    for d in trans_dict['outputs']:
        validate_transaction_output(d)
    if('height' in trans_dict):
        if(not isinstance(trans_dict['height'], int) or trans_dict['height'] <= 0):
            raise InvalidFormatException('Transaction key height is invalid: {}.'.format(trans_dict['height']))
    else:
        for d in trans_dict['inputs']:
            validate_transaction_input(d)
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
    h = hashlib.sha256()
    h.update(canonicalize(obj_dict))
    return h.hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    # TODO: TASK 2
    return True

class TXVerifyException(Exception):
    pass # TODO: TASK 2 -> move to error messages?

def verify_transaction(tx_dict, input_txs):
    pass # TODO: TASK 2

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
