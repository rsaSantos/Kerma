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
    pass # TODO: TASK 2

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    pass # TODO: TASK 2


SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    pass # TODO: TASK 2

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    pass # todo


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    pass # todo


def validate_transaction_input(in_dict):
    # TODO: TASK 2
    return True

def validate_transaction_output(out_dict):
    # TODO: TASK 2
    return True

def validate_transaction(trans_dict):
    # TODO: TASK 2
    return True

def validate_block(block_dict):
    # todo
    return True

def validate_object(obj_dict):
    # TODO: TASK 2
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
