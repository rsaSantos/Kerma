from Peer import Peer
import constants as const
from message.msgexceptions import *
from jcs import canonicalize

import mempool
import objects
import peer_db

import asyncio
import ipaddress
import json
import random
import re
import sqlite3
import sys

PEERS = set()
CONNECTIONS = dict()
BACKGROUND_TASKS = set()
BLOCK_VERIFY_TASKS = dict()
BLOCK_WAIT_LOCK = None
TX_WAIT_LOCK = None
MEMPOOL = mempool.Mempool(const.GENESIS_BLOCK_ID, {})
LISTEN_CFG = {
        "address": const.ADDRESS,
        "port": const.PORT
}

# Add peer to your list of peers
def add_peer(peer):
    pass # TODO

# Add connection if not already open
def add_connection(peer, queue):
    pass # TODO

# Delete connection
def del_connection(peer):
    pass # TODO

# Make msg objects
def mk_error_msg(error_str, error_name):
    pass # TODO

def mk_hello_msg():
    hello_str = '{"type":"hello","version":"0.10.0","agent":"Sending messages"}' + '\n'
    return canonicalize(hello_str)


def mk_getpeers_msg():
    getpeers_str = '{"type":"getpeers"}' + '\n'
    return canonicalize(getpeers_str)

def mk_peers_msg():
    pass # TODO

def mk_getobject_msg(objid):
    pass # TODO

def mk_object_msg(obj_dict):
    pass # TODO

def mk_ihaveobject_msg(objid):
    pass # TODO

def mk_chaintip_msg(blockid):
    pass # TODO

def mk_mempool_msg(txids):
    pass # TODO

def mk_getchaintip_msg():
    pass # TODO

def mk_getmempool_msg():
    pass # TODO

# parses a message as json. returns decoded message
def parse_msg(msg_str):
    pass # TODO

# Send data over the network as a message
async def write_msg(writer, msg_dict):
    pass # TODO

# Check if message contains no invalid keys,
# raises a MalformedMsgException
def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    pass # TODO


# Validate the hello message
# raises an exception
def validate_hello_msg(msg_dict):
    pass # TODO

# returns true iff host_str is a valid hostname
def validate_hostname(host_str):
    pass # TODO

# returns true iff host_str is a valid ipv4 address
def validate_ipv4addr(host_str):
    pass # TODO

# returns true iff peer_str is a valid peer address
def validate_peer_str(peer_str):
    pass # TODO

# raise an exception if not valid
def validate_peers_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_getpeers_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_getchaintip_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_getmempool_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_error_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_ihaveobject_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_getobject_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_object_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_chaintip_msg(msg_dict):
    pass # todo
    
# raise an exception if not valid
def validate_mempool_msg(msg_dict):
    pass # todo
        
def validate_msg(msg_dict):
    msg_type = msg_dict['type']
    if msg_type == 'hello':
        validate_hello_msg(msg_dict)
    elif msg_type == 'getpeers':
        validate_getpeers_msg(msg_dict)
    elif msg_type == 'peers':
        validate_peers_msg(msg_dict)
    elif msg_type == 'getchaintip':
        validate_getchaintip_msg(msg_dict)
    elif msg_type == 'getmempool':
        validate_getmempool_msg(msg_dict)
    elif msg_type == 'error':
        validate_error_msg(msg_dict)
    elif msg_type == 'ihaveobject':
        validate_ihaveobject_msg(msg_dict)
    elif msg_type == 'getobject':
        validate_getobject_msg(msg_dict)
    elif msg_type == 'object':
        validate_object_msg(msg_dict)
    elif msg_type == 'chaintip':
        validate_chaintip_msg(msg_dict)
    elif msg_type == 'mempool':
        validate_mempool_msg(msg_dict)
    else:
        pass # TODO


def handle_peers_msg(msg_dict):
    pass # TODO


def handle_error_msg(msg_dict, peer_self):
    pass # TODO


async def handle_ihaveobject_msg(msg_dict, writer):
    pass # TODO


async def handle_getobject_msg(msg_dict, writer):
    pass # TODO

# return a list of transactions that tx_dict references
def gather_previous_txs(db_cur, tx_dict):
    # coinbase transaction
    if 'height' in tx_dict:
        return {}

    pass # TODO

# get the block, the current utxo and block height
def get_block_utxo_height(blockid):
    # TODO
    block = ''
    utxo = ''
    height = ''
    return (block, utxo, height)

# get all transactions as a dict txid -> tx from a list of ids
def get_block_txs(txids):
    pass # TODO


# Stores for a block its utxoset and height
def store_block_utxo_height(block, utxo, height: int):
    pass # TODO

# runs a task to verify a block
# raises blockverifyexception
async def verify_block_task(block_dict):
    pass # TODO

# adds a block verify task to queue and starting it
def add_verify_block_task(objid, block, queue):
    pass # TODO

# abort a block verify task
async def del_verify_block_task(task, objid):
    pass # TODO

# what to do when an object message arrives
async def handle_object_msg(msg_dict, peer_self, writer):
    pass # TODO


# returns the chaintip blockid
def get_chaintip_blockid():
    pass # TODO


async def handle_getchaintip_msg(msg_dict, writer):
    pass # TODO


async def handle_getmempool_msg(msg_dict, writer):
    pass # TODO


async def handle_chaintip_msg(msg_dict):
    pass # TODO


async def handle_mempool_msg(msg_dict):
    pass # TODO

# Helper function
async def handle_queue_msg(msg_dict, writer):
    pass # TODO

# how to handle a connection
async def handle_connection(reader, writer):
    read_task = None
    queue_task = None

    peer = None
    queue = asyncio.Queue()
    try:
        peer = writer.get_extra_info('peername')
        if not peer:
            raise Exception("Failed to get peername!")

        print("New connection with {}".format(peer))
    except Exception as e:
        print(str(e))
        try:
            writer.close()
        except:
            pass
        return

    try:
        # Send initial messages
        #
        # Start with hello message
        await write_msg(writer, mk_hello_msg())
        #
        # Wait to receive another hello message
        # Validate the message
        #  - if its not hello, pass more than 20 seconds, or received a second hello
        #  - THEN raise an exception, return INVALID_HANDSHAKE
        try:
            raw_hello_future = await asyncio.wait_for(
                await reader.readline(),
                timeout=const.HELLO_MSG_TIMEOUT
            )
            
            # Validate the hello message (raises an exception if not valid)
            validate_hello_msg(parse_msg(raw_hello_future))

        except asyncio.TimeoutError:
            print("Waited too long for hello message from {}".format(peer))
            # TODO: Raise exception, return INVALID_HANDSHAKE

        except Exception as e: # TODO: Maybe indicate the type of exception?
            print(str(e))
            # TODO: Raise exception, return INVALID_HANDSHAKE

        # TODO: Create task for get peers? Instead of waiting for it..
        await write_msg(writer, mk_getpeers_msg())

        msg_str = None
        while True:
            if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            if queue_task is None:
                queue_task = asyncio.create_task(queue.get())

            # wait for network or queue messages
            done, pending = await asyncio.wait([read_task, queue_task],
                    return_when = asyncio.FIRST_COMPLETED)
            if read_task in done:
                msg_str = read_task.result()
                read_task = None
            # handle queue messages
            if queue_task in done:
                queue_msg = queue_task.result()
                queue_task = None
                await handle_queue_msg(queue_msg, writer)
                queue.task_done()

            # if no message was received over the network continue
            if read_task is not None:
                continue

            print(f"Received: {msg_str}")
            # todo handle message
            
            # for now, close connection
            raise MessageException("closing connection")

    except asyncio.exceptions.TimeoutError:
        print("{}: Timeout".format(peer))
        try:
            await write_msg(writer, mk_error_msg("Timeout"))
        except:
            pass
    except MessageException as e:
        print("{}: {}".format(peer, str(e)))
        try:
            await write_msg(writer, mk_error_msg(e.NETWORK_ERROR_MESSAGE))
        except:
            pass
    except Exception as e:
        print("{}: {}".format(peer, str(e)))
    finally:
        print("Closing connection with {}".format(peer))
        writer.close()
        del_connection(peer)
        if read_task is not None and not read_task.done():
            read_task.cancel()
        if queue_task is not None and not queue_task.done():
            queue_task.cancel()


async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(peer.host, peer.port, limit=const.RECV_BUFFER_LIMIT),
            timeout=5
        )
    except asyncio.TimeoutError:
        # Handle timeout error here
        print("Connection attempt timed out.")
        return

    except Exception as e:
        print(str(e))
        return

    await handle_connection(reader, writer)


async def listen():
    server = await asyncio.start_server(handle_connection, LISTEN_CFG['address'],
            LISTEN_CFG['port'], limit=const.RECV_BUFFER_LIMIT)

    print("Listening on {}:{}".format(LISTEN_CFG['address'], LISTEN_CFG['port']))

    async with server:
        await server.serve_forever()

async def bootstrap():
    for peer in const.PRELOADED_PEERS:
        if str(peer.host) == str(LISTEN_CFG['address']) and str(peer.port) == str(LISTEN_CFG['port']):
            continue

        print("Trying to connect to {}:{}".format(peer.host, peer.port))
        await connect_to_node(peer)

# connect to some peers
def resupply_connections():
    pass # TODO


async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    # PEERS.update(peer_db.load_peers())

    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())

    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(set(CONNECTIONS.keys())))

        # Open more connections if necessary
        resupply_connections()

        await asyncio.sleep(const.SERVICE_LOOP_DELAY)

    await bootstrap_task
    await listen_task


def main():
    asyncio.run(init())


if __name__ == "__main__":
    if len(sys.argv) == 3:
        LISTEN_CFG['address'] = sys.argv[1]
        LISTEN_CFG['port'] = sys.argv[2]
        
    main()
