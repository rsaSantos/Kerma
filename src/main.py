from Peer import Peer
import constants as const
from message.msgexceptions import *
from jcs import canonicalize

import mempool
import objects
import peer_db
import kermastorage

import asyncio
import ipaddress
import json
import random
import re
import sqlite3
import sys
import time

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
    # Do not add banned peer addresses
    if peer.host_str in const.BANNED_HOSTS:
        return

    # Do not add loopback or multicast addrs
    ip = peer.host_ip
    if ip is None or ip.is_loopback or ip.is_multicast or ip.is_private or ip.is_reserved:
        return
    
    PEERS.add(peer)

# Add connection if not already open
def add_connection(peer, queue):
    print("Adding connection with {}".format(peer))
    ip, port = peer

    p = Peer(ip, port)
    if p in CONNECTIONS:
        raise Exception("Connection with {} already open!".format(peer))

    CONNECTIONS[p] = queue


# Delete connection
def del_connection(peer):
    ip, port = peer
    del CONNECTIONS[Peer(ip, port)]

# Make msg objects
def mk_error_msg(error_name, error_str=""):
    return {"type": "error", "name": error_name, "msg": error_str}


def mk_hello_msg():
    return {'type':'hello','version':const.VERSION,'agent':const.AGENT}

  
def mk_getpeers_msg():
    return {"type": "getpeers"}


def mk_peers_msg():
    peers_list = [str(const.EXTERNAL_IP + ':' + str(LISTEN_CFG['port']))]
    peers_list.extend(peer_db.get_shareable_peers())

    peers_msg = {'type': 'peers', 'peers': peers_list}
    print("Sending peers message: {}".format(peers_msg))
    return peers_msg


def mk_getobject_msg(objid):
    return {'type':'getobject','objectid':objid}


def mk_object_msg(obj_dict):
    return {'type':'object', 'object': obj_dict}


def mk_ihaveobject_msg(objid):
    return {'type': 'ihaveobject', 'objectid' : objid}

def mk_broadcast_ihaveobject_msg(objid):
    return {'type': 'broadcast_ihaveobject', 'objectid' : objid}

def mk_chaintip_msg(blockid):
    pass  # TODO


def mk_mempool_msg(txids):
    pass  # TODO


def mk_getchaintip_msg():
    pass  # TODO


def mk_getmempool_msg():
    pass  # TODO


# parses a message as json. returns decoded message
def parse_msg(msg_str):
    try:
        json_str = json.loads(msg_str.decode())
        return json_str
    except Exception:
        raise InvalidFormatException("Message is not valid json.")


# Send data over the network as a message
async def write_msg(writer, msg_dict):
    writer.write(b''.join([canonicalize(msg_dict), b'\n']))
    await writer.drain()


# Check if message contains no invalid keys,
# raises a MalformedMsgException
def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    pass  # TODO


# Validate the hello message
# raises an exception
def validate_hello_msg(msg_dict):
    if ('type' not in msg_dict):
        raise InvalidFormatException("Message does not contain key 'type'.")

    if (msg_dict['type'] != "hello"):
        raise InvalidHandshakeException("The first message needs to be of type 'hello'")
    if (sorted(list(msg_dict.keys())) != sorted(['agent', 'type', 'version'])):
        raise InvalidFormatException("Expected keys: agent, type, version.")
    if ((not msg_dict['agent'].isprintable()) or (len(msg_dict['agent']) > 128)):
        raise InvalidFormatException("Agent must be printable and less than 128 characters.")
    if (not re.match(r'^0\.10\.\d$', msg_dict['version'])):
        raise InvalidFormatException("Version must be of the form 0.10.x.")


# returns true iff host_str is a valid hostname
def validate_hostname(host_str):
    return re.match(r"^(?=.*[a-zA-Z])[a-zA-Z0-9.\-_]{3,50}$", host_str) and '.' in host_str[1:-1]


# returns true iff host_str is a valid ipv4 address
def validate_ipv4addr(host_str):
    try:
        ipaddress.IPv4Address(host_str)
        return True
    except Exception as e:
        return False


# returns true iff peer_str is a valid peer address
def validate_peer_str(peer_str):
    if (peer_str.count(":") != 1):
        raise InvalidFormatException("Invalid peer address (add:port): {}".format(peer_str))
    host, port = peer_str.split(":")
    if (int(port) < 1 or int(port) > 65535):
        raise InvalidFormatException("Invalid port: {}".format(port))
    if ((not validate_hostname(host)) and (not validate_ipv4addr(host))):
        raise InvalidFormatException("Invalid peer address: {}".format(host))


# raise an exception if not valid
def validate_peers_msg(msg_dict):
    if (sorted(list(msg_dict.keys())) != sorted(['type', 'peers'])):
        raise InvalidFormatException("Invalid peers msg: {}.".format(msg_dict))
    if (len(msg_dict['peers']) > 30):
        raise InvalidFormatException("Too many peers in peers message.")
    for peer_str in msg_dict['peers']:
        validate_peer_str(peer_str)

# raise an exception if not valid
def validate_getpeers_msg(msg_dict):
    if (list(msg_dict.keys()) != ['type']):
        raise InvalidFormatException("Invalid getpeers msg: {}.".format(msg_dict))


# raise an exception if not valid
def validate_getchaintip_msg(msg_dict):
    pass  # TODO


# raise an exception if not valid
def validate_getmempool_msg(msg_dict):
    pass  # TODO


# raise an exception if not valid
def validate_error_msg(msg_dict):
    if (sorted(list(msg_dict.keys())) != sorted(['type', 'name', 'msg'])):
        raise InvalidFormatException("Invalid error msg: {}.".format(msg_dict))


# raise an exception if not valid
def validate_ihaveobject_msg(msg_dict):
    if (sorted(list(msg_dict.keys())) != sorted(['type', 'objectid'])):
        raise InvalidFormatException("Invalid ihaveobject msg: {}.".format(msg_dict))


# raise an exception if not valid
def validate_getobject_msg(msg_dict):
    if sorted(list(msg_dict.keys())) != sorted(['type', 'objectid']):
        raise InvalidFormatException("Invalid getobject msg: {}.".format(msg_dict))


# raise an exception if not valid
def validate_object_msg(msg_dict):
    if sorted(list(msg_dict.keys())) != sorted(['type', 'object']):
        raise InvalidFormatException('Invalid object msg: {}.'.format(msg_dict))
    

# raise an exception if not valid
def validate_chaintip_msg(msg_dict):
    pass  # todo


# raise an exception if not valid
def validate_mempool_msg(msg_dict):
    pass  # todo


def validate_msg(msg_dict):
    if 'type' not in msg_dict:
        raise InvalidFormatException("Message does not contain key 'type'.")

    msg_type = msg_dict['type']
    if msg_type == 'hello':
        raise InvalidHandshakeException("Received hello message after handshake")
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
    elif msg_type == 'broadcast_ihaveobject':
        return True
    elif msg_type == 'getobject':
        validate_getobject_msg(msg_dict)
    elif msg_type == 'object':
        validate_object_msg(msg_dict)
    elif msg_type == 'chaintip':
        validate_chaintip_msg(msg_dict)
    elif msg_type == 'mempool':
        validate_mempool_msg(msg_dict)
    else:
        raise InvalidFormatException("Invalid message type: {}".format(msg_type))

def handle_peers_msg(msg_dict):
    peers_list = msg_dict['peers']
    rcv_peers = set()
    for peer_str in peers_list:
        # Syntax: <host>:<port>
        host_str, port_str = peer_str.split(':')
        peer = Peer(host_str, port_str)

        # Check if we received ourselves
        if peer.host_str == const.EXTERNAL_IP and peer.port == LISTEN_CFG['port']:
            print("Received ourselves, skipping...")
            continue

        add_peer(peer)
        rcv_peers.add(peer)

    peer_db.store_peers(rcv_peers)


def handle_error_msg(msg_dict, peer_self):
    print("Received error of type {}: {}".format(msg_dict['name'], msg_dict['msg']))

async def handle_ihaveobject_msg(msg_dict, writer):
    #
    #
    # Get the object ID
    object_id = msg_dict['objectid']

    # If we don't have it, send a getobject message
    if not kermastorage.check_objectid_exists(object_id):
        getobject_msg = mk_getobject_msg(object_id)
        await write_msg(writer, getobject_msg)
        print("Sent getobject message: {}".format(getobject_msg))

async def handle_getobject_msg(msg_dict, writer):
    #
    # Get the object ID
    object_id = msg_dict['objectid']

    # If we have it, send an object message
    if kermastorage.check_objectid_exists(object_id):
        object_dict = kermastorage.get_object(object_id)
        object_msg = mk_object_msg(object_dict)
        await write_msg(writer, object_msg)
        print("Sent object message: {}".format(object_msg))
    else:
        unknown_object_msg = mk_error_msg(UNKNOWN_OBJECT_ERROR, "Object with id {} not found.".format(object_id))
        await write_msg(writer, unknown_object_msg)
        print("Sent error message: {}".format(unknown_object_msg))

# return a list of transactions that tx_dict references
def gather_previous_txs(db_cur, tx_dict):
    # coinbase transaction
    if 'height' in tx_dict:
        return {}

    pass  # TODO


# get the block, the current utxo and block height
def get_block_utxo_height(blockid):
    # TODO
    block = ''
    utxo = ''
    height = ''
    return (block, utxo, height)


# get all transactions as a dict txid -> tx from a list of ids
def get_block_txs(txids):
    pass  # TODO


# Stores for a block its utxoset and height
def store_block_utxo_height(block, utxo, height: int):
    pass  # TODO


# runs a task to verify a block
# raises blockverifyexception
async def verify_block_task(block_dict):
    pass  # TODO


# adds a block verify task to queue and starting it
def add_verify_block_task(objid, block, queue):
    pass  # TODO


# abort a block verify task
async def del_verify_block_task(task, objid):
    pass  # TODO


# what to do when an object message arrives
async def handle_object_msg(msg_dict, writer):
    #
    # Get object ID
    object_dict = dict(msg_dict['object'])

    # Validate the object
    objects.validate_object(object_dict)

    object_id = objects.get_objid(object_dict)

    # Check if we already have it
    if not kermastorage.check_objectid_exists(object_id):
        # Save object in database.
        kermastorage.save_object(object_id, object_dict)

        # Gossip to all peers
        broadcast_ihaveobject_msg = mk_broadcast_ihaveobject_msg(object_id)
        for connection in CONNECTIONS.values():
            await connection.put(broadcast_ihaveobject_msg)

# returns the chaintip blockid
def get_chaintip_blockid():
    pass  # TODO


async def handle_getchaintip_msg(msg_dict, writer):
    pass  # TODO


async def handle_getmempool_msg(msg_dict, writer):
    pass  # TODO


async def handle_chaintip_msg(msg_dict):
    pass  # TODO


async def handle_mempool_msg(msg_dict):
    pass  # TODO


# Helper function
async def handle_queue_msg(msg_dict, writer):
    #
    # Let's identify the message type and pass it to the appropriate handler
    #
    print("Handling message: {}".format(msg_dict))
    if msg_dict['type'] == 'getpeers':
        await write_msg(writer, mk_peers_msg())
        print("Sent peers message.")

    elif msg_dict['type'] == 'peers':
        handle_peers_msg(msg_dict)
        print("Handled peers message!")

    elif msg_dict['type'] == 'error':
        handle_error_msg(msg_dict, writer)
        print("Handled error message!")

    elif msg_dict['type'] == 'ihaveobject':
        await handle_ihaveobject_msg(msg_dict, writer)
        print("Handled ihaveobject message!")

    elif msg_dict['type'] == 'broadcast_ihaveobject':
        msg_dict['type'] = 'ihaveobject'
        await write_msg(writer, msg_dict)

    elif msg_dict['type'] == 'getobject':
        await handle_getobject_msg(msg_dict, writer)
        print("Handled getobject message!")

    elif msg_dict['type'] == 'object':
        await handle_object_msg(msg_dict, writer)
        print("Handled object message!")
    
    elif msg_dict['type'] == 'sendtopeer': # INTERNAL MESSAGE
        await write_msg(writer, msg_dict['msg'])
        print("Sent message to peer: {}".format(msg_dict['msg']))

    elif msg_dict['type'] == 'getchaintip':
        await handle_getchaintip_msg(msg_dict, writer)
        print("Handled getchaintip message!")

    elif msg_dict['type'] == 'chaintip':
        await handle_chaintip_msg(msg_dict)
        print("Handled chaintip message!")

    elif msg_dict['type'] == 'getmempool':
        await handle_getmempool_msg(msg_dict, writer)
        print("Handled getmempool message!")

    elif msg_dict['type'] == 'mempool':
        await handle_mempool_msg(msg_dict)
        print("Handled mempool message!")

    else:
        raise Exception("CRITICAL ERROR: Unsupported message type after validation. Message received: {}".format(msg_dict))

#
# Send initial messages
#  - Start with hello message
#  - Wait for hello message
#    - Validate the message
#      - if its not hello, pass more than 20 seconds, or received a second hello
#      - THEN raise an exception, return INVALID_HANDSHAKE
#
async def handshake(reader, writer):
    #
    await write_msg(writer, mk_hello_msg())
    #
    # Create task for get peers (no need to wait for it, keep going)
    asyncio.create_task(write_msg(writer, mk_getpeers_msg()))
    print("Sending getpeers message...")
    #
    try:
        raw_hello_future = await asyncio.wait_for(
            reader.readline(),
            timeout=const.HELLO_MSG_TIMEOUT
        )
        # Validate the hello message (raises an exception if not valid)
        validate_hello_msg(parse_msg(raw_hello_future))
    except asyncio.TimeoutError:
        raise InvalidHandshakeException("Waited too long for hello message (>20s).")
    except InvalidFormatException as e:
        raise InvalidFormatException("Incorrect format for hello message ({}): {}".format(raw_hello_future, str(e)))
    except MessageException as e:
        raise InvalidHandshakeException(str(e))


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
        
        add_connection(peer, queue)

        print("New connection with {}".format(peer))
    except Exception as e:
        print(str(e))
        try:
            writer.close()
        except:
            pass
        finally:
            return

    try:
        # Handshake the connection -> exchange hello messages
        await handshake(reader, writer)
        print("Handshake successful with {}".format(peer))

        msg_str = None
        while True:
            if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            if queue_task is None:
                queue_task = asyncio.create_task(queue.get())

            # wait for network or queue messages
            done, pending = await asyncio.wait([read_task, queue_task],
                                               return_when=asyncio.FIRST_COMPLETED)
            if read_task in done:
                msg_str = read_task.result()
                read_task = None
            # handle queue messages
            if queue_task in done:
                queue_msg = queue_task.result()
                queue_task = None
                await handle_queue_msg(queue_msg, writer) # TODO: Can we execute tasks asynchroniously?
                queue.task_done()

            # if no message was received over the network continue
            if read_task is not None:
                continue

            # Validate message (handle double hello messages here)
            msg_dict = parse_msg(msg_str)
            validate_msg(msg_dict)
            
            # For further message processing, create a task
            await queue.put(msg_dict)

    except UnknownObjectException as e:
        try:
            error_msg = mk_error_msg(e.error_name, str(e.message))
            print("Sending error message: {}".format(error_msg))
            await write_msg(writer, error_msg)
        except:
            pass

    except MessageException as e:
        try:
            error_msg = mk_error_msg(e.error_name, str(e.message))
            print("Sending error message: {}".format(error_msg))
            await write_msg(writer, error_msg)
        except:
            pass
        finally:
            print("Closing connection with {}".format(peer))
            writer.close()
            del_connection(peer)
            if read_task is not None and not read_task.done():
                read_task.cancel()
            if queue_task is not None and not queue_task.done():
                queue_task.cancel()

    except Exception as e:
        print("Error not handled: {}: {}".format(peer, str(e)))

    # finally:
    #     print("Closing connection with {}".format(peer))
    #     writer.close()
    #     del_connection(peer)
    #     if read_task is not None and not read_task.done():
    #         read_task.cancel()
    #     if queue_task is not None and not queue_task.done():
    #         queue_task.cancel()


async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(peer.host_str, peer.port, limit=const.RECV_BUFFER_LIMIT),
            timeout=5
        )
        peer_db.update_timestamp(peer, time.time())

    except Exception as e:
        print("Failed to connect to {}:{}. Error: {}".format(peer.host_str, peer.port, str(e)))
        PEERS.discard(peer)
        peer_db.remove_peer(peer)
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
        if str(peer.host_str) == str(LISTEN_CFG['address']) and str(peer.port) == str(LISTEN_CFG['port']):
            print("Skipping bootstrap peer {}:{}".format(peer.host_str, peer.port))
            continue

        print("Trying to connect to {}:{}".format(peer.host_str, peer.port))
        t = asyncio.create_task(connect_to_node(peer))

        BACKGROUND_TASKS.add(t)
        t.add_done_callback(BACKGROUND_TASKS.discard)

        add_peer(peer)

# connect to some peers
def resupply_connections():
    cons = set(CONNECTIONS.keys())

    # If we have more or equal than threshold, do nothing
    if len(cons) >= const.LOW_CONNECTION_THRESHOLD:
        return

    neededPeers = const.LOW_CONNECTION_THRESHOLD - len(cons)
    availablePeers = list(PEERS - cons)

    if len(availablePeers) == 0:
        print("No more peers to connect to.")
        return

    if len(availablePeers) < neededPeers:
        neededPeers = len(availablePeers)

    print("Connecting to {} new peers...".format(neededPeers))

    chosenPeers = random.sample(availablePeers, neededPeers)
    for peer in chosenPeers:
        print("Trying to connect to {}:{}".format(peer.host_str, peer.port))
        t = asyncio.create_task(connect_to_node(peer))

        BACKGROUND_TASKS.add(t)
        t.add_done_callback(BACKGROUND_TASKS.discard)

async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    PEERS.update(peer_db.load_peers())
    print("Loaded peers: {}".format(PEERS))

    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())

    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(set(CONNECTIONS.keys())))
        print("Number of background tasks: {}".format(len(BACKGROUND_TASKS)))

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
        LISTEN_CFG['port'] = int(sys.argv[2])
    
    kermastorage.create_db()
    main()