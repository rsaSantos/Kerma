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
import copy

MISSING_OBJECTS = dict()
PENDING_VALIDATION_OBJECTS = dict()
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

def mk_chaintip_msg(blockid):
    return {'type': 'chaintip', 'blockid': blockid}


def mk_mempool_msg(txids):
    pass  # TODO


def mk_getchaintip_msg():
    return {'type': 'getchaintip'}


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


def validate_peers_msg(msg_dict):
    if (sorted(list(msg_dict.keys())) != sorted(['type', 'peers'])):
        raise InvalidFormatException("Invalid peers msg: {}.".format(msg_dict))
    if (len(msg_dict['peers']) > 30):
        raise InvalidFormatException("Too many peers in peers message.")
    for peer_str in msg_dict['peers']:
        validate_peer_str(peer_str)


def validate_getpeers_msg(msg_dict):
    if (list(msg_dict.keys()) != ['type']):
        raise InvalidFormatException("Invalid getpeers msg: {}.".format(msg_dict))


def validate_getchaintip_msg(msg_dict):
    if (list(msg_dict.keys()) != ['type']):
        raise InvalidFormatException("Invalid getchaintip msg: {}.".format(msg_dict))


def validate_getmempool_msg(msg_dict):
    pass  # TODO


def validate_error_msg(msg_dict):
    if (sorted(list(msg_dict.keys())) != sorted(['type', 'name', 'msg'])):
        raise InvalidFormatException("Invalid error msg: {}.".format(msg_dict))


def validate_ihaveobject_msg(msg_dict):
    if (sorted(list(msg_dict.keys())) != sorted(['type', 'objectid'])):
        raise InvalidFormatException("Invalid ihaveobject msg: {}.".format(msg_dict))


def validate_getobject_msg(msg_dict):
    if sorted(list(msg_dict.keys())) != sorted(['type', 'objectid']):
        raise InvalidFormatException("Invalid getobject msg: {}.".format(msg_dict))


def validate_object_msg(msg_dict):
    if sorted(list(msg_dict.keys())) != sorted(['type', 'object']):
        raise InvalidFormatException('Invalid object msg: {}.'.format(msg_dict))
    

def validate_chaintip_msg(msg_dict):
    if sorted(list(msg_dict.keys())) != sorted(['type', 'blockid']):
        raise InvalidFormatException('Invalid chaintip msg: {}'.format(msg_dict))
    if not isinstance(msg_dict['blockid'], str):
        raise InvalidFormatException('Invalid objectid format: {}'.format(msg_dict))


def validate_mempool_msg(msg_dict):
    pass  # TODO


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
    object_dict = kermastorage.get_object(object_id)
    if object_dict is not None:
        object_msg = mk_object_msg(object_dict)
        await write_msg(writer, object_msg)
        print("Sent object message: {}".format(object_msg))
    else:
        unknown_object_msg = mk_error_msg(UNKNOWN_OBJECT_ERROR, "Object with id {} not found.".format(object_id))
        await write_msg(writer, unknown_object_msg)
        print("Sent error message: {}".format(unknown_object_msg))

# when an object validation fails, send fail messages to all other dependencies
async def handle_object_validation_failure(failed_objid):
    #
    # Check the entire structure of missing objects
    base_obj_id_to_remove = []
    for base_obj_id, (_, missing_objects_list, writer) in MISSING_OBJECTS.items():
        # If the object is in the missing txs, send an INVALID_ANCESTRY!
        if failed_objid in missing_objects_list:
            try:
                base_obj_id_to_remove.append(base_obj_id)

                error_msg = mk_error_msg('INVALID_ANCESTRY', "Object with id {} failed validation.".format(base_obj_id))
                await write_msg(writer, error_msg)
                print("Sent error message: {}".format(error_msg))
            except:
                pass

    for base_obj_id, (_, pending_validation_objects, writer) in PENDING_VALIDATION_OBJECTS.items():
        # If the object is in the missing txs, send an INVALID_ANCESTRY! (but don't send the message twice)
        if failed_objid in pending_validation_objects and base_obj_id not in base_obj_id_to_remove:
            try:
                base_obj_id_to_remove.append(base_obj_id)

                error_msg = mk_error_msg('INVALID_ANCESTRY', "Object with id {} failed validation.".format(base_obj_id))
                await write_msg(writer, error_msg)
                print("Sent error message: {}".format(error_msg))
            except:
                pass

    # Remove the blocks that we sent the error message for
    for base_obj_id in base_obj_id_to_remove:
        if base_obj_id in MISSING_OBJECTS:
            del MISSING_OBJECTS[base_obj_id]
        if base_obj_id in PENDING_VALIDATION_OBJECTS:
            del PENDING_VALIDATION_OBJECTS[base_obj_id]

    if failed_objid in MISSING_OBJECTS.keys():
        del MISSING_OBJECTS[failed_objid]
    if failed_objid in PENDING_VALIDATION_OBJECTS.keys():
        del PENDING_VALIDATION_OBJECTS[failed_objid]

async def handle_unfindable_object(objid):
    await asyncio.sleep(const.UNFINDABLE_OBJECT_DELAY)
    if objid in MISSING_OBJECTS:
        _, missing_obj_list, writer = MISSING_OBJECTS[objid]
        if len(missing_obj_list) > 0:

            unfidable_error_msg = mk_error_msg('UNFINDABLE_OBJECT', "Dependencies of object with id {} not found in time.".format(objid))
            try:
                await write_msg(writer, unfidable_error_msg)
                print("Sent error message: {}".format(unfidable_error_msg))
            except:
                pass
            finally:
                del MISSING_OBJECTS[objid]
                if objid in PENDING_VALIDATION_OBJECTS:
                    del PENDING_VALIDATION_OBJECTS[objid]

async def save_and_gossip_object(object_id, object_dict, object_validation_set):
    if not kermastorage.check_objectid_exists(object_id):
        # Save object in database. If successful, gossip to all peers
        utxo = None if 'utxo' not in object_validation_set else object_validation_set['utxo']
        height = None if 'height' not in object_validation_set else object_validation_set['height']
        #
        if kermastorage.save_object(object_id, object_dict, utxo, height):
            # Gossip to all peers
            ihaveobject_msg = mk_ihaveobject_msg(object_id)
            for connection_queue in CONNECTIONS.values():
                await connection_queue.put(ihaveobject_msg)
        else:
            return False
    return True

def get_objects_to_validate(trigger_obj_id):
    objects_to_validate = []
    for objid, (_, pending_validation_objects, _) in PENDING_VALIDATION_OBJECTS.items():
        if trigger_obj_id in pending_validation_objects:
            pending_validation_objects.remove(trigger_obj_id)

        # We can validate this object since all its dependencies are validated!
        if len(pending_validation_objects) == 0:
            objects_to_validate.append(objid)
    
    return objects_to_validate

# This function is called when a new object is validated and saved in the database
# We will try to validate all objects that were waiting for this object to be validated
# Also, for each new object that is validated, we will try to validate all objects that were waiting for it to be validated
# This is done recursively until there are no more objects to validate
async def recursive_validation(object_id):

    await asyncio.sleep(0.01) # Dumb, but it works...

    print("Starting recursive validation for object with id {}.".format(object_id))
    # Now, since we received, validated and saved the object, we can check other pending objects
    # If this object was a dependency of other objects, they might be ready to be validated now
    objects_to_validate = get_objects_to_validate(object_id)
    #
    # Now, validate each object and, for every validated object, update the objects to validate list.
    while len(objects_to_validate) > 0:
        #
        # Validate the objects in list...
        validated_objects = []
        for object_to_validate in objects_to_validate:
            if not object_to_validate in PENDING_VALIDATION_OBJECTS:
                continue # This object was already validated and saved in the database. Skip it.
            
            object_dict, _, writer = PENDING_VALIDATION_OBJECTS[object_to_validate]
            try:
                print("Recursive validation of object with id {}.".format(object_to_validate))
                if object_dict['type'] == 'transaction':
                    object_validation_set = objects.validate_transaction(object_dict)
                    if not object_validation_set: # Return dictionary is empty, transaction is valid!
                        validated_objects.append((object_to_validate, {}))
                        continue


                elif object_dict['type'] == 'block':
                    object_validation_set = objects.validate_block_step_2(object_dict)
                    if 'utxo' not in object_validation_set or 'height' not in object_validation_set:
                        print("Logic error: still missing dependencies for block validation. No exception is thrown but validation is compromised.")
                        continue
                    validated_objects.append((object_to_validate, object_validation_set))

            except Exception as e:
                try:
                    await handle_object_validation_failure(object_to_validate)
                    objects_to_validate.remove(object_to_validate)
                finally:
                    if isinstance(e, MessageException):
                        error_msg = mk_error_msg(e.error_name, str(e.message))
                        try:
                            await write_msg(writer, error_msg)
                            print("Sent error message: {}".format(error_msg))
                        except:
                            pass

            except Exception as e:
                try:
                    await handle_object_validation_failure(object_id)
                finally:
                    if isinstance(e, MessageException):
                        error_msg = mk_error_msg(e.error_name, str(e.message))
                        try:
                            await write_msg(writer, error_msg)
                            print("Sent error message: {}".format(error_msg))
                        except:
                            pass
        
        # Now, save and gossip all validated objects
        for object_to_save, object_validation_set in validated_objects:
            if not await save_and_gossip_object(object_to_save, object_dict, object_validation_set):
                print("Error in saving and gossip object. No error is thrown but validation is compromised.")
            else:
                print("Object with id {} was recursively validated and saved in the database.".format(object_to_save))
                # All went fine, remove the object from all lists
                if object_to_save in PENDING_VALIDATION_OBJECTS:
                    del PENDING_VALIDATION_OBJECTS[object_to_save]
                if object_to_save in objects_to_validate:
                    objects_to_validate.remove(object_to_save)
                # Get new objects that can be validated and extend the list
                new_objects = get_objects_to_validate(object_to_save)
                unique_objects = [obj for obj in new_objects if obj not in objects_to_validate]
                objects_to_validate += unique_objects
                
        # Starting another round of recursive validation
        if len(objects_to_validate) > 0:
            print("Starting another round of recursive validation for {} objects.".format(len(objects_to_validate)))
            
# what to do when an object message arrives
async def handle_object_msg(msg_dict, writer):
    #
    # Get object dict.
    object_dict = dict(msg_dict['object'])
    #
    # Before everything, if we have the object in the database, do nothing
    object_id = objects.get_objid(object_dict)
    if kermastorage.check_objectid_exists(object_id):
        print("Object with id {} already exists in database.".format(object_id))
        return
    
    #
    object_validation_set = None
    try:
        object_validation_set = objects.validate_object(object_dict)
    except Exception as e:
        try:
            await handle_object_validation_failure(object_id)
        finally:
            raise e
    
    # Sanity check
    if object_validation_set is None or not isinstance(object_validation_set, dict):
        raise Exception("CRITICAL ERROR: Object validation set is None or not a dictionary.")
    
    # First of all, let's remove the object from the missing objects dict.
    # This is done because we received the object, so it is not missing anymore, even if it has missing dependencies...
    for _, (_, missing_objects_list, _) in MISSING_OBJECTS.items():
        if object_id in missing_objects_list:
            missing_objects_list.remove(object_id)

    # Check if there are missing dependencies
    if 'missing_objects' in object_validation_set:
        # Save missing objects in missing objects dict
        MISSING_OBJECTS[object_id] = (object_dict, object_validation_set['missing_objects'], writer)
        
        obj_validation_set_2 = copy.deepcopy(object_validation_set['missing_objects'])

        # Save object in pending validation objects dict
        PENDING_VALIDATION_OBJECTS[object_id] = (object_dict, obj_validation_set_2, writer)

        # Ask all peers for the missing objects
        for objid in object_validation_set['missing_objects']:
            getobject_msg = mk_getobject_msg(objid)
            for connection_queue in CONNECTIONS.values():
                await connection_queue.put(getobject_msg)

        # Launch task to prevent the object to be in the pending state forever
        asyncio.create_task(handle_unfindable_object(object_id))

    else:
        # This object is no longer pending for validation...
        if object_id in PENDING_VALIDATION_OBJECTS:
            del PENDING_VALIDATION_OBJECTS[object_id]
        
        # All dependencies are satisfied, save the object in the database and gossip it
        if not await save_and_gossip_object(object_id, object_dict, object_validation_set):
            print("Error in saving and gossip object. No error is thrown but validation is compromised.")
            return

        # Start a task for validating objects that were waiting for this object to be validated...
        asyncio.create_task(recursive_validation(object_id))

# returns the chaintip blockid
def get_chaintip_blockid():
    return kermastorage.get_chaintip_blockid()


async def handle_getchaintip_msg(msg_dict, writer):
    chain_tip_blockid = get_chaintip_blockid()
    if chain_tip_blockid is None:
        raise Exception("CRITICAL ERROR: Chain tip blockid is None.")
    
    chaintip_msg = mk_chaintip_msg(chain_tip_blockid)
    await write_msg(writer, chaintip_msg)
    print("Sent chaintip message: {}".format(chaintip_msg))


async def handle_getmempool_msg(msg_dict, writer):
    pass  # TODO


async def handle_chaintip_msg(msg_dict):
    #
    block_id = msg_dict['blockid']

    # Check PoW
    if block_id >= const.BLOCK_TARGET:
        raise InvalidBlockPoWException('PoW is wrong for chaintip object message with block id: {}.'.format(block_id))
    #
    # If we have the object...
    exists, object_type = kermastorage.check_objectid_exists(block_id, True)
    if exists:
        if object_type != kermastorage.BLOCK:
            raise InvalidFormatException("Object with id {}, received in chaintip msg, is not a block.".format(block_id))

        # Get the block and its height
        rcv_block_dict, _, rcv_height = kermastorage.get_block_full(block_id)

        # Get our current chaintip height
        curr_chaintip_height = kermastorage.get_chaintip_height()

        # TODO: Well, I am not sure what to do...
        if rcv_height == curr_chaintip_height:
            # If its the same height, should be the same block?
            pass
        elif rcv_height < curr_chaintip_height:
            # If its lower height than ours, should we send a chaintip message?
            pass
        else:
            # If its higher height than ours, and its already on our database, what does this mean?
            pass


    # If we don't have the block, send a getobject message
    else:
        getobject_msg = mk_getobject_msg(block_id)
        for connection_queue in CONNECTIONS.values():
            await connection_queue.put(getobject_msg)
        print("Sent getobject message: {}".format(getobject_msg))


async def handle_mempool_msg(msg_dict):
    pass  # TODO

async def handle_queue_msg(msg_dict, writer):
    print("Handling queue message: {}".format(msg_dict))
    await write_msg(writer, msg_dict)

# Helper function
async def handle_rcv_msg(msg_dict, writer):
    #
    # Let's identify the message type and pass it to the appropriate handler
    #
    print("Handling received message: {}".format(msg_dict))
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
    # Create task for get peers
    asyncio.create_task(write_msg(writer, mk_getpeers_msg()))
    print("Sending getpeers message...")
    #
    # Create task for getchaintip
    asyncio.create_task(write_msg(writer, mk_getchaintip_msg()))
    print("Sending getchaintip message...")
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
                await handle_queue_msg(queue_msg, writer)
                queue.task_done()

            # if no message was received over the network continue
            if read_task is not None:
                continue

            # Validate message (handle double hello messages here)
            msg_dict = parse_msg(msg_str)
            validate_msg(msg_dict)
            
            await handle_rcv_msg(msg_dict, writer)

    except MessageException as e:
        try:
            error_msg = mk_error_msg(e.error_name, str(e.message))
            print("Sending error message: {}".format(error_msg))
            await write_msg(writer, error_msg)
        except:
            pass

    except Exception as e:
        print("Error not handled: {}: {}".format(peer, str(e)))

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
