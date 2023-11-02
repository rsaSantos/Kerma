import asyncio
import ipaddress
import json
import random
import re
import sys
import unittest
from unittest.mock import MagicMock

import kermastorage
import constants as const
import objects
import main
from message.msgexceptions import *

from jcs import canonicalize

def parse_msg(msg_str):
    return json.loads(msg_str.decode())

async def write_msg(writer, msg_dict):
    writer.write(b''.join([canonicalize(msg_dict), b'\n']))
    await writer.drain()

class Test(unittest.IsolatedAsyncioTestCase):
    # async def test_hello_message(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test hello message validity")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "hello")
    #     self.assertEqual(sorted(list(msg_dict.keys())), sorted(['agent', 'type', 'version']))
    #     self.assertEqual(True, msg_dict['agent'].isprintable())
    #     self.assertEqual(True, len(msg_dict['agent']) <= 128)
    #     self.assertIsNotNone(re.match(r'^0\.10\.\d$', msg_dict['version']))

    #     writer.close() 

    # async def test_invalid_handshake_1(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_HANDSHAKE_1")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     invalid_msg = {'type':'getpeers'}
    #     await write_msg(writer, invalid_msg)
    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

    #     writer.close() 

    # async def test_invalid_handshake_2(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_HANDSHAKE_2")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     await asyncio.sleep(20)

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

    #     writer.close() 

    # async def test_invalid_handshake_3(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_HANDSHAKE_3")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)
        
    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )                                        # Here we expect the node to act in a good way, thus send any message besides hello
        

    #     await write_msg(writer, hello_msg)       # Send one more hello message on purpose

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )                                         # Node should be able to detect a second hello message thus send an error message
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

    #     writer.close() 

    # async def test_invalid_format_1(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)
        
    #     print("Test INVALID_FORMAT_1")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     non_printable_string = "Sending\nmessages"
    #     self.assertEqual(False, non_printable_string.isprintable())
    #     hello_msg = {'type':'hello','version':'0.10.0','agent':non_printable_string}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")
        
    #     writer.close() 

    # async def test_invalid_format_2(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_2")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     long_string = ""
    #     for i in range(0, 129):
    #         long_string += 'a'
    #     self.assertEqual(True, len(long_string) == 129)
    #     hello_msg = {'type':'hello','version':'0.10.0','agent':long_string}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close() 

    # async def test_invalid_format_3(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_3")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     version = '0.10.10'
    #     hello_msg = {'type':'hello','version':version,'agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close() 

    # async def test_invalid_format_4(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_4")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     hello_msg = {'type':'hello','version':'0.10.0'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close() 

    # async def test_invalid_format_5(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_5")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(True, msg_dict['type'] == "getpeers")

    #     peers_msg = {'type':'peers','peers':[], 'extra':'key'}
    #     await write_msg(writer, peers_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close() 

    # async def test_invalid_format_6(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_6")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(True, msg_dict['type'] == "getpeers")

    #     l = []
    #     for i in range(0, 31):
    #         l.append("0.0.0.1:256")
    #     peers_msg = {'type':'peers','peers':l}
    #     await write_msg(writer, peers_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close()  

    # async def test_invalid_format_7(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_7")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(True, msg_dict['type'] == "getpeers")

    #     l = ["0.0.0.1:65536"]
    #     peers_msg = {'type':'peers','peers':l}
    #     await write_msg(writer, peers_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close()
    
    # async def test_invalid_format_7(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_7")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(True, msg_dict['type'] == "getpeers")

    #     l = ["256.2.3.4:18018"]
    #     peers_msg = {'type':'peers','peers':l}
    #     await write_msg(writer, peers_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close()

    # async def test_invalid_format_8(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_8")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(True, msg_dict['type'] == "getpeers")

    #     l = ["1.2.3.4.5:678"]
    #     peers_msg = {'type':'peers','peers':l}
    #     await write_msg(writer, peers_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close()

    # async def test_invalid_format_9(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_9")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(True, msg_dict['type'] == "getpeers")

    #     l = ["nodotindomain:1234"]
    #     peers_msg = {'type':'peers','peers':l}
    #     await write_msg(writer, peers_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close()

    # async def test_invalid_format_10(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test INVALID_FORMAT_10")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(True, msg_dict['type'] == "getpeers")

    #     l = ["kermanode.net"]
    #     peers_msg = {'type':'peers','peers':l}
    #     await write_msg(writer, peers_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close()

    # async def test_getpeers_message(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test getpeers message validity")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     self.assertEqual(msg_dict['type'], "getpeers")
    #     self.assertEqual(list(msg_dict.keys()), ['type'])

    #     writer.close()  

    # async def test_peers_message(self):
    #     reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

    #     print("Test peers message validity")

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )

    #     getpeers_msg = {'type':'getpeers'}
    #     await write_msg(writer, getpeers_msg)

    #     msg_str = await asyncio.wait_for(
    #         reader.readline(),
    #         timeout=5.0
    #     )
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     self.assertEqual(msg_dict['type'], "peers")
    #     self.assertEqual(sorted(list(msg_dict.keys())), sorted(['peers', 'type']))
    #     self.assertEqual(len(msg_dict['peers']) > 30, False)

    #     writer.close()  

    async def test_tx_validation(self):
        print("Transaction validation 1")
        tx_object = {
            "height" : 0 ,
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 50000000000000
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        
        self.assertTrue(objects.validate_object(tx_object))

    async def test_tx_validation2(self):
        print("Transaction validation 2")
        tx_object = {
            "height" : -1 ,
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 50000000000000
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Transaction key height is invalid" in e.message)

    async def test_tx_validation3(self):
        print("Transaction validation 3")
        tx_object = {
            "height" : 0 ,
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969" ,
                    "value" : 50000000000000
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Object's 'pubkey' is of incorrect format" in e.message)

    async def test_tx_validation4(self):
        print("Transaction validation 4")
        tx_object = {
            "height" : 0 ,
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : -1
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Transaction key value is invalid" in e.message)

    async def test_tx_validation5(self):
        print("Transaction validation 5")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "height" : 0 ,
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Invalid transaction msg" in e.message)

    async def test_tx_validation6(self):
        print("Transaction validation 6")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            kermastorage.check_objectid_exists = MagicMock(return_value = False)
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "UNKNOWN_OBJECT")
            self.assertTrue("Object not present in DB" in e.message)

    async def test_tx_validation7(self):
        print("Transaction validation 7")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04",
                    "random": "random"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Invalid transaction field inputs" in e.message)

    async def test_tx_validation8(self):
        print("Transaction validation 8 - One extra letter in signature")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f045"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Object's 'sig' is of incorrect format" in e.message)

    async def test_tx_validation9(self):
        print("Transaction validation 9")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347",
                        "random": "random"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Invalid transaction field outpoint" in e.message)

    async def test_tx_validation10(self):
        print("Transaction validation 10 - One extra letter in txid")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b2893467"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Object's 'objectid' is of incorrect format" in e.message)

    async def test_tx_validation11(self):
        print("Transaction validation 11")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0.002,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Invalid transaction field index" in e.message)

    async def test_tx_validation12(self):
        print("Transaction validation 12")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            prev_tx_object = {
                "height" : 0,
                "outputs" : [
                    {
                        "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                        "value" : 50000000000000
                    }
                ],
                "type" : "block"
            }
            prev_tx_object = canonicalize(prev_tx_object)
            prev_tx_object = json.loads(prev_tx_object.decode())
            kermastorage.check_objectid_exists = MagicMock(return_value = True)
            kermastorage.get_object = MagicMock(return_value = prev_tx_object)
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_FORMAT")
            self.assertTrue("Wrong object referenced in the DB" in e.message)

    async def test_tx_validation13(self):
        print("Transaction validation 13")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 1,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                    "value" : 0
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        try:
            prev_tx_object = {
                "height" : 0,
                "outputs" : [
                    {
                        "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                        "value" : 50000000000000
                    }
                ],
                "type" : "transaction"
            }
            prev_tx_object = canonicalize(prev_tx_object)
            prev_tx_object = json.loads(prev_tx_object.decode())
            kermastorage.check_objectid_exists = MagicMock(return_value = True)
            kermastorage.get_object = MagicMock(return_value = prev_tx_object)
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_TX_OUTPOINT")
            self.assertTrue("Transaction index is out of scope" in e.message)

    async def test_tx_validation15(self):
        print("Transaction validation 15 - Weak conservation")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985" ,
                    "value" : 11
                },
                {
                    "pubkey" : "8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9" ,
                    "value" : 49999999999990
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        prev_tx_object = {
                "height" : 0,
                "outputs" : [
                    {
                        "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                        "value" : 50000000000000
                    }
                ],
                "type" : "transaction"
        }
        try:
            prev_tx_object = canonicalize(prev_tx_object)
            prev_tx_object = json.loads(prev_tx_object.decode())
            kermastorage.check_objectid_exists = MagicMock(return_value = True)
            kermastorage.get_object = MagicMock(return_value = prev_tx_object)
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_TX_CONSERVATION")
            self.assertTrue("Sum of outputs is larger than sum of inputs" in e.message)

    async def test_tx_validation16(self):
        print("Transaction validation 16 - Double spending")
        tx_object = {
            "inputs": [
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                },
                {
                    "outpoint" :      {
                        "index" : 0,
                        "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                    },
                    "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                }
            ],
            "outputs" : [
                {
                    "pubkey" : "b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985" ,
                    "value" : 10
                },
                {
                    "pubkey" : "8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9" ,
                    "value" : 49999999999990
                }
            ],
            "type" : "transaction"
        }
        tx_object = canonicalize(tx_object)
        tx_object = json.loads(tx_object.decode())
        prev_tx_object = {
                "height" : 0,
                "outputs" : [
                    {
                        "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
                        "value" : 50000000000000
                    }
                ],
                "type" : "transaction"
        }
        try:
            prev_tx_object = canonicalize(prev_tx_object)
            prev_tx_object = json.loads(prev_tx_object.decode())
            kermastorage.check_objectid_exists = MagicMock(return_value = True)
            kermastorage.get_object = MagicMock(return_value = prev_tx_object)
            objects.validate_object(tx_object)
        except MessageException as e:
            self.assertEqual(e.error_name, "INVALID_TX_CONSERVATION")
            self.assertTrue("Double spending" in e.message)

    # async def test_tx_validation14(self):
    #     print("Transaction validation 14 - Assert all is correct per protocol description")
    #     tx_object = {
    #         "inputs": [
    #             {
    #                 "outpoint" :      {
    #                     "index" : 0,
    #                     "txid" : "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
    #                 },
    #                 "sig" : "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
    #             }
    #         ],
    #         "outputs" : [
    #             {
    #                 "pubkey" : "b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985" ,
    #                 "value" : 10
    #             },
    #             {
    #                 "pubkey" : "8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9" ,
    #                 "value" : 49999999999990
    #             }
    #         ],
    #         "type" : "transaction"
    #     }
    #     tx_object = canonicalize(tx_object)
    #     tx_object = json.loads(tx_object.decode())
    #     prev_tx_object = {
    #             "height" : 0,
    #             "outputs" : [
    #                 {
    #                     "pubkey" : "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b" ,
    #                     "value" : 50000000000000
    #                 }
    #             ],
    #             "type" : "transaction"
    #     }
    #     prev_tx_object = canonicalize(prev_tx_object)
    #     prev_tx_object = json.loads(prev_tx_object.decode())
    #     kermastorage.check_objectid_exists = MagicMock(return_value = True)
    #     kermastorage.get_object = MagicMock(return_value = prev_tx_object)
    #     self.assertTrue(objects.validate_object(tx_object))

    

if __name__ == "__main__":
    unittest.main()