import asyncio
import ipaddress
import json
import random
import re
import hashlib
import sys
import unittest
from unittest.mock import MagicMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import kermastorage
import constants as const
import objects
import main
from message.msgexceptions import *

from jcs import canonicalize

def parse_msg(msg_str):
    return json.loads(msg_str.decode())

def get_objid(obj_dict):
    h = hashlib.blake2s()
    h.update(canonicalize(obj_dict))
    return h.hexdigest()

async def write_msg(writer, msg_dict):
    writer.write(b''.join([canonicalize(msg_dict), b'\n']))
    await writer.drain()

class Test(unittest.IsolatedAsyncioTestCase):
    async def test_task4_1(self):
        reader, writer = await asyncio.open_connection(const.ADDRESS, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        ### 1.) SEND HELLO AND BLOCK

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)
        
        block_object = {"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671619268,"miner":"grader","nonce":"400000000000000000000000000000000000000000000000000000000829de57","note":"This block spends coinbase transaction twice","previd":"0000000060b3533ef3085c25c932fb9bc8ce7a7b5df416810bd90d064426e7db","txids":["775f50d658a491d1dc24c8897f1641625a7aa3b03bd954e2df044739634d5fb2","0fa69da6414a70cb63ff10e85575eaad7c8ab5d87d8d2d46fd8c5071a7f7596b"],"type":"block"},"type":"object"}
        await write_msg(writer, block_object)
        
        ### 2.) RECEIVE HELLO, GETPEERS, GETOBJECT since tx is missing

        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "hello")
            
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "getpeers")
        
        ### CHECK FOR FIRST getobject
        
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "getobject")
        
        print(msg_dict)
        
        ### CHECK FOR SECOND getobject
        
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "getobject")
        
        print(msg_dict)
        
        ### CHECK FOR THIRD getobject
        
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "getobject")
        
        print(msg_dict)
        
        ### 3.) SEND MISSING txs FIRST
        
        tx_object = {"object":{"inputs":[{"outpoint":{"index":0,"txid":"82c4e79709e8e1e02ddc83732cffe3378a10157b277b3783de7d9159fd28b177"},"sig":"50045a2ff86cd4dfcc84b68fe1a5886473adce286f8190f28221ca2aabf958d9366bd4c8998ae7cb6a454d4c5feedf3e7f2a9479b25413213ed05a29bc0dae01"}],"outputs":[{"pubkey":"24da8dc19699303e97fe409d051f5df970382b3cf8d15db50f497283cfda3b60","value":46000000000000}],"type":"transaction"},"type":"object"}
        await write_msg(writer, tx_object)
        
        tx_object = {"object":{"inputs":[{"outpoint":{"index":0,"txid":"82c4e79709e8e1e02ddc83732cffe3378a10157b277b3783de7d9159fd28b177"},"sig":"88e54d03e0c63e7e4ce7e876f4892a4dde5530f43e997bc03757b88fd5be6b0c3dbbf3e580175fd7df768cb5364fcf4ad6f7607ba9998d5448fa1ff906c2ed0b"}],"outputs":[{"pubkey":"49d81be4620eb0d2e4cfefc9a2e5f5e86d5a66dbd27366ceefc2226b37378597","value":48000000000000}],"type":"transaction"},"type":"object"}
        await write_msg(writer, tx_object)
        
        ### RECEIVE getobject
        
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "getobject")
        
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "getobject")
        
        ### SEND MISSING tx
        
        tx_object = {"object":{"height":1,"outputs":[{"pubkey":"899409ae22db1045a60a3bde49654b12ba145c2f49249a3639be0d0de0e2ef72","value":50000000000000}],"type":"transaction"},"type":"object"}
        await write_msg(writer, tx_object)
        
        ### RECEIVE ihaveobject
        
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "ihaveobject")
            
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "ihaveobject")
        
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "ihaveobject")
        
        ### 4.) SEND MISSING BLOCK
        
        block_object = {"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671590312,"miner":"grader","nonce":"c4b7acc9d2eec9df7b3ed1b1f4ea6f75aeb1f9be651d12c9e23c1725f1c661b9","note":"This block has a coinbase transaction","previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","txids":["82c4e79709e8e1e02ddc83732cffe3378a10157b277b3783de7d9159fd28b177"],"type":"block"},"type":"object"}
        await write_msg(writer, block_object)
        
        ### RECEIVE ihaveobject
        
        # msg_str = await asyncio.wait_for(
        #     reader.readline(),
        #     timeout=5.0
        # )
        # try:
        #     parse_msg(msg_str)
        # except Exception as e:
        #     self.fail("Message was parsed incorrectly")
        # msg_dict = parse_msg(msg_str)    
        # self.assertEqual(msg_dict['type'], "ihaveobject")
        
        ### 5.) INVALID_TX_OUTPOINT ON THE INITIAL OBJECT
        
        msg_str = await asyncio.wait_for(
            reader.readline(),
            timeout=5.0
        )
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)    
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_TX_OUTPOINT")

        writer.close()

if __name__ == "__main__":
    unittest.main()