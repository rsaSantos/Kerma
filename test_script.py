import asyncio
import ipaddress
import json
import random
import re
import sys
import unittest

from jcs import canonicalize

def parse_msg(msg_str):
    return json.loads(msg_str.decode())

class Test(unittest.IsolatedAsyncioTestCase):
    async def test_hello_message(self):
        reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))
        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "hello")

if __name__ == "__main__":
    unittest.main()