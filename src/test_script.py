import asyncio
import ipaddress
import json
import random
import re
import sys
import unittest

import constants as const

from jcs import canonicalize

def parse_msg(msg_str):
    return json.loads(msg_str.decode())

async def write_msg(writer, msg_dict):
    writer.write(b''.join([canonicalize(msg_dict), b'\n']))
    await writer.drain()

class Test(unittest.IsolatedAsyncioTestCase):
    async def test_hello_message(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test hello message validity")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "hello")
        self.assertEqual(list(msg_dict.keys()), ['agent', 'type', 'version'])
        self.assertEqual(True, msg_dict['agent'].isprintable())
        self.assertEqual(True, len(msg_dict['agent']) <= 128)
        self.assertIsNotNone(re.match(r'^0\.10\.\d$', msg_dict['version']))

        writer.close() 

    async def test_invalid_handshake_1(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_HANDSHAKE_1")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        invalid_msg = {'type':'getpeers'}
        await write_msg(writer, invalid_msg)
        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

        writer.close() 

    async def test_invalid_handshake_2(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_HANDSHAKE_2")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        await asyncio.sleep(20)

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

        writer.close() 

    async def test_invalid_handshake_3(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_HANDSHAKE_3")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)
        
        msg_str = await reader.readline()  # Here we expect the node to act in a good way, thus send any message besides hello
        
        await write_msg(writer, hello_msg)       # Send one more hello message on purpose
        msg_str = await reader.readline()  # Node should be able to detect a second hello message thus send an error message
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

        writer.close() 

    async def test_invalid_format_1(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)
        
        print("Test INVALID_FORMAT_1")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        non_printable_string = "Sending\nmessages"
        self.assertEqual(False, non_printable_string.isprintable())
        hello_msg = {'type':'hello','version':'0.10.0','agent':non_printable_string}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")
        
        writer.close() 

    async def test_invalid_format_2(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_2")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        long_string = ""
        for i in range(0, 129):
            long_string += 'a'
        self.assertEqual(True, len(long_string) == 129)
        hello_msg = {'type':'hello','version':'0.10.0','agent':long_string}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close() 

    async def test_invalid_format_3(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_3")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        version = '0.10.10'
        hello_msg = {'type':'hello','version':version,'agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close() 

    async def test_invalid_format_4(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_4")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        hello_msg = {'type':'hello','version':'0.10.0'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close() 

    async def test_invalid_format_5(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_5")

        await reader.readline()

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(True, msg_dict['type'] == "getpeers")

        peers_msg = {'type':'peers','peers':[], 'extra':'key'}
        await write_msg(writer, peers_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close() 

    async def test_invalid_format_6(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_6")

        await reader.readline()

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(True, msg_dict['type'] == "getpeers")

        l = []
        for i in range(0, 31):
            l.append("0.0.0.1:256")
        peers_msg = {'type':'peers','peers':l}
        await write_msg(writer, peers_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close()  

    async def test_invalid_format_7(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_7")

        await reader.readline()

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(True, msg_dict['type'] == "getpeers")

        l = ["0.0.0.1:65536"]
        peers_msg = {'type':'peers','peers':l}
        await write_msg(writer, peers_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close()
    
    async def test_invalid_format_7(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_7")

        await reader.readline()

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(True, msg_dict['type'] == "getpeers")

        l = ["256.2.3.4:18018"]
        peers_msg = {'type':'peers','peers':l}
        await write_msg(writer, peers_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close()

    async def test_invalid_format_8(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_8")

        await reader.readline()

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(True, msg_dict['type'] == "getpeers")

        l = ["1.2.3.4.5:678"]
        peers_msg = {'type':'peers','peers':l}
        await write_msg(writer, peers_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close()

    async def test_invalid_format_9(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_9")

        await reader.readline()

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(True, msg_dict['type'] == "getpeers")

        l = ["nodotindomain:1234"]
        peers_msg = {'type':'peers','peers':l}
        await write_msg(writer, peers_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close()

    async def test_invalid_format_10(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test INVALID_FORMAT_10")

        await reader.readline()

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(True, msg_dict['type'] == "getpeers")

        l = ["kermanode.net"]
        peers_msg = {'type':'peers','peers':l}
        await write_msg(writer, peers_msg)

        msg_str = await reader.readline()
        msg_dict = parse_msg(msg_str)
        self.assertEqual(msg_dict['type'], "error")
        self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

        writer.close()

    async def test_getpeers_message(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test getpeers message validity")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        self.assertEqual(msg_dict['type'], "getpeers")
        self.assertEqual(list(msg_dict.keys()), ['type'])

        writer.close()  

    async def test_peers_message(self):
        reader, writer = await asyncio.open_connection(const.EXTERNAL_IP, const.PORT, limit=const.RECV_BUFFER_LIMIT)

        print("Test peers message validity")

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
        await write_msg(writer, hello_msg)

        await reader.readline()

        getpeers_msg = {'type':'getpeers'}
        await write_msg(writer, getpeers_msg)

        msg_str = await reader.readline()
        try:
            parse_msg(msg_str)
        except Exception as e:
            self.fail("Message was parsed incorrectly")
        msg_dict = parse_msg(msg_str)

        self.assertEqual(msg_dict['type'], "peers")
        self.assertEqual(list(msg_dict.keys()), sorted(['peers', 'type']))
        self.assertEqual(len(msg_dict['peers']) > 30, False)

        writer.close()  

if __name__ == "__main__":
    unittest.main()