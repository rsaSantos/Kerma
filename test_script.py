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

async def write_msg(writer, msg_dict):
    writer.write(b''.join([canonicalize(msg_dict), b'\n']))
    await writer.drain()

class Test(unittest.IsolatedAsyncioTestCase):
    # async def test_hello_message(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

    #     print("Test hello message validity")

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "hello")
    #     self.assertEqual(list(msg_dict.keys()), ['agent', 'type', 'version'])
    #     print("Here")
    #     self.assertEqual(True, msg_dict['agent'].isprintable())
    #     print("Here")
    #     self.assertEqual(True, len(msg_dict['agent']) <= 128)
    #     print("Here")
    #     self.assertIsNotNone(re.match(r'^0\.10\.\d$', msg_dict['version']))
    #     print("Here")

    #     writer.close() 

    # async def test_invalid_handshake_1(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

    #     print("Test INVALID_HANDSHAKE_1")

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     invalid_msg = {'type':'getpeers'}
    #     await write_msg(writer, invalid_msg)
    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

    #     writer.close() 

    # async def test_invalid_handshake_2(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

    #     print("Test INVALID_HANDSHAKE_2")

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     await asyncio.sleep(20)

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

    #     writer.close() 

    # async def test_invalid_handshake_3(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

    #     print("Test INVALID_HANDSHAKE_3")

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)
        
    #     msg_str = await reader.readline()  # Here we expect the node to act in a good way, thus send any message besides hello
        
    #     await write_msg(writer, hello_msg)       # Send one more hello message on purpose
    #     msg_str = await reader.readline()  # Node should be able to detect a second hello message thus send an error message
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_HANDSHAKE")

    #     writer.close() 

    # async def test_invalid_format_1(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))
        
    #     print("Test INVALID_FORMAT_1")

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     non_printable_string = "Sending\nmessages"
    #     self.assertEqual(False, non_printable_string.isprintable())
    #     hello_msg = {'type':'hello','version':'0.10.0','agent':non_printable_string}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")
        
    #     writer.close() 

    # async def test_invalid_format_2(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

    #     print("Test INVALID_FORMAT_2")

    #     msg_str = await reader.readline()
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

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close() 

    # async def test_invalid_format_3(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

    #     print("Test INVALID_FORMAT_3")

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     version = '0.10.10'
    #     hello_msg = {'type':'hello','version':version,'agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close() 

    # async def test_invalid_format_4(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

    #     print("Test INVALID_FORMAT_4")

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     hello_msg = {'type':'hello','version':'0.10.0'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)
    #     self.assertEqual(msg_dict['type'], "error")
    #     self.assertEqual(msg_dict['name'], "INVALID_FORMAT")

    #     writer.close() 

    # async def test_getpeers_message(self):
    #     reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

    #     print("Test getpeers message validity")

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     hello_msg = {'type':'hello','version':'0.10.0','agent':'Sending messages'}
    #     await write_msg(writer, hello_msg)

    #     msg_str = await reader.readline()
    #     try:
    #         parse_msg(msg_str)
    #     except Exception as e:
    #         self.fail("Message was parsed incorrectly")
    #     msg_dict = parse_msg(msg_str)

    #     self.assertEqual(msg_dict['type'], "getpeers")
    #     self.assertEqual(list(msg_dict.keys()), ['type'])

    #     writer.close()  

    async def test_peers_message(self):
        reader, writer = await asyncio.open_connection("0.0.0.0", 18020, limit= (512 * 1024))

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
        self.assertEqual(list(msg_dict.keys()), ['peers', 'type'])
        self.assertEqual(len(msg_dict['peers']) > 30, False)

        writer.close()  

if __name__ == "__main__":
    unittest.main()