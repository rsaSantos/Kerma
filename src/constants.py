from Peer import Peer

EXTERNAL_IP = "35.207.97.80" # This is hardcoded...

PORT = 18018
ADDRESS = "0.0.0.0"
SERVICE_LOOP_DELAY = 10
UNFINDABLE_OBJECT_DELAY = 5
VERSION = '0.10.1'
AGENT = 'kerma-node-g4'
LOW_CONNECTION_THRESHOLD = 3
HELLO_MSG_TIMEOUT = 20.0
DB_NAME = 'db.db'
RECV_BUFFER_LIMIT = 512 * 1024
BLOCK_TARGET = "00000000abc00000000000000000000000000000000000000000000000000000"
BLOCK_VERIFY_WAIT_FOR_PREV_MUL = 10
BLOCK_VERIFY_WAIT_FOR_PREV = 1
BLOCK_VERIFY_WAIT_FOR_TXS_MUL = 10
BLOCK_VERIFY_WAIT_FOR_TXS = 1
BLOCK_REWARD = 50_000_000_000_000
GENESIS_BLOCK_ID = "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2"
GENESIS_BLOCK = {
        "T":"00000000abc00000000000000000000000000000000000000000000000000000",
        "created":1671062400,
        "miner":"Marabu",
        "nonce":"000000000000000000000000000000000000000000000000000000021bea03ed",
        "note":"The New York Times 2022-12-13: Scientists Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers",
        "previd": None,
        "txids":[],
        "type":"block"
}


BANNED_HOSTS = [ # TODO: TASK 2: Ban hosts that send invalid data ?
]

# TODO: Uncomment the following lines to connect to the network...
PRELOADED_PEERS = {
    Peer("128.130.122.101", 18018), # lecturers node
    #Peer("35.207.97.80", 18018),    # google cloud node
    #Peer("127.0.0.1", 18019),         # For testing purposes
}