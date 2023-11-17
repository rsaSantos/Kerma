import sqlite3
import os
from jcs import canonicalize
import json

import constants as const

BLOCK = "block"
TRANSACTION = "transaction"

TABLE_BLOCKS = "blocks"
TABLE_TRANSACTIONS = "transactions"

GET_BLOCK_QUERY = "SELECT * FROM " + TABLE_BLOCKS + " WHERE block_id=?"
CHECK_BLOCK_EXISTS_QUERY = "SELECT COUNT(*) FROM " + TABLE_BLOCKS + " WHERE block_id=?"

GET_TRANSACTION_QUERY = "SELECT * FROM " + TABLE_TRANSACTIONS + " WHERE transaction_id=?"
CHECK_TRANSACTION_EXISTS_QUERY = "SELECT COUNT(*) FROM " + TABLE_TRANSACTIONS + " WHERE transaction_id=?"

def get_object_table_name(obj_type):
    if obj_type == BLOCK:
        return TABLE_BLOCKS
    if obj_type == BLOCK:
        return TABLE_TRANSACTIONS
    return None

def get_connection():
    return sqlite3.connect(const.DB_NAME)

# Reduce the usage of this method if we want to get the object anyway!
def check_objectid_exists(obj_id):
    global TABLE_BLOCKS, TABLE_TRANSACTIONS

    con = get_connection()
    try:
        cur = con.cursor()
        cur.execute(CHECK_TRANSACTION_EXISTS_QUERY, (obj_id,))
        row = cur.fetchone()
        if row[0] == 0:
            cur.execute(CHECK_BLOCK_EXISTS_QUERY, (obj_id,))
            row = cur.fetchone()
        
        return row[0] > 0    
    except Exception as e:
        print("Error checking object id: " + str(e))
        return False
    finally:
        con.close()

# Saving an object in the database. The object can be either a block or a transaction
def save_object(obj_id, obj_dict, utxo_set = None, height = None):
    global TABLE_BLOCKS, TABLE_TRANSACTIONS

    # Decide which table to use based on the object type
    table_name = get_object_table_name(obj_dict["type"])

    if table_name is None:
        print("Error in finding database table. Unknown object type: " + obj_dict["type"])
        return False

    con = get_connection()
    try:        
        cur = con.cursor()
        if table_name == TABLE_TRANSACTIONS:
            cur.execute("INSERT INTO " + table_name + " VALUES (?,?)", (obj_id, canonicalize(obj_dict)))
        elif table_name == TABLE_BLOCKS and height is not None:
            cur.execute("INSERT INTO " + table_name + " VALUES (?,?,?)", (obj_id, canonicalize(obj_dict), utxo_set, height))
        else:
            if height is None:
                raise Exception("Height is not defined")
            else:
                raise Exception("Unknown object type: " + obj_dict["type"])

        con.commit()
        return True

    except Exception as e:
        con.rollback()
        print("Error saving object: " + str(e))
        return False
    finally:
        con.close()

# The following methods are used to get the data of a block or a transaction
# We can get only the data or the full row (without the object id)
#
# The transaction query will return: (tx_id, tx_data)
# The block query will return: (block_id, block_data, utxo_set, height)
#
#
# Returns all the columns of the block table (without block_id)
def get_block_full(block_id):
    block_row = get_object(block_id, BLOCK)
    if block_row is None:
        return None
    else:
        return block_row[1:] # Returns: (block_data, utxo_set, height)

def get_block_data(block_id):
    block_row = get_object(block_id, BLOCK)
    if block_row is None:
        return None
    else:
        return block_row[1]

def get_utxo_set(block_id):
    block_row = get_object(block_id, BLOCK)
    if block_row is None:
        return None
    else:
        return block_row[2]
    
def get_block_height(block_id):
    block_row = get_object(block_id, BLOCK)
    if block_row is None:
        return None
    else:
        return block_row[3]

def get_transaction_data(transaction_id):
    transaction_row = get_object(transaction_id, TRANSACTION)
    if transaction_row is None:
        return None
    else:
        return transaction_row[1]

def handle_row(row, return_only_data):
    # If the row is empty, return None
    if row is None:
        return None
    if return_only_data:
        return json.loads(row[1])
    
    # Iterate tuple and convert respective JSON strings to python objects
    ret = []
    for i in range(len(row)):
        decoded = row[i] if type(row[i]) != bytes else row[i].decode("utf-8")

        if decoded is None:
            ret.append(None)
        elif isinstance(decoded, str) and decoded.startswith("{"):
            ret.append(json.loads(decoded))
        else:
            ret.append(decoded)

    return ret

# Only use this method when only the object id is known.
def get_object(obj_id, obj_type=None):
    global TABLE_BLOCKS, TABLE_TRANSACTIONS

    # Get table name based on object type.
    # If the object type is not specified, use the transaction table by default.
    check_all_tables = obj_type is None
    return_only_data = check_all_tables # If we queried without specifying the object type, we only want the data
    table_name = get_object_table_name(obj_type)
    if table_name is None:
        table_name = TABLE_TRANSACTIONS
    
    con = get_connection()
    try:
        cur = con.cursor()
        if table_name == TABLE_TRANSACTIONS:
            cur.execute(GET_TRANSACTION_QUERY, (obj_id,))
        elif table_name == TABLE_BLOCKS:
            cur.execute(GET_BLOCK_QUERY, (obj_id,))
        else:
            raise Exception("Error in finding database table. Unknown object type: " + obj_type)

        row = cur.fetchone()

        # We got no results, let's search the block table if we didn't already...
        if check_all_tables and row is None:
            cur.execute(GET_BLOCK_QUERY, (obj_id,))
            row = cur.fetchone()

        return None if row is None else handle_row(row, return_only_data)
    except Exception as e:
        print("Error getting object: " + str(e))
        return None
    finally:
        con.close()

def create_db():
    # If the database already exists, no need to create it again
    if os.path.exists(const.DB_NAME):
        print("Database already exists...")
        return

    con = get_connection()
    try:
        cur = con.cursor()

        # Build database
        cur.execute("CREATE TABLE " + TABLE_BLOCKS + " (block_id TEXT PRIMARY KEY, block_data BLOB NOT NULL, utxo_set BLOB, height INTEGER NOT NULL)")
        cur.execute("CREATE TABLE " + TABLE_TRANSACTIONS + " (transaction_id TEXT PRIMARY KEY, transaction_data BLOB NOT NULL)")
        # Preload genesis block
        genesis_block = canonicalize(const.GENESIS_BLOCK)
        genesis_block_row = (const.GENESIS_BLOCK_ID, genesis_block, None, 0)
        cur.execute("INSERT INTO " + TABLE_BLOCKS + " VALUES (?,?,?,?)", genesis_block_row)
        con.commit()

        print("Database created successfully!")
    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()
