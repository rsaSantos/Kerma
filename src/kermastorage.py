import sqlite3
import os
from jcs import canonicalize
import json

import objects
import constants as const

TABLE_BLOCKS = "blocks"
TABLE_TRANSACTIONS = "transactions"

GET_BLOCK_QUERY = "SELECT block_data FROM " + TABLE_BLOCKS + " WHERE block_id=?"
GET_TRANSACTION_QUERY = "SELECT transaction_data FROM " + TABLE_TRANSACTIONS + " WHERE transaction_id=?"

def get_object_table_name(obj_type):
    if obj_type == "block":
        return TABLE_BLOCKS
    if obj_type == "transaction":
        return TABLE_TRANSACTIONS
    return None

def get_connection():
    return sqlite3.connect(const.DB_NAME)

# Reduce the usage of this method if we want to get the object anyway!
def check_objectid_exists(obj_id):
    return get_object(obj_id) is not None

# Saving an object in the database. The object can be either a block or a transaction
def save_object(obj_id, obj_dict):
    global TABLE_BLOCKS, TABLE_TRANSACTIONS

    # Decide which table to use based on the object type
    table_name = get_object_table_name(obj_dict["type"])

    if table_name is None:
        print("Error in finding database table. Unknown object type: " + obj_dict["type"])
        return False

    con = get_connection()
    try:        
        cur = con.cursor()
        cur.execute("INSERT INTO " + table_name + " VALUES (?,?)", (obj_id, canonicalize(obj_dict)))
        con.commit()
        return True
    except Exception as e:
        con.rollback()
        print("Error saving object: " + str(e))
        return False
    finally:
        con.close()

def get_block(block_id):
    return get_object(block_id, "block")

def get_transaction(transaction_id):
    return get_object(transaction_id, "transaction")

# Only use this method when only the object id is known.
def get_object(obj_id, obj_type=None):
    global TABLE_BLOCKS, TABLE_TRANSACTIONS

    # Get table name based on object type.
    # If the object type is not specified, use the transaction table by default.
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

        # We got no results, let's search the block table only if we were searching the transaction table
        # If we already searched the block table it means that was the intended table and we should return None
        if row is None and table_name == TABLE_TRANSACTIONS:
            cur.execute(GET_BLOCK_QUERY, (obj_id,))
            row = cur.fetchone()

        return None if row is None else json.loads(row[0])
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
        #
        # For now its just one table with the following columns:
        # - object_id (TEXT)
        # - object (TEXT -> JSON)
        #
        cur.execute("CREATE TABLE " + TABLE_BLOCKS + " (block_id TEXT PRIMARY KEY, block_data BLOB)")
        cur.execute("CREATE TABLE " + TABLE_TRANSACTIONS + " (transaction_id TEXT PRIMARY KEY, transaction_data BLOB)")
        # Preload genesis block
        genesis_block = canonicalize(const.GENESIS_BLOCK)
        genesis_block_row = (const.GENESIS_BLOCK_ID, genesis_block)
        cur.execute("INSERT INTO " + TABLE_BLOCKS + " VALUES (?,?)", genesis_block_row)
        con.commit()

        print("Database created successfully!")
    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()
