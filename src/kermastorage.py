import sqlite3
import os
from jcs import canonicalize

import objects
import constants as const

def get_connection():
    return sqlite3.connect(const.DB_NAME)

def check_objectid_exists(objid_str):
    con = get_connection()
    try:
        cur = con.cursor()
        cur.execute("SELECT * FROM objects WHERE object_id=?", (objid_str,))
        row = cur.fetchone()
        return row is not None
    except Exception as e:
        print("Error checking if object exists: " + str(e))
    finally:
        con.close()

def save_object(obj_id, obj_dict):
    con = get_connection()
    try:        
        cur = con.cursor()
        cur.execute("INSERT INTO objects VALUES (?,?)", (obj_id, canonicalize(obj_dict)))
        con.commit()
    except Exception as e:
        con.rollback()
        print("Error saving object: " + str(e))
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
        cur.execute("CREATE TABLE objects (object_id TEXT PRIMARY KEY, object TEXT)")

        # Preload genesis block -> For now we are treating it as an object as well.
        genesis_block = canonicalize(const.GENESIS_BLOCK)
        genesis_block_row = (const.GENESIS_BLOCK_ID, genesis_block)
        cur.execute("INSERT INTO objects VALUES (?,?)", genesis_block_row)
        con.commit()

    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()
        print("Database created successfully!")
