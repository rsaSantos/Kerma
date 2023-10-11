import sqlite3

import objects
import constants as const

def main():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        # TODO - Build database

        # TODO - Preload genesis block

    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()


if __name__ == "__main__":
    main()
