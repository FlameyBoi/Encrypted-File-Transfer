import sqlite3
import os
import errno
from datetime import datetime

try:
    ram_db = sqlite3.connect(":memory:")
except sqlite3.Error:
    print("Fatal error: Couldn't generate in memory database, terminating server")
    exit(errno.ENOMEM)

# Template for generating empty tables
db_preset = \
    "CREATE TABLE clients ( \
    ID CHAR(16) PRIMARY KEY, \
    Name CHAR(255) NOT NULL, \
    PublicKey CHAR(160), \
    LastSeen DATETIME, \
    AES CHAR(16) ); \
    CREATE TABLE files ( \
    ID CHAR(16) NOT NULL, \
    `File Name` CHAR(255) NOT NULL, \
    `Path Name` CHAR(160) NOT NULL, \
    Verified INT NOT NULL, \
    PRIMARY KEY(ID, 'File Name') \
    )"


# Initialize database: handles all startup setup of the database used by the server
def init_db():
    fail = True
    if os.path.exists("server.db"):
        try:
            old_db = sqlite3.connect("server.db")  # load saved disk db
            for line in old_db.iterdump():  # copy disk db into in mem db
                if line not in ('BEGIN;', 'COMMIT;'):
                    ram_db.execute(line)
            ram_db.commit()
            fail = False
        except sqlite3.Error:
            print("Error: Failed to load stored server data from server.db, using empty db")
            ram_db.rollback()
        finally:
            old_db.close()
    if fail:  # in case failed to initialize in mem db using disk db
        try:
            ram_db.executescript(db_preset)  # create db in mem with empty tables
            ram_db.commit()
        except sqlite3.Error as e:
            # Exiting and assuming lack of memory is the culprit - without ram_db no functionality can be maintained
            print("Fatal error: Couldn't generate in memory database, terminating server")
            print(e)
            exit(errno.ENOMEM)


# Check name: checks whether name is already taken. (unused since names aren't unique)
def check_name(name):
    try:
        cur = ram_db.cursor()
        sql = "SELECT Name FROM clients WHERE Name = ?"
        arg = (name,)
        res = cur.execute(sql, arg)
        cur.close()
        if not(res.fetchall() is None):
            return False
    except sqlite3.Error:
        print("Error: Failed to retrieve data from db, assuming name is taken")
        return False
    return True


# Check ID: Checks whether Name and ID combo exist in db and whether valid key is attached (used for reconnect check)
def check_id(name, uid):
    try:
        cur = ram_db.cursor()
        sql = "SELECT Name, ID, PublicKey FROM clients WHERE Name = ? AND ID = ?"
        name = name[:name.find('\0')] + '\0'
        name = bytes(name, "ascii")
        arg = (name, uid)
        res = cur.execute(sql, arg)
        res = res.fetchall()
        cur.close()
        if len(res) == 1:
            key = res[0][2]
            if len(key) != 0:
                return True
    except sqlite3.Error:
        print("Error: Failed to retrieve data from db, assuming mismatch")
        return False
    return False


# Check if ID exists: Checks whether a user with a given UID exists already (used when generating new UID)
def check_id_exists(uid):
    try:
        cur = ram_db.cursor()
        sql = "SELECT ID FROM clients WHERE ID = ?"
        arg = (uid,)
        res = cur.execute(sql, arg)
        res = res.fetchall()
        cur.close()
        if res is not None:
            return True
    except sqlite3.Error as e:
        print("Error: Failed to retrieve data from db, assuming mismatch", e)
        return False
    return False


# Check ID and file: checks whether file entry exists with given file name and ID (used in protocol ack_good to verify)
def check_id_file(uid, name):
    try:
        cur = ram_db.cursor()
        sql = "SELECT Verified FROM files WHERE `File Name` = ? AND ID = ?"
        name = name[:name.find(0)] + b'\0'
        args = (name, uid)
        res = cur.execute(sql, args)
        res = res.fetchall()
        cur.close()
        if len(res) != 0:
            return True
    except sqlite3.Error:
        print("Error: Failed to retrieve data from db, assuming mismatch")
        return False
    return False


# Register (db): creates new entry in clients table with given name and ID (used in protocol register)
def register(name, uid):
    try:
        cur = ram_db.cursor()
        name = str(name)
        name = name[:name.find('\0')] + '\0'
        name = bytes(name, "ascii")
        args = (name, uid)
        sql = "INSERT INTO clients(Name, ID) VALUES(?, ?)"
        cur.execute(sql, args)
        sql = "UPDATE clients SET NAME = ? WHERE ID = ?"
        cur.execute(sql, args)
        cur.close()
        ram_db.commit()
    except sqlite3.Error as e:
        print("Error: Failed to write data back to db, registration failed")
        print(e)
        return False
    return True


# Register file: creates new entry in files table with given ID, filename and path (used in protocol recv_file)
def register_file(uid, filename, path):
    try:
        cur = ram_db.cursor()
        sql = "SELECT ID FROM files WHERE ID = ? AND `File Name` = ?"
        args = (uid, filename)
        res = cur.execute(sql, args)
        res = res.fetchall()
        if not (len(res) == 0):  # if the user is re-sending existing file
            sql = "DELETE FROM files WHERE ID = ? AND `File Name` = ?"
            cur.execute(sql, args)  # Delete existing entry
        args = (uid, filename, path, 0)
        sql = "INSERT INTO files(ID, `File Name`, `Path Name`, Verified) VALUES(?, ?, ?, ?)"
        cur.execute(sql, args)
        cur.close()
        ram_db.commit()
    except sqlite3.Error as e:
        print("Error: Failed to write data back to db, file registration failed")
        print(e)
        return False
    return True


# Update keys: update AES and PublicKey fields of a client entry (used in protocol recv_key)
def update_keys(pubkey, privkey, uid):
    try:
        cur = ram_db.cursor()
        args = (pubkey, privkey, uid)
        sql = "UPDATE clients SET PublicKey = ?, AES = ? WHERE ID = ?"
        cur.execute(sql, args)
        cur.close()
        ram_db.commit()
    except sqlite3.Error:
        print("Error: Failed to write data back to db, failed to update key data")
        return False
    return True


# Verify: sets Verify field of entry in files table to "TRUE" (1) (used in protocol ack_good)
def verify(uid, filename):
    try:
        cur = ram_db.cursor()
        args = (uid, filename)
        sql = "UPDATE files SET Verified = 1 WHERE ID = ? AND `File Name` = ?"
        cur.execute(sql, args)
        cur.close()
        ram_db.commit()
    except sqlite3.Error:
        print("Error: Failed to write data back to db, failed to update key data")
        return False
    return True


# Get key: used to retrieve PublicKey from client entry upon client reconnect
def get_key(uid):
    try:
        cur = ram_db.cursor()
        arg = (uid,)
        sql = "SELECT PublicKey FROM clients WHERE ID = ?"
        res = cur.execute(sql, arg)
        res = res.fetchone()[0]
        cur.close()
    except sqlite3.Error:
        print("Error: Failed to read data from db")
        return False
    return res


# Get AES: fetches AES key in clients entry with given ID (used in protocol recv_file)
def get_aes(uid):
    try:
        cur = ram_db.cursor()
        arg = (uid,)
        sql = "SELECT AES FROM clients WHERE ID = ?"
        res = cur.execute(sql, arg)
        res = res.fetchone()[0]
        cur.close()
    except sqlite3.Error:
        print("Error: Failed to read data from db")
        return False
    return res


# Get name: Fetches name of client entry with given ID (used in recv_file for path generation)
def get_name(uid):
    try:
        cur = ram_db.cursor()
        arg = (uid,)
        sql = "SELECT Name FROM clients WHERE ID = ?"
        res = cur.execute(sql, arg)
        res = res.fetchone()
        cur.close()
    except sqlite3.Error:
        print("Error: Failed to read data from db")
        return False
    return res


# Write back: backs up in mem db on the server.db file to avoid data loss upon server failure
def write_back():
    try:
        try:
            os.remove("temp.db")
        except OSError:
            pass
        server_db = sqlite3.connect("temp.db")
        for line in ram_db.iterdump():
            if line not in ('BEGIN;', 'COMMIT;'):
                server_db.execute(line)
        server_db.commit()
        server_db.close()
        try:
            os.remove("server.db")
        except OSError:
            pass
        os.rename("temp.db", "server.db")
    except sqlite3.Error as e:
        print("Error: Failed to save volatile server data into server.db", e)
    finally:
        server_db.close()  # note that server can function without backing up


# Update time: sets the last seen field of client entry to current time
def update_time(uid):
    try:
        cur = ram_db.cursor()
        now = datetime.now()
        now = now.strftime("%Y-%m-%d %H:%M:%S").__str__()
        args = (now, uid)
        sql = "UPDATE clients SET LastSeen = ? WHERE ID = ?"
        cur.execute(sql, args)
        cur.close()
        ram_db.commit()
    except sqlite3.Error as e:
        print("Error: Failed to write data back to db, failed to update key data", e)
        return False
    return True
