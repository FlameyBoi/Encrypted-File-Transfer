import socket
import uuid
import struct
import db
from header import *
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
from main import sel
import time
import os

# Dict detailing response codes to sent code
codeDict = {REGISTER: {GOOD: REGISTER_GOOD, BAD: REGISTER_BAD}, SEND_KEY: GOT_KEY, SEND_FILE: SEND_CRC,
            RECONNECT: {GOOD: RECONNECT_GOOD, BAD: RECONNECT_BAD}, GOOD_CRC: CRC_ACK, FAIL_CRC: CRC_ACK}
# Dict detailing size of static portion of payloads according to code
sizeDict = {REGISTER: NAME_SIZE, SEND_KEY: NAME_SIZE + KEY_SIZE, RECONNECT: NAME_SIZE, SEND_FILE: SIZE_SIZE + NAME_SIZE,
            BAD_CRC: NAME_SIZE, GOOD_CRC: NAME_SIZE, FAIL_CRC: NAME_SIZE, REGISTER_GOOD: UID_SIZE, REGISTER_BAD: 0,
            RECONNECT_GOOD: UID_SIZE, SEND_CRC: UID_SIZE + SIZE_SIZE + NAME_SIZE + CRC_SIZE, CRC_ACK: UID_SIZE,
            RECONNECT_BAD: UID_SIZE, GOT_KEY: UID_SIZE, GENERIC_ERROR: 0}
# Dict detailing possible response codes from client based on last sent code
nextcodeDict = {REGISTER: [SEND_KEY], RECONNECT: [SEND_FILE], SEND_KEY: [SEND_FILE],
                SEND_FILE: [GOOD_CRC, BAD_CRC, FAIL_CRC], BAD_CRC: [SEND_FILE]}
# Dict that holds protocol state of currently open connections
openConns = {}
connUID = {}


# Register: create new user entry in clients table with newly generated ID
def register(header, conn):
    # Check size validity before reading payload to avoid DOS attack caused by absurdly large payloads
    if header.size != sizeDict[header.code]:
        print("Error: Bad payload size, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    payload = conn.recv(header.size)  # receive payload (name)
    time.sleep(1)
    payload = payload.decode("ascii", errors="ignore")  # decode name from ascii encoding
    index = payload.find('\0')
    payload = payload[:index] + '\0'  # null terminate
    payload = payload + ('\0' * (NAME_SIZE - len(payload)))  # pad name
    uid = generate_uuid()
    if not db.register(payload, uid):
        fail_register(conn)
        return
    code = codeDict[header.code][GOOD]
    h = ServerHeader(code, sizeDict[code])
    packet = struct.pack("<BHI16s", h.ver, h.code, h.size, uid)  # generate bytes representation of packet
    num = conn.send(packet)
    print(num)
    time.sleep(1)
    expected_codes = nextcodeDict[header.code]  # set of expected codes
    openConns[uid] = [payload, conn, expected_codes, RETRIES, RETRIES, None, None, None, None, None]
    db.update_time(uid)  # update last seen


# Reconnect: set up connection with already registered user
def reconnect(header, conn):
    if header.size != sizeDict[header.code]:
        print("Error: Bad payload size, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    payload = conn.recv(header.size).decode("ascii", errors="ignore")  # receive payload (name)
    index = payload.find('\0')
    payload = payload[:index] + '\0'  # null terminate
    payload = payload + ('\0' * (NAME_SIZE - len(payload)))  # pad name
    if not(db.check_id(payload, header.uid)):
        print("Error: Reconnect failed, no such Name - UID combination or no valid key available")
        fail_reconnect(conn)
        return
    plainKey = Random.get_random_bytes(16)  # generate plain AES key
    key = db.get_key(header.uid)
    pubKey = RSA.importKey(key)  # public key from bytes
    cipher = PKCS1_OAEP.new(pubKey)  # generate wrapper for public key
    encrypted = cipher.encrypt(plainKey)  # encrypt AES using public key
    code = codeDict[header.code][GOOD]
    h = ServerHeader(code, sizeDict[code] + len(encrypted))
    if not (db.update_keys(pubKey.exportKey(), plainKey, header.uid)):
        print("Error: Keys weren't written to db, unable to proceed")
        fail_generic(conn, header.uid)
        return
    # generate bytes representation of packet
    packet = struct.pack("<BHI16s" + str(len(encrypted)) + "s", h.ver, h.code, h.size, header.uid, encrypted)
    conn.send(packet)
    expected_codes = nextcodeDict[header.code]  # set of expected codes
    openConns[header.uid] = [payload, conn, expected_codes, RETRIES, RETRIES, None, None, None, None, None]
    db.update_time(header.uid)  # update last seen
    db.write_back()  # update disk db


# Receive key: get public rsa key from client, and send AES key encrypted using the rsa key
def recv_key(header, conn):
    db.update_time(header.uid)  # update last seen
    if not (header.code in openConns[header.uid][CODES]):
        print("Error: Unexpected opcode, may retry", conn)
        fail_generic(conn, header.uid)
        return
    if header.size != sizeDict[header.code]:
        print("Error: Bad payload size, may retry", conn)
        fail_generic(conn, header.uid)
        return
    try:
        payload = conn.recv(header.size)  # receive payload (name + key)
        print("Public key:"+str(payload[255:]))
        plainKey = Random.get_random_bytes(16)  # generate plain AES key
        print("AES:"+str(plainKey))
        print("RSA:" + str(payload[255:]))
        pubKey = RSA.importKey(payload[255:])  # public key from bytes
        print("RSA SIZE:", pubKey.size_in_bits())
        cipher = PKCS1_OAEP.new(pubKey)  # generate wrapper for public key
        encrypted = cipher.encrypt(plainKey)  # encrypt AES using public key
        print("AES ENC:"+str(encrypted))
        code = codeDict[header.code]
        h = ServerHeader(code, sizeDict[code] + len(encrypted))
        if not(db.update_keys(pubKey.exportKey(), plainKey, header.uid)):
            print("Error: Keys weren't written to db, unable to proceed")
            fail_generic(conn, header.uid)
            return
        # generate bytes representation of packet
        packet = struct.pack("<BHI16s" + str(len(encrypted)) + "s", h.ver, h.code, h.size, header.uid, encrypted)
        conn.send(packet)
        expected_codes = nextcodeDict[header.code]  # set of expected codes
        openConns[header.uid][CODES] = expected_codes  # update connection state
        openConns[header.uid][RETRY] = RETRIES  # update connection state
        db.write_back()  # update disk db
    except Exception as e:  # For debugging
        print(e)
        exit(1)


# Receive file: get file from client, decrypt it using AES key and store it
def recv_file(header, conn):
    db.update_time(header.uid)  # update last seen
    if not (header.code in openConns[header.uid][CODES]):
        print("Error: Unexpected opcode, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    if header.size < sizeDict[header.code]:
        print("Error: Bad payload size, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    try:
        size = conn.recv(SIZE_SIZE, socket.MSG_WAITALL)
        print(str(size[3]))
        size = int.from_bytes(size, byteorder="little")  # reported size of file
        if size != (header.size - NAME_SIZE - SIZE_SIZE):  # sanity check both sizes
            print("Error: Size mismatch, terminating connection", conn)
            fail_generic(conn, header.uid)
            return
        openConns[header.uid][REM] = size
        filename = conn.recv(NAME_SIZE, socket.MSG_WAITALL).decode("ascii", errors="ignore")
        print(str(filename[254]))
        index = filename.find('\0')
        filename = filename[:index] + '\0'  # null terminate
        filename = filename.replace("\\", "")  # remove all occurrences of backslash to avoid path traversal
        filename = filename.replace("..", "")  # remove all occurrences of backslash to avoid path traversal
        if len(filename) == 0:
            print("Error: Bad filename", conn)
            fail_generic(conn, header.uid)
            return
        aes = db.get_aes(header.uid)  # retrieve aes from db
        print("AES retrieved:" + str(aes))
        if not aes:
            print("Error: Couldn't retrieve public key cannot proceed, terminating connection", conn)
            openConns[header.uid][RETRY] = 0
            fail_generic(conn, header.uid)
            return
        aes = AES.new(aes, AES.MODE_CBC, iv=bytes(16))  # init usable key
        path = header.uid.hex()  # generate HEX UID PATH
        wd = os.getcwd()  # get path to working directory
        if not wd.endswith('\\'):
            wd = wd + '\\'
        try:
            path = wd + path
            os.mkdir(path)  # generate new dir for client if one doesn't exist already
        except FileExistsError:
            pass
        path = path + "\\" + filename[:filename.find('\0')]  # concat name to user dir to generate full path
        out = open(path, "wb")
        out.close()
        openConns[header.uid][REM] = size
        openConns[header.uid][KEY] = aes
        openConns[header.uid][F_NAME] = filename.encode("ascii")
        openConns[header.uid][PATH] = path
        openConns[header.uid][CODES] = READING
        connUID[conn] = header.uid
    except Exception as e:  # For debugging
        print(e)
        exit(1)


# Receive file end: finalize file transfer and send a 2103 message to the client
def end_recv(uid, conn):
    openConns[CODES] = nextcodeDict[SEND_FILE]
    db.write_back()
    code = SEND_CRC
    h = ServerHeader(code, sizeDict[code])
    file = open(openConns[uid][PATH], "rb")
    content = file.read()
    crc = memcrc(content)  # calculate crc of file
    print(crc)
    filename = openConns[uid][F_NAME]  # ascii representation of name of file as saved on server
    # generate bytes representation of packet
    if not db.register_file(uid, filename, openConns[uid][PATH]):  # update files table to include new file
        fail_generic(conn, uid)
        return
    size = len(content) + (16-(len(content) % 16))  # AES blocks are 16 bytes - calculate the padding
    packet = struct.pack("<BHI16sI255sI", h.ver, h.code, h.size, uid, size, filename, crc)
    conn.send(packet)
    expected_codes = nextcodeDict[SEND_FILE]  # set of expected codes
    openConns[uid][CODES] = expected_codes  # update connection state
    db.write_back()  # update disk db


# Mid-file receive: this function handles all chunk transfers and, decryption and writing back to file
def mid_recv(uid, conn):
    vals = openConns[uid]
    req = min(vals[REM], CHUNK_SIZE)
    file = conn.recv(req, socket.MSG_WAITALL)  # guarantees everything has been read
    file = vals[KEY].decrypt(file)  # decrypt file
    out = open(vals[PATH], "ab")
    if vals[REM] == req:
        file = unpad(file, vals[KEY].block_size)  # remove padding
    out.write(file)  # save to file
    out.close()
    openConns[uid][REM] = vals[REM] - req
    if openConns[uid][REM] == 0:
        end_recv(uid, conn)
        return


# Acknowledge good crc: Send final message to client to confirm file has been marked as verified
def ack_good(header, conn):
    db.update_time(header.uid)  # update last seen
    if not (header.code in openConns[header.uid][CODES]):
        print("Error: Unexpected opcode, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    if header.size != sizeDict[header.code]:
        print("Error: Bad payload size, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    payload = conn.recv(header.size)
    if not(db.check_id_file(header.uid, payload)):
        print("Error: Don't own any file with that name, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    db.verify(header.uid, payload)  # mark file as verified
    code = codeDict[header.code]
    h = ServerHeader(code, sizeDict[code])
    # generate bytes representation of packet
    packet = struct.pack("<BHI16s", h.ver, h.code, h.size, header.uid)
    conn.send(packet)
    try:
        sel.unregister(conn)  # unregister user from open connections monitored by selector
    except KeyError:
        pass
    # need to delete from openConns here
    conn.close()
    db.write_back()  # update disk db


# Acknowledge bad crc: get message about bad crc from client, prepare to get file again
def ack_bad(header, conn):
    if openConns[header.uid][F_RETRY] == 0:
        print("Error: Too many retries attempted, terminating connection")
        openConns[header.uid][RETRY] = 0
        fail_generic(conn, header.uid)
        return
    openConns[header.uid][F_RETRY] = openConns[header.uid][F_RETRY] - 1
    db.update_time(header.uid)
    if not (header.code in openConns[header.uid][CODES]):
        print("Error: Unexpected opcode, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    if header.size != sizeDict[header.code]:
        print("Error: Bad payload size, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    payload = conn.recv(header.size)
    if not(db.check_id_file(header.uid, payload)):
        print("Error: Don't own any file with that name, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    db.write_back()
    expected_codes = nextcodeDict[header.code]
    openConns[header.uid][CODES] = expected_codes
    openConns[header.uid][F_RETRY] = openConns[header.uid][F_RETRY] - 1


# Acknowledge crc fail: get message about 4th file transfer failure from client, send ack to client and close connection
def ack_fail(header, conn):
    db.update_time(header.uid)  # update last seen
    if not (header.code in openConns[header.uid][CODES]):
        print("Error: Unexpected opcode, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    if header.size != sizeDict[header.code]:
        print("Error: Bad payload size, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    payload = conn.recv(header.size)
    if not(db.check_id_file(header.uid, payload)):
        print("Error: Don't own any file with that name, terminating connection", conn)
        fail_generic(conn, header.uid)
        return
    code = codeDict[header.code]
    h = ServerHeader(code, sizeDict[code])
    packet = struct.pack("<BHI16s", h.ver, h.code, h.size, header.uid)  # generate bytes representation of packet
    conn.send(packet)
    print("Alert: File CRC mismatched 4 times, client aborted on connection:", conn)
    try:
        sel.unregister(conn)  # unregister client from open connections monitored by selector
    except KeyError:
        pass
    del openConns[header.uid]  # delete from open connections
    db.write_back()  # update disk db


# Fail register: notify client of failure in registering him as a user
def fail_register(conn):
    code = REGISTER_BAD
    h = ServerHeader(code, 0)
    packet = struct.pack("<BHI", h.ver, h.code, h.size)  # generate bytes representation of packet
    try:  # flush buffer
        conn.setblocking(False)
        conn.recv(2**32)
    except BlockingIOError:
        pass
    finally:
        conn.setblocking(True)
    conn.send(packet)
    try:
        sel.unregister(conn)  # unregister client from open connections monitored by selector
    except KeyError:
        pass


# Fail reconnect: notify client of failure in reconnecting him as existing user
def fail_reconnect(conn):
    uid = generate_uuid()
    code = RECONNECT_BAD
    h = ServerHeader(code, 0)
    packet = struct.pack("<BHI16s", h.ver, h.code, h.size, uid)  # generate bytes representation of packet
    # Need to add deletion of uid from clients
    try:  # flush buffer
        conn.setblocking(False)
        conn.recv(2 ** 32)
    except BlockingIOError:
        pass
    finally:
        conn.setblocking(True)
    conn.send(packet)
    try:
        sel.unregister(conn)  # unregister client from open connections monitored by selector
    except KeyError:
        pass


# Fail generic: notify client of an error not explicitly addressed by other error codes
def fail_generic(conn, uid):
    code = GENERIC_ERROR
    h = ServerHeader(code, 0)
    packet = struct.pack("<BHI", h.ver, h.code, h.size)  # generate bytes representation of packet
    try:  # flush buffer
        conn.setblocking(False)
        conn.recv(2 ** 32)
    except BlockingIOError:
        pass
    finally:
        conn.setblocking(True)
    if openConns[uid][RETRY] == 0:
        try:
            sel.unregister(conn)  # unregister client from open connections monitored by selector
        except KeyError:
            pass
        del openConns[uid]  # delete from open connections
    else:
        openConns[uid][RETRY] = openConns[uid][RETRY] - 1
    conn.send(packet)


# Generate UUID: uses builtin uuid4 routine to generate IDs until a new unique one is generated
def generate_uuid():
    new_uuid = uuid.uuid4()
    new_uuid = new_uuid.bytes
    while not db.check_id_exists(new_uuid):  # Collisions should be rare, also registered IDs are always in DB
        new_uuid = uuid.uuid4()
        new_uuid = new_uuid.bytes
    return new_uuid


crctab = [0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc,
          0x17c56b6b, 0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f,
          0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a,
          0x384fbdbd, 0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
          0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8,
          0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
          0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e,
          0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
          0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84,
          0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027,
          0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022,
          0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
          0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077,
          0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c,
          0x2e003dc5, 0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1,
          0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
          0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb,
          0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
          0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d,
          0x40d816ba, 0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
          0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f,
          0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044,
          0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689,
          0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
          0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683,
          0xd1799b34, 0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59,
          0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c,
          0x774bb0eb, 0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
          0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e,
          0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
          0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48,
          0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
          0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2,
          0xe6ea3d65, 0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601,
          0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604,
          0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
          0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6,
          0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad,
          0x81b02d74, 0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7,
          0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
          0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd,
          0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
          0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b,
          0x0fdc1bec, 0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
          0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679,
          0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12,
          0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af,
          0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
          0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5,
          0x9e7d9662, 0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06,
          0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03,
          0xb1f740b4]


def UNSIGNED(n):
    return n & 0xffffffff


# Memory crc: calculates cksum as specified by POSIX, on a given bytes object
def memcrc(b):
    n = len(b)
    c = s = 0
    count = 0
    for ch in b:
        count += 1
        c = ch
        tabidx = (s >> 24) ^ c
        s = UNSIGNED((s << 8)) ^ crctab[tabidx]

    while n:
        c = n & 0o377
        n = n >> 8
        s = UNSIGNED(s << 8) ^ crctab[(s >> 24) ^ c]
    return UNSIGNED(~s)
