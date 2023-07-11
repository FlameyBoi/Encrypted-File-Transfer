from protocol import *
import struct
import selectors
import socket
import db
from header import *
import time

sel = selectors.DefaultSelector()
port = 1234
backlog = 100


# Main: core server loop
def main():
    db.init_db()  # Make sure databases are ready
    sock = socket.socket()
    get_port()
    sock.bind(("localhost", port))
    sock.listen(backlog)  # open socket
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ, accept)  # set up new connection handler
    while True:
        try:
            events = sel.select()  # get all connections with reading pending
        except OSError as e:
            print("Select error:", e)
        for key, mask in events:  # tend to any connections requiring attention
            if key.fileobj._closed:
                sel.unregister(key.fileobj)
                continue
            callback = key.data
            try:
                callback(key.fileobj, mask)  # call read on the connection
            except ConnectionResetError:
                print("Error: Client has prematurely terminated the connection:", key.fileobj)
                try:
                    sel.unregister(key.fileobj)
                except KeyError or OSError:
                    pass
                key.fileobj.close()
                exit(1)


# Accept connection: upon detecting new connection set appropriate handler (read) for any further communication
def accept(sock, mask):
    conn, addr = sock.accept()
    print("Accepted:", conn)
    conn.setblocking(True)
    sel.register(conn, selectors.EVENT_READ, read)


# Read: Centralizes all active communication with client while handling retries and exceptions
def read(conn, mask):
    try:
        if openConns[connUID[conn]][CODES] == READING:
            mid_recv(connUID[conn], conn)
            return
    except KeyError:
        pass
    try:
        data = conn.recv(USER_HEADER_SIZE, socket.MSG_WAITALL)
        if len(data) == 0:  # connection closed
            try:
                sel.unregister(conn)
            except KeyError:
                pass
            finally:
                return
        time.sleep(1)
        h = header_unpacking(data)
        if h.code != REGISTER and h.code != RECONNECT and h.uid not in openConns.keys():
            return
        handle_payload(h, conn)
    except ValueError as e:
        print(e, "terminating connection", conn)
        try:
            sel.unregister(conn)
        except KeyError:
            pass
        return


# Header unpacking: This function unpacks the user sent header according to the protocol's format into a ClientHeader
def header_unpacking(header):
    data = struct.unpack("<16schI", header)
    uid = data[0]
    if int.from_bytes(data[1], "little") != VER:
        raise Exception("Error: Incompatible client version")
    code = data[2]
    size = data[3]
    return ClientHeader(uid, code, size)


# Handle payload: This function calls the appropriate protocol function based on the code in the user sent header
def handle_payload(header, conn):
    #  Error handling is done in calling context
    print("Going into", header.code, "with", conn)  # log which conn is being serviced and how
    if header.code == REGISTER:
        register(header, conn)
    elif header.code == RECONNECT:
        reconnect(header, conn)
    elif header.code == SEND_KEY:
        recv_key(header, conn)
    elif header.code == SEND_FILE:
        recv_file(header, conn)
    elif header.code == GOOD_CRC:
        ack_good(header, conn)
    elif header.code == BAD_CRC:
        ack_bad(header, conn)
    elif header.code == FAIL_CRC:
        ack_fail(header, conn)


# Get port: this function reads the port given in the config file port.info
def get_port():
    global port
    try:
        file = open("port.info", "rb")
        data = file.read()
        port = int(data)
        if port < 0 or port > 65535:  # Valid port range
            raise ValueError
    except FileNotFoundError:
        print("Warning: Couldn't open port.info - using default port 1234")
        port = 1234
    except ValueError:
        print("Warning: Value in port.info is not a valid port - using default port 1234")
        port = 1234


# allows running in interactive mode
if __name__ == '__main__':
    try:
        print("Alert: Initiating server")
        main()
    except KeyboardInterrupt:
        print("Alert: Detected keyboard interrupt, server shutting down")
        exit(0)
