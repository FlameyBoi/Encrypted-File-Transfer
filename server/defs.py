USER_HEADER_SIZE = 23
SERVER_HEADER_SIZE = 7
TIMEOUT = 5
RETRIES = 3
VER = 3

# Client codes
REGISTER = 1100
SEND_KEY = 1101
RECONNECT = 1102
SEND_FILE = 1103
GOOD_CRC = 1104
BAD_CRC = 1105
FAIL_CRC = 1106
READING = 3000

# Server codes
REGISTER_GOOD = 2100
REGISTER_BAD = 2101
GOT_KEY = 2102
SEND_CRC = 2103
CRC_ACK = 2104
RECONNECT_GOOD = 2105
RECONNECT_BAD = 2106
GENERIC_ERROR = 2107

# Field sizes
SIZE_SIZE = 4
NAME_SIZE = 255
KEY_SIZE = 160
UID_SIZE = 16
CRC_SIZE = 4
CHUNK_SIZE = 1024

# Open connection fields
NAME = 0
CONN = 1
CODES = 2
RETRY = 3
F_RETRY = 4
REM = 5
KEY = 6
FILE = 7
F_NAME = 8
PATH = 9

# Misc
BAD = "BAD"
GOOD = "GOOD"
