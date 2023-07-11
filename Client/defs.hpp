
// Version info
#define CLIENT_VER 3
#define SERVER_VER 3

// Field sizes
#define UID_SIZE 16
#define CODE_SIZE 2
#define SIZE_SIZE 4 // this is the size of the size field in the header struct in bytes
#define CRC_SIZE 4
#define NAME_SIZE 255
#define KEY_SIZE 160
#define HEADER_SIZE 23
#define SERVER_HEADER_SIZE 7
#define MAX_SIZE 1024 // max size of incoming message
#define MAX_FILE_SIZE 4294967296 // Protocol allows at most 4 Gb
#define RSA_SIZE 1024
#define AES_SIZE 16

// Request codes
#define REGISTER 1100
#define SEND_KEY 1101
#define RECONNECT 1102
#define SEND_FILE 1103
#define CRC_ACK 1104
#define CRC_NACK 1105
#define CRC_FAIL 1106
#define END 0 // tells protocol to close connection - never actually sent

// Respone codes
#define REGISTER_GOOD 2100
#define REGISTER_BAD 2101
#define GOOD_KEY 2102
#define GET_CRC 2103
#define ACK 2104
#define RECONNECT_GOOD 2105
#define RECONNECT_BAD 2106
#define GENERIC_ERROR 2107

// Arg counts
#define REGISTER_ARGS 1
#define SEND_FILE_ARGS 2
#define SEND_KEY_ARGS 2
#define SEND_CRC_ARGS 1

// Misc
#define MAX_PORT 65535