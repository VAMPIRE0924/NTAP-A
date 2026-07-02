#ifndef NTAP_COMMON_PROTO_H
#define NTAP_COMMON_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NTAP_MAGIC 0x4e544150u
#define NTAP_VERSION 1u
#define NTAP_HDR_SIZE 16u

#define NTAP_NONCE_SIZE 16u
#define NTAP_HMAC_SHA256_SIZE 32u
#define NTAP_SHA256_HEX_SIZE 65u

#define NTAP_PAYLOAD_MAX_CONTROL (64u * 1024u)
#define NTAP_PAYLOAD_MAX_SOCKS (16u * 1024u)
#define NTAP_DEFAULT_MTU 1400u
#define NTAP_MIN_MTU 576u
#define NTAP_MAX_MTU 1500u
#define NTAP_TAP_PAYLOAD_EXTRA 32u

#define NTAP_SESSION_QUEUE_MAX (1024u * 1024u)
#define NTAP_OPENWRT_QUEUE_MAX (256u * 1024u)

typedef enum ntap_result {
    NTAP_OK = 0,
    NTAP_ERR_INVALID_ARG = -1,
    NTAP_ERR_BAD_MAGIC = -2,
    NTAP_ERR_BAD_VERSION = -3,
    NTAP_ERR_BAD_TYPE = -4,
    NTAP_ERR_PAYLOAD_TOO_LARGE = -5
} ntap_result_t;

typedef enum ntap_role {
    NTAP_ROLE_SERVER = 0,
    NTAP_ROLE_NODE = 1,
    NTAP_ROLE_TAP_CLIENT = 2
} ntap_role_t;

typedef enum ntap_msg_type {
    NTAP_MSG_HELLO = 0x01,
    NTAP_MSG_AUTH_NODE = 0x02,
    NTAP_MSG_AUTH_TAP = 0x03,
    NTAP_MSG_AUTH_OK = 0x04,
    NTAP_MSG_AUTH_FAIL = 0x05,
    NTAP_MSG_CONFIG_PUSH = 0x06,
    NTAP_MSG_TAP_FRAME = 0x07,
    NTAP_MSG_PING = 0x08,
    NTAP_MSG_PONG = 0x09,
    NTAP_MSG_ERROR = 0x0a,
    NTAP_MSG_DIRECT_TOKEN = 0x0b,
    NTAP_MSG_SOCKS_STREAM_OPEN = 0x0c,
    NTAP_MSG_SOCKS_STREAM_DATA = 0x0d,
    NTAP_MSG_SOCKS_STREAM_CLOSE = 0x0e
} ntap_msg_type_t;

typedef enum ntap_error_code {
    NTAP_WIRE_ERR_BAD_MAGIC = 1,
    NTAP_WIRE_ERR_BAD_VERSION = 2,
    NTAP_WIRE_ERR_BAD_STATE = 3,
    NTAP_WIRE_ERR_AUTH_FAILED = 4,
    NTAP_WIRE_ERR_PERMISSION_DENIED = 5,
    NTAP_WIRE_ERR_PAYLOAD_TOO_LARGE = 6,
    NTAP_WIRE_ERR_MALFORMED_PAYLOAD = 7,
    NTAP_WIRE_ERR_RESOURCE_LIMITED = 8,
    NTAP_WIRE_ERR_NODE_OFFLINE = 9,
    NTAP_WIRE_ERR_STREAM_NOT_FOUND = 10,
    NTAP_WIRE_ERR_TARGET_CONNECT_FAILED = 11
} ntap_error_code_t;

typedef enum ntap_conn_state {
    NTAP_STATE_TCP_CONNECTED = 0,
    NTAP_STATE_HELLO_RECV,
    NTAP_STATE_AUTH_PENDING,
    NTAP_STATE_AUTHENTICATED,
    NTAP_STATE_CONFIGURED,
    NTAP_STATE_RUNNING,
    NTAP_STATE_CLOSING
} ntap_conn_state_t;

typedef struct ntap_hdr {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t session_id;
    uint32_t length;
} ntap_hdr_t;

int ntap_hdr_encode(uint8_t out[NTAP_HDR_SIZE], const ntap_hdr_t *hdr);
int ntap_hdr_decode(ntap_hdr_t *hdr, const uint8_t in[NTAP_HDR_SIZE]);

bool ntap_msg_type_is_valid(uint8_t type);
bool ntap_payload_length_allowed(uint8_t type, uint32_t length, uint16_t mtu);
const char *ntap_msg_type_name(uint8_t type);
const char *ntap_result_name(int result);

#endif
