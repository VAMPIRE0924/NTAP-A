#ifndef NTAP_COMMON_WIRE_H
#define NTAP_COMMON_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "common/config.h"
#include "common/proto.h"

#define NTAP_VERSION_TEXT_MAX 64u
#define NTAP_NODE_ID_MAX 128u
#define NTAP_AUTH_OK_SIZE 20u
#define NTAP_TAP_FRAME_OVERHEAD 6u
#define NTAP_TAP_NAME_MAX 64u
#define NTAP_BRIDGE_NAME_MAX 64u
#define NTAP_DIRECT_MODE_MAX 32u
#define NTAP_DIRECT_ADDR_MAX 256u
#define NTAP_DIRECT_TOKEN_TEXT_MAX 1024u
#define NTAP_SOCKS_HOST_MAX 256u
#define NTAP_SOCKS_DATA_OVERHEAD 4u
#define NTAP_SOCKS_CLOSE_BASE_SIZE 4u
#define NTAP_SOCKS_CLOSE_REASON_SIZE 8u
#define NTAP_SOCKS_CLOSE_FLAG_FIN 0x0001u

enum {
    NTAP_SOCKS_CLOSE_REASON_CLOSED = 0,
    NTAP_SOCKS_CLOSE_REASON_CLIENT_CLOSED = 1,
    NTAP_SOCKS_CLOSE_REASON_REMOTE_CLOSED = 2,
    NTAP_SOCKS_CLOSE_REASON_TARGET_CONNECT_FAILED = 3,
    NTAP_SOCKS_CLOSE_REASON_RESOURCE_LIMITED = 4,
    NTAP_SOCKS_CLOSE_REASON_IDLE_TIMEOUT = 5
};

typedef struct ntap_hello {
    uint8_t role;
    char version_text[NTAP_VERSION_TEXT_MAX];
    uint32_t feature_bits;
    uint8_t nonce[NTAP_NONCE_SIZE];
} ntap_hello_t;

typedef struct ntap_auth_node {
    char node_id[NTAP_NODE_ID_MAX];
    uint8_t client_nonce[NTAP_NONCE_SIZE];
    uint8_t sign[NTAP_HMAC_SHA256_SIZE];
} ntap_auth_node_t;

typedef struct ntap_auth_tap {
    char username[NTAP_CONFIG_VALUE_MAX];
    char password[NTAP_CONFIG_VALUE_MAX];
    uint32_t network_id;
    uint8_t client_nonce[NTAP_NONCE_SIZE];
} ntap_auth_tap_t;

typedef struct ntap_auth_ok {
    uint32_t session_id;
    uint32_t network_id;
    uint64_t server_time;
    uint32_t feature_bits;
} ntap_auth_ok_t;

typedef struct ntap_config_push {
    uint32_t config_version;
    uint32_t network_id;
    uint8_t tap_enabled;
    uint8_t socks_enabled;
    uint8_t direct_enabled;
    char tap_name[NTAP_TAP_NAME_MAX];
    char bridge_name[NTAP_BRIDGE_NAME_MAX];
    uint16_t mtu;
    uint16_t direct_port;
    uint32_t flags;
    char direct_mode[NTAP_DIRECT_MODE_MAX];
    char direct_addr[NTAP_DIRECT_ADDR_MAX];
    char direct_token[NTAP_DIRECT_TOKEN_TEXT_MAX];
} ntap_config_push_t;

typedef struct ntap_tap_frame {
    uint32_t network_id;
    uint16_t frame_len;
    const uint8_t *frame;
} ntap_tap_frame_t;

typedef struct ntap_socks_open {
    uint32_t stream_id;
    char host[NTAP_SOCKS_HOST_MAX];
    uint16_t port;
} ntap_socks_open_t;

typedef struct ntap_socks_data {
    uint32_t stream_id;
    const uint8_t *data;
    uint32_t data_len;
} ntap_socks_data_t;

typedef struct ntap_socks_close {
    uint32_t stream_id;
    uint16_t reason_code;
    uint16_t flags;
} ntap_socks_close_t;

int ntap_random_nonce(uint8_t nonce[NTAP_NONCE_SIZE]);

int ntap_encode_hello(uint8_t *out, size_t cap, size_t *len,
                      uint8_t role, const char *version_text,
                      uint32_t feature_bits, const uint8_t nonce[NTAP_NONCE_SIZE]);
int ntap_decode_hello(ntap_hello_t *out, const uint8_t *payload, size_t len);

int ntap_encode_auth_node(uint8_t *out, size_t cap, size_t *len,
                          const char *node_id,
                          const uint8_t client_nonce[NTAP_NONCE_SIZE],
                          const uint8_t sign[NTAP_HMAC_SHA256_SIZE]);
int ntap_decode_auth_node(ntap_auth_node_t *out, const uint8_t *payload, size_t len);

int ntap_encode_auth_tap(uint8_t *out, size_t cap, size_t *len,
                         const char *username, const char *password,
                         uint32_t network_id,
                         const uint8_t client_nonce[NTAP_NONCE_SIZE]);
int ntap_decode_auth_tap(ntap_auth_tap_t *out, const uint8_t *payload, size_t len);

int ntap_encode_auth_ok(uint8_t out[NTAP_AUTH_OK_SIZE], const ntap_auth_ok_t *auth_ok);
int ntap_decode_auth_ok(ntap_auth_ok_t *out, const uint8_t payload[NTAP_AUTH_OK_SIZE],
                        size_t len);

int ntap_encode_config_push(uint8_t *out, size_t cap, size_t *len,
                            const ntap_config_push_t *config);
int ntap_decode_config_push(ntap_config_push_t *out, const uint8_t *payload, size_t len);

int ntap_encode_tap_frame(uint8_t *out, size_t cap, size_t *len,
                          uint32_t network_id, const uint8_t *frame,
                          uint16_t frame_len);
int ntap_decode_tap_frame(ntap_tap_frame_t *out, const uint8_t *payload, size_t len);

int ntap_encode_socks_open(uint8_t *out, size_t cap, size_t *len,
                           uint32_t stream_id, const char *host, uint16_t port);
int ntap_decode_socks_open(ntap_socks_open_t *out, const uint8_t *payload, size_t len);
int ntap_encode_socks_data(uint8_t *out, size_t cap, size_t *len,
                           uint32_t stream_id, const uint8_t *data, uint32_t data_len);
int ntap_decode_socks_data(ntap_socks_data_t *out, const uint8_t *payload, size_t len);
int ntap_encode_socks_close(uint8_t out[NTAP_SOCKS_DATA_OVERHEAD],
                            uint32_t stream_id);
int ntap_encode_socks_close_reason(uint8_t out[NTAP_SOCKS_CLOSE_REASON_SIZE],
                                   uint32_t stream_id, uint16_t reason_code,
                                   uint16_t flags);
int ntap_decode_socks_close(ntap_socks_close_t *out, const uint8_t *payload,
                            size_t len);

int ntap_auth_node_sign(const char *node_key,
                        const uint8_t server_nonce[NTAP_NONCE_SIZE],
                        const uint8_t client_nonce[NTAP_NONCE_SIZE],
                        const char *node_id,
                        uint8_t out[NTAP_HMAC_SHA256_SIZE]);

#endif
