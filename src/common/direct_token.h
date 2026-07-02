#ifndef NTAP_COMMON_DIRECT_TOKEN_H
#define NTAP_COMMON_DIRECT_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#include "common/config.h"
#include "common/proto.h"

#define NTAP_DIRECT_TOKEN_MAX 1024u
#define NTAP_DIRECT_TOKEN_NONCE_HEX_SIZE 33u

typedef struct ntap_direct_token {
    int64_t user_id;
    char node_id[NTAP_CONFIG_VALUE_MAX];
    int64_t network_id;
    uint64_t expire_at;
    char nonce[NTAP_DIRECT_TOKEN_NONCE_HEX_SIZE];
} ntap_direct_token_t;

int ntap_direct_token_random_nonce(char out[NTAP_DIRECT_TOKEN_NONCE_HEX_SIZE]);
int ntap_direct_token_make(char *out, size_t out_len,
                           const char *node_key, int64_t user_id,
                           const char *node_id, int64_t network_id,
                           uint64_t expire_at, const char *nonce_hex);
int ntap_direct_token_verify(const char *token, const char *node_key,
                             const char *expected_node_id,
                             int64_t expected_network_id, uint64_t now,
                             ntap_direct_token_t *out);

#endif
