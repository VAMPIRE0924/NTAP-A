#include "common/direct_token.h"

#include "common/hash.h"

#include <openssl/rand.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void bytes_to_hex_local(const uint8_t *bytes, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;

    for (i = 0; i < len; i++) {
        out[i * 2u] = hex[(bytes[i] >> 4) & 0x0fu];
        out[(i * 2u) + 1u] = hex[bytes[i] & 0x0fu];
    }
    out[len * 2u] = '\0';
}

static int direct_token_hex_string(const char *value, size_t hex_len)
{
    size_t i = 0;

    if (value == NULL || strlen(value) != hex_len) {
        return 0;
    }
    for (i = 0; i < hex_len; i++) {
        if (!isxdigit((unsigned char)value[i])) {
            return 0;
        }
    }
    return 1;
}

static int direct_token_node_id_ok(const char *node_id)
{
    return node_id != NULL && *node_id != '\0' &&
           strlen(node_id) < NTAP_CONFIG_VALUE_MAX &&
           strchr(node_id, '|') == NULL;
}

static int direct_token_sign(char out_hex[NTAP_SHA256_HEX_SIZE],
                             const char *node_key, int64_t user_id,
                             const char *node_id, int64_t network_id,
                             uint64_t expire_at, const char *nonce_hex)
{
    char signing[NTAP_DIRECT_TOKEN_MAX];
    int n = 0;

    if (node_key == NULL || *node_key == '\0' ||
        !direct_token_node_id_ok(node_id) || user_id <= 0 ||
        network_id <= 0 || expire_at == 0 ||
        !direct_token_hex_string(nonce_hex,
                                 NTAP_DIRECT_TOKEN_NONCE_HEX_SIZE - 1u)) {
        return -1;
    }
    n = snprintf(signing, sizeof(signing),
                 "ntap-direct-v1\n%" PRId64 "\n%s\n%" PRId64 "\n%" PRIu64 "\n%s",
                 user_id, node_id, network_id, expire_at, nonce_hex);
    if (n <= 0 || (size_t)n >= sizeof(signing)) {
        return -1;
    }
    return ntap_hmac_sha256_hex((const uint8_t *)node_key, strlen(node_key),
                                (const uint8_t *)signing, (size_t)n,
                                out_hex);
}

static int direct_token_hex_equal_ci(const char *a, const char *b)
{
    unsigned char diff = 0;
    size_t i = 0;

    if (!direct_token_hex_string(a, NTAP_SHA256_HEX_SIZE - 1u) ||
        !direct_token_hex_string(b, NTAP_SHA256_HEX_SIZE - 1u)) {
        return 0;
    }
    for (i = 0; i < NTAP_SHA256_HEX_SIZE - 1u; i++) {
        diff = (unsigned char)(diff |
                               (unsigned char)(tolower((unsigned char)a[i]) ^
                                               tolower((unsigned char)b[i])));
    }
    return diff == 0;
}

static char *direct_token_next_field(char **cursor)
{
    char *start = NULL;
    char *sep = NULL;

    if (cursor == NULL || *cursor == NULL) {
        return NULL;
    }
    start = *cursor;
    sep = strchr(start, '|');
    if (sep != NULL) {
        *sep = '\0';
        *cursor = sep + 1;
    } else {
        *cursor = NULL;
    }
    return start;
}

static int direct_token_parse_i64(const char *text, int64_t *out)
{
    intmax_t value = 0;
    char tail = '\0';

    if (text == NULL || out == NULL) {
        return -1;
    }
    if (sscanf(text, "%jd%c", &value, &tail) != 1 || value <= 0) {
        return -1;
    }
    *out = (int64_t)value;
    return 0;
}

static int direct_token_parse_u64(const char *text, uint64_t *out)
{
    uintmax_t value = 0;
    char tail = '\0';

    if (text == NULL || out == NULL) {
        return -1;
    }
    if (sscanf(text, "%ju%c", &value, &tail) != 1 || value == 0) {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

int ntap_direct_token_random_nonce(char out[NTAP_DIRECT_TOKEN_NONCE_HEX_SIZE])
{
    uint8_t raw[16];

    if (out == NULL || RAND_bytes(raw, (int)sizeof(raw)) != 1) {
        return -1;
    }
    bytes_to_hex_local(raw, sizeof(raw), out);
    return 0;
}

int ntap_direct_token_make(char *out, size_t out_len,
                           const char *node_key, int64_t user_id,
                           const char *node_id, int64_t network_id,
                           uint64_t expire_at, const char *nonce_hex)
{
    char sign[NTAP_SHA256_HEX_SIZE];
    int n = 0;

    if (out == NULL || out_len == 0 ||
        direct_token_sign(sign, node_key, user_id, node_id, network_id,
                          expire_at, nonce_hex) != 0) {
        return -1;
    }
    n = snprintf(out, out_len,
                 "ntap1|%" PRId64 "|%s|%" PRId64 "|%" PRIu64 "|%s|%s",
                 user_id, node_id, network_id, expire_at, nonce_hex, sign);
    return n > 0 && (size_t)n < out_len ? 0 : -1;
}

int ntap_direct_token_verify(const char *token, const char *node_key,
                             const char *expected_node_id,
                             int64_t expected_network_id, uint64_t now,
                             ntap_direct_token_t *out)
{
    char copy[NTAP_DIRECT_TOKEN_MAX];
    char expected_sign[NTAP_SHA256_HEX_SIZE];
    char *cursor = NULL;
    char *version = NULL;
    char *user_id_s = NULL;
    char *node_id = NULL;
    char *network_id_s = NULL;
    char *expire_at_s = NULL;
    char *nonce = NULL;
    char *sign = NULL;
    int64_t user_id = 0;
    int64_t network_id = 0;
    uint64_t expire_at = 0;

    if (token == NULL || node_key == NULL || *node_key == '\0' ||
        !direct_token_node_id_ok(expected_node_id) ||
        expected_network_id <= 0 || strlen(token) >= sizeof(copy)) {
        return -1;
    }
    (void)snprintf(copy, sizeof(copy), "%s", token);
    cursor = copy;
    version = direct_token_next_field(&cursor);
    user_id_s = direct_token_next_field(&cursor);
    node_id = direct_token_next_field(&cursor);
    network_id_s = direct_token_next_field(&cursor);
    expire_at_s = direct_token_next_field(&cursor);
    nonce = direct_token_next_field(&cursor);
    sign = direct_token_next_field(&cursor);
    if (cursor != NULL || version == NULL || strcmp(version, "ntap1") != 0 ||
        direct_token_parse_i64(user_id_s, &user_id) != 0 ||
        !direct_token_node_id_ok(node_id) ||
        strcmp(node_id, expected_node_id) != 0 ||
        direct_token_parse_i64(network_id_s, &network_id) != 0 ||
        network_id != expected_network_id ||
        direct_token_parse_u64(expire_at_s, &expire_at) != 0 ||
        expire_at <= now ||
        !direct_token_hex_string(nonce, NTAP_DIRECT_TOKEN_NONCE_HEX_SIZE - 1u) ||
        !direct_token_hex_string(sign, NTAP_SHA256_HEX_SIZE - 1u)) {
        return -1;
    }
    if (direct_token_sign(expected_sign, node_key, user_id, node_id,
                          network_id, expire_at, nonce) != 0 ||
        !direct_token_hex_equal_ci(sign, expected_sign)) {
        return -1;
    }
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
        out->user_id = user_id;
        (void)snprintf(out->node_id, sizeof(out->node_id), "%s", node_id);
        out->network_id = network_id;
        out->expire_at = expire_at;
        (void)snprintf(out->nonce, sizeof(out->nonce), "%s", nonce);
    }
    return 0;
}
