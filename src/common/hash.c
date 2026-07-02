#include "common/hash.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;

    for (i = 0; i < len; i++) {
        out[i * 2u] = hex[(bytes[i] >> 4) & 0x0fu];
        out[(i * 2u) + 1u] = hex[bytes[i] & 0x0fu];
    }
    out[len * 2u] = '\0';
}

int ntap_sha256(const uint8_t *data, size_t len, uint8_t out[NTAP_SHA256_SIZE])
{
    if (out == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    if (SHA256(data, len, out) == NULL) {
        return -1;
    }
    return 0;
}

int ntap_sha256_hex(const uint8_t *data, size_t len, char out_hex[NTAP_SHA256_HEX_SIZE])
{
    uint8_t digest[NTAP_SHA256_SIZE];

    if (out_hex == NULL) {
        return -1;
    }
    if (ntap_sha256(data, len, digest) != 0) {
        return -1;
    }
    bytes_to_hex(digest, sizeof(digest), out_hex);
    return 0;
}

int ntap_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[NTAP_HMAC_SHA256_SIZE])
{
    unsigned int out_len = 0;

    if (out == NULL || (key == NULL && key_len > 0) ||
        (data == NULL && data_len > 0)) {
        return -1;
    }
    if (HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len) == NULL) {
        return -1;
    }
    return out_len == NTAP_HMAC_SHA256_SIZE ? 0 : -1;
}

int ntap_hmac_sha256_hex(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         char out_hex[NTAP_SHA256_HEX_SIZE])
{
    uint8_t digest[NTAP_HMAC_SHA256_SIZE];

    if (out_hex == NULL) {
        return -1;
    }
    if (ntap_hmac_sha256(key, key_len, data, data_len, digest) != 0) {
        return -1;
    }
    bytes_to_hex(digest, sizeof(digest), out_hex);
    return 0;
}

int ntap_pbkdf2_sha256_hex(const char *password, const uint8_t *salt, size_t salt_len,
                           int iterations, char out_hex[NTAP_SHA256_HEX_SIZE])
{
    uint8_t digest[NTAP_SHA256_SIZE];

    if (password == NULL || out_hex == NULL || (salt == NULL && salt_len > 0) ||
        iterations < NTAP_PBKDF2_MIN_ITERATIONS) {
        return -1;
    }
    if (PKCS5_PBKDF2_HMAC(password, (int)-1, salt, (int)salt_len, iterations,
                          EVP_sha256(), (int)sizeof(digest), digest) != 1) {
        return -1;
    }
    bytes_to_hex(digest, sizeof(digest), out_hex);
    return 0;
}

bool ntap_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i = 0;

    if (a == NULL || b == NULL) {
        return false;
    }
    for (i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
    }
    return diff == 0;
}
