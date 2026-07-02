#ifndef NTAP_COMMON_HASH_H
#define NTAP_COMMON_HASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/proto.h"

#define NTAP_SHA256_SIZE 32u
#define NTAP_PBKDF2_MIN_ITERATIONS 100000

int ntap_sha256(const uint8_t *data, size_t len, uint8_t out[NTAP_SHA256_SIZE]);
int ntap_sha256_hex(const uint8_t *data, size_t len, char out_hex[NTAP_SHA256_HEX_SIZE]);
int ntap_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[NTAP_HMAC_SHA256_SIZE]);
int ntap_hmac_sha256_hex(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         char out_hex[NTAP_SHA256_HEX_SIZE]);
int ntap_pbkdf2_sha256_hex(const char *password, const uint8_t *salt, size_t salt_len,
                           int iterations, char out_hex[NTAP_SHA256_HEX_SIZE]);
bool ntap_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif
