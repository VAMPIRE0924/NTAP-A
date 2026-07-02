#include "common/wire.h"

#include "common/buffer.h"
#include "common/hash.h"

#include <openssl/rand.h>

#include <string.h>

static void put_be16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)((value >> 8) & 0xffu);
    out[1] = (uint8_t)(value & 0xffu);
}

static void put_be32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xffu);
    out[1] = (uint8_t)((value >> 16) & 0xffu);
    out[2] = (uint8_t)((value >> 8) & 0xffu);
    out[3] = (uint8_t)(value & 0xffu);
}

static void put_be64(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)((value >> 56) & 0xffu);
    out[1] = (uint8_t)((value >> 48) & 0xffu);
    out[2] = (uint8_t)((value >> 40) & 0xffu);
    out[3] = (uint8_t)((value >> 32) & 0xffu);
    out[4] = (uint8_t)((value >> 24) & 0xffu);
    out[5] = (uint8_t)((value >> 16) & 0xffu);
    out[6] = (uint8_t)((value >> 8) & 0xffu);
    out[7] = (uint8_t)(value & 0xffu);
}

static uint16_t get_be16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t get_be32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static uint64_t get_be64(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) |
           ((uint64_t)in[1] << 48) |
           ((uint64_t)in[2] << 40) |
           ((uint64_t)in[3] << 32) |
           ((uint64_t)in[4] << 24) |
           ((uint64_t)in[5] << 16) |
           ((uint64_t)in[6] << 8) |
           (uint64_t)in[7];
}

static int append_string(ntap_buffer_t *buf, const char *value)
{
    size_t len = value == NULL ? 0 : strlen(value);
    uint8_t raw_len[2];

    if (len > 65535u) {
        return -1;
    }
    put_be16(raw_len, (uint16_t)len);
    if (ntap_buffer_append(buf, raw_len, sizeof(raw_len)) != 0) {
        return -1;
    }
    return ntap_buffer_append(buf, value, len);
}

static int read_string(char *out, size_t out_len, const uint8_t *payload,
                       size_t len, size_t *pos)
{
    uint16_t text_len = 0;

    if (out == NULL || out_len == 0 || payload == NULL || pos == NULL ||
        *pos + 2u > len) {
        return -1;
    }
    text_len = get_be16(payload + *pos);
    *pos += 2u;
    if (*pos + text_len > len || (size_t)text_len >= out_len) {
        return -1;
    }
    (void)memcpy(out, payload + *pos, text_len);
    out[text_len] = '\0';
    *pos += text_len;
    return 0;
}

int ntap_random_nonce(uint8_t nonce[NTAP_NONCE_SIZE])
{
    if (nonce == NULL) {
        return -1;
    }
    return RAND_bytes(nonce, NTAP_NONCE_SIZE) == 1 ? 0 : -1;
}

int ntap_encode_hello(uint8_t *out, size_t cap, size_t *len,
                      uint8_t role, const char *version_text,
                      uint32_t feature_bits, const uint8_t nonce[NTAP_NONCE_SIZE])
{
    ntap_buffer_t buf;
    int rc = -1;

    if (out == NULL || len == NULL || nonce == NULL) {
        return -1;
    }
    ntap_buffer_init(&buf);
    if (ntap_buffer_append(&buf, &role, 1u) != 0 ||
        append_string(&buf, version_text) != 0) {
        goto done;
    }
    {
        uint8_t raw_features[4];

        put_be32(raw_features, feature_bits);
        if (ntap_buffer_append(&buf, raw_features, sizeof(raw_features)) != 0 ||
            ntap_buffer_append(&buf, nonce, NTAP_NONCE_SIZE) != 0) {
            goto done;
        }
    }
    if (buf.len > cap) {
        goto done;
    }
    (void)memcpy(out, buf.data, buf.len);
    *len = buf.len;
    rc = 0;

done:
    ntap_buffer_free(&buf);
    return rc;
}

int ntap_decode_hello(ntap_hello_t *out, const uint8_t *payload, size_t len)
{
    size_t pos = 0;

    if (out == NULL || payload == NULL || len < 1u) {
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    out->role = payload[pos++];
    if (read_string(out->version_text, sizeof(out->version_text), payload, len, &pos) != 0 ||
        pos + 4u + NTAP_NONCE_SIZE != len) {
        return -1;
    }
    out->feature_bits = get_be32(payload + pos);
    pos += 4u;
    (void)memcpy(out->nonce, payload + pos, NTAP_NONCE_SIZE);
    return 0;
}

int ntap_encode_auth_node(uint8_t *out, size_t cap, size_t *len,
                          const char *node_id,
                          const uint8_t client_nonce[NTAP_NONCE_SIZE],
                          const uint8_t sign[NTAP_HMAC_SHA256_SIZE])
{
    ntap_buffer_t buf;
    int rc = -1;

    if (out == NULL || len == NULL || client_nonce == NULL || sign == NULL) {
        return -1;
    }
    ntap_buffer_init(&buf);
    if (append_string(&buf, node_id) != 0 ||
        ntap_buffer_append(&buf, client_nonce, NTAP_NONCE_SIZE) != 0 ||
        ntap_buffer_append(&buf, sign, NTAP_HMAC_SHA256_SIZE) != 0) {
        goto done;
    }
    if (buf.len > cap) {
        goto done;
    }
    (void)memcpy(out, buf.data, buf.len);
    *len = buf.len;
    rc = 0;

done:
    ntap_buffer_free(&buf);
    return rc;
}

int ntap_decode_auth_node(ntap_auth_node_t *out, const uint8_t *payload, size_t len)
{
    size_t pos = 0;

    if (out == NULL || payload == NULL) {
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    if (read_string(out->node_id, sizeof(out->node_id), payload, len, &pos) != 0 ||
        pos + NTAP_NONCE_SIZE + NTAP_HMAC_SHA256_SIZE != len) {
        return -1;
    }
    (void)memcpy(out->client_nonce, payload + pos, NTAP_NONCE_SIZE);
    pos += NTAP_NONCE_SIZE;
    (void)memcpy(out->sign, payload + pos, NTAP_HMAC_SHA256_SIZE);
    return 0;
}

int ntap_encode_auth_tap(uint8_t *out, size_t cap, size_t *len,
                         const char *username, const char *password,
                         uint32_t network_id,
                         const uint8_t client_nonce[NTAP_NONCE_SIZE])
{
    ntap_buffer_t buf;
    uint8_t raw_network_id[4];
    int rc = -1;

    if (out == NULL || len == NULL || client_nonce == NULL) {
        return -1;
    }
    ntap_buffer_init(&buf);
    put_be32(raw_network_id, network_id);
    if (append_string(&buf, username) != 0 ||
        append_string(&buf, password) != 0 ||
        ntap_buffer_append(&buf, raw_network_id, sizeof(raw_network_id)) != 0 ||
        ntap_buffer_append(&buf, client_nonce, NTAP_NONCE_SIZE) != 0) {
        goto done;
    }
    if (buf.len > cap) {
        goto done;
    }
    (void)memcpy(out, buf.data, buf.len);
    *len = buf.len;
    rc = 0;

done:
    ntap_buffer_free(&buf);
    return rc;
}

int ntap_decode_auth_tap(ntap_auth_tap_t *out, const uint8_t *payload, size_t len)
{
    size_t pos = 0;

    if (out == NULL || payload == NULL) {
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    if (read_string(out->username, sizeof(out->username), payload, len, &pos) != 0 ||
        read_string(out->password, sizeof(out->password), payload, len, &pos) != 0 ||
        pos + 4u + NTAP_NONCE_SIZE != len) {
        return -1;
    }
    out->network_id = get_be32(payload + pos);
    pos += 4u;
    (void)memcpy(out->client_nonce, payload + pos, NTAP_NONCE_SIZE);
    return 0;
}

int ntap_encode_auth_ok(uint8_t out[NTAP_AUTH_OK_SIZE], const ntap_auth_ok_t *auth_ok)
{
    if (out == NULL || auth_ok == NULL) {
        return -1;
    }
    put_be32(out, auth_ok->session_id);
    put_be32(out + 4u, auth_ok->network_id);
    put_be64(out + 8u, auth_ok->server_time);
    put_be32(out + 16u, auth_ok->feature_bits);
    return 0;
}

int ntap_decode_auth_ok(ntap_auth_ok_t *out, const uint8_t payload[NTAP_AUTH_OK_SIZE],
                        size_t len)
{
    if (out == NULL || payload == NULL || len != NTAP_AUTH_OK_SIZE) {
        return -1;
    }
    out->session_id = get_be32(payload);
    out->network_id = get_be32(payload + 4u);
    out->server_time = get_be64(payload + 8u);
    out->feature_bits = get_be32(payload + 16u);
    return 0;
}

int ntap_encode_config_push(uint8_t *out, size_t cap, size_t *len,
                            const ntap_config_push_t *config)
{
    ntap_buffer_t buf;
    uint8_t raw32[4];
    uint8_t raw16[2];
    int rc = -1;

    if (out == NULL || len == NULL || config == NULL) {
        return -1;
    }
    ntap_buffer_init(&buf);
    put_be32(raw32, config->config_version);
    if (ntap_buffer_append(&buf, raw32, sizeof(raw32)) != 0) {
        goto done;
    }
    put_be32(raw32, config->network_id);
    if (ntap_buffer_append(&buf, raw32, sizeof(raw32)) != 0 ||
        ntap_buffer_append(&buf, &config->tap_enabled, 1u) != 0 ||
        ntap_buffer_append(&buf, &config->socks_enabled, 1u) != 0 ||
        ntap_buffer_append(&buf, &config->direct_enabled, 1u) != 0 ||
        append_string(&buf, config->tap_name) != 0 ||
        append_string(&buf, config->bridge_name) != 0) {
        goto done;
    }
    put_be16(raw16, config->mtu);
    if (ntap_buffer_append(&buf, raw16, sizeof(raw16)) != 0) {
        goto done;
    }
    put_be16(raw16, config->direct_port);
    if (ntap_buffer_append(&buf, raw16, sizeof(raw16)) != 0) {
        goto done;
    }
    put_be32(raw32, config->flags);
    if (ntap_buffer_append(&buf, raw32, sizeof(raw32)) != 0) {
        goto done;
    }
    if (buf.len > cap) {
        goto done;
    }
    (void)memcpy(out, buf.data, buf.len);
    *len = buf.len;
    rc = 0;

done:
    ntap_buffer_free(&buf);
    return rc;
}

int ntap_decode_config_push(ntap_config_push_t *out, const uint8_t *payload, size_t len)
{
    size_t pos = 0;

    if (out == NULL || payload == NULL || len < 4u + 4u + 3u + 2u + 2u + 4u) {
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    out->config_version = get_be32(payload + pos);
    pos += 4u;
    out->network_id = get_be32(payload + pos);
    pos += 4u;
    out->tap_enabled = payload[pos++];
    out->socks_enabled = payload[pos++];
    out->direct_enabled = payload[pos++];
    if (read_string(out->tap_name, sizeof(out->tap_name), payload, len, &pos) != 0 ||
        read_string(out->bridge_name, sizeof(out->bridge_name), payload, len, &pos) != 0 ||
        pos + 2u + 2u + 4u != len) {
        return -1;
    }
    out->mtu = get_be16(payload + pos);
    pos += 2u;
    out->direct_port = get_be16(payload + pos);
    pos += 2u;
    out->flags = get_be32(payload + pos);
    if (out->network_id == 0u || out->mtu < NTAP_MIN_MTU || out->mtu > NTAP_MAX_MTU) {
        return -1;
    }
    return 0;
}

int ntap_encode_tap_frame(uint8_t *out, size_t cap, size_t *len,
                          uint32_t network_id, const uint8_t *frame,
                          uint16_t frame_len)
{
    if (out == NULL || len == NULL || (frame == NULL && frame_len > 0) ||
        frame_len < 14u || cap < NTAP_TAP_FRAME_OVERHEAD + frame_len) {
        return -1;
    }
    put_be32(out, network_id);
    put_be16(out + 4u, frame_len);
    (void)memcpy(out + NTAP_TAP_FRAME_OVERHEAD, frame, frame_len);
    *len = NTAP_TAP_FRAME_OVERHEAD + frame_len;
    return 0;
}

int ntap_decode_tap_frame(ntap_tap_frame_t *out, const uint8_t *payload, size_t len)
{
    uint16_t frame_len = 0;

    if (out == NULL || payload == NULL || len < NTAP_TAP_FRAME_OVERHEAD) {
        return -1;
    }
    frame_len = get_be16(payload + 4u);
    if (frame_len < 14u || len != NTAP_TAP_FRAME_OVERHEAD + frame_len) {
        return -1;
    }
    out->network_id = get_be32(payload);
    out->frame_len = frame_len;
    out->frame = payload + NTAP_TAP_FRAME_OVERHEAD;
    return 0;
}

int ntap_encode_socks_open(uint8_t *out, size_t cap, size_t *len,
                           uint32_t stream_id, const char *host, uint16_t port)
{
    ntap_buffer_t buf;
    uint8_t raw32[4];
    uint8_t raw16[2];
    int rc = -1;

    if (out == NULL || len == NULL || host == NULL || *host == '\0' ||
        port == 0) {
        return -1;
    }
    ntap_buffer_init(&buf);
    put_be32(raw32, stream_id);
    put_be16(raw16, port);
    if (ntap_buffer_append(&buf, raw32, sizeof(raw32)) != 0 ||
        append_string(&buf, host) != 0 ||
        ntap_buffer_append(&buf, raw16, sizeof(raw16)) != 0) {
        goto done;
    }
    if (buf.len > cap || buf.len > NTAP_PAYLOAD_MAX_SOCKS) {
        goto done;
    }
    (void)memcpy(out, buf.data, buf.len);
    *len = buf.len;
    rc = 0;

done:
    ntap_buffer_free(&buf);
    return rc;
}

int ntap_decode_socks_open(ntap_socks_open_t *out, const uint8_t *payload, size_t len)
{
    size_t pos = 0;

    if (out == NULL || payload == NULL || len < 4u + 2u + 2u) {
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    out->stream_id = get_be32(payload + pos);
    pos += 4u;
    if (read_string(out->host, sizeof(out->host), payload, len, &pos) != 0 ||
        pos + 2u != len) {
        return -1;
    }
    out->port = get_be16(payload + pos);
    return out->stream_id == 0 || out->host[0] == '\0' || out->port == 0 ? -1 : 0;
}

int ntap_encode_socks_data(uint8_t *out, size_t cap, size_t *len,
                           uint32_t stream_id, const uint8_t *data, uint32_t data_len)
{
    if (out == NULL || len == NULL || stream_id == 0 ||
        (data == NULL && data_len > 0) ||
        data_len == 0 || data_len > NTAP_PAYLOAD_MAX_SOCKS - NTAP_SOCKS_DATA_OVERHEAD ||
        cap < NTAP_SOCKS_DATA_OVERHEAD + data_len) {
        return -1;
    }
    put_be32(out, stream_id);
    (void)memcpy(out + NTAP_SOCKS_DATA_OVERHEAD, data, data_len);
    *len = NTAP_SOCKS_DATA_OVERHEAD + data_len;
    return 0;
}

int ntap_decode_socks_data(ntap_socks_data_t *out, const uint8_t *payload, size_t len)
{
    if (out == NULL || payload == NULL || len <= NTAP_SOCKS_DATA_OVERHEAD ||
        len > NTAP_PAYLOAD_MAX_SOCKS) {
        return -1;
    }
    out->stream_id = get_be32(payload);
    out->data = payload + NTAP_SOCKS_DATA_OVERHEAD;
    out->data_len = (uint32_t)(len - NTAP_SOCKS_DATA_OVERHEAD);
    return out->stream_id == 0 || out->data_len == 0 ? -1 : 0;
}

int ntap_encode_socks_close(uint8_t out[NTAP_SOCKS_DATA_OVERHEAD],
                            uint32_t stream_id)
{
    if (out == NULL || stream_id == 0) {
        return -1;
    }
    put_be32(out, stream_id);
    return 0;
}

int ntap_decode_socks_close(ntap_socks_close_t *out, const uint8_t *payload,
                            size_t len)
{
    if (out == NULL || payload == NULL || len != NTAP_SOCKS_DATA_OVERHEAD) {
        return -1;
    }
    out->stream_id = get_be32(payload);
    return out->stream_id == 0 ? -1 : 0;
}

int ntap_auth_node_sign(const char *node_key,
                        const uint8_t server_nonce[NTAP_NONCE_SIZE],
                        const uint8_t client_nonce[NTAP_NONCE_SIZE],
                        const char *node_id,
                        uint8_t out[NTAP_HMAC_SHA256_SIZE])
{
    ntap_buffer_t data;
    uint8_t version = NTAP_VERSION;
    int rc = -1;

    if (node_key == NULL || server_nonce == NULL || client_nonce == NULL ||
        node_id == NULL || out == NULL) {
        return -1;
    }
    ntap_buffer_init(&data);
    if (ntap_buffer_append(&data, server_nonce, NTAP_NONCE_SIZE) != 0 ||
        ntap_buffer_append(&data, client_nonce, NTAP_NONCE_SIZE) != 0 ||
        ntap_buffer_append(&data, node_id, strlen(node_id)) != 0 ||
        ntap_buffer_append(&data, &version, 1u) != 0) {
        goto done;
    }
    rc = ntap_hmac_sha256((const uint8_t *)node_key, strlen(node_key),
                          data.data, data.len, out);

done:
    ntap_buffer_free(&data);
    return rc;
}
