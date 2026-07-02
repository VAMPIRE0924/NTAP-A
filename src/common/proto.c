#include "common/proto.h"

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

int ntap_hdr_encode(uint8_t out[NTAP_HDR_SIZE], const ntap_hdr_t *hdr)
{
    if (out == NULL || hdr == NULL) {
        return NTAP_ERR_INVALID_ARG;
    }
    if (hdr->magic != NTAP_MAGIC) {
        return NTAP_ERR_BAD_MAGIC;
    }
    if (hdr->version != NTAP_VERSION) {
        return NTAP_ERR_BAD_VERSION;
    }
    if (!ntap_msg_type_is_valid(hdr->type)) {
        return NTAP_ERR_BAD_TYPE;
    }

    put_be32(out, hdr->magic);
    out[4] = hdr->version;
    out[5] = hdr->type;
    put_be16(out + 6, hdr->flags);
    put_be32(out + 8, hdr->session_id);
    put_be32(out + 12, hdr->length);
    return NTAP_OK;
}

int ntap_hdr_decode(ntap_hdr_t *hdr, const uint8_t in[NTAP_HDR_SIZE])
{
    if (hdr == NULL || in == NULL) {
        return NTAP_ERR_INVALID_ARG;
    }

    hdr->magic = get_be32(in);
    hdr->version = in[4];
    hdr->type = in[5];
    hdr->flags = get_be16(in + 6);
    hdr->session_id = get_be32(in + 8);
    hdr->length = get_be32(in + 12);

    if (hdr->magic != NTAP_MAGIC) {
        return NTAP_ERR_BAD_MAGIC;
    }
    if (hdr->version != NTAP_VERSION) {
        return NTAP_ERR_BAD_VERSION;
    }
    if (!ntap_msg_type_is_valid(hdr->type)) {
        return NTAP_ERR_BAD_TYPE;
    }
    return NTAP_OK;
}

bool ntap_msg_type_is_valid(uint8_t type)
{
    return type >= NTAP_MSG_HELLO && type <= NTAP_MSG_SOCKS_STREAM_CLOSE;
}

bool ntap_payload_length_allowed(uint8_t type, uint32_t length, uint16_t mtu)
{
    if (!ntap_msg_type_is_valid(type)) {
        return false;
    }
    if (mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU) {
        mtu = NTAP_DEFAULT_MTU;
    }
    if (type == NTAP_MSG_TAP_FRAME) {
        return length <= ((uint32_t)mtu + NTAP_TAP_PAYLOAD_EXTRA);
    }
    if (type >= NTAP_MSG_SOCKS_STREAM_OPEN &&
        type <= NTAP_MSG_SOCKS_STREAM_CLOSE) {
        return length <= NTAP_PAYLOAD_MAX_SOCKS;
    }
    return length <= NTAP_PAYLOAD_MAX_CONTROL;
}

const char *ntap_msg_type_name(uint8_t type)
{
    switch (type) {
    case NTAP_MSG_HELLO:
        return "HELLO";
    case NTAP_MSG_AUTH_NODE:
        return "AUTH_NODE";
    case NTAP_MSG_AUTH_TAP:
        return "AUTH_TAP";
    case NTAP_MSG_AUTH_OK:
        return "AUTH_OK";
    case NTAP_MSG_AUTH_FAIL:
        return "AUTH_FAIL";
    case NTAP_MSG_CONFIG_PUSH:
        return "CONFIG_PUSH";
    case NTAP_MSG_TAP_FRAME:
        return "TAP_FRAME";
    case NTAP_MSG_PING:
        return "PING";
    case NTAP_MSG_PONG:
        return "PONG";
    case NTAP_MSG_ERROR:
        return "ERROR";
    case NTAP_MSG_DIRECT_TOKEN:
        return "DIRECT_TOKEN";
    case NTAP_MSG_SOCKS_STREAM_OPEN:
        return "SOCKS_STREAM_OPEN";
    case NTAP_MSG_SOCKS_STREAM_DATA:
        return "SOCKS_STREAM_DATA";
    case NTAP_MSG_SOCKS_STREAM_CLOSE:
        return "SOCKS_STREAM_CLOSE";
    default:
        return "UNKNOWN";
    }
}

const char *ntap_result_name(int result)
{
    switch (result) {
    case NTAP_OK:
        return "ok";
    case NTAP_ERR_INVALID_ARG:
        return "invalid_arg";
    case NTAP_ERR_BAD_MAGIC:
        return "bad_magic";
    case NTAP_ERR_BAD_VERSION:
        return "bad_version";
    case NTAP_ERR_BAD_TYPE:
        return "bad_type";
    case NTAP_ERR_PAYLOAD_TOO_LARGE:
        return "payload_too_large";
    default:
        return "unknown";
    }
}
