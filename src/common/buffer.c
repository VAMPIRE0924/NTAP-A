#include "common/buffer.h"

#include <stdlib.h>
#include <string.h>

void ntap_buffer_init(ntap_buffer_t *buf)
{
    if (buf == NULL) {
        return;
    }
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

void ntap_buffer_free(ntap_buffer_t *buf)
{
    if (buf == NULL) {
        return;
    }
    free(buf->data);
    ntap_buffer_init(buf);
}

int ntap_buffer_reserve(ntap_buffer_t *buf, size_t cap)
{
    uint8_t *next = NULL;

    if (buf == NULL) {
        return -1;
    }
    if (cap <= buf->cap) {
        return 0;
    }

    next = (uint8_t *)realloc(buf->data, cap);
    if (next == NULL) {
        return -1;
    }
    buf->data = next;
    buf->cap = cap;
    return 0;
}

int ntap_buffer_append(ntap_buffer_t *buf, const void *data, size_t len)
{
    size_t next_cap = 0;

    if (buf == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (buf->len > ((size_t)-1) - len) {
        return -1;
    }

    if (buf->len + len > buf->cap) {
        next_cap = buf->cap == 0 ? 256u : buf->cap;
        while (next_cap < buf->len + len) {
            if (next_cap > ((size_t)-1) / 2u) {
                next_cap = buf->len + len;
                break;
            }
            next_cap *= 2u;
        }
        if (ntap_buffer_reserve(buf, next_cap) != 0) {
            return -1;
        }
    }

    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

void ntap_buffer_clear(ntap_buffer_t *buf)
{
    if (buf == NULL) {
        return;
    }
    buf->len = 0;
}
