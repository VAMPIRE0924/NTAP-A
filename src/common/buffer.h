#ifndef NTAP_COMMON_BUFFER_H
#define NTAP_COMMON_BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct ntap_buffer {
    uint8_t *data;
    size_t len;
    size_t cap;
} ntap_buffer_t;

void ntap_buffer_init(ntap_buffer_t *buf);
void ntap_buffer_free(ntap_buffer_t *buf);
int ntap_buffer_reserve(ntap_buffer_t *buf, size_t cap);
int ntap_buffer_append(ntap_buffer_t *buf, const void *data, size_t len);
void ntap_buffer_clear(ntap_buffer_t *buf);

#endif
