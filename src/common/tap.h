#ifndef NTAP_COMMON_TAP_H
#define NTAP_COMMON_TAP_H

#include <stddef.h>
#include <stdint.h>

typedef struct ntap_tap {
    int fd;
    char name[64];
} ntap_tap_t;

int ntap_tap_open(ntap_tap_t *tap, const char *name, uint16_t mtu,
                  char *err, size_t err_len);
int ntap_tap_read(ntap_tap_t *tap, uint8_t *buf, size_t cap, size_t *len,
                  char *err, size_t err_len);
int ntap_tap_write(ntap_tap_t *tap, const uint8_t *buf, size_t len,
                   char *err, size_t err_len);
int ntap_tap_attach_bridge(ntap_tap_t *tap, const char *bridge_name,
                           char *err, size_t err_len);
void ntap_tap_close(ntap_tap_t *tap);

#endif
