#ifndef NTAP_A_CONFIG_H
#define NTAP_A_CONFIG_H

#include <stddef.h>

#include "common/config.h"

typedef struct ntap_a_config {
    char path[NTAP_CONFIG_VALUE_MAX];
    char tap_addr[NTAP_CONFIG_VALUE_MAX];
    char socks_addr[NTAP_CONFIG_VALUE_MAX];
    char api_addr[NTAP_CONFIG_VALUE_MAX];
    char db_file[NTAP_CONFIG_VALUE_MAX];
    char api_key[NTAP_CONFIG_VALUE_MAX];
    char log_level[NTAP_CONFIG_VALUE_MAX];
    char log_file[NTAP_CONFIG_VALUE_MAX];
} ntap_a_config_t;

int ntap_a_config_load(ntap_a_config_t *out, const char *path, char *err, size_t err_len);

#endif
