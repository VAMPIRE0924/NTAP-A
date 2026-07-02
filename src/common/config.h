#ifndef NTAP_COMMON_CONFIG_H
#define NTAP_COMMON_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define NTAP_CONFIG_MAX_ENTRIES 128u
#define NTAP_CONFIG_SECTION_MAX 64u
#define NTAP_CONFIG_KEY_MAX 64u
#define NTAP_CONFIG_VALUE_MAX 512u

typedef struct ntap_config_entry {
    char section[NTAP_CONFIG_SECTION_MAX];
    char key[NTAP_CONFIG_KEY_MAX];
    char value[NTAP_CONFIG_VALUE_MAX];
} ntap_config_entry_t;

typedef struct ntap_config {
    ntap_config_entry_t entries[NTAP_CONFIG_MAX_ENTRIES];
    size_t count;
} ntap_config_t;

void ntap_config_init(ntap_config_t *cfg);
int ntap_config_load(ntap_config_t *cfg, const char *path, char *err, size_t err_len);
const char *ntap_config_get(const ntap_config_t *cfg, const char *section, const char *key);
int ntap_config_require(const ntap_config_t *cfg, const char *section, const char *key,
                        char *out, size_t out_len, char *err, size_t err_len);
int ntap_config_require_addr(const ntap_config_t *cfg, const char *section, const char *key,
                             char *out, size_t out_len, char *err, size_t err_len);
int ntap_config_get_u16(const ntap_config_t *cfg, const char *section, const char *key,
                        uint16_t fallback, uint16_t min_value, uint16_t max_value,
                        uint16_t *out, char *err, size_t err_len);

#endif
