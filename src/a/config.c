#include "a/config.h"

#include <stdio.h>
#include <string.h>

static void copy_optional(char *out, size_t out_len, const char *value)
{
    if (out == NULL || out_len == 0) {
        return;
    }
    if (value == NULL) {
        out[0] = '\0';
        return;
    }
    (void)snprintf(out, out_len, "%s", value);
}

int ntap_a_config_load(ntap_a_config_t *out, const char *path, char *err, size_t err_len)
{
    ntap_config_t cfg;

    if (out == NULL) {
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    if (path == NULL || *path == '\0') {
        path = "ntap-a.conf";
    }
    (void)snprintf(out->path, sizeof(out->path), "%s", path);

    if (ntap_config_load(&cfg, path, err, err_len) != 0) {
        return -1;
    }
    if (ntap_config_require_addr(&cfg, "server", "tap_addr",
                                 out->tap_addr, sizeof(out->tap_addr), err, err_len) != 0 ||
        ntap_config_require_addr(&cfg, "server", "socks_addr",
                                 out->socks_addr, sizeof(out->socks_addr), err, err_len) != 0 ||
        ntap_config_require_addr(&cfg, "server", "api_addr",
                                 out->api_addr, sizeof(out->api_addr), err, err_len) != 0 ||
        ntap_config_require(&cfg, "server", "db_file",
                            out->db_file, sizeof(out->db_file), err, err_len) != 0 ||
        ntap_config_require(&cfg, "auth", "api_key",
                            out->api_key, sizeof(out->api_key), err, err_len) != 0) {
        return -1;
    }

    copy_optional(out->log_level, sizeof(out->log_level),
                  ntap_config_get(&cfg, "log", "level"));
    copy_optional(out->log_file, sizeof(out->log_file),
                  ntap_config_get(&cfg, "log", "file"));
    if (out->log_level[0] == '\0') {
        (void)snprintf(out->log_level, sizeof(out->log_level), "info");
    }
    return 0;
}
