#include "common/config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_err(char *err, size_t err_len, const char *fmt,
                    const char *a, const char *b, unsigned long line)
{
    if (err == NULL || err_len == 0) {
        return;
    }
    if (line > 0) {
        (void)snprintf(err, err_len, fmt, a, b, line);
    } else {
        (void)snprintf(err, err_len, fmt, a, b);
    }
}

static char *trim(char *s)
{
    char *end = NULL;

    while (isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1u;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

static void strip_inline_comment(char *s)
{
    int in_quote = 0;

    while (*s != '\0') {
        if (*s == '"') {
            in_quote = !in_quote;
        }
        if (!in_quote && (*s == '#' || *s == ';')) {
            *s = '\0';
            return;
        }
        s++;
    }
}

static int copy_text(char *dst, size_t dst_len, const char *src)
{
    size_t len = 0;

    if (dst == NULL || dst_len == 0 || src == NULL) {
        return -1;
    }
    len = strlen(src);
    if (len >= dst_len) {
        return -1;
    }
    (void)memcpy(dst, src, len + 1u);
    return 0;
}

static int find_entry(const ntap_config_t *cfg, const char *section, const char *key)
{
    size_t i = 0;

    if (cfg == NULL || section == NULL || key == NULL) {
        return -1;
    }
    for (i = 0; i < cfg->count; i++) {
        if (strcmp(cfg->entries[i].section, section) == 0 &&
            strcmp(cfg->entries[i].key, key) == 0) {
            return (int)i;
        }
    }
    return -1;
}

void ntap_config_init(ntap_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    (void)memset(cfg, 0, sizeof(*cfg));
}

int ntap_config_load(ntap_config_t *cfg, const char *path, char *err, size_t err_len)
{
    FILE *fp = NULL;
    char line_buf[1024];
    char section[NTAP_CONFIG_SECTION_MAX] = "";
    unsigned long line_no = 0;

    if (cfg == NULL || path == NULL || *path == '\0') {
        set_err(err, err_len, "%s%s", "missing config path", "", 0);
        return -1;
    }

    ntap_config_init(cfg);
    fp = fopen(path, "r");
    if (fp == NULL) {
        set_err(err, err_len, "failed to open %s: %s", path, strerror(errno), 0);
        return -1;
    }

    while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
        char *line = NULL;
        char *eq = NULL;

        line_no++;
        line = trim(line_buf);
        if (*line == '\0' || *line == '#' || *line == ';') {
            continue;
        }
        if (*line == '[') {
            char *end = strchr(line, ']');
            if (end == NULL) {
                set_err(err, err_len, "%s%s at line %lu", "invalid section", "", line_no);
                (void)fclose(fp);
                return -1;
            }
            *end = '\0';
            if (copy_text(section, sizeof(section), trim(line + 1)) != 0 || section[0] == '\0') {
                set_err(err, err_len, "%s%s at line %lu", "invalid section", "", line_no);
                (void)fclose(fp);
                return -1;
            }
            continue;
        }

        eq = strchr(line, '=');
        if (eq == NULL || section[0] == '\0') {
            set_err(err, err_len, "%s%s at line %lu", "invalid key/value", "", line_no);
            (void)fclose(fp);
            return -1;
        }

        *eq = '\0';
        strip_inline_comment(eq + 1);
        {
            char *key = trim(line);
            char *value = trim(eq + 1);
            int existing = find_entry(cfg, section, key);
            ntap_config_entry_t *entry = NULL;

            if (*key == '\0') {
                set_err(err, err_len, "%s%s at line %lu", "empty key", "", line_no);
                (void)fclose(fp);
                return -1;
            }
            if (existing >= 0) {
                entry = &cfg->entries[existing];
            } else {
                if (cfg->count >= NTAP_CONFIG_MAX_ENTRIES) {
                    set_err(err, err_len, "%s%s", "too many config entries", "", 0);
                    (void)fclose(fp);
                    return -1;
                }
                entry = &cfg->entries[cfg->count++];
                if (copy_text(entry->section, sizeof(entry->section), section) != 0 ||
                    copy_text(entry->key, sizeof(entry->key), key) != 0) {
                    set_err(err, err_len, "%s%s at line %lu", "section/key too long", "", line_no);
                    (void)fclose(fp);
                    return -1;
                }
            }
            if (copy_text(entry->value, sizeof(entry->value), value) != 0) {
                set_err(err, err_len, "%s%s at line %lu", "value too long", "", line_no);
                (void)fclose(fp);
                return -1;
            }
        }
    }

    if (ferror(fp)) {
        set_err(err, err_len, "failed to read %s: %s", path, strerror(errno), 0);
        (void)fclose(fp);
        return -1;
    }
    (void)fclose(fp);
    return 0;
}

const char *ntap_config_get(const ntap_config_t *cfg, const char *section, const char *key)
{
    int index = find_entry(cfg, section, key);

    if (index < 0) {
        return NULL;
    }
    return cfg->entries[index].value;
}

int ntap_config_require(const ntap_config_t *cfg, const char *section, const char *key,
                        char *out, size_t out_len, char *err, size_t err_len)
{
    const char *value = ntap_config_get(cfg, section, key);

    if (value == NULL || *value == '\0') {
        set_err(err, err_len, "missing %s.%s", section, key, 0);
        return -1;
    }
    if (copy_text(out, out_len, value) != 0) {
        set_err(err, err_len, "value too long for %s.%s", section, key, 0);
        return -1;
    }
    return 0;
}

int ntap_config_require_addr(const ntap_config_t *cfg, const char *section, const char *key,
                             char *out, size_t out_len, char *err, size_t err_len)
{
    char value[NTAP_CONFIG_VALUE_MAX];
    char *colon = NULL;
    char *port_s = NULL;
    char *end = NULL;
    long port = 0;

    if (ntap_config_require(cfg, section, key, value, sizeof(value), err, err_len) != 0) {
        return -1;
    }
    colon = strrchr(value, ':');
    if (colon == NULL || colon == value || colon[1] == '\0') {
        set_err(err, err_len, "invalid address in %s.%s", section, key, 0);
        return -1;
    }
    port_s = colon + 1;
    errno = 0;
    port = strtol(port_s, &end, 10);
    if (errno != 0 || end == port_s || *end != '\0' || port <= 0 || port > 65535) {
        set_err(err, err_len, "invalid port in %s.%s", section, key, 0);
        return -1;
    }
    if (copy_text(out, out_len, value) != 0) {
        set_err(err, err_len, "value too long for %s.%s", section, key, 0);
        return -1;
    }
    return 0;
}

int ntap_config_get_u16(const ntap_config_t *cfg, const char *section, const char *key,
                        uint16_t fallback, uint16_t min_value, uint16_t max_value,
                        uint16_t *out, char *err, size_t err_len)
{
    const char *value = ntap_config_get(cfg, section, key);
    char *end = NULL;
    long parsed = 0;

    if (out == NULL) {
        return -1;
    }
    if (value == NULL || *value == '\0') {
        *out = fallback;
        return 0;
    }
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed < min_value || parsed > max_value) {
        set_err(err, err_len, "invalid integer in %s.%s", section, key, 0);
        return -1;
    }
    *out = (uint16_t)parsed;
    return 0;
}
