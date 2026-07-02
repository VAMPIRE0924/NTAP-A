#include "a/api_server.h"

#include "a/db_sqlite.h"
#include "common/hash.h"
#include "common/net.h"
#include "common/ntap_time.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#define NTAP_A_API_HEADER_MAX 8192u
#define NTAP_A_API_BODY_MAX 16384u
#define NTAP_A_API_TIME_SKEW_SEC 20
#define NTAP_A_API_NONCE_CACHE_SIZE 1024u

typedef struct api_request {
    char method[8];
    char path[256];
    char version[16];
    char timestamp[64];
    char nonce[128];
    char body_sha256[NTAP_SHA256_HEX_SIZE];
    char sign[NTAP_SHA256_HEX_SIZE];
    size_t content_length;
    uint8_t *body;
} api_request_t;

typedef struct api_nonce_entry {
    int active;
    int64_t seen_at;
    char nonce[128];
} api_nonce_entry_t;

static api_nonce_entry_t g_nonce_cache[NTAP_A_API_NONCE_CACHE_SIZE];

static int ascii_case_equal(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static char *trim_ascii(char *s)
{
    char *end = NULL;

    if (s == NULL) {
        return NULL;
    }
    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    return s;
}

static int hex_equal_ci(const char *a, const char *b)
{
    unsigned char diff = 0;
    size_t i = 0;

    if (a == NULL || b == NULL ||
        strlen(a) != (NTAP_SHA256_HEX_SIZE - 1u) ||
        strlen(b) != (NTAP_SHA256_HEX_SIZE - 1u)) {
        return 0;
    }
    for (i = 0; i < NTAP_SHA256_HEX_SIZE - 1u; i++) {
        diff = (unsigned char)(diff |
                               (unsigned char)(tolower((unsigned char)a[i]) ^
                                               tolower((unsigned char)b[i])));
    }
    return diff == 0;
}

static int hex_digit_value(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') {
        return (int)(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return (int)(ch - 'a' + 10);
    }
    if (ch >= 'A' && ch <= 'F') {
        return (int)(ch - 'A' + 10);
    }
    return -1;
}

static int form_decode(const uint8_t *src, size_t len, char *out, size_t out_len)
{
    size_t i = 0;
    size_t pos = 0;

    if (out == NULL || out_len == 0 || (src == NULL && len > 0)) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        unsigned char ch = src[i];

        if (pos + 1u >= out_len) {
            return -1;
        }
        if (ch == '+') {
            out[pos++] = ' ';
        } else if (ch == '%') {
            int hi = 0;
            int lo = 0;

            if (i + 2u >= len) {
                return -1;
            }
            hi = hex_digit_value(src[i + 1u]);
            lo = hex_digit_value(src[i + 2u]);
            if (hi < 0 || lo < 0) {
                return -1;
            }
            out[pos++] = (char)((hi << 4) | lo);
            i += 2u;
        } else {
            out[pos++] = (char)ch;
        }
    }
    out[pos] = '\0';
    return 0;
}

static int api_form_get(const api_request_t *req, const char *name,
                        char *out, size_t out_len)
{
    size_t start = 0;
    size_t name_len = name == NULL ? 0u : strlen(name);

    if (req == NULL || name == NULL || out == NULL || out_len == 0) {
        return -1;
    }
    out[0] = '\0';
    while (start <= req->content_length) {
        size_t end = start;
        size_t eq = start;
        char key[128];

        while (end < req->content_length && req->body[end] != '&') {
            end++;
        }
        eq = start;
        while (eq < end && req->body[eq] != '=') {
            eq++;
        }
        if (eq > start &&
            form_decode(req->body + start, eq - start, key, sizeof(key)) == 0 &&
            strlen(key) == name_len && strcmp(key, name) == 0) {
            if (eq < end && req->body[eq] == '=') {
                return form_decode(req->body + eq + 1u, end - eq - 1u,
                                   out, out_len);
            }
            out[0] = '\0';
            return 0;
        }
        if (end >= req->content_length) {
            break;
        }
        start = end + 1u;
    }
    return 1;
}

static int api_form_required(const api_request_t *req, const char *name,
                             char *out, size_t out_len,
                             char *err, size_t err_len)
{
    int rc = api_form_get(req, name, out, out_len);

    if (rc != 0 || out[0] == '\0') {
        (void)snprintf(err, err_len, "missing form field %s", name);
        return -1;
    }
    return 0;
}

static int api_parse_i64(const char *value, int64_t *out)
{
    char *end = NULL;
    long long parsed = 0;

    if (value == NULL || *value == '\0' || out == NULL) {
        return -1;
    }
    parsed = strtoll(value, &end, 10);
    if (end == value || *end != '\0') {
        return -1;
    }
    *out = (int64_t)parsed;
    return 0;
}

static int api_parse_optional_u32(const api_request_t *req, const char *name,
                                  uint32_t fallback, uint32_t *out)
{
    char value[64];
    int64_t parsed = 0;
    int rc = 0;

    if (out == NULL) {
        return -1;
    }
    rc = api_form_get(req, name, value, sizeof(value));
    if (rc == 1 || value[0] == '\0') {
        *out = fallback;
        return 0;
    }
    if (rc != 0 || api_parse_i64(value, &parsed) != 0 ||
        parsed < 0 || parsed > 1000000) {
        return -1;
    }
    *out = (uint32_t)parsed;
    return 0;
}

static int api_parse_required_u32(const api_request_t *req, const char *name,
                                  uint32_t *out, char *err, size_t err_len)
{
    char value[64];
    int64_t parsed = 0;

    if (out == NULL) {
        return -1;
    }
    if (api_form_required(req, name, value, sizeof(value), err, err_len) != 0) {
        return -1;
    }
    if (api_parse_i64(value, &parsed) != 0 || parsed < 0 || parsed > 1000000) {
        (void)snprintf(err, err_len, "invalid %s", name);
        return -1;
    }
    *out = (uint32_t)parsed;
    return 0;
}

static int api_form_bool(const api_request_t *req, const char *name)
{
    char value[32];

    if (api_form_get(req, name, value, sizeof(value)) != 0) {
        return 0;
    }
    return strcmp(value, "1") == 0 ||
           ascii_case_equal(value, "true") ||
           ascii_case_equal(value, "yes") ||
           ascii_case_equal(value, "on");
}

static int api_form_required_i64(const api_request_t *req, const char *name,
                                 int64_t *out, char *err, size_t err_len)
{
    char value[64];

    if (out == NULL) {
        return -1;
    }
    if (api_form_required(req, name, value, sizeof(value), err, err_len) != 0) {
        return -1;
    }
    if (api_parse_i64(value, out) != 0 || *out <= 0) {
        (void)snprintf(err, err_len, "invalid %s", name);
        return -1;
    }
    return 0;
}

static int api_form_required_node_pk(const api_request_t *req, int64_t *out,
                                     char *err, size_t err_len)
{
    char value[64];
    int rc = 0;

    if (out == NULL) {
        return -1;
    }
    rc = api_form_get(req, "id", value, sizeof(value));
    if (rc == 1 || value[0] == '\0') {
        rc = api_form_get(req, "node_id", value, sizeof(value));
    }
    if (rc != 0 || value[0] == '\0') {
        (void)snprintf(err, err_len, "missing form field id");
        return -1;
    }
    if (api_parse_i64(value, out) != 0 || *out <= 0) {
        (void)snprintf(err, err_len, "invalid node id");
        return -1;
    }
    return 0;
}

static int api_strdup_response(const char *text, char **out_json,
                               char *err, size_t err_len)
{
    char *copy = NULL;
    size_t len = text == NULL ? 0u : strlen(text);

    if (out_json == NULL || text == NULL) {
        return -1;
    }
    copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        (void)snprintf(err, err_len, "failed to allocate api response");
        return -1;
    }
    (void)memcpy(copy, text, len + 1u);
    *out_json = copy;
    return 0;
}

static void api_nonce_cache_reset(void)
{
    (void)memset(g_nonce_cache, 0, sizeof(g_nonce_cache));
}

static int api_nonce_record(const char *nonce, int64_t now,
                            char *err, size_t err_len)
{
    size_t i = 0;
    size_t slot = NTAP_A_API_NONCE_CACHE_SIZE;
    int64_t oldest_seen = 0;
    size_t oldest_slot = 0;

    if (nonce == NULL || *nonce == '\0') {
        (void)snprintf(err, err_len, "missing api nonce");
        return -1;
    }
    for (i = 0; i < NTAP_A_API_NONCE_CACHE_SIZE; i++) {
        api_nonce_entry_t *entry = &g_nonce_cache[i];

        if (!entry->active) {
            if (slot == NTAP_A_API_NONCE_CACHE_SIZE) {
                slot = i;
            }
            continue;
        }
        if (entry->seen_at + NTAP_A_API_TIME_SKEW_SEC < now) {
            entry->active = 0;
            if (slot == NTAP_A_API_NONCE_CACHE_SIZE) {
                slot = i;
            }
            continue;
        }
        if (strcmp(entry->nonce, nonce) == 0) {
            (void)snprintf(err, err_len, "api nonce replay");
            return -1;
        }
        if (oldest_seen == 0 || entry->seen_at < oldest_seen) {
            oldest_seen = entry->seen_at;
            oldest_slot = i;
        }
    }
    if (slot == NTAP_A_API_NONCE_CACHE_SIZE) {
        slot = oldest_slot;
    }
    g_nonce_cache[slot].active = 1;
    g_nonce_cache[slot].seen_at = now;
    (void)snprintf(g_nonce_cache[slot].nonce, sizeof(g_nonce_cache[slot].nonce),
                   "%s", nonce);
    return 0;
}

static int api_send_response(ntap_socket_t fd, int status_code, const char *status_text,
                             const char *body, char *err, size_t err_len)
{
    char header[512];
    size_t body_len = body == NULL ? 0u : strlen(body);
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 %d %s\r\n"
                              "Content-Type: application/json\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              status_code, status_text, body_len);

    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        (void)snprintf(err, err_len, "api response header too large");
        return -1;
    }
    if (ntap_send_all(fd, header, (size_t)header_len, err, err_len) != 0) {
        return -1;
    }
    if (body_len > 0 && ntap_send_all(fd, body, body_len, err, err_len) != 0) {
        return -1;
    }
    return 0;
}

static int api_error(ntap_socket_t fd, int status_code, const char *status_text,
                     const char *msg, char *err, size_t err_len)
{
    char body[512];

    (void)snprintf(body, sizeof(body), "{\"code\":0,\"msg\":\"%s\"}",
                   msg == NULL ? "error" : msg);
    return api_send_response(fd, status_code, status_text, body, err, err_len);
}

static char *find_header_end(char *buf, size_t len)
{
    size_t i = 0;

    if (buf == NULL || len < 4u) {
        return NULL;
    }
    for (i = 0; i + 3u < len; i++) {
        if (buf[i] == '\r' && buf[i + 1u] == '\n' &&
            buf[i + 2u] == '\r' && buf[i + 3u] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

static int api_read_request(ntap_socket_t fd, api_request_t *req,
                            char *err, size_t err_len)
{
    char raw[NTAP_A_API_HEADER_MAX + 1u];
    char *header_end = NULL;
    char *line = NULL;
    char *next = NULL;
    size_t used = 0;
    size_t header_len = 0;
    size_t already_body = 0;

    if (req == NULL) {
        return -1;
    }
    (void)memset(req, 0, sizeof(*req));
    while (used < NTAP_A_API_HEADER_MAX) {
        int n = recv(fd, raw + used, (int)(NTAP_A_API_HEADER_MAX - used), 0);

        if (n <= 0) {
            (void)snprintf(err, err_len, "api read failed");
            return -1;
        }
        used += (size_t)n;
        header_end = find_header_end(raw, used);
        if (header_end != NULL) {
            break;
        }
    }
    if (header_end == NULL) {
        (void)snprintf(err, err_len, "api request header too large");
        return -1;
    }
    header_len = (size_t)(header_end - raw) + 4u;
    already_body = used - header_len;
    raw[header_len - 2u] = '\0';

    line = raw;
    next = strstr(line, "\r\n");
    if (next == NULL) {
        (void)snprintf(err, err_len, "bad api request line");
        return -1;
    }
    *next = '\0';
    if (sscanf(line, "%7s %255s %15s", req->method, req->path, req->version) != 3) {
        (void)snprintf(err, err_len, "bad api request line");
        return -1;
    }
    line = next + 2;
    while (*line != '\0') {
        char *colon = NULL;
        char *name = NULL;
        char *value = NULL;

        next = strstr(line, "\r\n");
        if (next != NULL) {
            *next = '\0';
        }
        colon = strchr(line, ':');
        if (colon != NULL) {
            *colon = '\0';
            name = trim_ascii(line);
            value = trim_ascii(colon + 1);
            if (ascii_case_equal(name, "Content-Length")) {
                char *end = NULL;
                unsigned long parsed = strtoul(value, &end, 10);

                if (end == value || *end != '\0' || parsed > NTAP_A_API_BODY_MAX) {
                    (void)snprintf(err, err_len, "invalid content length");
                    return -1;
                }
                req->content_length = (size_t)parsed;
            } else if (ascii_case_equal(name, "X-NTAP-Timestamp") ||
                       ascii_case_equal(name, "timestamp")) {
                (void)snprintf(req->timestamp, sizeof(req->timestamp), "%s", value);
            } else if (ascii_case_equal(name, "X-NTAP-Nonce") ||
                       ascii_case_equal(name, "nonce")) {
                (void)snprintf(req->nonce, sizeof(req->nonce), "%s", value);
            } else if (ascii_case_equal(name, "X-NTAP-Body-SHA256") ||
                       ascii_case_equal(name, "body_sha256")) {
                (void)snprintf(req->body_sha256, sizeof(req->body_sha256), "%s", value);
            } else if (ascii_case_equal(name, "X-NTAP-Sign") ||
                       ascii_case_equal(name, "api_sign")) {
                (void)snprintf(req->sign, sizeof(req->sign), "%s", value);
            }
        }
        if (next == NULL) {
            break;
        }
        line = next + 2;
    }
    if (req->content_length > 0) {
        req->body = (uint8_t *)malloc(req->content_length);
        if (req->body == NULL) {
            (void)snprintf(err, err_len, "failed to allocate api body");
            return -1;
        }
        if (already_body > req->content_length) {
            already_body = req->content_length;
        }
        if (already_body > 0) {
            (void)memcpy(req->body, raw + header_len, already_body);
        }
        if (already_body < req->content_length &&
            ntap_recv_all(fd, req->body + already_body,
                          req->content_length - already_body,
                          err, err_len) != 0) {
            free(req->body);
            req->body = NULL;
            return -1;
        }
    }
    return 0;
}

static int api_verify_signature(const ntap_a_config_t *cfg, const api_request_t *req,
                                char *err, size_t err_len)
{
    char actual_body_sha[NTAP_SHA256_HEX_SIZE];
    char signing[1024];
    char expected_sign[NTAP_SHA256_HEX_SIZE];
    char *end = NULL;
    long long timestamp = 0;
    long long now = (long long)ntap_time_unix_sec();
    int signing_len = 0;

    if (cfg == NULL || req == NULL) {
        return -1;
    }
    if (req->timestamp[0] == '\0' || req->nonce[0] == '\0' ||
        req->body_sha256[0] == '\0' || req->sign[0] == '\0') {
        (void)snprintf(err, err_len, "missing api signature fields");
        return -1;
    }
    timestamp = strtoll(req->timestamp, &end, 10);
    if (end == req->timestamp || *end != '\0' ||
        timestamp < now - NTAP_A_API_TIME_SKEW_SEC ||
        timestamp > now + NTAP_A_API_TIME_SKEW_SEC) {
        (void)snprintf(err, err_len, "invalid api timestamp");
        return -1;
    }
    if (ntap_sha256_hex(req->body, req->content_length, actual_body_sha) != 0 ||
        !hex_equal_ci(actual_body_sha, req->body_sha256)) {
        (void)snprintf(err, err_len, "body_sha256 mismatch");
        return -1;
    }
    signing_len = snprintf(signing, sizeof(signing), "%s\n%s\n%s\n%s\n%s",
                           req->method, req->path, actual_body_sha,
                           req->timestamp, req->nonce);
    if (signing_len < 0 || (size_t)signing_len >= sizeof(signing)) {
        (void)snprintf(err, err_len, "api signing input too large");
        return -1;
    }
    if (ntap_hmac_sha256_hex((const uint8_t *)cfg->api_key, strlen(cfg->api_key),
                             (const uint8_t *)signing, (size_t)signing_len,
                             expected_sign) != 0 ||
        !hex_equal_ci(expected_sign, req->sign)) {
        (void)snprintf(err, err_len, "api signature mismatch");
        return -1;
    }
    if (api_nonce_record(req->nonce, now, err, err_len) != 0) {
        return -1;
    }
    return 0;
}

static int api_handle_json_endpoint(const ntap_a_config_t *cfg, const api_request_t *req,
                                    char **out_json, char *err, size_t err_len)
{
    if (strcmp(req->path, "/api/network/add") == 0) {
        char name[NTAP_CONFIG_VALUE_MAX];
        char mtu_s[64];
        int64_t mtu = NTAP_DEFAULT_MTU;
        ntap_a_network_options_t opts;

        if (api_form_required(req, "name", name, sizeof(name), err, err_len) != 0) {
            return -1;
        }
        opts.mtu = NTAP_DEFAULT_MTU;
        opts.mac_ttl_sec = NTAP_A_DEFAULT_MAC_TTL_SEC;
        opts.broadcast_limit_pps = NTAP_A_DEFAULT_BROADCAST_LIMIT_PPS;
        opts.session_broadcast_limit_pps = NTAP_A_DEFAULT_SESSION_BROADCAST_LIMIT_PPS;
        opts.max_mac_per_session = NTAP_A_DEFAULT_MAX_MAC_PER_SESSION;
        opts.tap_queue_limit_bytes = NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES;
        opts.allow_client_to_client = api_form_bool(req, "allow_client_to_client");
        opts.allow_l2_control = api_form_bool(req, "allow_l2_control");
        if (api_form_get(req, "mtu", mtu_s, sizeof(mtu_s)) == 0 &&
            mtu_s[0] != '\0') {
            if (api_parse_i64(mtu_s, &mtu) != 0 ||
                mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU) {
                (void)snprintf(err, err_len, "invalid mtu");
                return -1;
            }
            opts.mtu = (uint16_t)mtu;
        }
        if (api_parse_optional_u32(req, "mac_ttl_sec", opts.mac_ttl_sec,
                                   &opts.mac_ttl_sec) != 0 ||
            api_parse_optional_u32(req, "broadcast_limit_pps",
                                   opts.broadcast_limit_pps,
                                   &opts.broadcast_limit_pps) != 0 ||
            api_parse_optional_u32(req, "session_broadcast_limit_pps",
                                   opts.session_broadcast_limit_pps,
                                   &opts.session_broadcast_limit_pps) != 0 ||
            api_parse_optional_u32(req, "max_mac_per_session",
                                   opts.max_mac_per_session,
                                   &opts.max_mac_per_session) != 0 ||
            api_parse_optional_u32(req, "tap_queue_limit_bytes",
                                   opts.tap_queue_limit_bytes,
                                   &opts.tap_queue_limit_bytes) != 0) {
            (void)snprintf(err, err_len, "invalid network option");
            return -1;
        }
        if (opts.max_mac_per_session == 0 || opts.tap_queue_limit_bytes == 0) {
            (void)snprintf(err, err_len, "invalid network limit");
            return -1;
        }
        if (ntap_a_db_add_network(cfg->db_file, name, &opts, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/node/add") == 0) {
        char name[NTAP_CONFIG_VALUE_MAX];
        char node_id[NTAP_CONFIG_VALUE_MAX];
        char node_key[NTAP_CONFIG_VALUE_MAX];
        char network_id_s[64];
        char mtu_s[64];
        char tap_name[NTAP_CONFIG_VALUE_MAX];
        char bridge_name[NTAP_CONFIG_VALUE_MAX];
        int64_t network_id = 0;
        int64_t mtu = NTAP_DEFAULT_MTU;
        uint32_t max_socks_streams = NTAP_A_DEFAULT_MAX_SOCKS_STREAMS;
        uint32_t socks_idle_timeout_sec = NTAP_A_DEFAULT_SOCKS_IDLE_TIMEOUT_SEC;

        if (api_form_required(req, "name", name, sizeof(name), err, err_len) != 0 ||
            api_form_required(req, "node_id", node_id, sizeof(node_id),
                              err, err_len) != 0 ||
            api_form_required(req, "node_key", node_key, sizeof(node_key),
                              err, err_len) != 0 ||
            api_form_required(req, "network_id", network_id_s,
                              sizeof(network_id_s), err, err_len) != 0) {
            return -1;
        }
        if (api_parse_i64(network_id_s, &network_id) != 0 || network_id <= 0) {
            (void)snprintf(err, err_len, "invalid network_id");
            return -1;
        }
        if (api_form_get(req, "mtu", mtu_s, sizeof(mtu_s)) == 0 &&
            mtu_s[0] != '\0' &&
            (api_parse_i64(mtu_s, &mtu) != 0 ||
             mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU)) {
            (void)snprintf(err, err_len, "invalid mtu");
            return -1;
        }
        if (api_form_get(req, "tap_name", tap_name, sizeof(tap_name)) != 0) {
            tap_name[0] = '\0';
        }
        if (api_form_get(req, "bridge_name", bridge_name,
                         sizeof(bridge_name)) != 0) {
            bridge_name[0] = '\0';
        }
        if (api_parse_optional_u32(req, "max_socks_streams",
                                   max_socks_streams,
                                   &max_socks_streams) != 0 ||
            api_parse_optional_u32(req, "socks_idle_timeout_sec",
                                   socks_idle_timeout_sec,
                                   &socks_idle_timeout_sec) != 0 ||
            max_socks_streams == 0 || socks_idle_timeout_sec == 0) {
            (void)snprintf(err, err_len, "invalid node socks limits");
            return -1;
        }
        if (ntap_a_db_add_node(cfg->db_file, name, node_id, node_key,
                               network_id, tap_name, bridge_name,
                               (uint16_t)mtu, max_socks_streams,
                               socks_idle_timeout_sec, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/tap-user/add") == 0) {
        char username[NTAP_CONFIG_VALUE_MAX];
        char password[NTAP_CONFIG_VALUE_MAX];
        char network_id_s[64];
        int64_t network_id = 0;

        if (api_form_required(req, "username", username, sizeof(username),
                              err, err_len) != 0 ||
            api_form_required(req, "password", password, sizeof(password),
                              err, err_len) != 0 ||
            api_form_required(req, "network_id", network_id_s,
                              sizeof(network_id_s), err, err_len) != 0) {
            return -1;
        }
        if (api_parse_i64(network_id_s, &network_id) != 0 || network_id <= 0) {
            (void)snprintf(err, err_len, "invalid network_id");
            return -1;
        }
        if (ntap_a_db_add_tap_user(cfg->db_file, username, password,
                                   network_id, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/socks-user/add") == 0) {
        char username[NTAP_CONFIG_VALUE_MAX];
        char password[NTAP_CONFIG_VALUE_MAX];
        char node_id_s[64];
        int64_t node_pk = 0;

        if (api_form_required(req, "username", username, sizeof(username),
                              err, err_len) != 0 ||
            api_form_required(req, "password", password, sizeof(password),
                              err, err_len) != 0) {
            return -1;
        }
        if (api_form_get(req, "node_id", node_id_s, sizeof(node_id_s)) == 0 &&
            node_id_s[0] != '\0' &&
            (api_parse_i64(node_id_s, &node_pk) != 0 || node_pk <= 0)) {
            (void)snprintf(err, err_len, "invalid node_id");
            return -1;
        }
        if (ntap_a_db_add_socks_user(cfg->db_file, username, password,
                                     node_pk, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/network/edit") == 0) {
        char name[NTAP_CONFIG_VALUE_MAX];
        int64_t id = 0;
        uint32_t mtu = 0;
        ntap_a_network_options_t opts;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0 ||
            api_form_required(req, "name", name, sizeof(name), err, err_len) != 0 ||
            api_parse_required_u32(req, "mtu", &mtu, err, err_len) != 0 ||
            api_parse_required_u32(req, "mac_ttl_sec", &opts.mac_ttl_sec,
                                   err, err_len) != 0 ||
            api_parse_required_u32(req, "broadcast_limit_pps",
                                   &opts.broadcast_limit_pps,
                                   err, err_len) != 0 ||
            api_parse_required_u32(req, "session_broadcast_limit_pps",
                                   &opts.session_broadcast_limit_pps,
                                   err, err_len) != 0 ||
            api_parse_required_u32(req, "max_mac_per_session",
                                   &opts.max_mac_per_session,
                                   err, err_len) != 0 ||
            api_parse_required_u32(req, "tap_queue_limit_bytes",
                                   &opts.tap_queue_limit_bytes,
                                   err, err_len) != 0) {
            return -1;
        }
        if (mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU) {
            (void)snprintf(err, err_len, "invalid mtu");
            return -1;
        }
        opts.mtu = (uint16_t)mtu;
        opts.allow_client_to_client = api_form_bool(req, "allow_client_to_client");
        opts.allow_l2_control = api_form_bool(req, "allow_l2_control");
        if (ntap_a_db_edit_network(cfg->db_file, id, name, &opts,
                                   err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/network/delete") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_delete_network(cfg->db_file, id, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/node/edit") == 0) {
        char name[NTAP_CONFIG_VALUE_MAX];
        char node_id[NTAP_CONFIG_VALUE_MAX];
        char node_key[NTAP_CONFIG_VALUE_MAX];
        char tap_name[NTAP_CONFIG_VALUE_MAX];
        char bridge_name[NTAP_CONFIG_VALUE_MAX];
        int64_t id = 0;
        int64_t network_id = 0;
        uint32_t mtu = 0;
        uint32_t max_socks_streams = NTAP_A_DEFAULT_MAX_SOCKS_STREAMS;
        uint32_t socks_idle_timeout_sec = NTAP_A_DEFAULT_SOCKS_IDLE_TIMEOUT_SEC;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0 ||
            api_form_required(req, "name", name, sizeof(name), err, err_len) != 0 ||
            api_form_required(req, "node_id", node_id, sizeof(node_id),
                              err, err_len) != 0 ||
            api_form_required_i64(req, "network_id", &network_id,
                                  err, err_len) != 0 ||
            api_parse_required_u32(req, "mtu", &mtu, err, err_len) != 0) {
            return -1;
        }
        if (mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU) {
            (void)snprintf(err, err_len, "invalid mtu");
            return -1;
        }
        if (api_form_get(req, "node_key", node_key, sizeof(node_key)) != 0) {
            node_key[0] = '\0';
        }
        if (api_form_get(req, "tap_name", tap_name, sizeof(tap_name)) != 0) {
            tap_name[0] = '\0';
        }
        if (api_form_get(req, "bridge_name", bridge_name,
                         sizeof(bridge_name)) != 0) {
            bridge_name[0] = '\0';
        }
        if (api_parse_optional_u32(req, "max_socks_streams",
                                   max_socks_streams,
                                   &max_socks_streams) != 0 ||
            api_parse_optional_u32(req, "socks_idle_timeout_sec",
                                   socks_idle_timeout_sec,
                                   &socks_idle_timeout_sec) != 0 ||
            max_socks_streams == 0 || socks_idle_timeout_sec == 0) {
            (void)snprintf(err, err_len, "invalid node socks limits");
            return -1;
        }
        if (ntap_a_db_edit_node(cfg->db_file, id, name, node_id, node_key,
                                network_id, tap_name, bridge_name,
                                (uint16_t)mtu, max_socks_streams,
                                socks_idle_timeout_sec, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/node/delete") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_delete_node(cfg->db_file, id, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/tap-user/edit") == 0) {
        char username[NTAP_CONFIG_VALUE_MAX];
        char password[NTAP_CONFIG_VALUE_MAX];
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0 ||
            api_form_required(req, "username", username, sizeof(username),
                              err, err_len) != 0) {
            return -1;
        }
        if (api_form_get(req, "password", password, sizeof(password)) != 0) {
            password[0] = '\0';
        }
        if (ntap_a_db_edit_tap_user(cfg->db_file, id, username, password,
                                    err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/tap-user/delete") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_delete_tap_user(cfg->db_file, id, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/tap-user/grant") == 0 ||
        strcmp(req->path, "/api/tap-user/revoke") == 0) {
        int64_t user_id = 0;
        int64_t network_id = 0;
        int grant = strcmp(req->path, "/api/tap-user/grant") == 0;

        if (api_form_required_i64(req, "user_id", &user_id, err, err_len) != 0 ||
            api_form_required_i64(req, "network_id", &network_id,
                                  err, err_len) != 0) {
            return -1;
        }
        if ((grant ? ntap_a_db_grant_tap_user(cfg->db_file, user_id, network_id,
                                              err, err_len) :
                     ntap_a_db_revoke_tap_user(cfg->db_file, user_id, network_id,
                                               err, err_len)) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/socks-user/edit") == 0) {
        char username[NTAP_CONFIG_VALUE_MAX];
        char password[NTAP_CONFIG_VALUE_MAX];
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0 ||
            api_form_required(req, "username", username, sizeof(username),
                              err, err_len) != 0) {
            return -1;
        }
        if (api_form_get(req, "password", password, sizeof(password)) != 0) {
            password[0] = '\0';
        }
        if (ntap_a_db_edit_socks_user(cfg->db_file, id, username, password,
                                      err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/socks-user/delete") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_delete_socks_user(cfg->db_file, id, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/socks-user/enable") == 0 ||
        strcmp(req->path, "/api/socks-user/disable") == 0) {
        int64_t id = 0;
        int enabled = strcmp(req->path, "/api/socks-user/enable") == 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_set_socks_user_enabled(cfg->db_file, id, enabled,
                                             err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/socks-user/grant") == 0 ||
        strcmp(req->path, "/api/socks-user/revoke") == 0) {
        int64_t user_id = 0;
        int64_t node_pk = 0;
        int grant = strcmp(req->path, "/api/socks-user/grant") == 0;

        if (api_form_required_i64(req, "user_id", &user_id, err, err_len) != 0 ||
            api_form_required_i64(req, "node_id", &node_pk,
                                  err, err_len) != 0) {
            return -1;
        }
        if ((grant ? ntap_a_db_grant_socks_user(cfg->db_file, user_id, node_pk,
                                                err, err_len) :
                     ntap_a_db_revoke_socks_user(cfg->db_file, user_id, node_pk,
                                                 err, err_len)) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/network/enable") == 0 ||
        strcmp(req->path, "/api/network/disable") == 0) {
        int64_t id = 0;
        int enabled = strcmp(req->path, "/api/network/enable") == 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_set_network_enabled(cfg->db_file, id, enabled,
                                          err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/node/enable") == 0 ||
        strcmp(req->path, "/api/node/disable") == 0) {
        int64_t id = 0;
        int enabled = strcmp(req->path, "/api/node/enable") == 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_set_node_enabled(cfg->db_file, id, enabled,
                                       err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/tap-user/enable") == 0 ||
        strcmp(req->path, "/api/tap-user/disable") == 0) {
        int64_t id = 0;
        int enabled = strcmp(req->path, "/api/tap-user/enable") == 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_set_tap_user_enabled(cfg->db_file, id, enabled,
                                           err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/service/start") == 0 ||
        strcmp(req->path, "/api/service/stop") == 0) {
        int64_t id = 0;
        int enabled = strcmp(req->path, "/api/service/start") == 0;
        char service_type[32];

        if (api_form_required_node_pk(req, &id, err, err_len) != 0 ||
            api_form_required(req, "type", service_type, sizeof(service_type),
                              err, err_len) != 0) {
            return -1;
        }
        if (ntap_a_db_set_node_service_enabled(cfg->db_file, id, service_type,
                                               enabled, err, err_len) != 0) {
            return -1;
        }
        return api_strdup_response("{\"code\":1,\"msg\":\"ok\"}", out_json,
                                   err, err_len);
    }
    if (strcmp(req->path, "/api/service/status") == 0) {
        int64_t id = 0;

        if (api_form_required_node_pk(req, &id, err, err_len) != 0) {
            return -1;
        }
        return ntap_a_db_json_node_service_status(cfg->db_file, id, out_json,
                                                  err, err_len);
    }
    if (strcmp(req->path, "/api/network/get") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        return ntap_a_db_json_network(cfg->db_file, id, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/node/get") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        return ntap_a_db_json_node(cfg->db_file, id, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/tap-user/get") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        return ntap_a_db_json_tap_user(cfg->db_file, id, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/socks-user/get") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        return ntap_a_db_json_socks_user(cfg->db_file, id, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/session/get") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        return ntap_a_db_json_session(cfg->db_file, id, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/socks-stream/get") == 0) {
        int64_t id = 0;

        if (api_form_required_i64(req, "id", &id, err, err_len) != 0) {
            return -1;
        }
        return ntap_a_db_json_socks_stream(cfg->db_file, id, out_json,
                                           err, err_len);
    }
    if (strcmp(req->path, "/api/network/list") == 0) {
        return ntap_a_db_json_networks(cfg->db_file, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/node/list") == 0) {
        return ntap_a_db_json_nodes(cfg->db_file, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/tap-user/list") == 0) {
        return ntap_a_db_json_tap_users(cfg->db_file, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/socks-user/list") == 0) {
        return ntap_a_db_json_socks_users(cfg->db_file, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/session/list") == 0) {
        return ntap_a_db_json_sessions(cfg->db_file, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/socks-stream/list") == 0) {
        return ntap_a_db_json_socks_streams(cfg->db_file, out_json, err, err_len);
    }
    if (strcmp(req->path, "/api/health") == 0) {
        char *body = (char *)malloc(38u);

        if (body == NULL) {
            (void)snprintf(err, err_len, "failed to allocate health response");
            return -1;
        }
        (void)snprintf(body, 38u, "{\"code\":1,\"data\":{\"status\":\"ok\"}}");
        *out_json = body;
        return 0;
    }
    (void)snprintf(err, err_len, "unknown api path");
    return 1;
}

static int api_handle_client(ntap_socket_t fd, const ntap_a_config_t *cfg,
                             char *err, size_t err_len)
{
    api_request_t req;
    char *json = NULL;
    int rc = 0;

    if (api_read_request(fd, &req, err, err_len) != 0) {
        (void)api_error(fd, 400, "Bad Request", err, err, err_len);
        return -1;
    }
    if (strcmp(req.method, "POST") != 0) {
        (void)api_error(fd, 405, "Method Not Allowed", "method not allowed",
                        err, err_len);
        free(req.body);
        return 0;
    }
    if (api_verify_signature(cfg, &req, err, err_len) != 0) {
        (void)api_error(fd, 401, "Unauthorized", err, err, err_len);
        free(req.body);
        return 0;
    }
    rc = api_handle_json_endpoint(cfg, &req, &json, err, err_len);
    if (rc == 1) {
        (void)api_error(fd, 404, "Not Found", "not found", err, err_len);
        free(req.body);
        return 0;
    }
    if (rc != 0) {
        (void)api_error(fd, 500, "Internal Server Error", err, err, err_len);
        free(req.body);
        return -1;
    }
    (void)api_send_response(fd, 200, "OK", json, err, err_len);
    free(json);
    free(req.body);
    return 0;
}

int ntap_a_api_server_run(const ntap_a_config_t *cfg, bool once, int max_requests,
                          char *err, size_t err_len)
{
    ntap_socket_t listen_fd = NTAP_INVALID_SOCKET;
    int handled = 0;
    int rc = 1;

    if (cfg == NULL) {
        return 1;
    }
    if (once) {
        max_requests = 1;
    }
    if (max_requests < 0) {
        max_requests = 0;
    }
    if (ntap_a_db_init(cfg->db_file, err, err_len) != 0 ||
        ntap_net_init(err, err_len) != 0) {
        return 1;
    }
    if (ntap_tcp_listen(cfg->api_addr, 16, &listen_fd, err, err_len) != 0) {
        ntap_net_cleanup();
        return 1;
    }
    api_nonce_cache_reset();
    (void)printf("ntap-a: api listening on %s\n", cfg->api_addr);
    (void)fflush(stdout);

    while (max_requests == 0 || handled < max_requests) {
        ntap_socket_t client_fd = NTAP_INVALID_SOCKET;
        char remote[128];

        remote[0] = '\0';
        if (ntap_tcp_accept(listen_fd, &client_fd, remote, sizeof(remote),
                            err, err_len) != 0) {
            break;
        }
        (void)api_handle_client(client_fd, cfg, err, err_len);
        ntap_socket_close(client_fd);
        handled++;
        rc = 0;
    }
    ntap_socket_close(listen_fd);
    ntap_net_cleanup();
    return rc;
}
