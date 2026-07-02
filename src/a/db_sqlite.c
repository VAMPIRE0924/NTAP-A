#include "a/db_sqlite.h"

#include "common/direct_token.h"
#include "common/hash.h"
#include "common/ntap_time.h"
#include "common/proto.h"

#include <sqlite3.h>
#include <openssl/rand.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct json_buf {
    char *data;
    size_t len;
    size_t cap;
} json_buf_t;

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i = 0;

    for (i = 0; i < len; i++) {
        out[i * 2u] = hex[(bytes[i] >> 4) & 0x0fu];
        out[(i * 2u) + 1u] = hex[bytes[i] & 0x0fu];
    }
    out[len * 2u] = '\0';
}

static int json_reserve(json_buf_t *buf, size_t extra)
{
    char *next = NULL;
    size_t need = 0;
    size_t cap = 0;

    if (buf == NULL || extra > ((size_t)-1) - buf->len - 1u) {
        return -1;
    }
    need = buf->len + extra + 1u;
    if (need <= buf->cap) {
        return 0;
    }
    cap = buf->cap == 0 ? 256u : buf->cap;
    while (cap < need) {
        if (cap > ((size_t)-1) / 2u) {
            cap = need;
            break;
        }
        cap *= 2u;
    }
    next = (char *)realloc(buf->data, cap);
    if (next == NULL) {
        return -1;
    }
    buf->data = next;
    buf->cap = cap;
    return 0;
}

static int json_append_len(json_buf_t *buf, const char *text, size_t len)
{
    if (buf == NULL || (text == NULL && len > 0)) {
        return -1;
    }
    if (json_reserve(buf, len) != 0) {
        return -1;
    }
    if (len > 0) {
        (void)memcpy(buf->data + buf->len, text, len);
        buf->len += len;
    }
    buf->data[buf->len] = '\0';
    return 0;
}

static int json_append(json_buf_t *buf, const char *text)
{
    return json_append_len(buf, text, text == NULL ? 0u : strlen(text));
}

static int json_appendf(json_buf_t *buf, const char *fmt, ...)
{
    va_list ap;
    va_list ap_copy;
    int needed = 0;

    if (buf == NULL || fmt == NULL) {
        return -1;
    }
    va_start(ap, fmt);
    va_copy(ap_copy, ap);
    needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0) {
        va_end(ap_copy);
        return -1;
    }
    if (json_reserve(buf, (size_t)needed) != 0) {
        va_end(ap_copy);
        return -1;
    }
    (void)vsnprintf(buf->data + buf->len, buf->cap - buf->len, fmt, ap_copy);
    va_end(ap_copy);
    buf->len += (size_t)needed;
    return 0;
}

static int json_append_string(json_buf_t *buf, const unsigned char *text)
{
    const unsigned char *p = text == NULL ? (const unsigned char *)"" : text;

    if (json_append(buf, "\"") != 0) {
        return -1;
    }
    while (*p != '\0') {
        unsigned char ch = *p++;

        switch (ch) {
        case '"':
            if (json_append(buf, "\\\"") != 0) {
                return -1;
            }
            break;
        case '\\':
            if (json_append(buf, "\\\\") != 0) {
                return -1;
            }
            break;
        case '\b':
            if (json_append(buf, "\\b") != 0) {
                return -1;
            }
            break;
        case '\f':
            if (json_append(buf, "\\f") != 0) {
                return -1;
            }
            break;
        case '\n':
            if (json_append(buf, "\\n") != 0) {
                return -1;
            }
            break;
        case '\r':
            if (json_append(buf, "\\r") != 0) {
                return -1;
            }
            break;
        case '\t':
            if (json_append(buf, "\\t") != 0) {
                return -1;
            }
            break;
        default:
            if (ch < 0x20u) {
                if (json_appendf(buf, "\\u%04x", (unsigned int)ch) != 0) {
                    return -1;
                }
            } else {
                char raw = (char)ch;

                if (json_append_len(buf, &raw, 1u) != 0) {
                    return -1;
                }
            }
            break;
        }
    }
    return json_append(buf, "\"");
}

static int json_finish_rows(json_buf_t *buf, int total, char **out_json)
{
    if (json_appendf(buf, "],\"total\":%d}", total) != 0) {
        return -1;
    }
    *out_json = buf->data;
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
    return 0;
}

static void db_set_err(char *err, size_t err_len, const char *prefix, sqlite3 *db)
{
    if (err == NULL || err_len == 0) {
        return;
    }
    (void)snprintf(err, err_len, "%s: %s", prefix,
                   db != NULL ? sqlite3_errmsg(db) : "unknown sqlite error");
}

static int db_open(const char *db_file, sqlite3 **out, char *err, size_t err_len)
{
    sqlite3 *db = NULL;

    if (db_file == NULL || *db_file == '\0' || out == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing db_file");
        }
        return -1;
    }
    if (sqlite3_open(db_file, &db) != SQLITE_OK) {
        db_set_err(err, err_len, "open database failed", db);
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_exec(db,
                     "PRAGMA foreign_keys = ON;"
                     "PRAGMA busy_timeout = 3000;",
                     NULL, NULL, NULL) != SQLITE_OK) {
        db_set_err(err, err_len, "set sqlite pragma failed", db);
        sqlite3_close(db);
        return -1;
    }
    *out = db;
    return 0;
}

static int exec_sql(sqlite3 *db, const char *sql, char *err, size_t err_len)
{
    if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
        db_set_err(err, err_len, "sqlite exec failed", db);
        return -1;
    }
    return 0;
}

static int db_table_has_id(sqlite3 *db, const char *table, int64_t id,
                           char *err, size_t err_len)
{
    sqlite3_stmt *stmt = NULL;
    char sql[128];
    int rc = 0;
    int found = 0;

    if (db == NULL || table == NULL || id <= 0) {
        return 0;
    }
    (void)snprintf(sql, sizeof(sql), "SELECT 1 FROM %s WHERE id = ?;", table);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare id existence check failed", db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        found = 1;
    } else if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "id existence check failed", db);
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return found;
}

static int make_password_hash(const char *password, char *salt_hex,
                              size_t salt_hex_len, char *password_hash,
                              size_t password_hash_len,
                              char *err, size_t err_len)
{
    uint8_t salt[16];

    if (password == NULL || *password == '\0' ||
        salt_hex == NULL || salt_hex_len < (sizeof(salt) * 2u) + 1u ||
        password_hash == NULL || password_hash_len < NTAP_SHA256_HEX_SIZE) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing password hash fields");
        }
        return -1;
    }
    if (RAND_bytes(salt, (int)sizeof(salt)) != 1) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "failed to generate password salt");
        }
        return -1;
    }
    bytes_to_hex(salt, sizeof(salt), salt_hex);
    if (ntap_pbkdf2_sha256_hex(password, (const uint8_t *)salt_hex,
                               strlen(salt_hex), NTAP_PBKDF2_MIN_ITERATIONS,
                               password_hash) != 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "failed to hash password");
        }
        return -1;
    }
    return 0;
}

static int column_exists(sqlite3 *db, const char *table, const char *column,
                         char *err, size_t err_len)
{
    sqlite3_stmt *stmt = NULL;
    char sql[128];
    int rc = 0;
    int found = 0;

    (void)snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare table_info failed", db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);

        if (name != NULL && strcmp((const char *)name, column) == 0) {
            found = 1;
            break;
        }
    }
    if (rc != SQLITE_DONE && !found) {
        db_set_err(err, err_len, "read table_info failed", db);
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return found;
}

static int add_column_if_missing(sqlite3 *db, const char *table, const char *column,
                                 const char *definition, char *err, size_t err_len)
{
    char sql[256];
    int exists = column_exists(db, table, column, err, err_len);

    if (exists < 0) {
        return -1;
    }
    if (exists) {
        return 0;
    }
    (void)snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s;",
                   table, column, definition);
    return exec_sql(db, sql, err, err_len);
}

int ntap_a_db_init(const char *db_file, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    const char *schema[] = {
        "PRAGMA foreign_keys = ON;",
        "PRAGMA journal_mode = WAL;",
        "PRAGMA busy_timeout = 3000;",
        "CREATE TABLE IF NOT EXISTS networks ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT UNIQUE NOT NULL,"
        " mtu INTEGER NOT NULL DEFAULT 1400,"
        " mac_ttl_sec INTEGER NOT NULL DEFAULT 300,"
        " broadcast_limit_pps INTEGER NOT NULL DEFAULT 200,"
        " session_broadcast_limit_pps INTEGER NOT NULL DEFAULT 50,"
        " max_mac_per_session INTEGER NOT NULL DEFAULT 32,"
        " tap_queue_limit_bytes INTEGER NOT NULL DEFAULT 262144,"
        " allow_client_to_client INTEGER NOT NULL DEFAULT 0,"
        " allow_vlan INTEGER NOT NULL DEFAULT 0,"
        " allow_l2_control INTEGER NOT NULL DEFAULT 0,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL"
        ");",
        "CREATE TABLE IF NOT EXISTS nodes ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " node_id TEXT UNIQUE NOT NULL,"
        " name TEXT NOT NULL,"
        " node_key_secret TEXT NOT NULL,"
        " node_key_hash TEXT NOT NULL,"
        " node_key_salt TEXT NOT NULL DEFAULT '',"
        " node_key_algo TEXT NOT NULL DEFAULT 'hmac-sha256',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " network_id INTEGER NOT NULL,"
        " tap_enabled INTEGER NOT NULL DEFAULT 1,"
        " socks_enabled INTEGER NOT NULL DEFAULT 0,"
        " direct_enabled INTEGER NOT NULL DEFAULT 0,"
        " direct_reachable INTEGER NOT NULL DEFAULT 0,"
        " tap_name TEXT NOT NULL DEFAULT 'ntap-b0',"
        " bridge_name TEXT NOT NULL DEFAULT 'br-lan',"
        " mtu INTEGER NOT NULL DEFAULT 1400,"
        " direct_port INTEGER NOT NULL DEFAULT 0,"
        " max_tap_sessions INTEGER NOT NULL DEFAULT 8,"
        " max_socks_streams INTEGER NOT NULL DEFAULT 64,"
        " socks_idle_timeout_sec INTEGER NOT NULL DEFAULT 1800,"
        " online INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL,"
        " FOREIGN KEY(network_id) REFERENCES networks(id) ON DELETE RESTRICT"
        ");",
        "CREATE TABLE IF NOT EXISTS tap_users ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " username TEXT UNIQUE NOT NULL,"
        " password_hash TEXT NOT NULL,"
        " password_salt TEXT NOT NULL,"
        " password_algo TEXT NOT NULL DEFAULT 'pbkdf2-sha256',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " expire_at INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL"
        ");",
        "CREATE TABLE IF NOT EXISTS tap_grants ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " tap_user_id INTEGER NOT NULL,"
        " network_id INTEGER NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL,"
        " UNIQUE(tap_user_id, network_id),"
        " FOREIGN KEY(tap_user_id) REFERENCES tap_users(id) ON DELETE CASCADE,"
        " FOREIGN KEY(network_id) REFERENCES networks(id) ON DELETE CASCADE"
        ");",
        "CREATE TABLE IF NOT EXISTS socks_users ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " username TEXT UNIQUE NOT NULL,"
        " password_hash TEXT NOT NULL,"
        " password_salt TEXT NOT NULL,"
        " password_algo TEXT NOT NULL DEFAULT 'pbkdf2-sha256',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " expire_at INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL"
        ");",
        "CREATE TABLE IF NOT EXISTS socks_grants ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " socks_user_id INTEGER NOT NULL,"
        " node_pk INTEGER NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL,"
        " UNIQUE(socks_user_id, node_pk),"
        " FOREIGN KEY(socks_user_id) REFERENCES socks_users(id) ON DELETE CASCADE,"
        " FOREIGN KEY(node_pk) REFERENCES nodes(id) ON DELETE CASCADE"
        ");",
        "CREATE TABLE IF NOT EXISTS sessions ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " session_type TEXT NOT NULL,"
        " user_id INTEGER NOT NULL DEFAULT 0,"
        " node_pk INTEGER NOT NULL DEFAULT 0,"
        " network_id INTEGER NOT NULL DEFAULT 0,"
        " remote_addr TEXT NOT NULL DEFAULT '',"
        " started_at INTEGER NOT NULL,"
        " last_active INTEGER NOT NULL DEFAULT 0,"
        " ended_at INTEGER NOT NULL DEFAULT 0,"
        " ended_reason TEXT NOT NULL DEFAULT '',"
        " in_bytes INTEGER NOT NULL DEFAULT 0,"
        " out_bytes INTEGER NOT NULL DEFAULT 0,"
        " auth_type TEXT NOT NULL DEFAULT ''"
        ");",
        "CREATE TABLE IF NOT EXISTS socks_streams ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " stream_id INTEGER NOT NULL,"
        " session_id INTEGER NOT NULL,"
        " node_pk INTEGER NOT NULL,"
        " socks_user_id INTEGER NOT NULL,"
        " target_host TEXT NOT NULL,"
        " target_port INTEGER NOT NULL,"
        " state TEXT NOT NULL,"
        " started_at INTEGER NOT NULL,"
        " last_active INTEGER NOT NULL,"
        " ended_at INTEGER NOT NULL DEFAULT 0,"
        " ended_reason TEXT NOT NULL DEFAULT '',"
        " in_bytes INTEGER NOT NULL DEFAULT 0,"
        " out_bytes INTEGER NOT NULL DEFAULT 0,"
        " UNIQUE(session_id, stream_id),"
        " FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,"
        " FOREIGN KEY(node_pk) REFERENCES nodes(id) ON DELETE CASCADE,"
        " FOREIGN KEY(socks_user_id) REFERENCES socks_users(id) ON DELETE CASCADE"
        ");",
        "CREATE INDEX IF NOT EXISTS idx_nodes_network_id ON nodes(network_id);",
        "CREATE INDEX IF NOT EXISTS idx_tap_grants_user ON tap_grants(tap_user_id);",
        "CREATE INDEX IF NOT EXISTS idx_tap_grants_network ON tap_grants(network_id);",
        "CREATE INDEX IF NOT EXISTS idx_socks_grants_user ON socks_grants(socks_user_id);",
        "CREATE INDEX IF NOT EXISTS idx_socks_grants_node ON socks_grants(node_pk);",
        "CREATE INDEX IF NOT EXISTS idx_sessions_node_time ON sessions(node_pk, started_at);",
        "CREATE INDEX IF NOT EXISTS idx_sessions_user_time ON sessions(user_id, started_at);",
        "CREATE INDEX IF NOT EXISTS idx_socks_streams_session ON socks_streams(session_id);"
    };
    size_t i = 0;

    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    for (i = 0; i < sizeof(schema) / sizeof(schema[0]); i++) {
        if (exec_sql(db, schema[i], err, err_len) != 0) {
            sqlite3_close(db);
            return -1;
        }
    }
    if (add_column_if_missing(db, "networks", "mac_ttl_sec",
                              "INTEGER NOT NULL DEFAULT 300", err, err_len) != 0 ||
        add_column_if_missing(db, "networks", "broadcast_limit_pps",
                              "INTEGER NOT NULL DEFAULT 200", err, err_len) != 0 ||
        add_column_if_missing(db, "networks", "session_broadcast_limit_pps",
                              "INTEGER NOT NULL DEFAULT 50", err, err_len) != 0 ||
        add_column_if_missing(db, "networks", "max_mac_per_session",
                              "INTEGER NOT NULL DEFAULT 32", err, err_len) != 0 ||
        add_column_if_missing(db, "networks", "tap_queue_limit_bytes",
                              "INTEGER NOT NULL DEFAULT 262144", err, err_len) != 0 ||
        add_column_if_missing(db, "networks", "allow_client_to_client",
                              "INTEGER NOT NULL DEFAULT 0", err, err_len) != 0 ||
        add_column_if_missing(db, "networks", "allow_l2_control",
                              "INTEGER NOT NULL DEFAULT 0", err, err_len) != 0 ||
        add_column_if_missing(db, "nodes", "direct_port",
                              "INTEGER NOT NULL DEFAULT 0", err, err_len) != 0 ||
        add_column_if_missing(db, "nodes", "max_socks_streams",
                              "INTEGER NOT NULL DEFAULT 64", err, err_len) != 0 ||
        add_column_if_missing(db, "nodes", "socks_idle_timeout_sec",
                              "INTEGER NOT NULL DEFAULT 1800", err, err_len) != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_add_network(const char *db_file, const char *name,
                          const ntap_a_network_options_t *opts,
                          char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    ntap_a_network_options_t defaults;
    const ntap_a_network_options_t *effective = opts;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (name == NULL || *name == '\0') {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing network name");
        }
        return -1;
    }
    if (effective == NULL) {
        defaults.mtu = NTAP_DEFAULT_MTU;
        defaults.mac_ttl_sec = NTAP_A_DEFAULT_MAC_TTL_SEC;
        defaults.broadcast_limit_pps = NTAP_A_DEFAULT_BROADCAST_LIMIT_PPS;
        defaults.session_broadcast_limit_pps = NTAP_A_DEFAULT_SESSION_BROADCAST_LIMIT_PPS;
        defaults.max_mac_per_session = NTAP_A_DEFAULT_MAX_MAC_PER_SESSION;
        defaults.tap_queue_limit_bytes = NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES;
        defaults.allow_client_to_client = 0;
        defaults.allow_l2_control = 0;
        effective = &defaults;
    }
    if (effective->mtu < NTAP_MIN_MTU || effective->mtu > NTAP_MAX_MTU) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "mtu must be between %u and %u",
                           NTAP_MIN_MTU, NTAP_MAX_MTU);
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO networks("
                            "name, mtu, mac_ttl_sec, broadcast_limit_pps,"
                            "session_broadcast_limit_pps, max_mac_per_session,"
                            "tap_queue_limit_bytes, allow_client_to_client,"
                            "allow_l2_control,"
                            "created_at, updated_at)"
                            " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare network insert failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int(stmt, 2, effective->mtu);
    (void)sqlite3_bind_int(stmt, 3, (int)effective->mac_ttl_sec);
    (void)sqlite3_bind_int(stmt, 4, (int)effective->broadcast_limit_pps);
    (void)sqlite3_bind_int(stmt, 5, (int)effective->session_broadcast_limit_pps);
    (void)sqlite3_bind_int(stmt, 6, (int)effective->max_mac_per_session);
    (void)sqlite3_bind_int(stmt, 7, (int)effective->tap_queue_limit_bytes);
    (void)sqlite3_bind_int(stmt, 8, effective->allow_client_to_client ? 1 : 0);
    (void)sqlite3_bind_int(stmt, 9, effective->allow_l2_control ? 1 : 0);
    (void)sqlite3_bind_int64(stmt, 10, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 11, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "insert network failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_add_node(const char *db_file, const char *name, const char *node_id,
                       const char *node_key, int64_t network_id,
                       const char *tap_name, const char *bridge_name, uint16_t mtu,
                       uint16_t direct_port,
                       uint32_t max_socks_streams,
                       uint32_t socks_idle_timeout_sec,
                       char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char key_hash[NTAP_SHA256_HEX_SIZE];
    const char *stored_tap_name = tap_name == NULL || *tap_name == '\0' ?
                                  "ntap-b0" : tap_name;
    const char *stored_bridge_name = bridge_name == NULL || *bridge_name == '\0' ?
                                     "br-lan" : bridge_name;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (name == NULL || *name == '\0' || node_id == NULL || *node_id == '\0' ||
        node_key == NULL || *node_key == '\0' || network_id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing node name/node-id/node-key/network-id");
        }
        return -1;
    }
    if (mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU) {
        mtu = NTAP_DEFAULT_MTU;
    }
    if (max_socks_streams == 0) {
        max_socks_streams = NTAP_A_DEFAULT_MAX_SOCKS_STREAMS;
    }
    if (socks_idle_timeout_sec == 0) {
        socks_idle_timeout_sec = NTAP_A_DEFAULT_SOCKS_IDLE_TIMEOUT_SEC;
    }
    if (ntap_sha256_hex((const uint8_t *)node_key, strlen(node_key), key_hash) != 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "failed to hash node key");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO nodes("
                            "node_id, name, node_key_secret, node_key_hash, network_id,"
                            "tap_name, bridge_name, mtu, direct_port,"
                            "max_socks_streams, socks_idle_timeout_sec,"
                            "created_at, updated_at)"
                            " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node insert failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, node_id, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 3, node_key, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 4, key_hash, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int64(stmt, 5, (sqlite3_int64)network_id);
    (void)sqlite3_bind_text(stmt, 6, stored_tap_name, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 7, stored_bridge_name, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int(stmt, 8, mtu);
    (void)sqlite3_bind_int(stmt, 9, (int)direct_port);
    (void)sqlite3_bind_int(stmt, 10, (int)max_socks_streams);
    (void)sqlite3_bind_int(stmt, 11, (int)socks_idle_timeout_sec);
    (void)sqlite3_bind_int64(stmt, 12, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 13, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "insert node failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_add_tap_user(const char *db_file, const char *username,
                           const char *password, int64_t network_id,
                           char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char salt_hex[33];
    char password_hash[NTAP_SHA256_HEX_SIZE];
    sqlite3_int64 tap_user_id = 0;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (username == NULL || *username == '\0' ||
        password == NULL || *password == '\0' || network_id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing username/password/network-id");
        }
        return -1;
    }
    if (make_password_hash(password, salt_hex, sizeof(salt_hex),
                           password_hash, sizeof(password_hash),
                           err, err_len) != 0) {
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    if (exec_sql(db, "BEGIN IMMEDIATE;", err, err_len) != 0) {
        sqlite3_close(db);
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO tap_users("
                            "username, password_hash, password_salt, created_at, updated_at)"
                            " VALUES(?, ?, ?, ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare tap user insert failed", db);
        goto fail;
    }
    (void)sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 3, salt_hex, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 5, (sqlite3_int64)now);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "insert tap user failed", db);
        goto fail;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    tap_user_id = sqlite3_last_insert_rowid(db);

    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO tap_grants("
                            "tap_user_id, network_id, created_at, updated_at)"
                            " VALUES(?, ?, ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare tap grant insert failed", db);
        goto fail;
    }
    (void)sqlite3_bind_int64(stmt, 1, tap_user_id);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)network_id);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "insert tap grant failed", db);
        goto fail;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (exec_sql(db, "COMMIT;", err, err_len) != 0) {
        (void)exec_sql(db, "ROLLBACK;", NULL, 0);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_close(db);
    return 0;

fail:
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    (void)exec_sql(db, "ROLLBACK;", NULL, 0);
    sqlite3_close(db);
    return -1;
}

int ntap_a_db_add_socks_user(const char *db_file, const char *username,
                             const char *password, int64_t node_pk,
                             char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char salt_hex[33];
    char password_hash[NTAP_SHA256_HEX_SIZE];
    sqlite3_int64 socks_user_id = 0;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (username == NULL || *username == '\0' ||
        password == NULL || *password == '\0') {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing username/password");
        }
        return -1;
    }
    if (make_password_hash(password, salt_hex, sizeof(salt_hex),
                           password_hash, sizeof(password_hash),
                           err, err_len) != 0) {
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    if (exec_sql(db, "BEGIN IMMEDIATE;", err, err_len) != 0) {
        sqlite3_close(db);
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO socks_users("
                            "username, password_hash, password_salt, created_at, updated_at)"
                            " VALUES(?, ?, ?, ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare socks user insert failed", db);
        goto fail;
    }
    (void)sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 3, salt_hex, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 5, (sqlite3_int64)now);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "insert socks user failed", db);
        goto fail;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    socks_user_id = sqlite3_last_insert_rowid(db);

    if (node_pk > 0) {
        rc = sqlite3_prepare_v2(db,
                                "INSERT INTO socks_grants("
                                "socks_user_id, node_pk, created_at, updated_at)"
                                " VALUES(?, ?, ?, ?);",
                                -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            db_set_err(err, err_len, "prepare socks grant insert failed", db);
            goto fail;
        }
        (void)sqlite3_bind_int64(stmt, 1, socks_user_id);
        (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)node_pk);
        (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
        (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            db_set_err(err, err_len, "insert socks grant failed", db);
            goto fail;
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    if (exec_sql(db, "COMMIT;", err, err_len) != 0) {
        (void)exec_sql(db, "ROLLBACK;", NULL, 0);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_close(db);
    return 0;

fail:
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    (void)exec_sql(db, "ROLLBACK;", NULL, 0);
    sqlite3_close(db);
    return -1;
}

int ntap_a_db_edit_network(const char *db_file, int64_t id, const char *name,
                           const ntap_a_network_options_t *opts,
                           char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (id <= 0 || name == NULL || *name == '\0' || opts == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing network edit fields");
        }
        return -1;
    }
    if (opts->mtu < NTAP_MIN_MTU || opts->mtu > NTAP_MAX_MTU ||
        opts->max_mac_per_session == 0 || opts->tap_queue_limit_bytes == 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid network edit options");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "UPDATE networks SET name = ?, mtu = ?,"
                            " mac_ttl_sec = ?, broadcast_limit_pps = ?,"
                            " session_broadcast_limit_pps = ?,"
                            " max_mac_per_session = ?, tap_queue_limit_bytes = ?,"
                            " allow_client_to_client = ?, allow_l2_control = ?,"
                            " updated_at = ? WHERE id = ?;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare network edit failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int(stmt, 2, opts->mtu);
    (void)sqlite3_bind_int(stmt, 3, (int)opts->mac_ttl_sec);
    (void)sqlite3_bind_int(stmt, 4, (int)opts->broadcast_limit_pps);
    (void)sqlite3_bind_int(stmt, 5, (int)opts->session_broadcast_limit_pps);
    (void)sqlite3_bind_int(stmt, 6, (int)opts->max_mac_per_session);
    (void)sqlite3_bind_int(stmt, 7, (int)opts->tap_queue_limit_bytes);
    (void)sqlite3_bind_int(stmt, 8, opts->allow_client_to_client ? 1 : 0);
    (void)sqlite3_bind_int(stmt, 9, opts->allow_l2_control ? 1 : 0);
    (void)sqlite3_bind_int64(stmt, 10, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 11, (sqlite3_int64)id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "edit network failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_changes(db) == 0) {
        int exists = db_table_has_id(db, "networks", id, err, err_len);

        if (exists <= 0) {
            if (exists == 0) {
                (void)snprintf(err, err_len, "network not found");
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_edit_node(const char *db_file, int64_t id, const char *name,
                        const char *node_id, const char *node_key,
                        int64_t network_id, const char *tap_name,
                        const char *bridge_name, uint16_t mtu,
                        uint16_t direct_port,
                        uint32_t max_socks_streams,
                        uint32_t socks_idle_timeout_sec,
                        char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const char *stored_tap_name = tap_name == NULL || *tap_name == '\0' ?
                                  "ntap-b0" : tap_name;
    const char *stored_bridge_name = bridge_name == NULL || *bridge_name == '\0' ?
                                     "br-lan" : bridge_name;
    const int update_key = node_key != NULL && *node_key != '\0';
    char key_hash[NTAP_SHA256_HEX_SIZE];
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (id <= 0 || name == NULL || *name == '\0' ||
        node_id == NULL || *node_id == '\0' || network_id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing node edit fields");
        }
        return -1;
    }
    if (mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid node mtu");
        }
        return -1;
    }
    if (max_socks_streams == 0 || socks_idle_timeout_sec == 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid node socks limits");
        }
        return -1;
    }
    if (update_key &&
        ntap_sha256_hex((const uint8_t *)node_key, strlen(node_key), key_hash) != 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "failed to hash node key");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(
        db,
        update_key ?
        "UPDATE nodes SET node_id = ?, name = ?, node_key_secret = ?,"
        " node_key_hash = ?, network_id = ?, tap_name = ?, bridge_name = ?,"
        " mtu = ?, direct_port = ?, max_socks_streams = ?,"
        " socks_idle_timeout_sec = ?, updated_at = ? WHERE id = ?;" :
        "UPDATE nodes SET node_id = ?, name = ?, network_id = ?,"
        " tap_name = ?, bridge_name = ?, mtu = ?, direct_port = ?,"
        " max_socks_streams = ?, socks_idle_timeout_sec = ?,"
        " updated_at = ? WHERE id = ?;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node edit failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, node_id, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    if (update_key) {
        (void)sqlite3_bind_text(stmt, 3, node_key, -1, SQLITE_TRANSIENT);
        (void)sqlite3_bind_text(stmt, 4, key_hash, -1, SQLITE_TRANSIENT);
        (void)sqlite3_bind_int64(stmt, 5, (sqlite3_int64)network_id);
        (void)sqlite3_bind_text(stmt, 6, stored_tap_name, -1, SQLITE_TRANSIENT);
        (void)sqlite3_bind_text(stmt, 7, stored_bridge_name, -1, SQLITE_TRANSIENT);
        (void)sqlite3_bind_int(stmt, 8, mtu);
        (void)sqlite3_bind_int(stmt, 9, (int)direct_port);
        (void)sqlite3_bind_int(stmt, 10, (int)max_socks_streams);
        (void)sqlite3_bind_int(stmt, 11, (int)socks_idle_timeout_sec);
        (void)sqlite3_bind_int64(stmt, 12, (sqlite3_int64)now);
        (void)sqlite3_bind_int64(stmt, 13, (sqlite3_int64)id);
    } else {
        (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)network_id);
        (void)sqlite3_bind_text(stmt, 4, stored_tap_name, -1, SQLITE_TRANSIENT);
        (void)sqlite3_bind_text(stmt, 5, stored_bridge_name, -1, SQLITE_TRANSIENT);
        (void)sqlite3_bind_int(stmt, 6, mtu);
        (void)sqlite3_bind_int(stmt, 7, (int)direct_port);
        (void)sqlite3_bind_int(stmt, 8, (int)max_socks_streams);
        (void)sqlite3_bind_int(stmt, 9, (int)socks_idle_timeout_sec);
        (void)sqlite3_bind_int64(stmt, 10, (sqlite3_int64)now);
        (void)sqlite3_bind_int64(stmt, 11, (sqlite3_int64)id);
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "edit node failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_changes(db) == 0) {
        int exists = db_table_has_id(db, "nodes", id, err, err_len);

        if (exists <= 0) {
            if (exists == 0) {
                (void)snprintf(err, err_len, "node not found");
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

static int db_edit_password_user(const char *db_file, const char *table,
                                 int64_t id, const char *username,
                                 const char *password, const char *missing_msg,
                                 char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char salt_hex[33];
    char password_hash[NTAP_SHA256_HEX_SIZE];
    char sql[256];
    const int update_password = password != NULL && *password != '\0';
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (id <= 0 || username == NULL || *username == '\0') {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing user edit fields");
        }
        return -1;
    }
    if (update_password &&
        make_password_hash(password, salt_hex, sizeof(salt_hex),
                           password_hash, sizeof(password_hash),
                           err, err_len) != 0) {
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    (void)snprintf(sql, sizeof(sql),
                   update_password ?
                   "UPDATE %s SET username = ?, password_hash = ?,"
                   " password_salt = ?, updated_at = ? WHERE id = ?;" :
                   "UPDATE %s SET username = ?, updated_at = ? WHERE id = ?;",
                   table);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare user edit failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    if (update_password) {
        (void)sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
        (void)sqlite3_bind_text(stmt, 3, salt_hex, -1, SQLITE_TRANSIENT);
        (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
        (void)sqlite3_bind_int64(stmt, 5, (sqlite3_int64)id);
    } else {
        (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
        (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)id);
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "edit user failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_changes(db) == 0) {
        int exists = db_table_has_id(db, table, id, err, err_len);

        if (exists <= 0) {
            if (exists == 0) {
                (void)snprintf(err, err_len, "%s", missing_msg);
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return -1;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_edit_tap_user(const char *db_file, int64_t id,
                            const char *username, const char *password,
                            char *err, size_t err_len)
{
    return db_edit_password_user(db_file, "tap_users", id, username, password,
                                 "tap user not found", err, err_len);
}

int ntap_a_db_edit_socks_user(const char *db_file, int64_t id,
                              const char *username, const char *password,
                              char *err, size_t err_len)
{
    return db_edit_password_user(db_file, "socks_users", id, username, password,
                                 "socks user not found", err, err_len);
}

static int db_delete_table_id(const char *db_file, const char *table, int64_t id,
                              const char *missing_msg, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char sql[128];
    int rc = 0;

    if (id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid id");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    (void)snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE id = ?;", table);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare delete failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "delete failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_changes(db) == 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "%s", missing_msg);
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_delete_network(const char *db_file, int64_t id,
                             char *err, size_t err_len)
{
    return db_delete_table_id(db_file, "networks", id, "network not found",
                              err, err_len);
}

int ntap_a_db_delete_node(const char *db_file, int64_t id,
                          char *err, size_t err_len)
{
    return db_delete_table_id(db_file, "nodes", id, "node not found",
                              err, err_len);
}

int ntap_a_db_delete_tap_user(const char *db_file, int64_t id,
                              char *err, size_t err_len)
{
    return db_delete_table_id(db_file, "tap_users", id, "tap user not found",
                              err, err_len);
}

int ntap_a_db_delete_socks_user(const char *db_file, int64_t id,
                                char *err, size_t err_len)
{
    return db_delete_table_id(db_file, "socks_users", id,
                              "socks user not found", err, err_len);
}

static int db_grant_pair(const char *db_file, const char *table,
                         const char *user_col, const char *target_col,
                         int64_t user_id, int64_t target_id,
                         char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char sql[256];
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (user_id <= 0 || target_id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid grant ids");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    if (exec_sql(db, "BEGIN IMMEDIATE;", err, err_len) != 0) {
        sqlite3_close(db);
        return -1;
    }
    (void)snprintf(sql, sizeof(sql),
                   "INSERT OR IGNORE INTO %s(%s, %s, created_at, updated_at)"
                   " VALUES(?, ?, ?, ?);",
                   table, user_col, target_col);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare grant insert failed", db);
        goto fail;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user_id);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)target_id);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "insert grant failed", db);
        goto fail;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    (void)snprintf(sql, sizeof(sql),
                   "UPDATE %s SET enabled = 1, updated_at = ?"
                   " WHERE %s = ? AND %s = ?;",
                   table, user_col, target_col);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare grant enable failed", db);
        goto fail;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)user_id);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)target_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "enable grant failed", db);
        goto fail;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (exec_sql(db, "COMMIT;", err, err_len) != 0) {
        (void)exec_sql(db, "ROLLBACK;", NULL, 0);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_close(db);
    return 0;

fail:
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    (void)exec_sql(db, "ROLLBACK;", NULL, 0);
    sqlite3_close(db);
    return -1;
}

static int db_revoke_pair(const char *db_file, const char *table,
                          const char *user_col, const char *target_col,
                          int64_t user_id, int64_t target_id,
                          char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char sql[256];
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (user_id <= 0 || target_id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid revoke ids");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    (void)snprintf(sql, sizeof(sql),
                   "UPDATE %s SET enabled = 0, updated_at = ?"
                   " WHERE %s = ? AND %s = ?;",
                   table, user_col, target_col);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare revoke failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)user_id);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)target_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "revoke grant failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_changes(db) == 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "grant not found");
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_grant_tap_user(const char *db_file, int64_t tap_user_id,
                             int64_t network_id, char *err, size_t err_len)
{
    return db_grant_pair(db_file, "tap_grants", "tap_user_id", "network_id",
                         tap_user_id, network_id, err, err_len);
}

int ntap_a_db_revoke_tap_user(const char *db_file, int64_t tap_user_id,
                              int64_t network_id, char *err, size_t err_len)
{
    return db_revoke_pair(db_file, "tap_grants", "tap_user_id", "network_id",
                          tap_user_id, network_id, err, err_len);
}

int ntap_a_db_grant_socks_user(const char *db_file, int64_t socks_user_id,
                               int64_t node_pk, char *err, size_t err_len)
{
    return db_grant_pair(db_file, "socks_grants", "socks_user_id", "node_pk",
                         socks_user_id, node_pk, err, err_len);
}

int ntap_a_db_revoke_socks_user(const char *db_file, int64_t socks_user_id,
                                int64_t node_pk, char *err, size_t err_len)
{
    return db_revoke_pair(db_file, "socks_grants", "socks_user_id", "node_pk",
                          socks_user_id, node_pk, err, err_len);
}

int ntap_a_db_get_node_auth(const char *db_file, const char *node_id,
                            ntap_a_node_auth_t *out, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = 0;

    if (node_id == NULL || *node_id == '\0' || out == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing node_id");
        }
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT id, network_id, enabled, node_key_secret"
                            " FROM nodes WHERE node_id = ?;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node lookup failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, node_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "node not found");
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    out->node_pk = sqlite3_column_int64(stmt, 0);
    out->network_id = sqlite3_column_int64(stmt, 1);
    out->enabled = sqlite3_column_int(stmt, 2);
    (void)snprintf(out->node_key_secret, sizeof(out->node_key_secret), "%s",
                   (const char *)sqlite3_column_text(stmt, 3));
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_get_tap_auth(const char *db_file, const char *username,
                           const char *password, int64_t requested_network_id,
                           ntap_a_tap_auth_t *out, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char stored_hash[NTAP_SHA256_HEX_SIZE];
    char salt[NTAP_CONFIG_VALUE_MAX];
    char expected_hash[NTAP_SHA256_HEX_SIZE];
    int user_enabled = 0;
    int grant_enabled = 0;
    int64_t expire_at = 0;
    int rc = 0;

    if (username == NULL || *username == '\0' || password == NULL || out == NULL ||
        requested_network_id < 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing tap auth fields");
        }
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT u.id, u.username, u.password_hash, u.password_salt,"
                            " u.enabled, u.expire_at, g.network_id, g.enabled"
                            " FROM tap_users u"
                            " JOIN tap_grants g ON g.tap_user_id = u.id"
                            " JOIN networks n ON n.id = g.network_id"
                            " WHERE u.username = ? AND (? = 0 OR g.network_id = ?)"
                            " AND n.enabled = 1"
                            " ORDER BY g.network_id LIMIT 1;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare tap auth lookup failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)requested_network_id);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)requested_network_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "tap user or grant not found");
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    out->tap_user_id = sqlite3_column_int64(stmt, 0);
    (void)snprintf(out->username, sizeof(out->username), "%s",
                   (const char *)sqlite3_column_text(stmt, 1));
    (void)snprintf(stored_hash, sizeof(stored_hash), "%s",
                   (const char *)sqlite3_column_text(stmt, 2));
    (void)snprintf(salt, sizeof(salt), "%s",
                   (const char *)sqlite3_column_text(stmt, 3));
    user_enabled = sqlite3_column_int(stmt, 4);
    expire_at = sqlite3_column_int64(stmt, 5);
    out->network_id = sqlite3_column_int64(stmt, 6);
    grant_enabled = sqlite3_column_int(stmt, 7);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (!user_enabled || !grant_enabled ||
        (expire_at > 0 && expire_at < (int64_t)ntap_time_unix_sec())) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "tap user disabled or expired");
        }
        return -1;
    }
    if (ntap_pbkdf2_sha256_hex(password, (const uint8_t *)salt, strlen(salt),
                               NTAP_PBKDF2_MIN_ITERATIONS, expected_hash) != 0 ||
        strlen(stored_hash) != strlen(expected_hash) ||
        !ntap_constant_time_equal((const uint8_t *)stored_hash,
                                  (const uint8_t *)expected_hash,
                                  strlen(expected_hash))) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "tap auth failed");
        }
        return -1;
    }
    out->enabled = 1;
    return 0;
}

int ntap_a_db_get_socks_auth(const char *db_file, const char *username,
                             const char *password, ntap_a_socks_auth_t *out,
                             char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char stored_hash[NTAP_SHA256_HEX_SIZE];
    char salt[NTAP_CONFIG_VALUE_MAX];
    char expected_hash[NTAP_SHA256_HEX_SIZE];
    int user_enabled = 0;
    int grant_enabled = 0;
    int node_enabled = 0;
    int socks_enabled = 0;
    int64_t expire_at = 0;
    int rc = 0;

    if (username == NULL || *username == '\0' || password == NULL || out == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing socks auth fields");
        }
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT u.id, u.username, u.password_hash, u.password_salt,"
                            " u.enabled, u.expire_at, g.node_pk, g.enabled,"
                            " n.node_id, n.network_id, n.enabled, n.socks_enabled,"
                            " n.max_socks_streams, n.socks_idle_timeout_sec"
                            " FROM socks_users u"
                            " JOIN socks_grants g ON g.socks_user_id = u.id"
                            " JOIN nodes n ON n.id = g.node_pk"
                            " WHERE u.username = ? AND n.online = 1"
                            " ORDER BY n.last_seen DESC LIMIT 1;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare socks auth lookup failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "socks user or online grant not found");
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    out->socks_user_id = sqlite3_column_int64(stmt, 0);
    (void)snprintf(out->username, sizeof(out->username), "%s",
                   (const char *)sqlite3_column_text(stmt, 1));
    (void)snprintf(stored_hash, sizeof(stored_hash), "%s",
                   (const char *)sqlite3_column_text(stmt, 2));
    (void)snprintf(salt, sizeof(salt), "%s",
                   (const char *)sqlite3_column_text(stmt, 3));
    user_enabled = sqlite3_column_int(stmt, 4);
    expire_at = sqlite3_column_int64(stmt, 5);
    out->node_pk = sqlite3_column_int64(stmt, 6);
    grant_enabled = sqlite3_column_int(stmt, 7);
    (void)snprintf(out->node_id, sizeof(out->node_id), "%s",
                   (const char *)sqlite3_column_text(stmt, 8));
    out->network_id = sqlite3_column_int64(stmt, 9);
    node_enabled = sqlite3_column_int(stmt, 10);
    socks_enabled = sqlite3_column_int(stmt, 11);
    out->max_socks_streams = sqlite3_column_int(stmt, 12) <= 0 ?
        NTAP_A_DEFAULT_MAX_SOCKS_STREAMS :
        (uint32_t)sqlite3_column_int(stmt, 12);
    out->socks_idle_timeout_sec = sqlite3_column_int(stmt, 13) <= 0 ?
        NTAP_A_DEFAULT_SOCKS_IDLE_TIMEOUT_SEC :
        (uint32_t)sqlite3_column_int(stmt, 13);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (!user_enabled || !grant_enabled || !node_enabled || !socks_enabled ||
        out->node_pk <= 0 ||
        (expire_at > 0 && expire_at < (int64_t)ntap_time_unix_sec())) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "socks user or node disabled");
        }
        return -1;
    }
    if (ntap_pbkdf2_sha256_hex(password, (const uint8_t *)salt, strlen(salt),
                               NTAP_PBKDF2_MIN_ITERATIONS, expected_hash) != 0 ||
        strlen(stored_hash) != strlen(expected_hash) ||
        !ntap_constant_time_equal((const uint8_t *)stored_hash,
                                  (const uint8_t *)expected_hash,
                                  strlen(expected_hash))) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "socks auth failed");
        }
        return -1;
    }
    out->enabled = 1;
    return 0;
}

static uint16_t runtime_mtu_from_int(int raw)
{
    if (raw < (int)NTAP_MIN_MTU || raw > (int)NTAP_MAX_MTU) {
        return NTAP_DEFAULT_MTU;
    }
    return (uint16_t)raw;
}

static uint32_t runtime_u32_or_default(int raw, uint32_t fallback)
{
    if (raw <= 0) {
        return fallback;
    }
    return (uint32_t)raw;
}

int ntap_a_db_get_node_runtime_config(const char *db_file, const char *node_id,
                                      ntap_a_runtime_config_t *out,
                                      char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int network_enabled = 0;
    int rc = 0;

    if (node_id == NULL || *node_id == '\0' || out == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing node runtime fields");
        }
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT n.network_id, net.mtu, n.tap_enabled,"
                            " n.socks_enabled, n.direct_enabled, n.tap_name,"
                            " n.bridge_name, n.direct_port, net.enabled,"
                            " net.mac_ttl_sec, net.broadcast_limit_pps,"
                            " net.session_broadcast_limit_pps, net.max_mac_per_session,"
                            " net.tap_queue_limit_bytes, net.allow_client_to_client,"
                            " net.allow_l2_control"
                            " FROM nodes n JOIN networks net ON net.id = n.network_id"
                            " WHERE n.node_id = ?;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node runtime lookup failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, node_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "node runtime not found");
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    out->network_id = sqlite3_column_int64(stmt, 0);
    out->mtu = runtime_mtu_from_int(sqlite3_column_int(stmt, 1));
    out->tap_enabled = sqlite3_column_int(stmt, 2);
    out->socks_enabled = sqlite3_column_int(stmt, 3);
    out->direct_enabled = sqlite3_column_int(stmt, 4);
    (void)snprintf(out->tap_name, sizeof(out->tap_name), "%s",
                   (const char *)sqlite3_column_text(stmt, 5));
    (void)snprintf(out->bridge_name, sizeof(out->bridge_name), "%s",
                   (const char *)sqlite3_column_text(stmt, 6));
    out->direct_port = (uint16_t)sqlite3_column_int(stmt, 7);
    network_enabled = sqlite3_column_int(stmt, 8);
    out->mac_ttl_sec = runtime_u32_or_default(sqlite3_column_int(stmt, 9),
                                              NTAP_A_DEFAULT_MAC_TTL_SEC);
    out->broadcast_limit_pps =
        runtime_u32_or_default(sqlite3_column_int(stmt, 10),
                               NTAP_A_DEFAULT_BROADCAST_LIMIT_PPS);
    out->session_broadcast_limit_pps =
        runtime_u32_or_default(sqlite3_column_int(stmt, 11),
                               NTAP_A_DEFAULT_SESSION_BROADCAST_LIMIT_PPS);
    out->max_mac_per_session =
        runtime_u32_or_default(sqlite3_column_int(stmt, 12),
                               NTAP_A_DEFAULT_MAX_MAC_PER_SESSION);
    out->tap_queue_limit_bytes =
        runtime_u32_or_default(sqlite3_column_int(stmt, 13),
                               NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES);
    out->allow_client_to_client = sqlite3_column_int(stmt, 14);
    out->allow_l2_control = sqlite3_column_int(stmt, 15);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (out->network_id <= 0 || !network_enabled) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "network disabled or invalid");
        }
        return -1;
    }
    return 0;
}

int ntap_a_db_get_tap_runtime_config(const char *db_file, int64_t network_id,
                                     ntap_a_runtime_config_t *out,
                                     char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int network_enabled = 0;
    int rc = 0;

    if (network_id <= 0 || out == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing tap runtime fields");
        }
        return -1;
    }
    (void)memset(out, 0, sizeof(*out));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT id, mtu, enabled, mac_ttl_sec,"
                            " broadcast_limit_pps, session_broadcast_limit_pps,"
                            " max_mac_per_session, allow_client_to_client,"
                            " allow_l2_control, tap_queue_limit_bytes"
                            " FROM networks WHERE id = ?;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare tap runtime lookup failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)network_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "tap runtime network not found");
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    out->network_id = sqlite3_column_int64(stmt, 0);
    out->mtu = runtime_mtu_from_int(sqlite3_column_int(stmt, 1));
    network_enabled = sqlite3_column_int(stmt, 2);
    out->mac_ttl_sec = runtime_u32_or_default(sqlite3_column_int(stmt, 3),
                                              NTAP_A_DEFAULT_MAC_TTL_SEC);
    out->broadcast_limit_pps =
        runtime_u32_or_default(sqlite3_column_int(stmt, 4),
                               NTAP_A_DEFAULT_BROADCAST_LIMIT_PPS);
    out->session_broadcast_limit_pps =
        runtime_u32_or_default(sqlite3_column_int(stmt, 5),
                               NTAP_A_DEFAULT_SESSION_BROADCAST_LIMIT_PPS);
    out->max_mac_per_session =
        runtime_u32_or_default(sqlite3_column_int(stmt, 6),
                               NTAP_A_DEFAULT_MAX_MAC_PER_SESSION);
    out->allow_client_to_client = sqlite3_column_int(stmt, 7);
    out->allow_l2_control = sqlite3_column_int(stmt, 8);
    out->tap_queue_limit_bytes =
        runtime_u32_or_default(sqlite3_column_int(stmt, 9),
                               NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (!network_enabled) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "network disabled");
        }
        return -1;
    }
    out->tap_enabled = 1;
    out->socks_enabled = 0;
    out->direct_enabled = 0;
    out->tap_name[0] = '\0';
    out->bridge_name[0] = '\0';
    out->direct_port = 0;
    return 0;
}

static int db_update_enabled_by_id(const char *db_file, const char *sql,
                                   int64_t id, int enabled,
                                   const char *prepare_prefix,
                                   const char *step_prefix,
                                   const char *missing_msg,
                                   char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid id");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, prepare_prefix, db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int(stmt, 1, enabled ? 1 : 0);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, step_prefix, db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_changes(db) == 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "%s", missing_msg);
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_set_node_online(const char *db_file, const char *node_id, int online,
                              char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (node_id == NULL || *node_id == '\0') {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing node_id");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "UPDATE nodes SET online = ?, last_seen = ?, updated_at = ?"
                            " WHERE node_id = ?;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node online update failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int(stmt, 1, online ? 1 : 0);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    (void)sqlite3_bind_text(stmt, 4, node_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "update node online failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_set_network_enabled(const char *db_file, int64_t id, int enabled,
                                  char *err, size_t err_len)
{
    return db_update_enabled_by_id(
        db_file,
        "UPDATE networks SET enabled = ?, updated_at = ? WHERE id = ?;",
        id, enabled, "prepare network enabled update failed",
        "update network enabled failed", "network not found", err, err_len);
}

int ntap_a_db_set_node_enabled(const char *db_file, int64_t id, int enabled,
                               char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid id");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "UPDATE nodes SET enabled = ?, updated_at = ?,"
                            " online = CASE WHEN ? = 0 THEN 0 ELSE online END"
                            " WHERE id = ?;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node enabled update failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int(stmt, 1, enabled ? 1 : 0);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    (void)sqlite3_bind_int(stmt, 3, enabled ? 1 : 0);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "update node enabled failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_changes(db) == 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "node not found");
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_set_tap_user_enabled(const char *db_file, int64_t id, int enabled,
                                   char *err, size_t err_len)
{
    return db_update_enabled_by_id(
        db_file,
        "UPDATE tap_users SET enabled = ?, updated_at = ? WHERE id = ?;",
        id, enabled, "prepare tap user enabled update failed",
        "update tap user enabled failed", "tap user not found", err, err_len);
}

int ntap_a_db_set_socks_user_enabled(const char *db_file, int64_t id, int enabled,
                                     char *err, size_t err_len)
{
    return db_update_enabled_by_id(
        db_file,
        "UPDATE socks_users SET enabled = ?, updated_at = ? WHERE id = ?;",
        id, enabled, "prepare socks user enabled update failed",
        "update socks user enabled failed", "socks user not found", err, err_len);
}

int ntap_a_db_set_node_service_enabled(const char *db_file, int64_t id,
                                       const char *service_type, int enabled,
                                       char *err, size_t err_len)
{
    const char *sql = NULL;

    if (service_type == NULL || *service_type == '\0') {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing service type");
        }
        return -1;
    }
    if (strcmp(service_type, "tap") == 0) {
        sql = "UPDATE nodes SET tap_enabled = ?, updated_at = ? WHERE id = ?;";
    } else if (strcmp(service_type, "socks") == 0) {
        sql = "UPDATE nodes SET socks_enabled = ?, updated_at = ? WHERE id = ?;";
    } else if (strcmp(service_type, "direct") == 0) {
        sql = "UPDATE nodes SET direct_enabled = ?, updated_at = ? WHERE id = ?;";
    } else {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid service type");
        }
        return -1;
    }
    return db_update_enabled_by_id(
        db_file, sql, id, enabled, "prepare node service update failed",
        "update node service failed", "node not found", err, err_len);
}

int ntap_a_db_issue_direct_token(const char *db_file, int64_t node_pk,
                                 int64_t tap_user_id, uint32_t ttl_sec,
                                 char **out_json, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    char token[NTAP_DIRECT_TOKEN_MAX];
    char nonce[NTAP_DIRECT_TOKEN_NONCE_HEX_SIZE];
    const unsigned char *node_id_text = NULL;
    const unsigned char *node_key_text = NULL;
    int64_t network_id = 0;
    int direct_enabled = 0;
    int direct_port = 0;
    int node_enabled = 0;
    int network_enabled = 0;
    int tap_user_enabled = 0;
    int grant_enabled = 0;
    uint64_t now = ntap_time_unix_sec();
    uint64_t expire_at = 0;
    int rc = 0;

    if (out_json == NULL) {
        return -1;
    }
    *out_json = NULL;
    if (node_pk <= 0 || tap_user_id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid direct token ids");
        }
        return -1;
    }
    if (ttl_sec == 0) {
        ttl_sec = 60u;
    }
    if (ttl_sec > 600u) {
        ttl_sec = 600u;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(
        db,
        "SELECT n.node_id, n.node_key_secret, n.network_id,"
        " n.direct_enabled, n.direct_port, n.enabled, net.enabled,"
        " u.enabled, g.enabled"
        " FROM nodes n"
        " JOIN networks net ON net.id = n.network_id"
        " JOIN tap_users u ON u.id = ?"
        " JOIN tap_grants g ON g.tap_user_id = u.id"
        "  AND g.network_id = n.network_id"
        " WHERE n.id = ?;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare direct token lookup failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)tap_user_id);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)node_pk);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (rc == SQLITE_DONE) {
            (void)snprintf(err, err_len, "node/tap grant not found");
        } else {
            db_set_err(err, err_len, "read direct token lookup failed", db);
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    node_id_text = sqlite3_column_text(stmt, 0);
    node_key_text = sqlite3_column_text(stmt, 1);
    network_id = sqlite3_column_int64(stmt, 2);
    direct_enabled = sqlite3_column_int(stmt, 3);
    direct_port = sqlite3_column_int(stmt, 4);
    node_enabled = sqlite3_column_int(stmt, 5);
    network_enabled = sqlite3_column_int(stmt, 6);
    tap_user_enabled = sqlite3_column_int(stmt, 7);
    grant_enabled = sqlite3_column_int(stmt, 8);
    if (node_id_text == NULL || node_key_text == NULL || network_id <= 0 ||
        !direct_enabled || direct_port <= 0 || !node_enabled ||
        !network_enabled || !tap_user_enabled || !grant_enabled) {
        (void)snprintf(err, err_len, "direct token not allowed");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    expire_at = now + ttl_sec;
    if (ntap_direct_token_random_nonce(nonce) != 0 ||
        ntap_direct_token_make(token, sizeof(token),
                               (const char *)node_key_text,
                               tap_user_id, (const char *)node_id_text,
                               network_id, expire_at, nonce) != 0) {
        (void)snprintf(err, err_len, "failed to issue direct token");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    (void)memset(&json, 0, sizeof(json));
    if (json_appendf(&json,
                     "{\"code\":1,\"data\":{\"token\":") != 0 ||
        json_append_string(&json, (const unsigned char *)token) != 0 ||
        json_appendf(&json,
                     ",\"expire_at\":%lld,\"ttl_sec\":%u,"
                     "\"node_id\":",
                     (long long)expire_at, ttl_sec) != 0 ||
        json_append_string(&json, node_id_text) != 0 ||
        json_appendf(&json,
                     ",\"network_id\":%lld,\"tap_user_id\":%lld,"
                     "\"direct_port\":%d}}",
                     (long long)network_id, (long long)tap_user_id,
                     direct_port) != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    *out_json = json.data;
    return 0;
}

int ntap_a_db_session_start(const char *db_file,
                            const ntap_a_session_start_t *session,
                            int64_t *out_session_id, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (session == NULL || session->session_type == NULL ||
        *session->session_type == '\0' || session->network_id <= 0 ||
        out_session_id == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing session start fields");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO sessions("
                            "session_type, user_id, node_pk, network_id,"
                            "remote_addr, started_at, last_active, auth_type)"
                            " VALUES(?, ?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare session insert failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_text(stmt, 1, session->session_type, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)session->user_id);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)session->node_pk);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)session->network_id);
    (void)sqlite3_bind_text(stmt, 5,
                            session->remote_addr == NULL ? "" : session->remote_addr,
                            -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 7, (sqlite3_int64)now);
    (void)sqlite3_bind_text(stmt, 8,
                            session->auth_type == NULL ? "" : session->auth_type,
                            -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "insert session failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    *out_session_id = (int64_t)sqlite3_last_insert_rowid(db);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_session_touch(const char *db_file, int64_t session_id,
                            uint64_t in_bytes, uint64_t out_bytes,
                            char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (session_id <= 0) {
        return 0;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "UPDATE sessions SET last_active = ?,"
                            " in_bytes = in_bytes + ?, out_bytes = out_bytes + ?"
                            " WHERE id = ? AND ended_at = 0;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare session touch failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)in_bytes);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)out_bytes);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)session_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "touch session failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_session_end(const char *db_file, int64_t session_id,
                          const char *reason, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (session_id <= 0) {
        return 0;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "UPDATE sessions SET last_active = ?, ended_at = ?,"
                            " ended_reason = ? WHERE id = ? AND ended_at = 0;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare session end failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    (void)sqlite3_bind_text(stmt, 3, reason == NULL ? "closed" : reason,
                            -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)session_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "end session failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_socks_stream_start(const char *db_file, uint32_t stream_id,
                                 int64_t session_id, int64_t node_pk,
                                 int64_t socks_user_id, const char *target_host,
                                 uint16_t target_port, int64_t *out_stream_db_id,
                                 char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (stream_id == 0 || session_id <= 0 || node_pk <= 0 ||
        socks_user_id <= 0 || target_host == NULL || *target_host == '\0' ||
        target_port == 0 || out_stream_db_id == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "missing socks stream start fields");
        }
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO socks_streams("
                            "stream_id, session_id, node_pk, socks_user_id,"
                            "target_host, target_port, state, started_at,"
                            "last_active)"
                            " VALUES(?, ?, ?, ?, ?, ?, 'established', ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare socks stream insert failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)stream_id);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)session_id);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)node_pk);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)socks_user_id);
    (void)sqlite3_bind_text(stmt, 5, target_host, -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int(stmt, 6, (int)target_port);
    (void)sqlite3_bind_int64(stmt, 7, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 8, (sqlite3_int64)now);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "insert socks stream failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    *out_stream_db_id = (int64_t)sqlite3_last_insert_rowid(db);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_socks_stream_touch(const char *db_file, int64_t stream_db_id,
                                 uint64_t in_bytes, uint64_t out_bytes,
                                 char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (stream_db_id <= 0) {
        return 0;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "UPDATE socks_streams SET"
                            " last_active = CASE WHEN ended_at = 0 THEN ? ELSE last_active END,"
                            " in_bytes = in_bytes + ?, out_bytes = out_bytes + ?"
                            " WHERE id = ?;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare socks stream touch failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)in_bytes);
    (void)sqlite3_bind_int64(stmt, 3, (sqlite3_int64)out_bytes);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)stream_db_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "touch socks stream failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_socks_stream_end(const char *db_file, int64_t stream_db_id,
                               const char *reason, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    uint64_t now = ntap_time_unix_sec();
    int rc = 0;

    if (stream_db_id <= 0) {
        return 0;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "UPDATE socks_streams SET last_active = ?,"
                            " ended_at = ?, ended_reason = ?, state = 'closed'"
                            " WHERE id = ? AND ended_at = 0;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare socks stream end failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    (void)sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    (void)sqlite3_bind_text(stmt, 3, reason == NULL ? "closed" : reason,
                            -1, SQLITE_TRANSIENT);
    (void)sqlite3_bind_int64(stmt, 4, (sqlite3_int64)stream_db_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "end socks stream failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int ntap_a_db_print_nodes(const char *db_file, FILE *out, char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = 0;

    if (out == NULL) {
        return -1;
    }
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT node_id, name, network_id, enabled, online, last_seen"
                            " FROM nodes ORDER BY id;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node list failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)fprintf(out, "node_id\tname\tnetwork_id\tenabled\tonline\tlast_seen\n");
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        (void)fprintf(out, "%s\t%s\t%lld\t%d\t%d\t%lld\n",
                      (const char *)sqlite3_column_text(stmt, 0),
                      (const char *)sqlite3_column_text(stmt, 1),
                      (long long)sqlite3_column_int64(stmt, 2),
                      sqlite3_column_int(stmt, 3),
                      sqlite3_column_int(stmt, 4),
                      (long long)sqlite3_column_int64(stmt, 5));
    }
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "list nodes failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

static int json_append_network_row(json_buf_t *json, sqlite3_stmt *stmt)
{
    return json_appendf(json, "{\"id\":%lld,\"name\":",
                        (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 1)) != 0 ||
           json_appendf(json,
                        ",\"mtu\":%d,\"enabled\":%d,"
                        "\"mac_ttl_sec\":%d,\"broadcast_limit_pps\":%d,"
                        "\"session_broadcast_limit_pps\":%d,"
                        "\"max_mac_per_session\":%d,"
                        "\"tap_queue_limit_bytes\":%d,"
                        "\"allow_client_to_client\":%d,"
                        "\"allow_l2_control\":%d,"
                        "\"created_at\":%lld,\"updated_at\":%lld}",
                        sqlite3_column_int(stmt, 2),
                        sqlite3_column_int(stmt, 3),
                        sqlite3_column_int(stmt, 4),
                        sqlite3_column_int(stmt, 5),
                        sqlite3_column_int(stmt, 6),
                        sqlite3_column_int(stmt, 7),
                        sqlite3_column_int(stmt, 8),
                        sqlite3_column_int(stmt, 9),
                        sqlite3_column_int(stmt, 10),
                        (long long)sqlite3_column_int64(stmt, 11),
                        (long long)sqlite3_column_int64(stmt, 12)) != 0 ? -1 : 0;
}

static int json_append_node_row(json_buf_t *json, sqlite3_stmt *stmt)
{
    return json_appendf(json, "{\"id\":%lld,\"node_id\":",
                        (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 1)) != 0 ||
           json_append(json, ",\"name\":") != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 2)) != 0 ||
           json_appendf(json,
                        ",\"network_id\":%lld,\"enabled\":%d,"
                        "\"tap_enabled\":%d,\"socks_enabled\":%d,"
                        "\"direct_enabled\":%d,\"tap_name\":",
                        (long long)sqlite3_column_int64(stmt, 3),
                        sqlite3_column_int(stmt, 4),
                        sqlite3_column_int(stmt, 5),
                        sqlite3_column_int(stmt, 6),
                        sqlite3_column_int(stmt, 7)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 8)) != 0 ||
           json_append(json, ",\"bridge_name\":") != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 9)) != 0 ||
           json_appendf(json,
                        ",\"mtu\":%d,\"direct_port\":%d,"
                        "\"max_socks_streams\":%d,"
                        "\"socks_idle_timeout_sec\":%d,"
                        "\"online\":%d,\"last_seen\":%lld,"
                        "\"created_at\":%lld,\"updated_at\":%lld}",
                        sqlite3_column_int(stmt, 10),
                        sqlite3_column_int(stmt, 11),
                        sqlite3_column_int(stmt, 12),
                        sqlite3_column_int(stmt, 13),
                        sqlite3_column_int(stmt, 14),
                        (long long)sqlite3_column_int64(stmt, 15),
                        (long long)sqlite3_column_int64(stmt, 16),
                        (long long)sqlite3_column_int64(stmt, 17)) != 0 ? -1 : 0;
}

static int json_append_tap_user_row(json_buf_t *json, sqlite3_stmt *stmt)
{
    return json_appendf(json, "{\"id\":%lld,\"username\":",
                        (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 1)) != 0 ||
           json_appendf(json,
                        ",\"enabled\":%d,\"expire_at\":%lld,"
                        "\"created_at\":%lld,\"updated_at\":%lld,"
                        "\"grant_count\":%d}",
                        sqlite3_column_int(stmt, 2),
                        (long long)sqlite3_column_int64(stmt, 3),
                        (long long)sqlite3_column_int64(stmt, 4),
                        (long long)sqlite3_column_int64(stmt, 5),
                        sqlite3_column_int(stmt, 6)) != 0 ? -1 : 0;
}

static int json_append_socks_user_row(json_buf_t *json, sqlite3_stmt *stmt)
{
    return json_appendf(json, "{\"id\":%lld,\"username\":",
                        (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 1)) != 0 ||
           json_appendf(json,
                        ",\"enabled\":%d,\"expire_at\":%lld,"
                        "\"created_at\":%lld,\"updated_at\":%lld,"
                        "\"grant_count\":%d}",
                        sqlite3_column_int(stmt, 2),
                        (long long)sqlite3_column_int64(stmt, 3),
                        (long long)sqlite3_column_int64(stmt, 4),
                        (long long)sqlite3_column_int64(stmt, 5),
                        sqlite3_column_int(stmt, 6)) != 0 ? -1 : 0;
}

static int json_append_session_row(json_buf_t *json, sqlite3_stmt *stmt)
{
    return json_appendf(json, "{\"id\":%lld,\"session_type\":",
                        (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 1)) != 0 ||
           json_appendf(json,
                        ",\"user_id\":%lld,\"node_pk\":%lld,"
                        "\"network_id\":%lld,\"remote_addr\":",
                        (long long)sqlite3_column_int64(stmt, 2),
                        (long long)sqlite3_column_int64(stmt, 3),
                        (long long)sqlite3_column_int64(stmt, 4)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 5)) != 0 ||
           json_appendf(json,
                        ",\"started_at\":%lld,\"last_active\":%lld,"
                        "\"ended_at\":%lld,\"ended_reason\":",
                        (long long)sqlite3_column_int64(stmt, 6),
                        (long long)sqlite3_column_int64(stmt, 7),
                        (long long)sqlite3_column_int64(stmt, 8)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 9)) != 0 ||
           json_appendf(json,
                        ",\"in_bytes\":%lld,\"out_bytes\":%lld,"
                        "\"auth_type\":",
                        (long long)sqlite3_column_int64(stmt, 10),
                        (long long)sqlite3_column_int64(stmt, 11)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 12)) != 0 ||
           json_append(json, "}") != 0 ? -1 : 0;
}

static int json_append_socks_stream_row(json_buf_t *json, sqlite3_stmt *stmt)
{
    return json_appendf(json,
                        "{\"id\":%lld,\"stream_id\":%lld,"
                        "\"session_id\":%lld,\"node_pk\":%lld,"
                        "\"node_id\":",
                        (long long)sqlite3_column_int64(stmt, 0),
                        (long long)sqlite3_column_int64(stmt, 1),
                        (long long)sqlite3_column_int64(stmt, 2),
                        (long long)sqlite3_column_int64(stmt, 3)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 4)) != 0 ||
           json_appendf(json,
                        ",\"socks_user_id\":%lld,\"username\":",
                        (long long)sqlite3_column_int64(stmt, 5)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 6)) != 0 ||
           json_append(json, ",\"target_host\":") != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 7)) != 0 ||
           json_appendf(json,
                        ",\"target_port\":%d,\"state\":",
                        sqlite3_column_int(stmt, 8)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 9)) != 0 ||
           json_appendf(json,
                        ",\"started_at\":%lld,\"last_active\":%lld,"
                        "\"ended_at\":%lld,\"ended_reason\":",
                        (long long)sqlite3_column_int64(stmt, 10),
                        (long long)sqlite3_column_int64(stmt, 11),
                        (long long)sqlite3_column_int64(stmt, 12)) != 0 ||
           json_append_string(json, sqlite3_column_text(stmt, 13)) != 0 ||
           json_appendf(json,
                        ",\"in_bytes\":%lld,\"out_bytes\":%lld}",
                        (long long)sqlite3_column_int64(stmt, 14),
                        (long long)sqlite3_column_int64(stmt, 15)) != 0 ? -1 : 0;
}

typedef int (*json_row_append_fn)(json_buf_t *json, sqlite3_stmt *stmt);

static int db_json_one_by_id(const char *db_file, int64_t id, const char *sql,
                             const char *prepare_msg, const char *missing_msg,
                             json_row_append_fn append_row, char **out_json,
                             char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    int rc = 0;

    if (out_json == NULL || sql == NULL || append_row == NULL) {
        return -1;
    }
    *out_json = NULL;
    if (id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid id");
        }
        return -1;
    }
    (void)memset(&json, 0, sizeof(json));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, prepare_msg, db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (rc == SQLITE_DONE) {
            (void)snprintf(err, err_len, "%s", missing_msg);
        } else {
            db_set_err(err, err_len, missing_msg, db);
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (json_append(&json, "{\"code\":1,\"data\":") != 0 ||
        append_row(&json, stmt) != 0 ||
        json_append(&json, "}") != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    *out_json = json.data;
    return 0;
}

int ntap_a_db_json_networks(const char *db_file, char **out_json,
                            char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    int rc = 0;
    int total = 0;

    if (out_json == NULL) {
        return -1;
    }
    *out_json = NULL;
    (void)memset(&json, 0, sizeof(json));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT id, name, mtu, enabled, mac_ttl_sec,"
                            " broadcast_limit_pps, session_broadcast_limit_pps,"
                            " max_mac_per_session, tap_queue_limit_bytes,"
                            " allow_client_to_client, allow_l2_control,"
                            " created_at, updated_at"
                            " FROM networks ORDER BY id;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare network json failed", db);
        sqlite3_close(db);
        return -1;
    }
    if (json_append(&json, "{\"rows\":[") != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (total > 0 && json_append(&json, ",") != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        if (json_appendf(&json, "{\"id\":%lld,\"name\":",
                         (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
            json_append_string(&json, sqlite3_column_text(stmt, 1)) != 0 ||
            json_appendf(&json,
                         ",\"mtu\":%d,\"enabled\":%d,"
                         "\"mac_ttl_sec\":%d,\"broadcast_limit_pps\":%d,"
                         "\"session_broadcast_limit_pps\":%d,"
                         "\"max_mac_per_session\":%d,"
                         "\"tap_queue_limit_bytes\":%d,"
                         "\"allow_client_to_client\":%d,"
                         "\"allow_l2_control\":%d,"
                         "\"created_at\":%lld,\"updated_at\":%lld}",
                         sqlite3_column_int(stmt, 2),
                         sqlite3_column_int(stmt, 3),
                         sqlite3_column_int(stmt, 4),
                         sqlite3_column_int(stmt, 5),
                         sqlite3_column_int(stmt, 6),
                         sqlite3_column_int(stmt, 7),
                         sqlite3_column_int(stmt, 8),
                         sqlite3_column_int(stmt, 9),
                         sqlite3_column_int(stmt, 10),
                         (long long)sqlite3_column_int64(stmt, 11),
                         (long long)sqlite3_column_int64(stmt, 12)) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        total++;
    }
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "network json failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (json_finish_rows(&json, total, out_json) != 0) {
        free(json.data);
        return -1;
    }
    return 0;
}

int ntap_a_db_json_network(const char *db_file, int64_t id, char **out_json,
                           char *err, size_t err_len)
{
    return db_json_one_by_id(
        db_file, id,
        "SELECT id, name, mtu, enabled, mac_ttl_sec,"
        " broadcast_limit_pps, session_broadcast_limit_pps,"
        " max_mac_per_session, tap_queue_limit_bytes,"
        " allow_client_to_client, allow_l2_control,"
        " created_at, updated_at"
        " FROM networks WHERE id = ?;",
        "prepare network get failed", "network not found",
        json_append_network_row, out_json, err, err_len);
}

int ntap_a_db_json_nodes(const char *db_file, char **out_json,
                         char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    int rc = 0;
    int total = 0;

    if (out_json == NULL) {
        return -1;
    }
    *out_json = NULL;
    (void)memset(&json, 0, sizeof(json));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT id, node_id, name, network_id, enabled,"
                            " tap_enabled, socks_enabled, direct_enabled,"
                            " tap_name, bridge_name, mtu, direct_port,"
                            " max_socks_streams, socks_idle_timeout_sec,"
                            " online, last_seen, created_at, updated_at"
                            " FROM nodes ORDER BY id;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node json failed", db);
        sqlite3_close(db);
        return -1;
    }
    if (json_append(&json, "{\"rows\":[") != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (total > 0 && json_append(&json, ",") != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        if (json_append_node_row(&json, stmt) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        total++;
    }
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "node json failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (json_finish_rows(&json, total, out_json) != 0) {
        free(json.data);
        return -1;
    }
    return 0;
}

int ntap_a_db_json_node(const char *db_file, int64_t id, char **out_json,
                        char *err, size_t err_len)
{
    return db_json_one_by_id(
        db_file, id,
        "SELECT id, node_id, name, network_id, enabled,"
        " tap_enabled, socks_enabled, direct_enabled,"
        " tap_name, bridge_name, mtu, direct_port,"
        " max_socks_streams, socks_idle_timeout_sec,"
        " online, last_seen, created_at, updated_at"
        " FROM nodes WHERE id = ?;",
        "prepare node get failed", "node not found",
        json_append_node_row, out_json, err, err_len);
}

int ntap_a_db_json_node_service_status(const char *db_file, int64_t id,
                                       char **out_json,
                                       char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    int rc = 0;

    if (out_json == NULL) {
        return -1;
    }
    *out_json = NULL;
    if (id <= 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid id");
        }
        return -1;
    }
    (void)memset(&json, 0, sizeof(json));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT id, node_id, name, tap_enabled,"
                            " socks_enabled, direct_enabled, direct_reachable,"
                            " direct_port, updated_at"
                            " FROM nodes WHERE id = ?;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare node service status failed", db);
        sqlite3_close(db);
        return -1;
    }
    (void)sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (rc == SQLITE_DONE) {
            if (err != NULL && err_len > 0) {
                (void)snprintf(err, err_len, "node not found");
            }
        } else {
            db_set_err(err, err_len, "read node service status failed", db);
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    if (json_appendf(&json, "{\"code\":1,\"data\":{\"id\":%lld,\"node_id\":",
                     (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
        json_append_string(&json, sqlite3_column_text(stmt, 1)) != 0 ||
        json_append(&json, ",\"name\":") != 0 ||
        json_append_string(&json, sqlite3_column_text(stmt, 2)) != 0 ||
        json_appendf(&json,
                     ",\"tap_enabled\":%d,\"socks_enabled\":%d,"
                     "\"direct_enabled\":%d,\"direct_reachable\":%d,"
                     "\"direct_port\":%d,\"updated_at\":%lld}}",
                     sqlite3_column_int(stmt, 3),
                     sqlite3_column_int(stmt, 4),
                     sqlite3_column_int(stmt, 5),
                     sqlite3_column_int(stmt, 6),
                     sqlite3_column_int(stmt, 7),
                     (long long)sqlite3_column_int64(stmt, 8)) != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    *out_json = json.data;
    return 0;
}

int ntap_a_db_json_tap_users(const char *db_file, char **out_json,
                             char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    int rc = 0;
    int total = 0;

    if (out_json == NULL) {
        return -1;
    }
    *out_json = NULL;
    (void)memset(&json, 0, sizeof(json));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT u.id, u.username, u.enabled, u.expire_at,"
                            " u.created_at, u.updated_at,"
                            " COUNT(g.id) AS grant_count"
                            " FROM tap_users u"
                            " LEFT JOIN tap_grants g ON g.tap_user_id = u.id"
                            " GROUP BY u.id, u.username, u.enabled, u.expire_at,"
                            " u.created_at, u.updated_at"
                            " ORDER BY u.id;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare tap user json failed", db);
        sqlite3_close(db);
        return -1;
    }
    if (json_append(&json, "{\"rows\":[") != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (total > 0 && json_append(&json, ",") != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        if (json_appendf(&json, "{\"id\":%lld,\"username\":",
                         (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
            json_append_string(&json, sqlite3_column_text(stmt, 1)) != 0 ||
            json_appendf(&json,
                         ",\"enabled\":%d,\"expire_at\":%lld,"
                         "\"created_at\":%lld,\"updated_at\":%lld,"
                         "\"grant_count\":%d}",
                         sqlite3_column_int(stmt, 2),
                         (long long)sqlite3_column_int64(stmt, 3),
                         (long long)sqlite3_column_int64(stmt, 4),
                         (long long)sqlite3_column_int64(stmt, 5),
                         sqlite3_column_int(stmt, 6)) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        total++;
    }
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "tap user json failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (json_finish_rows(&json, total, out_json) != 0) {
        free(json.data);
        return -1;
    }
    return 0;
}

int ntap_a_db_json_tap_user(const char *db_file, int64_t id, char **out_json,
                            char *err, size_t err_len)
{
    return db_json_one_by_id(
        db_file, id,
        "SELECT u.id, u.username, u.enabled, u.expire_at,"
        " u.created_at, u.updated_at,"
        " COUNT(g.id) AS grant_count"
        " FROM tap_users u"
        " LEFT JOIN tap_grants g ON g.tap_user_id = u.id"
        " WHERE u.id = ?"
        " GROUP BY u.id, u.username, u.enabled, u.expire_at,"
        " u.created_at, u.updated_at;",
        "prepare tap user get failed", "tap user not found",
        json_append_tap_user_row, out_json, err, err_len);
}

int ntap_a_db_json_socks_users(const char *db_file, char **out_json,
                               char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    int rc = 0;
    int total = 0;

    if (out_json == NULL) {
        return -1;
    }
    *out_json = NULL;
    (void)memset(&json, 0, sizeof(json));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT u.id, u.username, u.enabled, u.expire_at,"
                            " u.created_at, u.updated_at,"
                            " COALESCE(SUM(CASE WHEN g.enabled = 1 THEN 1 ELSE 0 END), 0)"
                            " AS grant_count"
                            " FROM socks_users u"
                            " LEFT JOIN socks_grants g ON g.socks_user_id = u.id"
                            " GROUP BY u.id, u.username, u.enabled, u.expire_at,"
                            " u.created_at, u.updated_at"
                            " ORDER BY u.id;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare socks user json failed", db);
        sqlite3_close(db);
        return -1;
    }
    if (json_append(&json, "{\"rows\":[") != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (total > 0 && json_append(&json, ",") != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        if (json_appendf(&json, "{\"id\":%lld,\"username\":",
                         (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
            json_append_string(&json, sqlite3_column_text(stmt, 1)) != 0 ||
            json_appendf(&json,
                         ",\"enabled\":%d,\"expire_at\":%lld,"
                         "\"created_at\":%lld,\"updated_at\":%lld,"
                         "\"grant_count\":%d}",
                         sqlite3_column_int(stmt, 2),
                         (long long)sqlite3_column_int64(stmt, 3),
                         (long long)sqlite3_column_int64(stmt, 4),
                         (long long)sqlite3_column_int64(stmt, 5),
                         sqlite3_column_int(stmt, 6)) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        total++;
    }
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "socks user json failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (json_finish_rows(&json, total, out_json) != 0) {
        free(json.data);
        return -1;
    }
    return 0;
}

int ntap_a_db_json_socks_user(const char *db_file, int64_t id, char **out_json,
                              char *err, size_t err_len)
{
    return db_json_one_by_id(
        db_file, id,
        "SELECT u.id, u.username, u.enabled, u.expire_at,"
        " u.created_at, u.updated_at,"
        " COALESCE(SUM(CASE WHEN g.enabled = 1 THEN 1 ELSE 0 END), 0)"
        " AS grant_count"
        " FROM socks_users u"
        " LEFT JOIN socks_grants g ON g.socks_user_id = u.id"
        " WHERE u.id = ?"
        " GROUP BY u.id, u.username, u.enabled, u.expire_at,"
        " u.created_at, u.updated_at;",
        "prepare socks user get failed", "socks user not found",
        json_append_socks_user_row, out_json, err, err_len);
}

int ntap_a_db_json_sessions(const char *db_file, char **out_json,
                            char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    int rc = 0;
    int total = 0;

    if (out_json == NULL) {
        return -1;
    }
    *out_json = NULL;
    (void)memset(&json, 0, sizeof(json));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(db,
                            "SELECT id, session_type, user_id, node_pk,"
                            " network_id, remote_addr, started_at,"
                            " last_active, ended_at, ended_reason,"
                            " in_bytes, out_bytes, auth_type"
                            " FROM sessions ORDER BY id DESC LIMIT 200;",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare session json failed", db);
        sqlite3_close(db);
        return -1;
    }
    if (json_append(&json, "{\"rows\":[") != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (total > 0 && json_append(&json, ",") != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        if (json_appendf(&json, "{\"id\":%lld,\"session_type\":",
                         (long long)sqlite3_column_int64(stmt, 0)) != 0 ||
            json_append_string(&json, sqlite3_column_text(stmt, 1)) != 0 ||
            json_appendf(&json,
                         ",\"user_id\":%lld,\"node_pk\":%lld,"
                         "\"network_id\":%lld,\"remote_addr\":",
                         (long long)sqlite3_column_int64(stmt, 2),
                         (long long)sqlite3_column_int64(stmt, 3),
                         (long long)sqlite3_column_int64(stmt, 4)) != 0 ||
            json_append_string(&json, sqlite3_column_text(stmt, 5)) != 0 ||
            json_appendf(&json,
                         ",\"started_at\":%lld,\"last_active\":%lld,"
                         "\"ended_at\":%lld,\"ended_reason\":",
                         (long long)sqlite3_column_int64(stmt, 6),
                         (long long)sqlite3_column_int64(stmt, 7),
                         (long long)sqlite3_column_int64(stmt, 8)) != 0 ||
            json_append_string(&json, sqlite3_column_text(stmt, 9)) != 0 ||
            json_appendf(&json,
                         ",\"in_bytes\":%lld,\"out_bytes\":%lld,"
                         "\"auth_type\":",
                         (long long)sqlite3_column_int64(stmt, 10),
                         (long long)sqlite3_column_int64(stmt, 11)) != 0 ||
            json_append_string(&json, sqlite3_column_text(stmt, 12)) != 0 ||
            json_append(&json, "}") != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        total++;
    }
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "session json failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (json_finish_rows(&json, total, out_json) != 0) {
        free(json.data);
        return -1;
    }
    return 0;
}

int ntap_a_db_json_session(const char *db_file, int64_t id, char **out_json,
                           char *err, size_t err_len)
{
    return db_json_one_by_id(
        db_file, id,
        "SELECT id, session_type, user_id, node_pk,"
        " network_id, remote_addr, started_at,"
        " last_active, ended_at, ended_reason,"
        " in_bytes, out_bytes, auth_type"
        " FROM sessions WHERE id = ?;",
        "prepare session get failed", "session not found",
        json_append_session_row, out_json, err, err_len);
}

int ntap_a_db_json_socks_streams(const char *db_file, char **out_json,
                                 char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    json_buf_t json;
    int rc = 0;
    int total = 0;

    if (out_json == NULL) {
        return -1;
    }
    *out_json = NULL;
    (void)memset(&json, 0, sizeof(json));
    if (db_open(db_file, &db, err, err_len) != 0) {
        return -1;
    }
    rc = sqlite3_prepare_v2(
        db,
        "SELECT s.id, s.stream_id, s.session_id, s.node_pk,"
        " COALESCE(n.node_id, ''), s.socks_user_id,"
        " COALESCE(u.username, ''), s.target_host, s.target_port,"
        " s.state, s.started_at, s.last_active, s.ended_at,"
        " s.ended_reason, s.in_bytes, s.out_bytes"
        " FROM socks_streams s"
        " LEFT JOIN nodes n ON n.id = s.node_pk"
        " LEFT JOIN socks_users u ON u.id = s.socks_user_id"
        " ORDER BY s.id DESC LIMIT 200;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_set_err(err, err_len, "prepare socks stream json failed", db);
        sqlite3_close(db);
        return -1;
    }
    if (json_append(&json, "{\"rows\":[") != 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (total > 0 && json_append(&json, ",") != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        if (json_append_socks_stream_row(&json, stmt) != 0) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            free(json.data);
            return -1;
        }
        total++;
    }
    if (rc != SQLITE_DONE) {
        db_set_err(err, err_len, "socks stream json failed", db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(json.data);
        return -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (json_finish_rows(&json, total, out_json) != 0) {
        free(json.data);
        return -1;
    }
    return 0;
}

int ntap_a_db_json_socks_stream(const char *db_file, int64_t id,
                                char **out_json, char *err, size_t err_len)
{
    return db_json_one_by_id(
        db_file, id,
        "SELECT s.id, s.stream_id, s.session_id, s.node_pk,"
        " COALESCE(n.node_id, ''), s.socks_user_id,"
        " COALESCE(u.username, ''), s.target_host, s.target_port,"
        " s.state, s.started_at, s.last_active, s.ended_at,"
        " s.ended_reason, s.in_bytes, s.out_bytes"
        " FROM socks_streams s"
        " LEFT JOIN nodes n ON n.id = s.node_pk"
        " LEFT JOIN socks_users u ON u.id = s.socks_user_id"
        " WHERE s.id = ?;",
        "prepare socks stream get failed", "socks stream not found",
        json_append_socks_stream_row, out_json, err, err_len);
}
