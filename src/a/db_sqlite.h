#ifndef NTAP_A_DB_SQLITE_H
#define NTAP_A_DB_SQLITE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "common/config.h"

#define NTAP_A_DEFAULT_MAC_TTL_SEC 300u
#define NTAP_A_DEFAULT_BROADCAST_LIMIT_PPS 200u
#define NTAP_A_DEFAULT_SESSION_BROADCAST_LIMIT_PPS 50u
#define NTAP_A_DEFAULT_MAX_MAC_PER_SESSION 32u
#define NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES (256u * 1024u)
#define NTAP_A_DEFAULT_MAX_SOCKS_STREAMS 64u
#define NTAP_A_DEFAULT_SOCKS_IDLE_TIMEOUT_SEC 1800u

typedef struct ntap_a_network_options {
    uint16_t mtu;
    uint32_t mac_ttl_sec;
    uint32_t broadcast_limit_pps;
    uint32_t session_broadcast_limit_pps;
    uint32_t max_mac_per_session;
    uint32_t tap_queue_limit_bytes;
    int allow_client_to_client;
    int allow_l2_control;
} ntap_a_network_options_t;

typedef struct ntap_a_node_auth {
    int64_t node_pk;
    int64_t network_id;
    int enabled;
    char node_key_secret[NTAP_CONFIG_VALUE_MAX];
} ntap_a_node_auth_t;

typedef struct ntap_a_tap_auth {
    int64_t tap_user_id;
    int64_t network_id;
    int enabled;
    char username[NTAP_CONFIG_VALUE_MAX];
} ntap_a_tap_auth_t;

typedef struct ntap_a_socks_auth {
    int64_t socks_user_id;
    int64_t node_pk;
    int64_t network_id;
    uint32_t max_socks_streams;
    uint32_t socks_idle_timeout_sec;
    int enabled;
    char username[NTAP_CONFIG_VALUE_MAX];
    char node_id[NTAP_CONFIG_VALUE_MAX];
} ntap_a_socks_auth_t;

typedef struct ntap_a_runtime_config {
    int64_t network_id;
    uint16_t mtu;
    int tap_enabled;
    int socks_enabled;
    int direct_enabled;
    char tap_name[NTAP_CONFIG_VALUE_MAX];
    char bridge_name[NTAP_CONFIG_VALUE_MAX];
    uint16_t direct_port;
    uint32_t mac_ttl_sec;
    uint32_t broadcast_limit_pps;
    uint32_t session_broadcast_limit_pps;
    uint32_t max_mac_per_session;
    uint32_t tap_queue_limit_bytes;
    int allow_client_to_client;
    int allow_l2_control;
} ntap_a_runtime_config_t;

typedef struct ntap_a_session_start {
    const char *session_type;
    int64_t user_id;
    int64_t node_pk;
    int64_t network_id;
    const char *remote_addr;
    const char *auth_type;
} ntap_a_session_start_t;

int ntap_a_db_init(const char *db_file, char *err, size_t err_len);
int ntap_a_db_add_network(const char *db_file, const char *name,
                          const ntap_a_network_options_t *opts,
                          char *err, size_t err_len);
int ntap_a_db_add_node(const char *db_file, const char *name, const char *node_id,
                       const char *node_key, int64_t network_id,
                       const char *tap_name, const char *bridge_name, uint16_t mtu,
                       uint32_t max_socks_streams,
                       uint32_t socks_idle_timeout_sec,
                       char *err, size_t err_len);
int ntap_a_db_add_tap_user(const char *db_file, const char *username,
                           const char *password, int64_t network_id,
                           char *err, size_t err_len);
int ntap_a_db_add_socks_user(const char *db_file, const char *username,
                             const char *password, int64_t node_pk,
                             char *err, size_t err_len);
int ntap_a_db_edit_network(const char *db_file, int64_t id, const char *name,
                           const ntap_a_network_options_t *opts,
                           char *err, size_t err_len);
int ntap_a_db_edit_node(const char *db_file, int64_t id, const char *name,
                        const char *node_id, const char *node_key,
                        int64_t network_id, const char *tap_name,
                        const char *bridge_name, uint16_t mtu,
                        uint32_t max_socks_streams,
                        uint32_t socks_idle_timeout_sec,
                        char *err, size_t err_len);
int ntap_a_db_edit_tap_user(const char *db_file, int64_t id,
                            const char *username, const char *password,
                            char *err, size_t err_len);
int ntap_a_db_edit_socks_user(const char *db_file, int64_t id,
                              const char *username, const char *password,
                              char *err, size_t err_len);
int ntap_a_db_delete_network(const char *db_file, int64_t id,
                             char *err, size_t err_len);
int ntap_a_db_delete_node(const char *db_file, int64_t id,
                          char *err, size_t err_len);
int ntap_a_db_delete_tap_user(const char *db_file, int64_t id,
                              char *err, size_t err_len);
int ntap_a_db_delete_socks_user(const char *db_file, int64_t id,
                                char *err, size_t err_len);
int ntap_a_db_grant_tap_user(const char *db_file, int64_t tap_user_id,
                             int64_t network_id, char *err, size_t err_len);
int ntap_a_db_revoke_tap_user(const char *db_file, int64_t tap_user_id,
                              int64_t network_id, char *err, size_t err_len);
int ntap_a_db_grant_socks_user(const char *db_file, int64_t socks_user_id,
                               int64_t node_pk, char *err, size_t err_len);
int ntap_a_db_revoke_socks_user(const char *db_file, int64_t socks_user_id,
                                int64_t node_pk, char *err, size_t err_len);
int ntap_a_db_get_node_auth(const char *db_file, const char *node_id,
                            ntap_a_node_auth_t *out, char *err, size_t err_len);
int ntap_a_db_get_tap_auth(const char *db_file, const char *username,
                           const char *password, int64_t requested_network_id,
                           ntap_a_tap_auth_t *out, char *err, size_t err_len);
int ntap_a_db_get_socks_auth(const char *db_file, const char *username,
                             const char *password, ntap_a_socks_auth_t *out,
                             char *err, size_t err_len);
int ntap_a_db_get_node_runtime_config(const char *db_file, const char *node_id,
                                      ntap_a_runtime_config_t *out,
                                      char *err, size_t err_len);
int ntap_a_db_get_tap_runtime_config(const char *db_file, int64_t network_id,
                                     ntap_a_runtime_config_t *out,
                                     char *err, size_t err_len);
int ntap_a_db_set_node_online(const char *db_file, const char *node_id, int online,
                              char *err, size_t err_len);
int ntap_a_db_set_network_enabled(const char *db_file, int64_t id, int enabled,
                                  char *err, size_t err_len);
int ntap_a_db_set_node_enabled(const char *db_file, int64_t id, int enabled,
                               char *err, size_t err_len);
int ntap_a_db_set_tap_user_enabled(const char *db_file, int64_t id, int enabled,
                                   char *err, size_t err_len);
int ntap_a_db_set_socks_user_enabled(const char *db_file, int64_t id, int enabled,
                                     char *err, size_t err_len);
int ntap_a_db_set_node_service_enabled(const char *db_file, int64_t id,
                                       const char *service_type, int enabled,
                                       char *err, size_t err_len);
int ntap_a_db_session_start(const char *db_file,
                            const ntap_a_session_start_t *session,
                            int64_t *out_session_id, char *err, size_t err_len);
int ntap_a_db_session_touch(const char *db_file, int64_t session_id,
                            uint64_t in_bytes, uint64_t out_bytes,
                            char *err, size_t err_len);
int ntap_a_db_session_end(const char *db_file, int64_t session_id,
                          const char *reason, char *err, size_t err_len);
int ntap_a_db_socks_stream_start(const char *db_file, uint32_t stream_id,
                                 int64_t session_id, int64_t node_pk,
                                 int64_t socks_user_id, const char *target_host,
                                 uint16_t target_port, int64_t *out_stream_db_id,
                                 char *err, size_t err_len);
int ntap_a_db_socks_stream_touch(const char *db_file, int64_t stream_db_id,
                                 uint64_t in_bytes, uint64_t out_bytes,
                                 char *err, size_t err_len);
int ntap_a_db_socks_stream_end(const char *db_file, int64_t stream_db_id,
                               const char *reason, char *err, size_t err_len);
int ntap_a_db_print_nodes(const char *db_file, FILE *out, char *err, size_t err_len);
int ntap_a_db_json_networks(const char *db_file, char **out_json,
                            char *err, size_t err_len);
int ntap_a_db_json_network(const char *db_file, int64_t id, char **out_json,
                           char *err, size_t err_len);
int ntap_a_db_json_nodes(const char *db_file, char **out_json,
                         char *err, size_t err_len);
int ntap_a_db_json_node(const char *db_file, int64_t id, char **out_json,
                        char *err, size_t err_len);
int ntap_a_db_json_tap_users(const char *db_file, char **out_json,
                             char *err, size_t err_len);
int ntap_a_db_json_tap_user(const char *db_file, int64_t id, char **out_json,
                            char *err, size_t err_len);
int ntap_a_db_json_socks_users(const char *db_file, char **out_json,
                               char *err, size_t err_len);
int ntap_a_db_json_socks_user(const char *db_file, int64_t id, char **out_json,
                              char *err, size_t err_len);
int ntap_a_db_json_sessions(const char *db_file, char **out_json,
                            char *err, size_t err_len);
int ntap_a_db_json_session(const char *db_file, int64_t id, char **out_json,
                           char *err, size_t err_len);
int ntap_a_db_json_socks_streams(const char *db_file, char **out_json,
                                 char *err, size_t err_len);
int ntap_a_db_json_socks_stream(const char *db_file, int64_t id,
                                char **out_json, char *err, size_t err_len);
int ntap_a_db_json_node_service_status(const char *db_file, int64_t id,
                                       char **out_json,
                                       char *err, size_t err_len);

#endif
