#include "a/config.h"
#include "a/api_server.h"
#include "a/db_sqlite.h"
#include "a/node_server.h"
#include "common/proto.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    (void)fprintf(out,
                  "usage:\n"
                  "  ntap-a -c <config> -t\n"
                  "  ntap-a -c <config> initdb\n"
                  "  ntap-a -c <config> serve [--once] [--max-sessions <n>]\n"
                  "  ntap-a -c <config> api [--once] [--max-requests <n>]\n"
                  "  ntap-a -c <config> network add --name <name> [--mtu <mtu>] "
                  "[--mac-ttl-sec <n>] [--broadcast-limit-pps <n>] "
                  "[--session-broadcast-limit-pps <n>] [--max-mac-per-session <n>] "
                  "[--tap-queue-limit-bytes <n>] [--allow-client-to-client] "
                  "[--allow-l2-control]\n"
                  "  ntap-a -c <config> node add --name <name> --node-id <id> "
                  "--node-key <key> --network-id <id> "
                  "[--tap-name <name>] [--bridge-name <name>] [--mtu <mtu>] "
                  "[--max-socks-streams <n>] [--socks-idle-timeout-sec <n>]\n"
                  "  ntap-a -c <config> tap-user add --username <name> "
                  "--password <password> --network-id <id>\n"
                  "  ntap-a -c <config> node list\n");
}

static const char *arg_value(int argc, char **argv, int start, const char *name)
{
    int i = 0;

    for (i = start; i < argc - 1; i++) {
        if (strcmp(argv[i], name) == 0) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static int parse_i64(const char *value, int64_t *out)
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

static bool has_flag(int argc, char **argv, int start, const char *name);

static int parse_optional_u32_arg(int argc, char **argv, int start, const char *name,
                                  uint32_t fallback, uint32_t *out)
{
    const char *value = arg_value(argc, argv, start, name);
    int64_t parsed = 0;

    if (out == NULL) {
        return -1;
    }
    if (value == NULL) {
        *out = fallback;
        return 0;
    }
    if (parse_i64(value, &parsed) != 0 || parsed < 0 || parsed > 1000000) {
        return -1;
    }
    *out = (uint32_t)parsed;
    return 0;
}

static int handle_initdb(const ntap_a_config_t *cfg, char *err, size_t err_len)
{
    if (ntap_a_db_init(cfg->db_file, err, err_len) != 0) {
        (void)fprintf(stderr, "ntap-a: initdb failed: %s\n", err);
        return 1;
    }
    (void)printf("ntap-a: database ready (%s)\n", cfg->db_file);
    return 0;
}

static int handle_network_add(const ntap_a_config_t *cfg, int argc, char **argv,
                              int start, char *err, size_t err_len)
{
    const char *name = arg_value(argc, argv, start, "--name");
    const char *mtu_s = arg_value(argc, argv, start, "--mtu");
    ntap_a_network_options_t opts;
    int64_t mtu = NTAP_DEFAULT_MTU;

    opts.mtu = NTAP_DEFAULT_MTU;
    opts.mac_ttl_sec = NTAP_A_DEFAULT_MAC_TTL_SEC;
    opts.broadcast_limit_pps = NTAP_A_DEFAULT_BROADCAST_LIMIT_PPS;
    opts.session_broadcast_limit_pps = NTAP_A_DEFAULT_SESSION_BROADCAST_LIMIT_PPS;
    opts.max_mac_per_session = NTAP_A_DEFAULT_MAX_MAC_PER_SESSION;
    opts.tap_queue_limit_bytes = NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES;
    opts.allow_client_to_client = has_flag(argc, argv, start, "--allow-client-to-client");
    opts.allow_l2_control = has_flag(argc, argv, start, "--allow-l2-control");

    if (mtu_s != NULL && parse_i64(mtu_s, &mtu) != 0) {
        (void)fprintf(stderr, "ntap-a: invalid --mtu\n");
        return 2;
    }
    if (mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU) {
        (void)fprintf(stderr, "ntap-a: --mtu must be between %u and %u\n",
                      NTAP_MIN_MTU, NTAP_MAX_MTU);
        return 2;
    }
    opts.mtu = (uint16_t)mtu;
    if (parse_optional_u32_arg(argc, argv, start, "--mac-ttl-sec",
                               NTAP_A_DEFAULT_MAC_TTL_SEC,
                               &opts.mac_ttl_sec) != 0 ||
        parse_optional_u32_arg(argc, argv, start, "--broadcast-limit-pps",
                               NTAP_A_DEFAULT_BROADCAST_LIMIT_PPS,
                               &opts.broadcast_limit_pps) != 0 ||
        parse_optional_u32_arg(argc, argv, start, "--session-broadcast-limit-pps",
                               NTAP_A_DEFAULT_SESSION_BROADCAST_LIMIT_PPS,
                               &opts.session_broadcast_limit_pps) != 0 ||
        parse_optional_u32_arg(argc, argv, start, "--max-mac-per-session",
                               NTAP_A_DEFAULT_MAX_MAC_PER_SESSION,
                               &opts.max_mac_per_session) != 0 ||
        parse_optional_u32_arg(argc, argv, start, "--tap-queue-limit-bytes",
                               NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES,
                               &opts.tap_queue_limit_bytes) != 0) {
        (void)fprintf(stderr, "ntap-a: invalid network limit option\n");
        return 2;
    }
    if (opts.max_mac_per_session == 0) {
        (void)fprintf(stderr, "ntap-a: --max-mac-per-session must be greater than 0\n");
        return 2;
    }
    if (opts.tap_queue_limit_bytes == 0) {
        (void)fprintf(stderr, "ntap-a: --tap-queue-limit-bytes must be greater than 0\n");
        return 2;
    }
    if (ntap_a_db_add_network(cfg->db_file, name, &opts, err, err_len) != 0) {
        (void)fprintf(stderr, "ntap-a: network add failed: %s\n", err);
        return 1;
    }
    (void)printf("ntap-a: network added name=%s mtu=%lld\n", name, (long long)mtu);
    return 0;
}

static int handle_node_add(const ntap_a_config_t *cfg, int argc, char **argv,
                           int start, char *err, size_t err_len)
{
    const char *name = arg_value(argc, argv, start, "--name");
    const char *node_id = arg_value(argc, argv, start, "--node-id");
    const char *node_key = arg_value(argc, argv, start, "--node-key");
    const char *network_id_s = arg_value(argc, argv, start, "--network-id");
    const char *tap_name = arg_value(argc, argv, start, "--tap-name");
    const char *bridge_name = arg_value(argc, argv, start, "--bridge-name");
    const char *mtu_s = arg_value(argc, argv, start, "--mtu");
    int64_t network_id = 0;
    int64_t mtu = NTAP_DEFAULT_MTU;
    uint32_t max_socks_streams = NTAP_A_DEFAULT_MAX_SOCKS_STREAMS;
    uint32_t socks_idle_timeout_sec = NTAP_A_DEFAULT_SOCKS_IDLE_TIMEOUT_SEC;

    if (parse_i64(network_id_s, &network_id) != 0) {
        (void)fprintf(stderr, "ntap-a: invalid --network-id\n");
        return 2;
    }
    if (mtu_s != NULL && parse_i64(mtu_s, &mtu) != 0) {
        (void)fprintf(stderr, "ntap-a: invalid --mtu\n");
        return 2;
    }
    if (mtu < NTAP_MIN_MTU || mtu > NTAP_MAX_MTU) {
        (void)fprintf(stderr, "ntap-a: --mtu must be between %u and %u\n",
                      NTAP_MIN_MTU, NTAP_MAX_MTU);
        return 2;
    }
    if (parse_optional_u32_arg(argc, argv, start, "--max-socks-streams",
                               NTAP_A_DEFAULT_MAX_SOCKS_STREAMS,
                               &max_socks_streams) != 0 ||
        parse_optional_u32_arg(argc, argv, start, "--socks-idle-timeout-sec",
                               NTAP_A_DEFAULT_SOCKS_IDLE_TIMEOUT_SEC,
                               &socks_idle_timeout_sec) != 0 ||
        max_socks_streams == 0 || socks_idle_timeout_sec == 0) {
        (void)fprintf(stderr, "ntap-a: invalid node socks limit option\n");
        return 2;
    }
    if (ntap_a_db_add_node(cfg->db_file, name, node_id, node_key, network_id,
                           tap_name, bridge_name, (uint16_t)mtu,
                           max_socks_streams, socks_idle_timeout_sec,
                           err, err_len) != 0) {
        (void)fprintf(stderr, "ntap-a: node add failed: %s\n", err);
        return 1;
    }
    (void)printf("ntap-a: node added node_id=%s network_id=%lld\n",
                 node_id, (long long)network_id);
    return 0;
}

static int handle_tap_user_add(const ntap_a_config_t *cfg, int argc, char **argv,
                               int start, char *err, size_t err_len)
{
    const char *username = arg_value(argc, argv, start, "--username");
    const char *password = arg_value(argc, argv, start, "--password");
    const char *network_id_s = arg_value(argc, argv, start, "--network-id");
    int64_t network_id = 0;

    if (parse_i64(network_id_s, &network_id) != 0) {
        (void)fprintf(stderr, "ntap-a: invalid --network-id\n");
        return 2;
    }
    if (ntap_a_db_add_tap_user(cfg->db_file, username, password, network_id,
                               err, err_len) != 0) {
        (void)fprintf(stderr, "ntap-a: tap-user add failed: %s\n", err);
        return 1;
    }
    (void)printf("ntap-a: tap user added username=%s network_id=%lld\n",
                 username, (long long)network_id);
    return 0;
}

static bool has_flag(int argc, char **argv, int start, const char *name)
{
    int i = 0;

    for (i = start; i < argc; i++) {
        if (strcmp(argv[i], name) == 0) {
            return true;
        }
    }
    return false;
}

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    bool test_config = false;
    ntap_a_config_t cfg;
    char err[256];
    int i = 0;
    int command_start = 0;

    err[0] = '\0';
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            if (i + 1 >= argc) {
                usage(stderr);
                return 2;
            }
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0) {
            test_config = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            command_start = i;
            break;
        }
    }

    if (ntap_a_config_load(&cfg, config_path, err, sizeof(err)) != 0) {
        (void)fprintf(stderr, "ntap-a: config error: %s\n", err);
        return 1;
    }

    if (test_config) {
        (void)printf("ntap-a: config ok (%s)\n", cfg.path);
        return 0;
    }

    if (command_start > 0) {
        if (strcmp(argv[command_start], "initdb") == 0) {
            return handle_initdb(&cfg, err, sizeof(err));
        }
        if (strcmp(argv[command_start], "serve") == 0) {
            bool once = has_flag(argc, argv, command_start + 1, "--once");
            const char *max_s = arg_value(argc, argv, command_start + 1, "--max-sessions");
            int64_t parsed_max = 0;
            int max_sessions = 0;
            int rc = 0;

            if (max_s != NULL) {
                if (parse_i64(max_s, &parsed_max) != 0 || parsed_max < 0 || parsed_max > 100000) {
                    (void)fprintf(stderr, "ntap-a: invalid --max-sessions\n");
                    return 2;
                }
                max_sessions = (int)parsed_max;
            }
            rc = ntap_a_node_server_run(&cfg, once, max_sessions, err, sizeof(err));

            if (rc != 0) {
                (void)fprintf(stderr, "ntap-a: serve failed: %s\n", err);
            }
            return rc;
        }
        if (strcmp(argv[command_start], "api") == 0) {
            bool once = has_flag(argc, argv, command_start + 1, "--once");
            const char *max_s = arg_value(argc, argv, command_start + 1,
                                          "--max-requests");
            int64_t parsed_max = 0;
            int max_requests = 0;
            int rc = 0;

            if (max_s != NULL) {
                if (parse_i64(max_s, &parsed_max) != 0 ||
                    parsed_max < 0 || parsed_max > 100000) {
                    (void)fprintf(stderr, "ntap-a: invalid --max-requests\n");
                    return 2;
                }
                max_requests = (int)parsed_max;
            }
            rc = ntap_a_api_server_run(&cfg, once, max_requests, err, sizeof(err));
            if (rc != 0) {
                (void)fprintf(stderr, "ntap-a: api failed: %s\n", err);
            }
            return rc;
        }
        if (strcmp(argv[command_start], "network") == 0 &&
            command_start + 1 < argc &&
            strcmp(argv[command_start + 1], "add") == 0) {
            return handle_network_add(&cfg, argc, argv, command_start + 2,
                                      err, sizeof(err));
        }
        if (strcmp(argv[command_start], "node") == 0 &&
            command_start + 1 < argc &&
            strcmp(argv[command_start + 1], "add") == 0) {
            return handle_node_add(&cfg, argc, argv, command_start + 2,
                                   err, sizeof(err));
        }
        if (strcmp(argv[command_start], "node") == 0 &&
            command_start + 1 < argc &&
            strcmp(argv[command_start + 1], "list") == 0) {
            if (ntap_a_db_print_nodes(cfg.db_file, stdout, err, sizeof(err)) != 0) {
                (void)fprintf(stderr, "ntap-a: node list failed: %s\n", err);
                return 1;
            }
            return 0;
        }
        if (strcmp(argv[command_start], "tap-user") == 0 &&
            command_start + 1 < argc &&
            strcmp(argv[command_start + 1], "add") == 0) {
            return handle_tap_user_add(&cfg, argc, argv, command_start + 2,
                                       err, sizeof(err));
        }
        (void)fprintf(stderr, "ntap-a: unknown command: %s\n", argv[command_start]);
        usage(stderr);
        return 2;
    }

    (void)printf("ntap-a: phase 0 skeleton ready; use -t to validate config\n");
    return 0;
}
