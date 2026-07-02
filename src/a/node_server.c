#include "a/node_server.h"

#include "a/db_sqlite.h"
#include "common/hash.h"
#include "common/net.h"
#include "common/ntap_time.h"
#include "common/wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
typedef HANDLE ntap_thread_t;
typedef CRITICAL_SECTION ntap_mutex_t;
typedef CONDITION_VARIABLE ntap_cond_t;
#else
#include <pthread.h>
#include <sys/socket.h>
typedef pthread_t ntap_thread_t;
typedef pthread_mutex_t ntap_mutex_t;
typedef pthread_cond_t ntap_cond_t;
#endif

#define NTAP_A_MAX_ACTIVE_SESSIONS 64
#define NTAP_A_MAX_MAC_ENTRIES 512
#define NTAP_A_MAX_NETWORK_RATE_ENTRIES 128
#define NTAP_A_MAX_SOCKS_STREAMS 128
#define NTAP_A_MAC_MOVE_WINDOW_SEC 10u
#define NTAP_A_MAC_MOVE_FREEZE_THRESHOLD 2u
#define NTAP_A_MAC_FREEZE_SEC 60u
#define NTAP_A_WRITER_STALL_TIMEOUT_MS 3000u
#define NTAP_A_SOCKS_READ_CHUNK 8192u

typedef struct node_session_args {
    ntap_socket_t fd;
    ntap_a_config_t cfg;
    char remote[128];
} node_session_args_t;

typedef struct outbound_msg {
    uint8_t type;
    uint32_t session_id;
    uint32_t payload_len;
    uint32_t queued_bytes;
    uint8_t *payload;
    struct outbound_msg *next;
} outbound_msg_t;

typedef struct active_session {
    int active;
    ntap_socket_t fd;
    int64_t db_session_id;
    int64_t node_pk;
    uint32_t session_id;
    uint32_t network_id;
    int is_tap_client;
    int socks_enabled;
    uint32_t mac_ttl_sec;
    uint32_t broadcast_limit_pps;
    uint32_t session_broadcast_limit_pps;
    uint32_t max_mac_per_session;
    uint32_t tap_queue_limit_bytes;
    int allow_client_to_client;
    int allow_l2_control;
    uint64_t flood_window_sec;
    uint32_t flood_count;
    uint64_t tap_queue_window_sec;
    uint32_t tap_queue_window_bytes;
    uint32_t tap_queue_drops;
    uint32_t tap_pending_bytes;
    int writer_started;
    int writer_stop;
    ntap_thread_t writer_thread;
    ntap_mutex_t writer_mu;
    ntap_cond_t writer_cv;
    outbound_msg_t *ctrl_head;
    outbound_msg_t *ctrl_tail;
    outbound_msg_t *tap_head;
    outbound_msg_t *tap_tail;
    char node_id[NTAP_CONFIG_VALUE_MAX];
    char db_file[NTAP_CONFIG_VALUE_MAX];
} active_session_t;

typedef struct socks_stream {
    int active;
    uint32_t stream_id;
    int64_t node_pk;
    int64_t db_stream_id;
    ntap_socket_t node_fd;
    ntap_socket_t client_fd;
    char db_file[NTAP_CONFIG_VALUE_MAX];
} socks_stream_t;

typedef struct socks_client_args {
    ntap_socket_t fd;
    ntap_a_config_t cfg;
    char remote[128];
} socks_client_args_t;

typedef struct socks_listener_args {
    ntap_socket_t listen_fd;
    ntap_a_config_t cfg;
    volatile int stop;
} socks_listener_args_t;

typedef struct mac_entry {
    int active;
    uint32_t network_id;
    ntap_socket_t fd;
    uint8_t mac[6];
    uint32_t ttl_sec;
    uint64_t last_seen;
    uint64_t move_window_sec;
    uint32_t move_count;
    uint64_t frozen_until;
} mac_entry_t;

typedef struct network_rate_entry {
    int active;
    uint32_t network_id;
    uint64_t window_sec;
    uint32_t flood_count;
} network_rate_entry_t;

static active_session_t g_sessions[NTAP_A_MAX_ACTIVE_SESSIONS];
static mac_entry_t g_mac_table[NTAP_A_MAX_MAC_ENTRIES];
static network_rate_entry_t g_network_rates[NTAP_A_MAX_NETWORK_RATE_ENTRIES];
static socks_stream_t g_socks_streams[NTAP_A_MAX_SOCKS_STREAMS];
static ntap_mutex_t g_sessions_mu;
static ntap_mutex_t g_socks_mu;
static uint32_t g_next_socks_stream_id = 1u;

#ifdef _WIN32
static void mutex_init(ntap_mutex_t *mu)
{
    InitializeCriticalSection(mu);
}

static void mutex_destroy(ntap_mutex_t *mu)
{
    DeleteCriticalSection(mu);
}

static void mutex_lock(ntap_mutex_t *mu)
{
    EnterCriticalSection(mu);
}

static void mutex_unlock(ntap_mutex_t *mu)
{
    LeaveCriticalSection(mu);
}

static void cond_init(ntap_cond_t *cv)
{
    InitializeConditionVariable(cv);
}

static void cond_destroy(ntap_cond_t *cv)
{
    (void)cv;
}

static void cond_signal(ntap_cond_t *cv)
{
    WakeConditionVariable(cv);
}

static void cond_wait(ntap_cond_t *cv, ntap_mutex_t *mu)
{
    (void)SleepConditionVariableCS(cv, mu, INFINITE);
}
#else
static void mutex_init(ntap_mutex_t *mu)
{
    (void)pthread_mutex_init(mu, NULL);
}

static void mutex_destroy(ntap_mutex_t *mu)
{
    (void)pthread_mutex_destroy(mu);
}

static void mutex_lock(ntap_mutex_t *mu)
{
    (void)pthread_mutex_lock(mu);
}

static void mutex_unlock(ntap_mutex_t *mu)
{
    (void)pthread_mutex_unlock(mu);
}

static void cond_init(ntap_cond_t *cv)
{
    (void)pthread_cond_init(cv, NULL);
}

static void cond_destroy(ntap_cond_t *cv)
{
    (void)pthread_cond_destroy(cv);
}

static void cond_signal(ntap_cond_t *cv)
{
    (void)pthread_cond_signal(cv);
}

static void cond_wait(ntap_cond_t *cv, ntap_mutex_t *mu)
{
    (void)pthread_cond_wait(cv, mu);
}
#endif

static int send_auth_fail(ntap_socket_t fd, char *err, size_t err_len)
{
    return ntap_send_msg(fd, NTAP_MSG_AUTH_FAIL, 0, NULL, 0, err, err_len);
}

static int copy_config_text(char *dst, size_t dst_len, const char *src,
                            const char *field, char *err, size_t err_len)
{
    size_t len = src == NULL ? 0 : strlen(src);

    if (dst == NULL || dst_len == 0 || field == NULL) {
        return -1;
    }
    if (len >= dst_len) {
        (void)snprintf(err, err_len, "CONFIG_PUSH %s too long", field);
        return -1;
    }
    if (len > 0) {
        (void)memcpy(dst, src, len);
    }
    dst[len] = '\0';
    return 0;
}

static int send_config_push(ntap_socket_t fd, uint32_t session_id,
                            const ntap_a_runtime_config_t *runtime,
                            char *err, size_t err_len)
{
    ntap_config_push_t config;
    uint8_t payload[256];
    size_t payload_len = 0;

    if (runtime == NULL || runtime->network_id <= 0) {
        (void)snprintf(err, err_len, "missing runtime config");
        return -1;
    }
    (void)memset(&config, 0, sizeof(config));
    config.config_version = 1u;
    config.network_id = (uint32_t)runtime->network_id;
    config.tap_enabled = runtime->tap_enabled ? 1u : 0u;
    config.socks_enabled = runtime->socks_enabled ? 1u : 0u;
    config.direct_enabled = runtime->direct_enabled ? 1u : 0u;
    if (copy_config_text(config.tap_name, sizeof(config.tap_name), runtime->tap_name,
                         "tap_name", err, err_len) != 0 ||
        copy_config_text(config.bridge_name, sizeof(config.bridge_name),
                         runtime->bridge_name, "bridge_name", err, err_len) != 0) {
        return -1;
    }
    config.mtu = runtime->mtu;
    config.direct_port = runtime->direct_port;
    if (ntap_encode_config_push(payload, sizeof(payload), &payload_len, &config) != 0) {
        (void)snprintf(err, err_len, "failed to encode CONFIG_PUSH");
        return -1;
    }
    return ntap_send_msg(fd, NTAP_MSG_CONFIG_PUSH, session_id, payload,
                         (uint32_t)payload_len, err, err_len);
}

static int recv_expected(ntap_socket_t fd, uint8_t expected_type, ntap_hdr_t *hdr,
                         uint8_t *payload, size_t payload_cap, size_t *payload_len,
                         char *err, size_t err_len)
{
    if (ntap_recv_msg(fd, hdr, payload, payload_cap, payload_len, err, err_len) != 0) {
        return -1;
    }
    if (hdr->type != expected_type) {
        (void)snprintf(err, err_len, "expected %s, got %s",
                       ntap_msg_type_name(expected_type), ntap_msg_type_name(hdr->type));
        return -1;
    }
    return 0;
}

static uint32_t queued_msg_bytes(size_t payload_len)
{
    if (payload_len > 0xffffffffu - NTAP_HDR_SIZE) {
        return 0xffffffffu;
    }
    return (uint32_t)payload_len + NTAP_HDR_SIZE;
}

static void outbound_msg_free(outbound_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    free(msg->payload);
    free(msg);
}

static outbound_msg_t *outbound_msg_create(uint8_t type, uint32_t session_id,
                                           const void *payload, uint32_t payload_len)
{
    outbound_msg_t *msg = (outbound_msg_t *)calloc(1u, sizeof(*msg));

    if (msg == NULL) {
        return NULL;
    }
    msg->type = type;
    msg->session_id = session_id;
    msg->payload_len = payload_len;
    msg->queued_bytes = queued_msg_bytes(payload_len);
    if (payload_len > 0) {
        msg->payload = (uint8_t *)malloc(payload_len);
        if (msg->payload == NULL) {
            outbound_msg_free(msg);
            return NULL;
        }
        (void)memcpy(msg->payload, payload, payload_len);
    }
    return msg;
}

static void queue_append(outbound_msg_t **head, outbound_msg_t **tail,
                         outbound_msg_t *msg)
{
    if (*tail != NULL) {
        (*tail)->next = msg;
    } else {
        *head = msg;
    }
    *tail = msg;
}

static outbound_msg_t *queue_pop(outbound_msg_t **head, outbound_msg_t **tail)
{
    outbound_msg_t *msg = *head;

    if (msg == NULL) {
        return NULL;
    }
    *head = msg->next;
    if (*head == NULL) {
        *tail = NULL;
    }
    msg->next = NULL;
    return msg;
}

static void session_queue_clear_locked(active_session_t *session)
{
    outbound_msg_t *msg = NULL;

    while ((msg = queue_pop(&session->ctrl_head, &session->ctrl_tail)) != NULL) {
        outbound_msg_free(msg);
    }
    while ((msg = queue_pop(&session->tap_head, &session->tap_tail)) != NULL) {
        outbound_msg_free(msg);
    }
    session->tap_pending_bytes = 0;
}

static outbound_msg_t *session_queue_pop_locked(active_session_t *session)
{
    outbound_msg_t *msg = queue_pop(&session->ctrl_head, &session->ctrl_tail);

    if (msg != NULL) {
        return msg;
    }
    msg = queue_pop(&session->tap_head, &session->tap_tail);
    if (msg != NULL) {
        if (session->tap_pending_bytes >= msg->queued_bytes) {
            session->tap_pending_bytes -= msg->queued_bytes;
        } else {
            session->tap_pending_bytes = 0;
        }
    }
    return msg;
}

static int session_enqueue_control(active_session_t *session, uint8_t type,
                                   const void *payload, uint32_t payload_len,
                                   char *err, size_t err_len)
{
    outbound_msg_t *msg = outbound_msg_create(type, session->session_id,
                                              payload, payload_len);

    if (msg == NULL) {
        (void)snprintf(err, err_len, "failed to allocate control queue message");
        return -1;
    }
    mutex_lock(&session->writer_mu);
    if (!session->writer_started || session->writer_stop) {
        mutex_unlock(&session->writer_mu);
        outbound_msg_free(msg);
        (void)snprintf(err, err_len, "writer is not active");
        return -1;
    }
    queue_append(&session->ctrl_head, &session->ctrl_tail, msg);
    cond_signal(&session->writer_cv);
    mutex_unlock(&session->writer_mu);
    return 0;
}

static int session_enqueue_tap(active_session_t *session, const void *payload,
                               uint32_t payload_len, int enforce_flood_budget,
                               uint64_t now, char *err, size_t err_len)
{
    outbound_msg_t *msg = NULL;
    uint32_t frame_bytes = queued_msg_bytes(payload_len);
    uint32_t limit = 0;

    mutex_lock(&session->writer_mu);
    if (!session->writer_started || session->writer_stop) {
        mutex_unlock(&session->writer_mu);
        (void)snprintf(err, err_len, "writer is not active");
        return -1;
    }
    if (enforce_flood_budget) {
        limit = session->tap_queue_limit_bytes == 0 ?
                NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES :
                session->tap_queue_limit_bytes;
        if (session->tap_queue_window_sec != now) {
            session->tap_queue_window_sec = now;
            session->tap_queue_window_bytes = 0;
        }
        if (frame_bytes > limit ||
            session->tap_pending_bytes > limit - frame_bytes ||
            session->tap_queue_window_bytes > limit - frame_bytes) {
            session->tap_queue_drops++;
            (void)printf("ntap-a: tap queue drop session=%s network_id=%u queued=%u frame=%u limit=%u drops=%u\n",
                         session->node_id, session->network_id,
                         session->tap_pending_bytes, frame_bytes, limit,
                         session->tap_queue_drops);
            (void)fflush(stdout);
            mutex_unlock(&session->writer_mu);
            return 0;
        }
    }
    msg = outbound_msg_create(NTAP_MSG_TAP_FRAME, session->session_id,
                              payload, payload_len);
    if (msg == NULL) {
        mutex_unlock(&session->writer_mu);
        (void)snprintf(err, err_len, "failed to allocate TAP queue message");
        return -1;
    }
    session->tap_pending_bytes += msg->queued_bytes;
    if (enforce_flood_budget) {
        session->tap_queue_window_bytes += msg->queued_bytes;
    }
    queue_append(&session->tap_head, &session->tap_tail, msg);
    cond_signal(&session->writer_cv);
    mutex_unlock(&session->writer_mu);
    return 1;
}

static void session_writer_run(active_session_t *session)
{
    char err[256];

    err[0] = '\0';
    for (;;) {
        outbound_msg_t *msg = NULL;

        mutex_lock(&session->writer_mu);
        while (!session->writer_stop && session->ctrl_head == NULL &&
               session->tap_head == NULL) {
            cond_wait(&session->writer_cv, &session->writer_mu);
        }
        if (session->writer_stop) {
            session_queue_clear_locked(session);
            mutex_unlock(&session->writer_mu);
            break;
        }
        msg = session_queue_pop_locked(session);
        mutex_unlock(&session->writer_mu);

        if (msg == NULL) {
            continue;
        }
        if (ntap_send_msg_timeout(session->fd, msg->type, msg->session_id,
                                  msg->payload, msg->payload_len,
                                  NTAP_A_WRITER_STALL_TIMEOUT_MS,
                                  err, sizeof(err)) != 0) {
            (void)fprintf(stderr, "ntap-a: writer send failed session=%s: %s\n",
                          session->node_id, err);
            outbound_msg_free(msg);
            ntap_socket_shutdown(session->fd);
            mutex_lock(&session->writer_mu);
            session->writer_stop = 1;
            session_queue_clear_locked(session);
            mutex_unlock(&session->writer_mu);
            break;
        }
        if (msg->type == NTAP_MSG_TAP_FRAME && session->db_session_id > 0 &&
            ntap_a_db_session_touch(session->db_file, session->db_session_id,
                                    0, msg->payload_len, err, sizeof(err)) != 0) {
            (void)fprintf(stderr, "ntap-a: failed to update session out_bytes session=%s: %s\n",
                          session->node_id, err);
        }
        outbound_msg_free(msg);
    }
}

#ifdef _WIN32
static DWORD WINAPI session_writer_thread_main(LPVOID opaque)
{
    session_writer_run((active_session_t *)opaque);
    return 0;
}

static int start_writer_thread(active_session_t *session)
{
    session->writer_thread = CreateThread(NULL, 0, session_writer_thread_main,
                                          session, 0, NULL);
    return session->writer_thread == NULL ? -1 : 0;
}

static void join_writer_thread(active_session_t *session)
{
    (void)WaitForSingleObject(session->writer_thread, INFINITE);
    (void)CloseHandle(session->writer_thread);
}
#else
static void *session_writer_thread_main(void *opaque)
{
    session_writer_run((active_session_t *)opaque);
    return NULL;
}

static int start_writer_thread(active_session_t *session)
{
    return pthread_create(&session->writer_thread, NULL,
                          session_writer_thread_main, session);
}

static void join_writer_thread(active_session_t *session)
{
    (void)pthread_join(session->writer_thread, NULL);
}
#endif

static void session_stop_writer(active_session_t *session)
{
    if (session == NULL || !session->writer_started) {
        return;
    }
    mutex_lock(&session->writer_mu);
    session->writer_stop = 1;
    cond_signal(&session->writer_cv);
    mutex_unlock(&session->writer_mu);
    ntap_socket_shutdown(session->fd);
    join_writer_thread(session);
    session->writer_started = 0;
    cond_destroy(&session->writer_cv);
    mutex_destroy(&session->writer_mu);
}

static void session_registry_reset(void)
{
    mutex_lock(&g_sessions_mu);
    (void)memset(g_sessions, 0, sizeof(g_sessions));
    (void)memset(g_mac_table, 0, sizeof(g_mac_table));
    (void)memset(g_network_rates, 0, sizeof(g_network_rates));
    mutex_unlock(&g_sessions_mu);
}

static void socks_stream_registry_reset(void)
{
    mutex_lock(&g_socks_mu);
    (void)memset(g_socks_streams, 0, sizeof(g_socks_streams));
    g_next_socks_stream_id = 1u;
    mutex_unlock(&g_socks_mu);
}

static uint32_t socks_next_stream_id_locked(void)
{
    uint32_t id = g_next_socks_stream_id++;

    if (g_next_socks_stream_id == 0) {
        g_next_socks_stream_id = 1u;
    }
    return id == 0 ? socks_next_stream_id_locked() : id;
}

static unsigned int socks_idle_timeout_ms(uint32_t idle_timeout_sec)
{
    uint32_t effective = idle_timeout_sec == 0 ?
                         NTAP_A_DEFAULT_SOCKS_IDLE_TIMEOUT_SEC :
                         idle_timeout_sec;
    uint32_t max_sec = ((uint32_t)-1) / 1000u;

    if (effective > max_sec) {
        return (unsigned int)(max_sec * 1000u);
    }
    return (unsigned int)(effective * 1000u);
}

static const char *socks_close_reason_name(uint16_t reason_code)
{
    switch (reason_code) {
    case NTAP_SOCKS_CLOSE_REASON_TARGET_CONNECT_FAILED:
        return "target_connect_failed";
    case NTAP_SOCKS_CLOSE_REASON_RESOURCE_LIMITED:
        return "resource_limited";
    case NTAP_SOCKS_CLOSE_REASON_IDLE_TIMEOUT:
        return "idle_timeout";
    case NTAP_SOCKS_CLOSE_REASON_CLIENT_CLOSED:
        return "client_closed";
    case NTAP_SOCKS_CLOSE_REASON_CLOSED:
    case NTAP_SOCKS_CLOSE_REASON_REMOTE_CLOSED:
    default:
        return "remote_closed";
    }
}

static uint32_t socks_stream_register(int64_t node_pk, ntap_socket_t node_fd,
                                      ntap_socket_t client_fd,
                                      const char *db_file,
                                      uint32_t max_socks_streams)
{
    int i = 0;
    uint32_t active_for_node = 0;
    uint32_t stream_id = 0;

    if (node_pk <= 0 || node_fd == NTAP_INVALID_SOCKET ||
        client_fd == NTAP_INVALID_SOCKET || db_file == NULL ||
        *db_file == '\0') {
        return 0;
    }
    if (max_socks_streams == 0) {
        max_socks_streams = NTAP_A_DEFAULT_MAX_SOCKS_STREAMS;
    }
    mutex_lock(&g_socks_mu);
    for (i = 0; i < NTAP_A_MAX_SOCKS_STREAMS; i++) {
        if (g_socks_streams[i].active &&
            g_socks_streams[i].node_pk == node_pk) {
            active_for_node++;
        }
    }
    if (active_for_node >= max_socks_streams) {
        mutex_unlock(&g_socks_mu);
        return 0;
    }
    for (i = 0; i < NTAP_A_MAX_SOCKS_STREAMS; i++) {
        if (!g_socks_streams[i].active) {
            stream_id = socks_next_stream_id_locked();
            g_socks_streams[i].active = 1;
            g_socks_streams[i].stream_id = stream_id;
            g_socks_streams[i].node_pk = node_pk;
            g_socks_streams[i].node_fd = node_fd;
            g_socks_streams[i].client_fd = client_fd;
            g_socks_streams[i].db_stream_id = 0;
            (void)snprintf(g_socks_streams[i].db_file,
                           sizeof(g_socks_streams[i].db_file), "%s", db_file);
            break;
        }
    }
    mutex_unlock(&g_socks_mu);
    return stream_id;
}

static void socks_stream_set_db_id(uint32_t stream_id, int64_t db_stream_id)
{
    int i = 0;

    if (stream_id == 0 || db_stream_id <= 0) {
        return;
    }
    mutex_lock(&g_socks_mu);
    for (i = 0; i < NTAP_A_MAX_SOCKS_STREAMS; i++) {
        if (g_socks_streams[i].active &&
            g_socks_streams[i].stream_id == stream_id) {
            g_socks_streams[i].db_stream_id = db_stream_id;
            break;
        }
    }
    mutex_unlock(&g_socks_mu);
}

static void socks_stream_unregister(uint32_t stream_id, int close_client,
                                    const char *reason)
{
    int i = 0;
    ntap_socket_t client_fd = NTAP_INVALID_SOCKET;
    int64_t db_stream_id = 0;
    char db_file[NTAP_CONFIG_VALUE_MAX];

    if (stream_id == 0) {
        return;
    }
    db_file[0] = '\0';
    mutex_lock(&g_socks_mu);
    for (i = 0; i < NTAP_A_MAX_SOCKS_STREAMS; i++) {
        if (g_socks_streams[i].active &&
            g_socks_streams[i].stream_id == stream_id) {
            client_fd = g_socks_streams[i].client_fd;
            db_stream_id = g_socks_streams[i].db_stream_id;
            (void)snprintf(db_file, sizeof(db_file), "%s",
                           g_socks_streams[i].db_file);
            g_socks_streams[i].active = 0;
            break;
        }
    }
    mutex_unlock(&g_socks_mu);
    if (close_client && client_fd != NTAP_INVALID_SOCKET) {
        ntap_socket_shutdown(client_fd);
    }
    if (db_stream_id > 0 && db_file[0] != '\0') {
        char db_err[256];

        db_err[0] = '\0';
        if (ntap_a_db_socks_stream_end(db_file, db_stream_id, reason,
                                       db_err, sizeof(db_err)) != 0) {
            (void)fprintf(stderr, "ntap-a: failed to end SOCKS stream: %s\n",
                          db_err);
        }
    }
}

static void socks_stream_close_node(ntap_socket_t node_fd)
{
    typedef struct socks_stream_close_item {
        ntap_socket_t client_fd;
        int64_t db_stream_id;
        char db_file[NTAP_CONFIG_VALUE_MAX];
    } socks_stream_close_item_t;

    int i = 0;
    socks_stream_close_item_t to_close[NTAP_A_MAX_SOCKS_STREAMS];
    int count = 0;

    if (node_fd == NTAP_INVALID_SOCKET) {
        return;
    }
    mutex_lock(&g_socks_mu);
    for (i = 0; i < NTAP_A_MAX_SOCKS_STREAMS; i++) {
        if (g_socks_streams[i].active && g_socks_streams[i].node_fd == node_fd) {
            to_close[count].client_fd = g_socks_streams[i].client_fd;
            to_close[count].db_stream_id = g_socks_streams[i].db_stream_id;
            (void)snprintf(to_close[count].db_file,
                           sizeof(to_close[count].db_file), "%s",
                           g_socks_streams[i].db_file);
            count++;
            g_socks_streams[i].active = 0;
        }
    }
    mutex_unlock(&g_socks_mu);
    for (i = 0; i < count; i++) {
        ntap_socket_shutdown(to_close[i].client_fd);
        if (to_close[i].db_stream_id > 0 && to_close[i].db_file[0] != '\0') {
            char db_err[256];

            db_err[0] = '\0';
            if (ntap_a_db_socks_stream_end(to_close[i].db_file,
                                           to_close[i].db_stream_id,
                                           "node_closed", db_err,
                                           sizeof(db_err)) != 0) {
                (void)fprintf(stderr,
                              "ntap-a: failed to end SOCKS stream: %s\n",
                              db_err);
            }
        }
    }
}

static int socks_stream_send_to_client(uint32_t stream_id, ntap_socket_t node_fd,
                                       const uint8_t *data, uint32_t data_len,
                                       char *err, size_t err_len)
{
    int i = 0;
    ntap_socket_t client_fd = NTAP_INVALID_SOCKET;
    int64_t db_stream_id = 0;
    char db_file[NTAP_CONFIG_VALUE_MAX];
    int rc = 0;

    if (stream_id == 0 || data == NULL || data_len == 0) {
        return -1;
    }
    db_file[0] = '\0';
    mutex_lock(&g_socks_mu);
    for (i = 0; i < NTAP_A_MAX_SOCKS_STREAMS; i++) {
        if (g_socks_streams[i].active &&
            g_socks_streams[i].stream_id == stream_id &&
            g_socks_streams[i].node_fd == node_fd) {
            client_fd = g_socks_streams[i].client_fd;
            db_stream_id = g_socks_streams[i].db_stream_id;
            (void)snprintf(db_file, sizeof(db_file), "%s",
                           g_socks_streams[i].db_file);
            break;
        }
    }
    mutex_unlock(&g_socks_mu);
    if (client_fd == NTAP_INVALID_SOCKET) {
        (void)snprintf(err, err_len, "socks stream not found");
        return -1;
    }
    rc = ntap_send_all(client_fd, data, data_len, err, err_len);
    if (rc == 0 && db_stream_id > 0 && db_file[0] != '\0') {
        char db_err[256];

        db_err[0] = '\0';
        if (ntap_a_db_socks_stream_touch(db_file, db_stream_id, 0,
                                         data_len, db_err,
                                         sizeof(db_err)) != 0) {
            (void)fprintf(stderr,
                          "ntap-a: failed to update SOCKS stream: %s\n",
                          db_err);
        }
    }
    return rc;
}

static int enqueue_socks_to_node(int64_t node_pk, uint8_t type,
                                 const void *payload, uint32_t payload_len,
                                 ntap_socket_t *out_node_fd,
                                 char *err, size_t err_len)
{
    int i = 0;
    int rc = -1;

    mutex_lock(&g_sessions_mu);
    for (i = 0; i < NTAP_A_MAX_ACTIVE_SESSIONS; i++) {
        if (g_sessions[i].active && !g_sessions[i].is_tap_client &&
            g_sessions[i].node_pk == node_pk && g_sessions[i].socks_enabled) {
            if (out_node_fd != NULL) {
                *out_node_fd = g_sessions[i].fd;
            }
            rc = session_enqueue_control(&g_sessions[i], type, payload,
                                         payload_len, err, err_len);
            mutex_unlock(&g_sessions_mu);
            return rc;
        }
    }
    mutex_unlock(&g_sessions_mu);
    (void)snprintf(err, err_len, "no active SOCKS node");
    return -1;
}

static int socks_active_node_fd(int64_t node_pk, ntap_socket_t *out_fd,
                                int64_t *out_db_session_id,
                                char *err, size_t err_len)
{
    int i = 0;

    if (out_fd == NULL || out_db_session_id == NULL || node_pk <= 0) {
        return -1;
    }
    *out_fd = NTAP_INVALID_SOCKET;
    *out_db_session_id = 0;
    mutex_lock(&g_sessions_mu);
    for (i = 0; i < NTAP_A_MAX_ACTIVE_SESSIONS; i++) {
        if (g_sessions[i].active && !g_sessions[i].is_tap_client &&
            g_sessions[i].node_pk == node_pk && g_sessions[i].socks_enabled) {
            *out_fd = g_sessions[i].fd;
            *out_db_session_id = g_sessions[i].db_session_id;
            mutex_unlock(&g_sessions_mu);
            return 0;
        }
    }
    mutex_unlock(&g_sessions_mu);
    (void)snprintf(err, err_len, "no active SOCKS node");
    return -1;
}

static int mac_equal(const uint8_t a[6], const uint8_t b[6])
{
    return memcmp(a, b, 6u) == 0;
}

static int mac_is_zero(const uint8_t mac[6])
{
    static const uint8_t zero[6] = {0, 0, 0, 0, 0, 0};

    return mac_equal(mac, zero);
}

static int mac_is_broadcast(const uint8_t mac[6])
{
    static const uint8_t broadcast[6] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    return mac_equal(mac, broadcast);
}

static int mac_is_multicast(const uint8_t mac[6])
{
    return (mac[0] & 0x01u) != 0;
}

static int mac_is_l2_control(const uint8_t mac[6])
{
    return mac[0] == 0x01u && mac[1] == 0x80u && mac[2] == 0xc2u &&
           mac[3] == 0x00u && mac[4] == 0x00u && mac[5] <= 0x0fu;
}

static int mac_is_learnable_src(const uint8_t mac[6])
{
    return !mac_is_zero(mac) && !mac_is_multicast(mac);
}

static void mac_to_text(const uint8_t mac[6], char out[18])
{
    (void)snprintf(out, 18u, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int session_active_locked(ntap_socket_t fd, uint32_t network_id)
{
    int i = 0;

    for (i = 0; i < NTAP_A_MAX_ACTIVE_SESSIONS; i++) {
        if (g_sessions[i].active && g_sessions[i].fd == fd &&
            g_sessions[i].network_id == network_id) {
            return 1;
        }
    }
    return 0;
}

static active_session_t *session_find_locked(ntap_socket_t fd, uint32_t network_id)
{
    int i = 0;

    for (i = 0; i < NTAP_A_MAX_ACTIVE_SESSIONS; i++) {
        if (g_sessions[i].active && g_sessions[i].fd == fd &&
            g_sessions[i].network_id == network_id) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

static void mac_age_locked(uint64_t now)
{
    int i = 0;
    uint32_t ttl = 0;

    for (i = 0; i < NTAP_A_MAX_MAC_ENTRIES; i++) {
        ttl = g_mac_table[i].ttl_sec == 0 ? NTAP_A_DEFAULT_MAC_TTL_SEC :
              g_mac_table[i].ttl_sec;
        if (g_mac_table[i].active &&
            ((now > g_mac_table[i].last_seen &&
              now - g_mac_table[i].last_seen > ttl) ||
             !session_active_locked(g_mac_table[i].fd, g_mac_table[i].network_id))) {
            g_mac_table[i].active = 0;
        }
    }
}

static int mac_count_for_fd_locked(ntap_socket_t fd, uint32_t network_id)
{
    int i = 0;
    int count = 0;

    for (i = 0; i < NTAP_A_MAX_MAC_ENTRIES; i++) {
        if (g_mac_table[i].active && g_mac_table[i].fd == fd &&
            g_mac_table[i].network_id == network_id) {
            count++;
        }
    }
    return count;
}

static int mac_learn_locked(const active_session_t *session, const uint8_t mac[6],
                            uint64_t now)
{
    int i = 0;
    int free_slot = -1;

    if (session == NULL || !mac_is_learnable_src(mac)) {
        return 0;
    }
    for (i = 0; i < NTAP_A_MAX_MAC_ENTRIES; i++) {
        if (g_mac_table[i].active && g_mac_table[i].network_id == session->network_id &&
            mac_equal(g_mac_table[i].mac, mac)) {
            if (g_mac_table[i].fd != session->fd) {
                char mac_text[18];

                mac_to_text(mac, mac_text);
                if (g_mac_table[i].frozen_until > now) {
                    (void)printf("ntap-a: mac freeze drop network_id=%u mac=%s source=%s\n",
                                 session->network_id, mac_text, session->node_id);
                    (void)fflush(stdout);
                    return -1;
                }
                if (g_mac_table[i].move_window_sec == 0 ||
                    now - g_mac_table[i].move_window_sec > NTAP_A_MAC_MOVE_WINDOW_SEC) {
                    g_mac_table[i].move_window_sec = now;
                    g_mac_table[i].move_count = 0;
                }
                g_mac_table[i].move_count++;
                if (g_mac_table[i].move_count >= NTAP_A_MAC_MOVE_FREEZE_THRESHOLD) {
                    g_mac_table[i].frozen_until = now + NTAP_A_MAC_FREEZE_SEC;
                    (void)printf("ntap-a: mac frozen network_id=%u mac=%s freeze_sec=%u\n",
                                 session->network_id, mac_text,
                                 NTAP_A_MAC_FREEZE_SEC);
                    (void)fflush(stdout);
                    return -1;
                }
                (void)printf("ntap-a: mac moved network_id=%u mac=%s\n",
                             session->network_id, mac_text);
                (void)fflush(stdout);
            } else if (g_mac_table[i].frozen_until <= now) {
                g_mac_table[i].frozen_until = 0;
            }
            g_mac_table[i].fd = session->fd;
            g_mac_table[i].ttl_sec = session->mac_ttl_sec;
            g_mac_table[i].last_seen = now;
            return 0;
        }
        if (!g_mac_table[i].active && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0 ||
        mac_count_for_fd_locked(session->fd, session->network_id) >=
            (int)session->max_mac_per_session) {
        return 0;
    }
    g_mac_table[free_slot].active = 1;
    g_mac_table[free_slot].network_id = session->network_id;
    g_mac_table[free_slot].fd = session->fd;
    (void)memcpy(g_mac_table[free_slot].mac, mac, 6u);
    g_mac_table[free_slot].ttl_sec = session->mac_ttl_sec;
    g_mac_table[free_slot].last_seen = now;
    g_mac_table[free_slot].move_window_sec = now;
    g_mac_table[free_slot].move_count = 0;
    g_mac_table[free_slot].frozen_until = 0;
    return 0;
}

static int mac_lookup_locked(uint32_t network_id, const uint8_t mac[6],
                             active_session_t **session)
{
    int i = 0;
    int j = 0;

    if (session == NULL || mac_is_multicast(mac)) {
        return 0;
    }
    *session = NULL;
    for (i = 0; i < NTAP_A_MAX_MAC_ENTRIES; i++) {
        if (!g_mac_table[i].active || g_mac_table[i].network_id != network_id ||
            !mac_equal(g_mac_table[i].mac, mac)) {
            continue;
        }
        for (j = 0; j < NTAP_A_MAX_ACTIVE_SESSIONS; j++) {
            if (g_sessions[j].active && g_sessions[j].fd == g_mac_table[i].fd &&
                g_sessions[j].network_id == network_id) {
                *session = &g_sessions[j];
                return 1;
            }
        }
        g_mac_table[i].active = 0;
        return 0;
    }
    return 0;
}

static void mac_forget_fd_locked(ntap_socket_t fd)
{
    int i = 0;

    for (i = 0; i < NTAP_A_MAX_MAC_ENTRIES; i++) {
        if (g_mac_table[i].active && g_mac_table[i].fd == fd) {
            g_mac_table[i].active = 0;
        }
    }
}

static network_rate_entry_t *network_rate_entry_locked(uint32_t network_id)
{
    int i = 0;
    int free_slot = -1;

    for (i = 0; i < NTAP_A_MAX_NETWORK_RATE_ENTRIES; i++) {
        if (g_network_rates[i].active && g_network_rates[i].network_id == network_id) {
            return &g_network_rates[i];
        }
        if (!g_network_rates[i].active && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        return NULL;
    }
    g_network_rates[free_slot].active = 1;
    g_network_rates[free_slot].network_id = network_id;
    return &g_network_rates[free_slot];
}

static int flood_allowed_locked(active_session_t *session, uint64_t now)
{
    network_rate_entry_t *network_rate = NULL;

    if (session == NULL) {
        return 0;
    }
    if (session->session_broadcast_limit_pps > 0) {
        if (session->flood_window_sec != now) {
            session->flood_window_sec = now;
            session->flood_count = 0;
        }
        if (session->flood_count >= session->session_broadcast_limit_pps) {
            return 0;
        }
    }
    if (session->broadcast_limit_pps > 0) {
        network_rate = network_rate_entry_locked(session->network_id);
        if (network_rate == NULL) {
            return 0;
        }
        if (network_rate->window_sec != now) {
            network_rate->window_sec = now;
            network_rate->flood_count = 0;
        }
        if (network_rate->flood_count >= session->broadcast_limit_pps) {
            return 0;
        }
    }
    if (session->session_broadcast_limit_pps > 0) {
        session->flood_count++;
    }
    if (network_rate != NULL && session->broadcast_limit_pps > 0) {
        network_rate->flood_count++;
    }
    return 1;
}

static uint32_t runtime_u32_default(uint32_t value, uint32_t fallback)
{
    return value == 0 ? fallback : value;
}

static int session_register(ntap_socket_t fd, const char *node_id,
                            uint32_t session_id, uint32_t network_id,
                            int64_t node_pk,
                            int is_tap_client,
                            const ntap_a_runtime_config_t *runtime,
                            int64_t db_session_id, const char *db_file,
                            char *err, size_t err_len)
{
    int i = 0;

    if (runtime == NULL) {
        (void)snprintf(err, err_len, "missing runtime config for session");
        return -1;
    }
    mutex_lock(&g_sessions_mu);
    for (i = 0; i < NTAP_A_MAX_ACTIVE_SESSIONS; i++) {
        if (!g_sessions[i].active) {
            (void)memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            mutex_init(&g_sessions[i].writer_mu);
            cond_init(&g_sessions[i].writer_cv);
            g_sessions[i].active = 1;
            g_sessions[i].fd = fd;
            g_sessions[i].db_session_id = db_session_id;
            g_sessions[i].node_pk = node_pk;
            g_sessions[i].session_id = session_id;
            g_sessions[i].network_id = network_id;
            g_sessions[i].is_tap_client = is_tap_client ? 1 : 0;
            g_sessions[i].socks_enabled = runtime->socks_enabled ? 1 : 0;
            g_sessions[i].mac_ttl_sec =
                runtime_u32_default(runtime->mac_ttl_sec, NTAP_A_DEFAULT_MAC_TTL_SEC);
            g_sessions[i].broadcast_limit_pps = runtime->broadcast_limit_pps;
            g_sessions[i].session_broadcast_limit_pps =
                runtime->session_broadcast_limit_pps;
            g_sessions[i].max_mac_per_session =
                runtime_u32_default(runtime->max_mac_per_session,
                                    NTAP_A_DEFAULT_MAX_MAC_PER_SESSION);
            g_sessions[i].tap_queue_limit_bytes =
                runtime_u32_default(runtime->tap_queue_limit_bytes,
                                    NTAP_A_DEFAULT_TAP_QUEUE_LIMIT_BYTES);
            g_sessions[i].allow_client_to_client =
                runtime->allow_client_to_client ? 1 : 0;
            g_sessions[i].allow_l2_control = runtime->allow_l2_control ? 1 : 0;
            g_sessions[i].flood_window_sec = 0;
            g_sessions[i].flood_count = 0;
            g_sessions[i].tap_queue_window_sec = 0;
            g_sessions[i].tap_queue_window_bytes = 0;
            g_sessions[i].tap_queue_drops = 0;
            (void)snprintf(g_sessions[i].node_id, sizeof(g_sessions[i].node_id),
                           "%s", node_id);
            (void)snprintf(g_sessions[i].db_file, sizeof(g_sessions[i].db_file),
                           "%s", db_file == NULL ? "" : db_file);
            if (ntap_socket_set_nonblocking(fd, 1, err, err_len) != 0) {
                g_sessions[i].active = 0;
                cond_destroy(&g_sessions[i].writer_cv);
                mutex_destroy(&g_sessions[i].writer_mu);
                mutex_unlock(&g_sessions_mu);
                return -1;
            }
            if (start_writer_thread(&g_sessions[i]) != 0) {
                g_sessions[i].active = 0;
                cond_destroy(&g_sessions[i].writer_cv);
                mutex_destroy(&g_sessions[i].writer_mu);
                mutex_unlock(&g_sessions_mu);
                (void)snprintf(err, err_len, "failed to start writer thread");
                return -1;
            }
            g_sessions[i].writer_started = 1;
            mutex_unlock(&g_sessions_mu);
            return 0;
        }
    }
    mutex_unlock(&g_sessions_mu);
    (void)snprintf(err, err_len, "active session limit reached");
    return -1;
}

static void session_unregister(ntap_socket_t fd)
{
    int i = 0;
    active_session_t *session = NULL;

    mutex_lock(&g_sessions_mu);
    mac_forget_fd_locked(fd);
    for (i = 0; i < NTAP_A_MAX_ACTIVE_SESSIONS; i++) {
        if (g_sessions[i].active && g_sessions[i].fd == fd) {
            g_sessions[i].active = 0;
            session = &g_sessions[i];
            break;
        }
    }
    mutex_unlock(&g_sessions_mu);
    socks_stream_close_node(fd);
    session_stop_writer(session);
}

static int relay_tap_frame(ntap_socket_t from_fd, uint32_t network_id,
                           const ntap_tap_frame_t *frame,
                           const uint8_t *payload, size_t payload_len,
                           const char **mode,
                           char *err, size_t err_len)
{
    int i = 0;
    int forwarded = 0;
    uint64_t now = ntap_time_unix_sec();
    const uint8_t *dst = NULL;
    const uint8_t *src = NULL;
    active_session_t *source = NULL;
    active_session_t *target = NULL;
    int known_unicast = 0;
    int queue_dropped = 0;
    int enqueue_rc = 0;

    if (frame == NULL || frame->frame == NULL || frame->frame_len < 14u) {
        return 0;
    }
    if (mode != NULL) {
        *mode = "flood";
    }
    dst = frame->frame;
    src = frame->frame + 6u;
    mutex_lock(&g_sessions_mu);
    mac_age_locked(now);
    source = session_find_locked(from_fd, network_id);
    if (source == NULL) {
        if (mode != NULL) {
            *mode = "drop_session";
        }
        mutex_unlock(&g_sessions_mu);
        return 0;
    }
    if (mac_is_l2_control(dst) && !source->allow_l2_control) {
        if (mode != NULL) {
            *mode = "drop_l2";
        }
        mutex_unlock(&g_sessions_mu);
        return 0;
    }
    if (mac_learn_locked(source, src, now) != 0) {
        if (mode != NULL) {
            *mode = "drop_mac_freeze";
        }
        mutex_unlock(&g_sessions_mu);
        return 0;
    }
    known_unicast = !mac_is_broadcast(dst) && !mac_is_multicast(dst) &&
                    mac_lookup_locked(network_id, dst, &target);
    if (known_unicast) {
        if (mode != NULL) {
            *mode = "unicast";
        }
        if (target != NULL && target->fd != from_fd) {
            if (source->is_tap_client && target->is_tap_client &&
                !source->allow_client_to_client) {
                if (mode != NULL) {
                    *mode = "drop_client";
                }
                mutex_unlock(&g_sessions_mu);
                return 0;
            }
            enqueue_rc = session_enqueue_tap(target, payload, (uint32_t)payload_len,
                                             0, now, err, err_len);
            if (enqueue_rc > 0) {
                forwarded++;
            } else if (enqueue_rc < 0) {
                if (mode != NULL) {
                    *mode = "drop_queue";
                }
            }
        }
        mutex_unlock(&g_sessions_mu);
        return forwarded;
    }
    if (!flood_allowed_locked(source, now)) {
        if (mode != NULL) {
            *mode = "drop_rate";
        }
        mutex_unlock(&g_sessions_mu);
        return 0;
    }
    for (i = 0; i < NTAP_A_MAX_ACTIVE_SESSIONS; i++) {
        if (!g_sessions[i].active || g_sessions[i].fd == from_fd ||
            g_sessions[i].network_id != network_id) {
            continue;
        }
        if (source->is_tap_client && g_sessions[i].is_tap_client &&
            !source->allow_client_to_client) {
            continue;
        }
        enqueue_rc = session_enqueue_tap(&g_sessions[i], payload,
                                         (uint32_t)payload_len, 1, now,
                                         err, err_len);
        if (enqueue_rc == 0) {
            queue_dropped++;
            continue;
        }
        if (enqueue_rc > 0) {
            forwarded++;
            continue;
        }
    }
    if (forwarded == 0 && queue_dropped > 0 && mode != NULL) {
        *mode = "drop_queue";
    }
    mutex_unlock(&g_sessions_mu);
    return forwarded;
}

static int handle_node(ntap_socket_t fd, const ntap_a_config_t *cfg,
                       const char *remote,
                       char *err, size_t err_len)
{
    uint8_t payload[NTAP_PAYLOAD_MAX_CONTROL];
    uint8_t reply[NTAP_PAYLOAD_MAX_CONTROL];
    size_t payload_len = 0;
    size_t reply_len = 0;
    ntap_hdr_t hdr;
    ntap_hello_t hello;
    ntap_auth_node_t auth;
    ntap_auth_tap_t tap_auth;
    ntap_a_node_auth_t node;
    ntap_a_tap_auth_t tap_user;
    ntap_a_runtime_config_t runtime_config;
    uint8_t server_nonce[NTAP_NONCE_SIZE];
    uint8_t expected_sign[NTAP_HMAC_SHA256_SIZE];
    ntap_auth_ok_t auth_ok;
    uint8_t auth_ok_payload[NTAP_AUTH_OK_SIZE];
    char authenticated_node_id[NTAP_NODE_ID_MAX];
    char session_name[NTAP_CONFIG_VALUE_MAX];
    int64_t db_session_id = 0;
    int authenticated = 0;
    int authenticated_is_node = 0;
    int registered = 0;

    authenticated_node_id[0] = '\0';
    session_name[0] = '\0';

    if (recv_expected(fd, NTAP_MSG_HELLO, &hdr, payload, sizeof(payload),
                      &payload_len, err, err_len) != 0 ||
        ntap_decode_hello(&hello, payload, payload_len) != 0) {
        return -1;
    }
    if (hello.role != NTAP_ROLE_NODE && hello.role != NTAP_ROLE_TAP_CLIENT) {
        (void)snprintf(err, err_len, "unsupported role %u", hello.role);
        return -1;
    }
    if (ntap_random_nonce(server_nonce) != 0 ||
        ntap_encode_hello(reply, sizeof(reply), &reply_len, NTAP_ROLE_SERVER,
                          "ntap-a/0.1", 0, server_nonce) != 0 ||
        ntap_send_msg(fd, NTAP_MSG_HELLO, 0, reply, (uint32_t)reply_len,
                      err, err_len) != 0) {
        return -1;
    }

    if (hello.role == NTAP_ROLE_NODE) {
        if (recv_expected(fd, NTAP_MSG_AUTH_NODE, &hdr, payload, sizeof(payload),
                          &payload_len, err, err_len) != 0 ||
            ntap_decode_auth_node(&auth, payload, payload_len) != 0) {
            return -1;
        }
        if (!ntap_constant_time_equal(hello.nonce, auth.client_nonce, NTAP_NONCE_SIZE)) {
            (void)send_auth_fail(fd, err, err_len);
            (void)snprintf(err, err_len, "client nonce mismatch");
            return -1;
        }
        if (ntap_a_db_get_node_auth(cfg->db_file, auth.node_id, &node, err, err_len) != 0 ||
            !node.enabled ||
            ntap_auth_node_sign(node.node_key_secret, server_nonce, auth.client_nonce,
                                auth.node_id, expected_sign) != 0 ||
            !ntap_constant_time_equal(expected_sign, auth.sign, NTAP_HMAC_SHA256_SIZE)) {
            (void)send_auth_fail(fd, err, err_len);
            (void)snprintf(err, err_len, "auth failed for node_id=%s", auth.node_id);
            return 0;
        }

        auth_ok.session_id = (uint32_t)(ntap_time_unix_sec() & 0xffffffffu);
        auth_ok.network_id = (uint32_t)node.network_id;
        auth_ok.server_time = ntap_time_unix_sec();
        auth_ok.feature_bits = 0;
        if (ntap_a_db_get_node_runtime_config(cfg->db_file, auth.node_id,
                                              &runtime_config, err, err_len) != 0 ||
            runtime_config.network_id != node.network_id ||
            ntap_encode_auth_ok(auth_ok_payload, &auth_ok) != 0 ||
            ntap_send_msg(fd, NTAP_MSG_AUTH_OK, auth_ok.session_id,
                          auth_ok_payload, sizeof(auth_ok_payload), err, err_len) != 0 ||
            send_config_push(fd, auth_ok.session_id, &runtime_config, err, err_len) != 0 ||
            ntap_a_db_set_node_online(cfg->db_file, auth.node_id, 1, err, err_len) != 0) {
            return -1;
        }
        {
            ntap_a_session_start_t start;

            start.session_type = "node";
            start.user_id = 0;
            start.node_pk = node.node_pk;
            start.network_id = node.network_id;
            start.remote_addr = remote;
            start.auth_type = "AUTH_NODE";
            if (ntap_a_db_session_start(cfg->db_file, &start,
                                        &db_session_id, err, err_len) != 0) {
                char offline_err[256];

                offline_err[0] = '\0';
                (void)ntap_a_db_set_node_online(cfg->db_file, auth.node_id, 0,
                                                offline_err, sizeof(offline_err));
                return -1;
            }
        }
        if (session_register(fd, auth.node_id, auth_ok.session_id,
                             auth_ok.network_id, node.node_pk, 0, &runtime_config,
                             db_session_id, cfg->db_file, err, err_len) != 0) {
            char cleanup_err[256];

            cleanup_err[0] = '\0';
            (void)ntap_a_db_session_end(cfg->db_file, db_session_id,
                                        "register_failed", cleanup_err,
                                        sizeof(cleanup_err));
            cleanup_err[0] = '\0';
            (void)ntap_a_db_set_node_online(cfg->db_file, auth.node_id, 0,
                                            cleanup_err, sizeof(cleanup_err));
            db_session_id = 0;
            return -1;
        }
        registered = 1;
        authenticated = 1;
        authenticated_is_node = 1;
        (void)snprintf(authenticated_node_id, sizeof(authenticated_node_id),
                       "%s", auth.node_id);
        (void)snprintf(session_name, sizeof(session_name), "%s", auth.node_id);
        (void)printf("ntap-a: node authenticated node_id=%s network_id=%lld\n",
                     auth.node_id, (long long)node.network_id);
        (void)fflush(stdout);
    } else {
        if (recv_expected(fd, NTAP_MSG_AUTH_TAP, &hdr, payload, sizeof(payload),
                          &payload_len, err, err_len) != 0 ||
            ntap_decode_auth_tap(&tap_auth, payload, payload_len) != 0) {
            return -1;
        }
        if (!ntap_constant_time_equal(hello.nonce, tap_auth.client_nonce,
                                      NTAP_NONCE_SIZE)) {
            (void)send_auth_fail(fd, err, err_len);
            (void)snprintf(err, err_len, "client nonce mismatch");
            return -1;
        }
        if (ntap_a_db_get_tap_auth(cfg->db_file, tap_auth.username,
                                   tap_auth.password, (int64_t)tap_auth.network_id,
                                   &tap_user, err, err_len) != 0) {
            (void)send_auth_fail(fd, err, err_len);
            (void)snprintf(err, err_len, "tap auth failed for username=%.128s",
                           tap_auth.username);
            return 0;
        }
        auth_ok.session_id = (uint32_t)(ntap_time_unix_sec() & 0xffffffffu);
        auth_ok.network_id = (uint32_t)tap_user.network_id;
        auth_ok.server_time = ntap_time_unix_sec();
        auth_ok.feature_bits = 0;
        if (ntap_a_db_get_tap_runtime_config(cfg->db_file, tap_user.network_id,
                                             &runtime_config, err, err_len) != 0 ||
            runtime_config.network_id != tap_user.network_id ||
            ntap_encode_auth_ok(auth_ok_payload, &auth_ok) != 0 ||
            ntap_send_msg(fd, NTAP_MSG_AUTH_OK, auth_ok.session_id,
                          auth_ok_payload, sizeof(auth_ok_payload), err, err_len) != 0 ||
            send_config_push(fd, auth_ok.session_id, &runtime_config, err, err_len) != 0) {
            return -1;
        }
        {
            ntap_a_session_start_t start;

            start.session_type = "tap";
            start.user_id = tap_user.tap_user_id;
            start.node_pk = 0;
            start.network_id = tap_user.network_id;
            start.remote_addr = remote;
            start.auth_type = "AUTH_TAP";
            if (ntap_a_db_session_start(cfg->db_file, &start,
                                        &db_session_id, err, err_len) != 0) {
                return -1;
            }
        }
        if (session_register(fd, tap_user.username, auth_ok.session_id,
                             auth_ok.network_id, 0, 1, &runtime_config,
                             db_session_id, cfg->db_file, err, err_len) != 0) {
            char cleanup_err[256];

            cleanup_err[0] = '\0';
            (void)ntap_a_db_session_end(cfg->db_file, db_session_id,
                                        "register_failed", cleanup_err,
                                        sizeof(cleanup_err));
            db_session_id = 0;
            return -1;
        }
        registered = 1;
        authenticated = 1;
        (void)snprintf(session_name, sizeof(session_name), "%s", tap_user.username);
        (void)printf("ntap-a: tap client authenticated username=%s network_id=%lld\n",
                     tap_user.username, (long long)tap_user.network_id);
        (void)fflush(stdout);
    }

    for (;;) {
        if (ntap_recv_msg(fd, &hdr, payload, sizeof(payload), &payload_len,
                          err, err_len) != 0) {
            break;
        }
        if (hdr.type == NTAP_MSG_PING) {
            active_session_t *session = NULL;

            if (authenticated_is_node &&
                ntap_a_db_set_node_online(cfg->db_file, authenticated_node_id,
                                          1, err, err_len) != 0) {
                break;
            }
            if (db_session_id > 0 &&
                ntap_a_db_session_touch(cfg->db_file, db_session_id, 0, 0,
                                        err, err_len) != 0) {
                break;
            }
            mutex_lock(&g_sessions_mu);
            session = session_find_locked(fd, auth_ok.network_id);
            if (session == NULL ||
                session_enqueue_control(session, NTAP_MSG_PONG, NULL, 0,
                                        err, err_len) != 0) {
                mutex_unlock(&g_sessions_mu);
                break;
            }
            mutex_unlock(&g_sessions_mu);
            (void)printf("ntap-a: pong queued session=%s\n", session_name);
            (void)fflush(stdout);
            continue;
        }
        if (hdr.type == NTAP_MSG_TAP_FRAME) {
            ntap_tap_frame_t frame;
            int forwarded = 0;
            const char *relay_mode = "flood";

            if (ntap_decode_tap_frame(&frame, payload, payload_len) != 0 ||
                frame.network_id != auth_ok.network_id) {
                (void)snprintf(err, err_len, "invalid TAP_FRAME from session=%s",
                               session_name);
                break;
            }
            if (db_session_id > 0 &&
                ntap_a_db_session_touch(cfg->db_file, db_session_id,
                                        payload_len, 0, err, err_len) != 0) {
                break;
            }
            forwarded = relay_tap_frame(fd, frame.network_id, &frame, payload, payload_len,
                                        &relay_mode, err, err_len);
            (void)printf("ntap-a: tap frame relayed session=%s network_id=%u forwarded=%d mode=%s\n",
                         session_name, frame.network_id, forwarded, relay_mode);
            (void)fflush(stdout);
            continue;
        }
        if (hdr.type == NTAP_MSG_SOCKS_STREAM_DATA) {
            ntap_socks_data_t data;

            if (ntap_decode_socks_data(&data, payload, payload_len) != 0 ||
                socks_stream_send_to_client(data.stream_id, fd, data.data,
                                            data.data_len, err, err_len) != 0) {
                break;
            }
            continue;
        }
        if (hdr.type == NTAP_MSG_SOCKS_STREAM_CLOSE) {
            ntap_socks_close_t close_msg;

            if (ntap_decode_socks_close(&close_msg, payload, payload_len) != 0) {
                (void)snprintf(err, err_len, "invalid SOCKS_STREAM_CLOSE");
                break;
            }
            socks_stream_unregister(close_msg.stream_id, 1,
                                    socks_close_reason_name(close_msg.reason_code));
            continue;
        }
        {
            (void)snprintf(err, err_len, "unexpected message after auth: %s",
                           ntap_msg_type_name(hdr.type));
            break;
        }
    }

    if (registered) {
        session_unregister(fd);
    }
    if (db_session_id > 0) {
        char session_err[256];

        session_err[0] = '\0';
        if (ntap_a_db_session_end(cfg->db_file, db_session_id, "closed",
                                  session_err, sizeof(session_err)) != 0) {
            (void)fprintf(stderr, "ntap-a: failed to end session: %s\n", session_err);
        }
    }
    if (authenticated && authenticated_is_node) {
        char offline_err[256];

        offline_err[0] = '\0';
        if (ntap_a_db_set_node_online(cfg->db_file, authenticated_node_id, 0,
                                      offline_err, sizeof(offline_err)) != 0) {
            (void)fprintf(stderr, "ntap-a: failed to mark offline: %s\n", offline_err);
        } else {
            (void)printf("ntap-a: node offline node_id=%s\n", authenticated_node_id);
            (void)fflush(stdout);
        }
    } else if (authenticated) {
        (void)printf("ntap-a: tap client offline username=%s\n", session_name);
        (void)fflush(stdout);
    }
    return 0;
}

static int socks_send_method_reply(ntap_socket_t fd, uint8_t method,
                                   char *err, size_t err_len)
{
    uint8_t reply[2] = {0x05u, method};

    return ntap_send_all(fd, reply, sizeof(reply), err, err_len);
}

static int socks_send_auth_reply(ntap_socket_t fd, uint8_t status,
                                 char *err, size_t err_len)
{
    uint8_t reply[2] = {0x01u, status};

    return ntap_send_all(fd, reply, sizeof(reply), err, err_len);
}

static int socks_send_connect_reply(ntap_socket_t fd, uint8_t status,
                                    char *err, size_t err_len)
{
    uint8_t reply[10] = {
        0x05u, status, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u
    };

    return ntap_send_all(fd, reply, sizeof(reply), err, err_len);
}

static int socks5_authenticate(ntap_socket_t fd, const ntap_a_config_t *cfg,
                               ntap_a_socks_auth_t *auth,
                               char *err, size_t err_len)
{
    uint8_t header[2];
    uint8_t methods[255];
    uint8_t auth_header[2];
    uint8_t ulen = 0;
    uint8_t plen = 0;
    char username[NTAP_CONFIG_VALUE_MAX];
    char password[NTAP_CONFIG_VALUE_MAX];
    int i = 0;
    int has_userpass = 0;

    if (auth == NULL) {
        return -1;
    }
    if (ntap_recv_all(fd, header, sizeof(header), err, err_len) != 0 ||
        header[0] != 0x05u || header[1] == 0u ||
        ntap_recv_all(fd, methods, header[1], err, err_len) != 0) {
        (void)snprintf(err, err_len, "invalid SOCKS5 greeting");
        return -1;
    }
    for (i = 0; i < header[1]; i++) {
        if (methods[i] == 0x02u) {
            has_userpass = 1;
            break;
        }
    }
    if (!has_userpass) {
        (void)socks_send_method_reply(fd, 0xffu, err, err_len);
        (void)snprintf(err, err_len, "SOCKS5 username/password method missing");
        return -1;
    }
    if (socks_send_method_reply(fd, 0x02u, err, err_len) != 0 ||
        ntap_recv_all(fd, auth_header, sizeof(auth_header), err, err_len) != 0 ||
        auth_header[0] != 0x01u) {
        (void)snprintf(err, err_len, "invalid SOCKS5 auth header");
        return -1;
    }
    ulen = auth_header[1];
    if (ulen == 0 ||
        ntap_recv_all(fd, username, ulen, err, err_len) != 0 ||
        ntap_recv_all(fd, &plen, 1u, err, err_len) != 0 ||
        plen == 0 ||
        ntap_recv_all(fd, password, plen, err, err_len) != 0) {
        (void)snprintf(err, err_len, "invalid SOCKS5 auth payload");
        return -1;
    }
    username[ulen] = '\0';
    password[plen] = '\0';
    if (ntap_a_db_get_socks_auth(cfg->db_file, username, password, auth,
                                 err, err_len) != 0) {
        (void)socks_send_auth_reply(fd, 0x01u, err, err_len);
        return -1;
    }
    return socks_send_auth_reply(fd, 0x00u, err, err_len);
}

static int socks5_read_connect(ntap_socket_t fd, char *host, size_t host_len,
                               uint16_t *port, char *err, size_t err_len)
{
    uint8_t header[4];
    uint8_t raw_port[2];

    if (host == NULL || host_len == 0 || port == NULL) {
        return -1;
    }
    host[0] = '\0';
    *port = 0;
    if (ntap_recv_all(fd, header, sizeof(header), err, err_len) != 0 ||
        header[0] != 0x05u || header[1] != 0x01u || header[2] != 0x00u) {
        (void)snprintf(err, err_len, "invalid SOCKS5 CONNECT request");
        return -1;
    }
    if (header[3] == 0x01u) {
        uint8_t ip[4];

        if (ntap_recv_all(fd, ip, sizeof(ip), err, err_len) != 0) {
            return -1;
        }
        (void)snprintf(host, host_len, "%u.%u.%u.%u",
                       (unsigned int)ip[0], (unsigned int)ip[1],
                       (unsigned int)ip[2], (unsigned int)ip[3]);
    } else if (header[3] == 0x03u) {
        uint8_t len = 0;

        if (ntap_recv_all(fd, &len, 1u, err, err_len) != 0 ||
            len == 0 || (size_t)len >= host_len ||
            ntap_recv_all(fd, host, len, err, err_len) != 0) {
            (void)snprintf(err, err_len, "invalid SOCKS5 domain");
            return -1;
        }
        host[len] = '\0';
    } else {
        (void)snprintf(err, err_len, "unsupported SOCKS5 atyp");
        return -1;
    }
    if (ntap_recv_all(fd, raw_port, sizeof(raw_port), err, err_len) != 0) {
        return -1;
    }
    *port = (uint16_t)(((uint16_t)raw_port[0] << 8) | raw_port[1]);
    return *port == 0 ? -1 : 0;
}

static void socks_client_run(socks_client_args_t *args)
{
    char err[256];
    ntap_a_socks_auth_t auth;
    ntap_socket_t node_fd = NTAP_INVALID_SOCKET;
    int64_t node_db_session_id = 0;
    int64_t db_stream_id = 0;
    char host[NTAP_SOCKS_HOST_MAX];
    uint16_t port = 0;
    uint32_t stream_id = 0;
    int open_sent = 0;
    uint8_t payload[NTAP_PAYLOAD_MAX_SOCKS];
    uint8_t close_payload[NTAP_SOCKS_DATA_OVERHEAD];
    uint8_t buf[NTAP_A_SOCKS_READ_CHUNK];
    size_t payload_len = 0;
    unsigned int idle_timeout_ms = 0;
    const char *close_reason = "client_closed";

    err[0] = '\0';
    if (socks5_authenticate(args->fd, &args->cfg, &auth, err, sizeof(err)) != 0 ||
        socks5_read_connect(args->fd, host, sizeof(host), &port,
                            err, sizeof(err)) != 0 ||
        socks_active_node_fd(auth.node_pk, &node_fd, &node_db_session_id,
                             err, sizeof(err)) != 0) {
        (void)socks_send_connect_reply(args->fd, 0x01u, err, sizeof(err));
        goto done;
    }
    stream_id = socks_stream_register(auth.node_pk, node_fd, args->fd,
                                      args->cfg.db_file,
                                      auth.max_socks_streams);
    if (stream_id == 0) {
        (void)snprintf(err, sizeof(err), "SOCKS stream limit reached");
        (void)socks_send_connect_reply(args->fd, 0x01u, err, sizeof(err));
        goto done;
    }
    if (ntap_a_db_socks_stream_start(args->cfg.db_file, stream_id,
                                     node_db_session_id, auth.node_pk,
                                     auth.socks_user_id, host, port,
                                     &db_stream_id, err, sizeof(err)) != 0 ||
        ntap_encode_socks_open(payload, sizeof(payload), &payload_len,
                               stream_id, host, port) != 0 ||
        enqueue_socks_to_node(auth.node_pk, NTAP_MSG_SOCKS_STREAM_OPEN,
                              payload, (uint32_t)payload_len, NULL,
                              err, sizeof(err)) != 0) {
        if (stream_id != 0 && db_stream_id > 0) {
            socks_stream_set_db_id(stream_id, db_stream_id);
        }
        (void)socks_send_connect_reply(args->fd, 0x01u, err, sizeof(err));
        goto done;
    }
    socks_stream_set_db_id(stream_id, db_stream_id);
    open_sent = 1;
    if (socks_send_connect_reply(args->fd, 0x00u, err, sizeof(err)) != 0) {
        goto done;
    }
    (void)printf("ntap-a: SOCKS stream open stream_id=%u user=%s node=%s target=%s:%u\n",
                 stream_id, auth.username, auth.node_id, host, port);
    (void)fflush(stdout);
    idle_timeout_ms = socks_idle_timeout_ms(auth.socks_idle_timeout_sec);
    for (;;) {
        int wait_rc = ntap_socket_wait_read(args->fd, idle_timeout_ms,
                                            err, sizeof(err));
        int n = 0;

        if (wait_rc == 1) {
            close_reason = "idle_timeout";
            break;
        }
        if (wait_rc != 0) {
            close_reason = "client_closed";
            break;
        }

        n = recv(args->fd, (char *)buf, (int)sizeof(buf), 0);

        if (n <= 0) {
            break;
        }
        if (ntap_encode_socks_data(payload, sizeof(payload), &payload_len,
                                   stream_id, buf, (uint32_t)n) != 0 ||
            enqueue_socks_to_node(auth.node_pk, NTAP_MSG_SOCKS_STREAM_DATA,
                                  payload, (uint32_t)payload_len, NULL,
                                  err, sizeof(err)) != 0) {
            break;
        }
        if (db_stream_id > 0 &&
            ntap_a_db_socks_stream_touch(args->cfg.db_file, db_stream_id,
                                         (uint32_t)n, 0, err,
                                         sizeof(err)) != 0) {
            break;
        }
    }

done:
    if (stream_id != 0) {
        if (open_sent && ntap_encode_socks_close(close_payload, stream_id) == 0) {
            (void)enqueue_socks_to_node(auth.node_pk, NTAP_MSG_SOCKS_STREAM_CLOSE,
                                        close_payload, sizeof(close_payload),
                                        NULL, err, sizeof(err));
        }
        socks_stream_unregister(stream_id, 0,
                                open_sent ? close_reason : "open_failed");
    }
    ntap_socket_close(args->fd);
    free(args);
}

static void node_session_run(node_session_args_t *args)
{
    char err[256];

    err[0] = '\0';
    (void)printf("ntap-a: accepted %s\n", args->remote);
    (void)fflush(stdout);
    if (handle_node(args->fd, &args->cfg, args->remote, err, sizeof(err)) != 0) {
        (void)fprintf(stderr, "ntap-a: session error: %s\n", err);
    }
    ntap_socket_close(args->fd);
    free(args);
}

#ifdef _WIN32
static DWORD WINAPI node_session_thread_main(LPVOID opaque)
{
    node_session_run((node_session_args_t *)opaque);
    return 0;
}

static int start_session_thread(ntap_thread_t *thread, node_session_args_t *args)
{
    *thread = CreateThread(NULL, 0, node_session_thread_main, args, 0, NULL);
    return *thread == NULL ? -1 : 0;
}

static void join_session_thread(ntap_thread_t thread)
{
    (void)WaitForSingleObject(thread, INFINITE);
    (void)CloseHandle(thread);
}

static void detach_session_thread(ntap_thread_t thread)
{
    (void)CloseHandle(thread);
}
#else
static void *node_session_thread_main(void *opaque)
{
    node_session_run((node_session_args_t *)opaque);
    return NULL;
}

static int start_session_thread(ntap_thread_t *thread, node_session_args_t *args)
{
    return pthread_create(thread, NULL, node_session_thread_main, args);
}

static void join_session_thread(ntap_thread_t thread)
{
    (void)pthread_join(thread, NULL);
}

static void detach_session_thread(ntap_thread_t thread)
{
    (void)pthread_detach(thread);
}
#endif

static void socks_listener_run(socks_listener_args_t *args);

#ifdef _WIN32
static DWORD WINAPI socks_client_thread_main(LPVOID opaque)
{
    socks_client_run((socks_client_args_t *)opaque);
    return 0;
}

static DWORD WINAPI socks_listener_thread_main(LPVOID opaque)
{
    socks_listener_run((socks_listener_args_t *)opaque);
    return 0;
}
#else
static void *socks_client_thread_main(void *opaque)
{
    socks_client_run((socks_client_args_t *)opaque);
    return NULL;
}

static void *socks_listener_thread_main(void *opaque)
{
    socks_listener_run((socks_listener_args_t *)opaque);
    return NULL;
}
#endif

static int start_detached_socks_client(socks_client_args_t *args)
{
    ntap_thread_t thread;

#ifdef _WIN32
    thread = CreateThread(NULL, 0, socks_client_thread_main, args, 0, NULL);
    if (thread == NULL) {
        return -1;
    }
    (void)CloseHandle(thread);
    return 0;
#else
    if (pthread_create(&thread, NULL, socks_client_thread_main, args) != 0) {
        return -1;
    }
    (void)pthread_detach(thread);
    return 0;
#endif
}

static int start_socks_listener_thread(ntap_thread_t *thread,
                                       socks_listener_args_t *args)
{
#ifdef _WIN32
    *thread = CreateThread(NULL, 0, socks_listener_thread_main, args, 0, NULL);
    return *thread == NULL ? -1 : 0;
#else
    return pthread_create(thread, NULL, socks_listener_thread_main, args);
#endif
}

static void join_socks_listener_thread(ntap_thread_t thread)
{
#ifdef _WIN32
    (void)WaitForSingleObject(thread, INFINITE);
    (void)CloseHandle(thread);
#else
    (void)pthread_join(thread, NULL);
#endif
}

static void socks_listener_run(socks_listener_args_t *args)
{
    char err[256];

    err[0] = '\0';
    for (;;) {
        ntap_socket_t client_fd = NTAP_INVALID_SOCKET;
        socks_client_args_t *client = NULL;
        char remote[128];

        if (args->stop) {
            break;
        }
        remote[0] = '\0';
        if (ntap_tcp_accept(args->listen_fd, &client_fd, remote, sizeof(remote),
                            err, sizeof(err)) != 0) {
            break;
        }
        if (args->stop) {
            ntap_socket_close(client_fd);
            break;
        }
        client = (socks_client_args_t *)calloc(1u, sizeof(*client));
        if (client == NULL) {
            ntap_socket_close(client_fd);
            continue;
        }
        client->fd = client_fd;
        client->cfg = args->cfg;
        (void)snprintf(client->remote, sizeof(client->remote), "%s", remote);
        if (start_detached_socks_client(client) != 0) {
            ntap_socket_close(client_fd);
            free(client);
        }
    }
}

int ntap_a_node_server_run(const ntap_a_config_t *cfg, bool once, int max_sessions,
                           char *err, size_t err_len)
{
    ntap_socket_t listen_fd = NTAP_INVALID_SOCKET;
    ntap_socket_t socks_listen_fd = NTAP_INVALID_SOCKET;
    socks_listener_args_t *socks_args = NULL;
    ntap_thread_t socks_thread;
    int socks_thread_started = 0;
    ntap_thread_t *threads = NULL;
    int accepted = 0;
    int joined = 0;
    int rc = 1;

    if (cfg == NULL) {
        return 1;
    }
    if (once) {
        max_sessions = 1;
    }
    if (max_sessions < 0) {
        max_sessions = 0;
    }
    if (ntap_a_db_init(cfg->db_file, err, err_len) != 0 ||
        ntap_net_init(err, err_len) != 0) {
        return 1;
    }
    mutex_init(&g_sessions_mu);
    mutex_init(&g_socks_mu);
    session_registry_reset();
    socks_stream_registry_reset();
    if (max_sessions > 1) {
        threads = (ntap_thread_t *)calloc((size_t)max_sessions, sizeof(*threads));
        if (threads == NULL) {
            (void)snprintf(err, err_len, "failed to allocate thread handles");
            mutex_destroy(&g_socks_mu);
            mutex_destroy(&g_sessions_mu);
            ntap_net_cleanup();
            return 1;
        }
    }
    if (ntap_tcp_listen(cfg->tap_addr, 16, &listen_fd, err, err_len) != 0) {
        free(threads);
        mutex_destroy(&g_socks_mu);
        mutex_destroy(&g_sessions_mu);
        ntap_net_cleanup();
        return 1;
    }
    if (ntap_tcp_listen(cfg->socks_addr, 16, &socks_listen_fd, err, err_len) != 0) {
        ntap_socket_close(listen_fd);
        free(threads);
        mutex_destroy(&g_socks_mu);
        mutex_destroy(&g_sessions_mu);
        ntap_net_cleanup();
        return 1;
    }
    socks_args = (socks_listener_args_t *)calloc(1u, sizeof(*socks_args));
    if (socks_args == NULL) {
        (void)snprintf(err, err_len, "failed to allocate socks listener args");
        ntap_socket_close(socks_listen_fd);
        ntap_socket_close(listen_fd);
        free(threads);
        mutex_destroy(&g_socks_mu);
        mutex_destroy(&g_sessions_mu);
        ntap_net_cleanup();
        return 1;
    }
    socks_args->listen_fd = socks_listen_fd;
    socks_args->cfg = *cfg;
    if (start_socks_listener_thread(&socks_thread, socks_args) != 0) {
        (void)snprintf(err, err_len, "failed to start socks listener thread");
        free(socks_args);
        ntap_socket_close(socks_listen_fd);
        ntap_socket_close(listen_fd);
        free(threads);
        mutex_destroy(&g_socks_mu);
        mutex_destroy(&g_sessions_mu);
        ntap_net_cleanup();
        return 1;
    }
    socks_thread_started = 1;
    (void)printf("ntap-a: listening on %s\n", cfg->tap_addr);
    (void)printf("ntap-a: SOCKS listening on %s\n", cfg->socks_addr);
    (void)fflush(stdout);

    while (max_sessions == 0 || accepted < max_sessions) {
        ntap_socket_t client_fd = NTAP_INVALID_SOCKET;
        node_session_args_t *args = NULL;
        char remote[128];

        remote[0] = '\0';
        if (ntap_tcp_accept(listen_fd, &client_fd, remote, sizeof(remote), err, err_len) != 0) {
            break;
        }
        args = (node_session_args_t *)calloc(1u, sizeof(*args));
        if (args == NULL) {
            (void)snprintf(err, err_len, "failed to allocate session args");
            ntap_socket_close(client_fd);
            break;
        }
        args->fd = client_fd;
        args->cfg = *cfg;
        (void)snprintf(args->remote, sizeof(args->remote), "%s", remote);

        if (max_sessions == 1) {
            node_session_run(args);
            accepted++;
            rc = 0;
            break;
        }

        if (threads != NULL) {
            if (start_session_thread(&threads[accepted], args) != 0) {
                (void)snprintf(err, err_len, "failed to start session thread");
                ntap_socket_close(client_fd);
                free(args);
                break;
            }
        } else {
            ntap_thread_t thread;

            if (start_session_thread(&thread, args) != 0) {
                (void)snprintf(err, err_len, "failed to start session thread");
                ntap_socket_close(client_fd);
                free(args);
                break;
            }
            detach_session_thread(thread);
        }
        accepted++;
        rc = 0;
    }

    for (joined = 0; threads != NULL && joined < accepted; joined++) {
        join_session_thread(threads[joined]);
    }

    if (socks_thread_started) {
        ntap_socket_t wake_fd = NTAP_INVALID_SOCKET;

        if (socks_args != NULL) {
            socks_args->stop = 1;
        }
        (void)ntap_tcp_connect(cfg->socks_addr, &wake_fd, NULL, 0);
        ntap_socket_close(wake_fd);
        ntap_socket_close(socks_listen_fd);
        join_socks_listener_thread(socks_thread);
        free(socks_args);
    } else {
        ntap_socket_close(socks_listen_fd);
    }
    ntap_socket_close(listen_fd);
    free(threads);
    mutex_destroy(&g_socks_mu);
    mutex_destroy(&g_sessions_mu);
    ntap_net_cleanup();
    return rc;
}
