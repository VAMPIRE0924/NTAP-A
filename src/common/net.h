#ifndef NTAP_COMMON_NET_H
#define NTAP_COMMON_NET_H

#include <stddef.h>
#include <stdint.h>

#include "common/proto.h"

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET ntap_socket_t;
#define NTAP_INVALID_SOCKET INVALID_SOCKET
#else
typedef int ntap_socket_t;
#define NTAP_INVALID_SOCKET (-1)
#endif

int ntap_net_init(char *err, size_t err_len);
void ntap_net_cleanup(void);
void ntap_socket_close(ntap_socket_t fd);
void ntap_socket_shutdown(ntap_socket_t fd);
void ntap_socket_shutdown_send(ntap_socket_t fd);
int ntap_socket_set_send_timeout(ntap_socket_t fd, unsigned int timeout_ms,
                                 char *err, size_t err_len);
int ntap_socket_set_nonblocking(ntap_socket_t fd, int nonblocking,
                                char *err, size_t err_len);
/* Returns 0 when readable, 1 on timeout, and -1 on socket/select error. */
int ntap_socket_wait_read(ntap_socket_t fd, unsigned int timeout_ms,
                          char *err, size_t err_len);

int ntap_tcp_listen(const char *addr, int backlog, ntap_socket_t *out,
                    char *err, size_t err_len);
int ntap_tcp_accept(ntap_socket_t listen_fd, ntap_socket_t *out,
                    char *remote, size_t remote_len, char *err, size_t err_len);
int ntap_tcp_connect(const char *addr, ntap_socket_t *out, char *err, size_t err_len);
int ntap_tcp_connect_timeout(const char *addr, unsigned int timeout_ms,
                             ntap_socket_t *out, char *err, size_t err_len);

int ntap_send_all(ntap_socket_t fd, const void *data, size_t len, char *err, size_t err_len);
int ntap_send_all_timeout(ntap_socket_t fd, const void *data, size_t len,
                          unsigned int stall_timeout_ms,
                          char *err, size_t err_len);
int ntap_recv_all(ntap_socket_t fd, void *data, size_t len, char *err, size_t err_len);
int ntap_send_msg(ntap_socket_t fd, uint8_t type, uint32_t session_id,
                  const void *payload, uint32_t payload_len, char *err, size_t err_len);
int ntap_send_msg_timeout(ntap_socket_t fd, uint8_t type, uint32_t session_id,
                          const void *payload, uint32_t payload_len,
                          unsigned int stall_timeout_ms,
                          char *err, size_t err_len);
int ntap_recv_msg(ntap_socket_t fd, ntap_hdr_t *hdr, uint8_t *payload,
                  size_t payload_cap, size_t *payload_len, char *err, size_t err_len);

#endif
