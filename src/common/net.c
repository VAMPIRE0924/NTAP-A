#ifndef _WIN32
#define _POSIX_C_SOURCE 200112L
#endif

#include "common/net.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define NTAP_WAIT_FOREVER 0xffffffffu

static void net_set_err(char *err, size_t err_len, const char *msg)
{
    if (err == NULL || err_len == 0) {
        return;
    }
#ifdef _WIN32
    (void)snprintf(err, err_len, "%s: wsa=%d", msg, WSAGetLastError());
#else
    (void)snprintf(err, err_len, "%s: %s", msg, strerror(errno));
#endif
}

static int net_would_block(void)
{
#ifdef _WIN32
    int rc = WSAGetLastError();

    return rc == WSAEWOULDBLOCK || rc == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

static int net_interrupted(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}

static int wait_socket_ready(ntap_socket_t fd, int want_write,
                             unsigned int timeout_ms,
                             char *err, size_t err_len)
{
    fd_set fds;
    struct timeval tv;
    struct timeval *tvp = NULL;
    int rc = 0;

    for (;;) {
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        if (timeout_ms != NTAP_WAIT_FOREVER) {
            tv.tv_sec = (long)(timeout_ms / 1000u);
            tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);
            tvp = &tv;
        } else {
            tvp = NULL;
        }
#ifdef _WIN32
        rc = select(0, want_write ? NULL : &fds, want_write ? &fds : NULL,
                    NULL, tvp);
#else
        rc = select(fd + 1, want_write ? NULL : &fds, want_write ? &fds : NULL,
                    NULL, tvp);
#endif
        if (rc > 0) {
            return 0;
        }
        if (rc == 0) {
            if (err != NULL && err_len > 0) {
                (void)snprintf(err, err_len, "%s timed out",
                               want_write ? "send wait" : "recv wait");
            }
            return -1;
        }
        if (net_interrupted()) {
            continue;
        }
        net_set_err(err, err_len, want_write ? "send wait failed" : "recv wait failed");
        return -1;
    }
}

static int parse_addr(const char *addr, char *host, size_t host_len, char *port, size_t port_len)
{
    const char *colon = NULL;
    size_t len = 0;

    if (addr == NULL || host == NULL || port == NULL || host_len == 0 || port_len == 0) {
        return -1;
    }
    colon = strrchr(addr, ':');
    if (colon == NULL || colon == addr || colon[1] == '\0') {
        return -1;
    }
    len = (size_t)(colon - addr);
    if (len >= host_len || strlen(colon + 1) >= port_len) {
        return -1;
    }
    (void)memcpy(host, addr, len);
    host[len] = '\0';
    (void)snprintf(port, port_len, "%s", colon + 1);
    return 0;
}

int ntap_net_init(char *err, size_t err_len)
{
#ifdef _WIN32
    WSADATA data;

    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        net_set_err(err, err_len, "WSAStartup failed");
        return -1;
    }
#else
    (void)err;
    (void)err_len;
#endif
    return 0;
}

void ntap_net_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

void ntap_socket_close(ntap_socket_t fd)
{
    if (fd == NTAP_INVALID_SOCKET) {
        return;
    }
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

void ntap_socket_shutdown(ntap_socket_t fd)
{
    if (fd == NTAP_INVALID_SOCKET) {
        return;
    }
#ifdef _WIN32
    (void)shutdown(fd, SD_BOTH);
#else
    (void)shutdown(fd, SHUT_RDWR);
#endif
}

int ntap_socket_set_send_timeout(ntap_socket_t fd, unsigned int timeout_ms,
                                 char *err, size_t err_len)
{
#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv,
                   (int)sizeof(tv)) != 0) {
        net_set_err(err, err_len, "set send timeout failed");
        return -1;
    }
#else
    struct timeval tv;

    tv.tv_sec = (time_t)(timeout_ms / 1000u);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv,
                   (socklen_t)sizeof(tv)) != 0) {
        net_set_err(err, err_len, "set send timeout failed");
        return -1;
    }
#endif
    return 0;
}

int ntap_socket_set_nonblocking(ntap_socket_t fd, int nonblocking,
                                char *err, size_t err_len)
{
#ifdef _WIN32
    u_long mode = nonblocking ? 1ul : 0ul;

    if (ioctlsocket(fd, FIONBIO, &mode) != 0) {
        net_set_err(err, err_len, "set nonblocking failed");
        return -1;
    }
#else
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        net_set_err(err, err_len, "get socket flags failed");
        return -1;
    }
    if (nonblocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    if (fcntl(fd, F_SETFL, flags) != 0) {
        net_set_err(err, err_len, "set nonblocking failed");
        return -1;
    }
#endif
    return 0;
}

int ntap_socket_wait_read(ntap_socket_t fd, unsigned int timeout_ms,
                          char *err, size_t err_len)
{
    fd_set fds;
    struct timeval tv;
    int rc = 0;

    for (;;) {
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = (long)(timeout_ms / 1000u);
        tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);
#ifdef _WIN32
        rc = select(0, &fds, NULL, NULL, &tv);
#else
        rc = select(fd + 1, &fds, NULL, NULL, &tv);
#endif
        if (rc > 0) {
            return 0;
        }
        if (rc == 0) {
            if (err != NULL && err_len > 0) {
                (void)snprintf(err, err_len, "recv wait timed out");
            }
            return 1;
        }
        if (net_interrupted()) {
            continue;
        }
        net_set_err(err, err_len, "recv wait failed");
        return -1;
    }
}

int ntap_tcp_listen(const char *addr, int backlog, ntap_socket_t *out,
                    char *err, size_t err_len)
{
    char host[256];
    char port[32];
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it = NULL;
    ntap_socket_t fd = NTAP_INVALID_SOCKET;
    int yes = 1;

    if (out == NULL || parse_addr(addr, host, sizeof(host), port, sizeof(port)) != 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid listen address");
        }
        return -1;
    }
    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        net_set_err(err, err_len, "getaddrinfo listen failed");
        return -1;
    }
    for (it = res; it != NULL; it = it->ai_next) {
        fd = (ntap_socket_t)socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == NTAP_INVALID_SOCKET) {
            continue;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
        if (bind(fd, it->ai_addr, (int)it->ai_addrlen) == 0 &&
            listen(fd, backlog) == 0) {
            freeaddrinfo(res);
            *out = fd;
            return 0;
        }
        ntap_socket_close(fd);
        fd = NTAP_INVALID_SOCKET;
    }
    freeaddrinfo(res);
    net_set_err(err, err_len, "listen failed");
    return -1;
}

int ntap_tcp_accept(ntap_socket_t listen_fd, ntap_socket_t *out,
                    char *remote, size_t remote_len, char *err, size_t err_len)
{
    struct sockaddr_storage addr;
#ifdef _WIN32
    int addr_len = (int)sizeof(addr);
#else
    socklen_t addr_len = (socklen_t)sizeof(addr);
#endif
    ntap_socket_t fd = NTAP_INVALID_SOCKET;

    if (out == NULL) {
        return -1;
    }
    fd = (ntap_socket_t)accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
    if (fd == NTAP_INVALID_SOCKET) {
        net_set_err(err, err_len, "accept failed");
        return -1;
    }
    if (remote != NULL && remote_len > 0) {
        char host[128];
        char service[32];

        if (getnameinfo((struct sockaddr *)&addr, (socklen_t)addr_len,
                        host, sizeof(host), service, sizeof(service),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            (void)snprintf(remote, remote_len, "%s:%s", host, service);
        } else {
            (void)snprintf(remote, remote_len, "unknown");
        }
    }
    *out = fd;
    return 0;
}

int ntap_tcp_connect(const char *addr, ntap_socket_t *out, char *err, size_t err_len)
{
    char host[256];
    char port[32];
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it = NULL;
    ntap_socket_t fd = NTAP_INVALID_SOCKET;

    if (out == NULL || parse_addr(addr, host, sizeof(host), port, sizeof(port)) != 0) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "invalid connect address");
        }
        return -1;
    }
    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        net_set_err(err, err_len, "getaddrinfo connect failed");
        return -1;
    }
    for (it = res; it != NULL; it = it->ai_next) {
        fd = (ntap_socket_t)socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == NTAP_INVALID_SOCKET) {
            continue;
        }
        if (connect(fd, it->ai_addr, (int)it->ai_addrlen) == 0) {
            freeaddrinfo(res);
            *out = fd;
            return 0;
        }
        ntap_socket_close(fd);
        fd = NTAP_INVALID_SOCKET;
    }
    freeaddrinfo(res);
    net_set_err(err, err_len, "connect failed");
    return -1;
}

int ntap_send_all(ntap_socket_t fd, const void *data, size_t len, char *err, size_t err_len)
{
    const uint8_t *p = (const uint8_t *)data;

    while (len > 0) {
        int chunk = len > 32768u ? 32768 : (int)len;
        int n = send(fd, (const char *)p, chunk, 0);

        if (n <= 0) {
            net_set_err(err, err_len, "send failed");
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int ntap_send_all_timeout(ntap_socket_t fd, const void *data, size_t len,
                          unsigned int stall_timeout_ms,
                          char *err, size_t err_len)
{
    const uint8_t *p = (const uint8_t *)data;

    while (len > 0) {
        int chunk = len > 32768u ? 32768 : (int)len;
        int n = send(fd, (const char *)p, chunk, 0);

        if (n > 0) {
            p += n;
            len -= (size_t)n;
            continue;
        }
        if (n == 0 || net_would_block()) {
            if (wait_socket_ready(fd, 1, stall_timeout_ms, err, err_len) != 0) {
                return -1;
            }
            continue;
        }
        net_set_err(err, err_len, "send failed");
        return -1;
    }
    return 0;
}

int ntap_recv_all(ntap_socket_t fd, void *data, size_t len, char *err, size_t err_len)
{
    uint8_t *p = (uint8_t *)data;

    while (len > 0) {
        int chunk = len > 32768u ? 32768 : (int)len;
        int n = recv(fd, (char *)p, chunk, 0);

        if (n == 0) {
            if (err != NULL && err_len > 0) {
                (void)snprintf(err, err_len, "connection closed");
            }
            return -1;
        }
        if (n < 0) {
            if (net_would_block()) {
                if (wait_socket_ready(fd, 0, NTAP_WAIT_FOREVER, err, err_len) != 0) {
                    return -1;
                }
                continue;
            }
            net_set_err(err, err_len, "recv failed");
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int ntap_send_msg_timeout(ntap_socket_t fd, uint8_t type, uint32_t session_id,
                          const void *payload, uint32_t payload_len,
                          unsigned int stall_timeout_ms,
                          char *err, size_t err_len)
{
    ntap_hdr_t hdr = {NTAP_MAGIC, NTAP_VERSION, type, 0, session_id, payload_len};
    uint8_t raw[NTAP_HDR_SIZE];

    if (payload_len > 0 && payload == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "payload is null");
        }
        return -1;
    }
    if (ntap_hdr_encode(raw, &hdr) != NTAP_OK) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "header encode failed");
        }
        return -1;
    }
    if (ntap_send_all_timeout(fd, raw, sizeof(raw), stall_timeout_ms,
                              err, err_len) != 0) {
        return -1;
    }
    if (payload_len > 0 &&
        ntap_send_all_timeout(fd, payload, payload_len, stall_timeout_ms,
                              err, err_len) != 0) {
        return -1;
    }
    return 0;
}

int ntap_send_msg(ntap_socket_t fd, uint8_t type, uint32_t session_id,
                  const void *payload, uint32_t payload_len, char *err, size_t err_len)
{
    ntap_hdr_t hdr = {NTAP_MAGIC, NTAP_VERSION, type, 0, session_id, payload_len};
    uint8_t raw[NTAP_HDR_SIZE];

    if (payload_len > 0 && payload == NULL) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "payload is null");
        }
        return -1;
    }
    if (ntap_hdr_encode(raw, &hdr) != NTAP_OK) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "header encode failed");
        }
        return -1;
    }
    if (ntap_send_all(fd, raw, sizeof(raw), err, err_len) != 0) {
        return -1;
    }
    if (payload_len > 0 &&
        ntap_send_all(fd, payload, payload_len, err, err_len) != 0) {
        return -1;
    }
    return 0;
}

int ntap_recv_msg(ntap_socket_t fd, ntap_hdr_t *hdr, uint8_t *payload,
                  size_t payload_cap, size_t *payload_len, char *err, size_t err_len)
{
    uint8_t raw[NTAP_HDR_SIZE];
    int rc = 0;

    if (hdr == NULL || payload_len == NULL) {
        return -1;
    }
    if (ntap_recv_all(fd, raw, sizeof(raw), err, err_len) != 0) {
        return -1;
    }
    rc = ntap_hdr_decode(hdr, raw);
    if (rc != NTAP_OK) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "bad header: %s", ntap_result_name(rc));
        }
        return -1;
    }
    if (!ntap_payload_length_allowed(hdr->type, hdr->length, NTAP_DEFAULT_MTU)) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "payload too large");
        }
        return -1;
    }
    if (hdr->length > payload_cap || (hdr->length > 0 && payload == NULL)) {
        if (err != NULL && err_len > 0) {
            (void)snprintf(err, err_len, "payload buffer too small");
        }
        return -1;
    }
    if (hdr->length > 0 &&
        ntap_recv_all(fd, payload, hdr->length, err, err_len) != 0) {
        return -1;
    }
    *payload_len = hdr->length;
    return 0;
}
