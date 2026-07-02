#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "common/tap.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
int ntap_tap_open(ntap_tap_t *tap, const char *name, uint16_t mtu,
                  char *err, size_t err_len)
{
    (void)tap;
    (void)name;
    (void)mtu;
    (void)snprintf(err, err_len, "TAP is not supported on Windows in current phase");
    return -1;
}

int ntap_tap_read(ntap_tap_t *tap, uint8_t *buf, size_t cap, size_t *len,
                  char *err, size_t err_len)
{
    (void)tap;
    (void)buf;
    (void)cap;
    (void)len;
    (void)snprintf(err, err_len, "TAP is not supported on Windows in current phase");
    return -1;
}

int ntap_tap_write(ntap_tap_t *tap, const uint8_t *buf, size_t len,
                   char *err, size_t err_len)
{
    (void)tap;
    (void)buf;
    (void)len;
    (void)snprintf(err, err_len, "TAP is not supported on Windows in current phase");
    return -1;
}

int ntap_tap_attach_bridge(ntap_tap_t *tap, const char *bridge_name,
                           char *err, size_t err_len)
{
    (void)tap;
    (void)bridge_name;
    (void)snprintf(err, err_len, "TAP bridge attach is not supported on Windows in current phase");
    return -1;
}

void ntap_tap_close(ntap_tap_t *tap)
{
    if (tap != NULL) {
        tap->fd = -1;
    }
}
#else
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static void tap_set_err(char *err, size_t err_len, const char *prefix)
{
    if (err == NULL || err_len == 0) {
        return;
    }
    (void)snprintf(err, err_len, "%s: %s", prefix, strerror(errno));
}

static int tap_fill_ifreq_name(struct ifreq *ifr, const char *name, char *err, size_t err_len)
{
    size_t len = 0;

    if (ifr == NULL || name == NULL || *name == '\0') {
        (void)snprintf(err, err_len, "invalid TAP name");
        return -1;
    }
    len = strlen(name);
    if (len >= IFNAMSIZ) {
        (void)snprintf(err, err_len, "TAP name too long: %s", name);
        return -1;
    }
    (void)memset(ifr, 0, sizeof(*ifr));
    (void)memcpy(ifr->ifr_name, name, len + 1u);
    return 0;
}

static int tap_set_mtu(const char *name, uint16_t mtu, char *err, size_t err_len)
{
    int ctl = -1;
    struct ifreq ifr;

    ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) {
        tap_set_err(err, err_len, "socket mtu failed");
        return -1;
    }
    if (tap_fill_ifreq_name(&ifr, name, err, err_len) != 0) {
        close(ctl);
        return -1;
    }
    ifr.ifr_mtu = (int)mtu;
    if (ioctl(ctl, SIOCSIFMTU, &ifr) < 0) {
        tap_set_err(err, err_len, "set TAP mtu failed");
        close(ctl);
        return -1;
    }
    close(ctl);
    return 0;
}

static int tap_set_up(const char *name, char *err, size_t err_len)
{
    int ctl = -1;
    struct ifreq ifr;

    ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) {
        tap_set_err(err, err_len, "socket flags failed");
        return -1;
    }
    if (tap_fill_ifreq_name(&ifr, name, err, err_len) != 0) {
        close(ctl);
        return -1;
    }
    if (ioctl(ctl, SIOCGIFFLAGS, &ifr) < 0) {
        tap_set_err(err, err_len, "get TAP flags failed");
        close(ctl);
        return -1;
    }
    ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
    if (ioctl(ctl, SIOCSIFFLAGS, &ifr) < 0) {
        tap_set_err(err, err_len, "set TAP up failed");
        close(ctl);
        return -1;
    }
    close(ctl);
    return 0;
}

int ntap_tap_open(ntap_tap_t *tap, const char *name, uint16_t mtu,
                  char *err, size_t err_len)
{
    int fd = -1;
    struct ifreq ifr;

    if (tap == NULL) {
        (void)snprintf(err, err_len, "invalid TAP handle");
        return -1;
    }
    if (tap_fill_ifreq_name(&ifr, name, err, err_len) != 0) {
        return -1;
    }
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        tap_set_err(err, err_len, "open /dev/net/tun failed");
        return -1;
    }
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        tap_set_err(err, err_len, "create TAP failed");
        close(fd);
        return -1;
    }
    if (tap_set_mtu(ifr.ifr_name, mtu, err, err_len) != 0 ||
        tap_set_up(ifr.ifr_name, err, err_len) != 0) {
        close(fd);
        return -1;
    }
    tap->fd = fd;
    (void)snprintf(tap->name, sizeof(tap->name), "%s", ifr.ifr_name);
    return 0;
}

int ntap_tap_attach_bridge(ntap_tap_t *tap, const char *bridge_name,
                           char *err, size_t err_len)
{
    int ctl = -1;
    struct ifreq ifr;
    unsigned int tap_index = 0;

    if (bridge_name == NULL || *bridge_name == '\0') {
        return 0;
    }
    if (tap == NULL || tap->fd < 0 || tap->name[0] == '\0') {
        (void)snprintf(err, err_len, "invalid TAP bridge attach arguments");
        return -1;
    }
    if (strlen(bridge_name) >= IFNAMSIZ) {
        (void)snprintf(err, err_len, "bridge name too long: %s", bridge_name);
        return -1;
    }
    errno = 0;
    if (if_nametoindex(bridge_name) == 0u) {
        (void)snprintf(err, err_len, "bridge interface not found: %s", bridge_name);
        return -1;
    }
    errno = 0;
    tap_index = if_nametoindex(tap->name);
    if (tap_index == 0u) {
        (void)snprintf(err, err_len, "TAP interface not found: %s", tap->name);
        return -1;
    }

    ctl = socket(AF_INET, SOCK_STREAM, 0);
    if (ctl < 0) {
        tap_set_err(err, err_len, "socket bridge attach failed");
        return -1;
    }
    (void)memset(&ifr, 0, sizeof(ifr));
    (void)snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", bridge_name);
    ifr.ifr_ifindex = (int)tap_index;
    if (ioctl(ctl, SIOCBRADDIF, &ifr) < 0) {
        tap_set_err(err, err_len, "attach TAP to bridge failed");
        close(ctl);
        return -1;
    }
    close(ctl);
    return 0;
}

int ntap_tap_read(ntap_tap_t *tap, uint8_t *buf, size_t cap, size_t *len,
                  char *err, size_t err_len)
{
    ssize_t n = 0;

    if (tap == NULL || tap->fd < 0 || buf == NULL || len == NULL) {
        (void)snprintf(err, err_len, "invalid TAP read arguments");
        return -1;
    }
    n = read(tap->fd, buf, cap);
    if (n < 0) {
        tap_set_err(err, err_len, "read TAP failed");
        return -1;
    }
    *len = (size_t)n;
    return 0;
}

int ntap_tap_write(ntap_tap_t *tap, const uint8_t *buf, size_t len,
                   char *err, size_t err_len)
{
    ssize_t n = 0;

    if (tap == NULL || tap->fd < 0 || buf == NULL || len == 0) {
        (void)snprintf(err, err_len, "invalid TAP write arguments");
        return -1;
    }
    n = write(tap->fd, buf, len);
    if (n < 0 || (size_t)n != len) {
        tap_set_err(err, err_len, "write TAP failed");
        return -1;
    }
    return 0;
}

void ntap_tap_close(ntap_tap_t *tap)
{
    if (tap == NULL || tap->fd < 0) {
        return;
    }
    close(tap->fd);
    tap->fd = -1;
    tap->name[0] = '\0';
}
#endif
