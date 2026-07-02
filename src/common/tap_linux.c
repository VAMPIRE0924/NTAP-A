#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "common/tap.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>

#define NTAP_NET_CLASS_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NTAP_NET_CONNECTION_ROOT \
    "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_WIN_CONTROL_CODE(request, method) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS TAP_WIN_CONTROL_CODE(6, METHOD_BUFFERED)

static void tap_win_set_err(char *err, size_t err_len, const char *prefix)
{
    if (err == NULL || err_len == 0) {
        return;
    }
    (void)snprintf(err, err_len, "%s: winerr=%lu", prefix, GetLastError());
}

static char tap_win_lower_ascii(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (char)(ch - 'A' + 'a');
    }
    return ch;
}

static int tap_win_contains_ci(const char *haystack, const char *needle)
{
    size_t needle_len = 0;
    size_t i = 0;

    if (haystack == NULL || needle == NULL) {
        return 0;
    }
    needle_len = strlen(needle);
    if (needle_len == 0) {
        return 1;
    }
    for (i = 0; haystack[i] != '\0'; i++) {
        size_t j = 0;

        for (j = 0; j < needle_len; j++) {
            if (haystack[i + j] == '\0' ||
                tap_win_lower_ascii(haystack[i + j]) != tap_win_lower_ascii(needle[j])) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static int tap_win_streq_ci(const char *a, const char *b)
{
    size_t i = 0;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0; a[i] != '\0' && b[i] != '\0'; i++) {
        if (tap_win_lower_ascii(a[i]) != tap_win_lower_ascii(b[i])) {
            return 0;
        }
    }
    return a[i] == '\0' && b[i] == '\0';
}

static int tap_win_query_reg_string(HKEY key, const char *value_name,
                                    char *out, size_t out_len)
{
    DWORD type = 0;
    DWORD bytes = 0;
    LONG rc = ERROR_SUCCESS;

    if (out == NULL || out_len == 0) {
        return 1;
    }
    out[0] = '\0';
    bytes = (DWORD)out_len;
    rc = RegQueryValueExA(key, value_name, NULL, &type, (LPBYTE)out, &bytes);
    if (rc != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ)) {
        out[0] = '\0';
        return 1;
    }
    out[out_len - 1u] = '\0';
    return 0;
}

static void tap_win_query_connection_name(const char *guid, char *out, size_t out_len)
{
    char key_path[384];
    HKEY key = NULL;

    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (guid == NULL || *guid == '\0') {
        return;
    }
    (void)snprintf(key_path, sizeof(key_path), "%s\\%s\\Connection",
                   NTAP_NET_CONNECTION_ROOT, guid);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return;
    }
    (void)tap_win_query_reg_string(key, "Name", out, out_len);
    RegCloseKey(key);
}

static int tap_win_is_tap_windows(const char *component_id,
                                  const char *matching_id,
                                  const char *driver_desc)
{
    return tap_win_contains_ci(component_id, "tap") ||
           tap_win_contains_ci(matching_id, "tap") ||
           tap_win_contains_ci(driver_desc, "tap");
}

static int tap_win_is_tun_only(const char *component_id,
                               const char *matching_id,
                               const char *driver_desc)
{
    return tap_win_contains_ci(component_id, "wintun") ||
           tap_win_contains_ci(matching_id, "wintun") ||
           tap_win_contains_ci(driver_desc, "wintun") ||
           tap_win_contains_ci(component_id, "wireguard") ||
           tap_win_contains_ci(matching_id, "wireguard") ||
           tap_win_contains_ci(driver_desc, "wireguard");
}

static int tap_win_adapter_matches(const char *requested,
                                   const char *guid,
                                   const char *connection_name,
                                   const char *driver_desc)
{
    if (requested == NULL || *requested == '\0') {
        return 0;
    }
    return tap_win_streq_ci(requested, guid) ||
           tap_win_streq_ci(requested, connection_name) ||
           tap_win_streq_ci(requested, driver_desc);
}

static int tap_win_find_adapter(const char *requested_name, char *guid_out,
                                size_t guid_out_len, char *display_out,
                                size_t display_out_len, char *err, size_t err_len)
{
    HKEY class_key = NULL;
    DWORD index = 0;
    unsigned int supported_count = 0;
    unsigned int tun_only_count = 0;
    char first_guid[128];
    char first_display[256];
    LONG open_rc = ERROR_SUCCESS;

    if (guid_out == NULL || guid_out_len == 0) {
        return -1;
    }
    guid_out[0] = '\0';
    if (display_out != NULL && display_out_len > 0) {
        display_out[0] = '\0';
    }
    first_guid[0] = '\0';
    first_display[0] = '\0';

    open_rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, NTAP_NET_CLASS_KEY, 0,
                            KEY_READ, &class_key);
    if (open_rc != ERROR_SUCCESS) {
        (void)snprintf(err, err_len, "open network adapter registry failed: winerr=%ld",
                       (long)open_rc);
        return -1;
    }

    for (;;) {
        char subkey_name[128];
        DWORD subkey_len = (DWORD)sizeof(subkey_name);
        HKEY adapter_key = NULL;
        char component_id[256];
        char matching_id[256];
        char driver_desc[256];
        char guid[128];
        char connection_name[256];
        const char *display_name = NULL;
        int supported = 0;
        LONG enum_rc = ERROR_SUCCESS;

        enum_rc = RegEnumKeyExA(class_key, index, subkey_name, &subkey_len,
                                NULL, NULL, NULL, NULL);
        if (enum_rc == ERROR_NO_MORE_ITEMS) {
            break;
        }
        index++;
        if (enum_rc != ERROR_SUCCESS ||
            RegOpenKeyExA(class_key, subkey_name, 0, KEY_READ, &adapter_key) != ERROR_SUCCESS) {
            continue;
        }

        (void)tap_win_query_reg_string(adapter_key, "ComponentId",
                                       component_id, sizeof(component_id));
        (void)tap_win_query_reg_string(adapter_key, "MatchingDeviceId",
                                       matching_id, sizeof(matching_id));
        (void)tap_win_query_reg_string(adapter_key, "DriverDesc",
                                       driver_desc, sizeof(driver_desc));
        (void)tap_win_query_reg_string(adapter_key, "NetCfgInstanceId",
                                       guid, sizeof(guid));
        tap_win_query_connection_name(guid, connection_name, sizeof(connection_name));
        display_name = connection_name[0] != '\0' ? connection_name : driver_desc;
        supported = tap_win_is_tap_windows(component_id, matching_id, driver_desc);
        if (!supported && tap_win_is_tun_only(component_id, matching_id, driver_desc)) {
            tun_only_count++;
        }
        if (supported && guid[0] != '\0') {
            supported_count++;
            if (first_guid[0] == '\0') {
                (void)snprintf(first_guid, sizeof(first_guid), "%s", guid);
                (void)snprintf(first_display, sizeof(first_display), "%s",
                               display_name == NULL || *display_name == '\0' ?
                               guid : display_name);
            }
            if (tap_win_adapter_matches(requested_name, guid, connection_name, driver_desc)) {
                (void)snprintf(guid_out, guid_out_len, "%s", guid);
                if (display_out != NULL && display_out_len > 0) {
                    (void)snprintf(display_out, display_out_len, "%s",
                                   display_name == NULL || *display_name == '\0' ?
                                   guid : display_name);
                }
                RegCloseKey(adapter_key);
                RegCloseKey(class_key);
                return 0;
            }
        }
        RegCloseKey(adapter_key);
    }
    RegCloseKey(class_key);

    if (supported_count == 1 && first_guid[0] != '\0') {
        (void)snprintf(guid_out, guid_out_len, "%s", first_guid);
        if (display_out != NULL && display_out_len > 0) {
            (void)snprintf(display_out, display_out_len, "%s", first_display);
        }
        return 0;
    }
    if (supported_count > 1) {
        (void)snprintf(err, err_len,
                       "TAP-Windows adapter not found for tap_name=%s; multiple adapters exist",
                       requested_name == NULL || *requested_name == '\0' ? "<empty>" : requested_name);
        return -1;
    }
    if (tun_only_count > 0) {
        (void)snprintf(err, err_len,
                       "only Wintun/WireGuard adapters found; TAP-Windows6 is required for this backend");
        return -1;
    }
    (void)snprintf(err, err_len, "no TAP-Windows adapter found");
    return -1;
}

static int tap_win_overlapped_readwrite(HANDLE handle, HANDLE event_handle,
                                        int is_write, uint8_t *buf,
                                        const uint8_t *write_buf, size_t len,
                                        DWORD *done, char *err, size_t err_len)
{
    OVERLAPPED ov;
    BOOL ok = FALSE;
    DWORD bytes = 0;
    DWORD wait_rc = 0;

    if (done != NULL) {
        *done = 0;
    }
    if (len > 0xffffffffu) {
        (void)snprintf(err, err_len, "TAP I/O buffer too large");
        return -1;
    }
    (void)memset(&ov, 0, sizeof(ov));
    ov.hEvent = event_handle;
    (void)ResetEvent(event_handle);
    if (is_write) {
        ok = WriteFile(handle, write_buf, (DWORD)len, &bytes, &ov);
    } else {
        ok = ReadFile(handle, buf, (DWORD)len, &bytes, &ov);
    }
    if (!ok) {
        DWORD winerr = GetLastError();

        if (winerr != ERROR_IO_PENDING) {
            tap_win_set_err(err, err_len, is_write ? "write TAP failed" : "read TAP failed");
            return -1;
        }
        wait_rc = WaitForSingleObject(event_handle, INFINITE);
        if (wait_rc != WAIT_OBJECT_0) {
            tap_win_set_err(err, err_len, is_write ? "wait TAP write failed" : "wait TAP read failed");
            (void)CancelIo(handle);
            return -1;
        }
        if (!GetOverlappedResult(handle, &ov, &bytes, FALSE)) {
            tap_win_set_err(err, err_len, is_write ? "finish TAP write failed" : "finish TAP read failed");
            return -1;
        }
    }
    if (done != NULL) {
        *done = bytes;
    }
    return 0;
}

int ntap_tap_open(ntap_tap_t *tap, const char *name, uint16_t mtu,
                  char *err, size_t err_len)
{
    char guid[128];
    char display_name[256];
    char device_path[320];
    HANDLE handle = INVALID_HANDLE_VALUE;
    ULONG status = TRUE;
    DWORD len = 0;

    (void)mtu;
    if (tap == NULL) {
        (void)snprintf(err, err_len, "invalid TAP handle");
        return -1;
    }
    (void)memset(tap, 0, sizeof(*tap));
    tap->fd = -1;
    tap->handle = INVALID_HANDLE_VALUE;
    tap->read_event = NULL;
    tap->write_event = NULL;
    if (tap_win_find_adapter(name, guid, sizeof(guid), display_name,
                             sizeof(display_name), err, err_len) != 0) {
        return -1;
    }
    (void)snprintf(device_path, sizeof(device_path), "\\\\.\\Global\\%s.tap", guid);
    handle = CreateFileA(device_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                         NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        tap_win_set_err(err, err_len, "open TAP-Windows device failed");
        return -1;
    }
    tap->read_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    tap->write_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (tap->read_event == NULL || tap->write_event == NULL) {
        tap_win_set_err(err, err_len, "create TAP event failed");
        ntap_tap_close(tap);
        CloseHandle(handle);
        return -1;
    }
    tap->handle = handle;
    if (!DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status), &status, sizeof(status),
                         &len, NULL)) {
        tap_win_set_err(err, err_len, "set TAP media status failed");
        ntap_tap_close(tap);
        return -1;
    }
    (void)snprintf(tap->name, sizeof(tap->name), "%s",
                   display_name[0] == '\0' ? guid : display_name);
    return 0;
}

int ntap_tap_read(ntap_tap_t *tap, uint8_t *buf, size_t cap, size_t *len,
                  char *err, size_t err_len)
{
    DWORD got = 0;

    if (tap == NULL || tap->handle == INVALID_HANDLE_VALUE ||
        tap->read_event == NULL || buf == NULL || len == NULL) {
        (void)snprintf(err, err_len, "invalid TAP read arguments");
        return -1;
    }
    if (tap_win_overlapped_readwrite((HANDLE)tap->handle, (HANDLE)tap->read_event,
                                     0, buf, NULL, cap, &got, err, err_len) != 0) {
        return -1;
    }
    *len = (size_t)got;
    return 0;
}

int ntap_tap_write(ntap_tap_t *tap, const uint8_t *buf, size_t len,
                   char *err, size_t err_len)
{
    DWORD done = 0;

    if (tap == NULL || tap->handle == INVALID_HANDLE_VALUE ||
        tap->write_event == NULL || buf == NULL || len == 0) {
        (void)snprintf(err, err_len, "invalid TAP write arguments");
        return -1;
    }
    if (tap_win_overlapped_readwrite((HANDLE)tap->handle, (HANDLE)tap->write_event,
                                     1, NULL, buf, len, &done, err, err_len) != 0) {
        return -1;
    }
    if ((size_t)done != len) {
        (void)snprintf(err, err_len, "short TAP write");
        return -1;
    }
    return 0;
}

int ntap_tap_attach_bridge(ntap_tap_t *tap, const char *bridge_name,
                           char *err, size_t err_len)
{
    (void)tap;
    (void)bridge_name;
    (void)snprintf(err, err_len, "TAP bridge attach is not supported on Windows in current phase");
    return -1;
}

void ntap_tap_interrupt(ntap_tap_t *tap)
{
    if (tap == NULL || tap->handle == INVALID_HANDLE_VALUE) {
        return;
    }
    (void)CancelIoEx((HANDLE)tap->handle, NULL);
}

void ntap_tap_close(ntap_tap_t *tap)
{
    if (tap != NULL) {
        if (tap->handle != INVALID_HANDLE_VALUE) {
            (void)CancelIoEx((HANDLE)tap->handle, NULL);
            CloseHandle((HANDLE)tap->handle);
            tap->handle = INVALID_HANDLE_VALUE;
        }
        if (tap->read_event != NULL) {
            CloseHandle((HANDLE)tap->read_event);
            tap->read_event = NULL;
        }
        if (tap->write_event != NULL) {
            CloseHandle((HANDLE)tap->write_event);
            tap->write_event = NULL;
        }
        tap->fd = -1;
        tap->name[0] = '\0';
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

void ntap_tap_interrupt(ntap_tap_t *tap)
{
    (void)tap;
}
#endif
