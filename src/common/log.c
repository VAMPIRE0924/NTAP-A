#include "common/log.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static ntap_log_level_t g_log_level = NTAP_LOG_INFO;

static int equals_ignore_case(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

ntap_log_level_t ntap_log_level_from_string(const char *value)
{
    if (value == NULL || *value == '\0') {
        return NTAP_LOG_INFO;
    }
    if (equals_ignore_case(value, "debug")) {
        return NTAP_LOG_DEBUG;
    }
    if (equals_ignore_case(value, "info")) {
        return NTAP_LOG_INFO;
    }
    if (equals_ignore_case(value, "warn") || equals_ignore_case(value, "warning")) {
        return NTAP_LOG_WARN;
    }
    if (equals_ignore_case(value, "error")) {
        return NTAP_LOG_ERROR;
    }
    if (equals_ignore_case(value, "none") || equals_ignore_case(value, "off")) {
        return NTAP_LOG_NONE;
    }
    return NTAP_LOG_INFO;
}

const char *ntap_log_level_name(ntap_log_level_t level)
{
    switch (level) {
    case NTAP_LOG_DEBUG:
        return "debug";
    case NTAP_LOG_INFO:
        return "info";
    case NTAP_LOG_WARN:
        return "warn";
    case NTAP_LOG_ERROR:
        return "error";
    case NTAP_LOG_NONE:
        return "none";
    default:
        return "unknown";
    }
}

void ntap_log_set_level(ntap_log_level_t level)
{
    g_log_level = level;
}

void ntap_log_vmsg(ntap_log_level_t level, const char *fmt, va_list ap)
{
    time_t now = 0;
    struct tm *tm_now = NULL;
    char ts[32];

    if (level < g_log_level || level == NTAP_LOG_NONE) {
        return;
    }

    now = time(NULL);
    tm_now = localtime(&now);
    if (tm_now != NULL) {
        (void)strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_now);
    } else {
        (void)snprintf(ts, sizeof(ts), "unknown-time");
    }

    (void)fprintf(stderr, "%s %-5s ", ts, ntap_log_level_name(level));
    (void)vfprintf(stderr, fmt, ap);
    (void)fprintf(stderr, "\n");
}

void ntap_log_msg(ntap_log_level_t level, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    ntap_log_vmsg(level, fmt, ap);
    va_end(ap);
}
