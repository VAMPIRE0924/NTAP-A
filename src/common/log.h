#ifndef NTAP_COMMON_LOG_H
#define NTAP_COMMON_LOG_H

#include <stdarg.h>

typedef enum ntap_log_level {
    NTAP_LOG_DEBUG = 0,
    NTAP_LOG_INFO = 1,
    NTAP_LOG_WARN = 2,
    NTAP_LOG_ERROR = 3,
    NTAP_LOG_NONE = 4
} ntap_log_level_t;

ntap_log_level_t ntap_log_level_from_string(const char *value);
const char *ntap_log_level_name(ntap_log_level_t level);
void ntap_log_set_level(ntap_log_level_t level);
void ntap_log_msg(ntap_log_level_t level, const char *fmt, ...);
void ntap_log_vmsg(ntap_log_level_t level, const char *fmt, va_list ap);

#endif
