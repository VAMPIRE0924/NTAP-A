#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "common/ntap_time.h"

#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

uint64_t ntap_time_unix_sec(void)
{
    return (uint64_t)time(NULL);
}

uint64_t ntap_time_unix_msec(void)
{
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER value;

    GetSystemTimeAsFileTime(&ft);
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return (value.QuadPart / 10000u) - 11644473600000ull;
#else
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return ntap_time_unix_sec() * 1000u;
    }
    return ((uint64_t)ts.tv_sec * 1000u) + ((uint64_t)ts.tv_nsec / 1000000u);
#endif
}
